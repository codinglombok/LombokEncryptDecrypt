/**
 * LombokEncryptDecrypt — Streaming Encrypt / Decrypt
 *
 * Chunk-by-chunk AEAD encryption for files of unlimited size.
 * Each chunk is independently authenticated (prevents truncation attacks).
 *
 * Format per chunk:
 *   [4-byte big-endian chunk index] [12-byte IV] [ciphertext] [16-byte tag]
 *
 * Final block:
 *   [4-byte 0xFFFFFFFF sentinel] [16-byte empty tag] — signals end-of-stream
 *
 * @module stream/encrypt_stream
 */

import type { StreamEncryptOptions } from '../../types.js';
import { STREAM_CHUNK_SIZE } from '../../constants.js';
import { randomIv } from '../../utils/random.js';
import { aesGcm } from '../../modes/gcm.js';
import { chaCha20Poly1305 } from '../core/chacha/chacha20.js';
import { concatBytes } from '../../utils/encoding.js';
import { LombokCryptoError, ErrorCode } from '../../errors.js';

export interface StreamEncryptState {
  readonly algorithm: string;
  readonly key: Uint8Array;
  readonly aad: Uint8Array | undefined;
  readonly chunkSize: number;
  chunkIndex: number;
  buffer: Uint8Array;
  finalised: boolean;
}

// ── Chunk AEAD encrypt ────────────────────────────────────────────────────

async function encryptChunk(
  state: StreamEncryptState,
  chunk: Uint8Array,
  chunkIndex: number,
): Promise<Uint8Array> {
  // Incorporate chunk index into AAD for ordering integrity
  const indexBytes = new Uint8Array(4);
  indexBytes[0] = (chunkIndex >>> 24) & 0xFF;
  indexBytes[1] = (chunkIndex >>> 16) & 0xFF;
  indexBytes[2] = (chunkIndex >>> 8) & 0xFF;
  indexBytes[3] = chunkIndex & 0xFF;

  const chunkAad = state.aad
    ? concatBytes(state.aad, indexBytes)
    : indexBytes;

  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  let tag: Uint8Array;

  if (state.algorithm === 'CHACHA20-POLY1305') {
    const result = await chaCha20Poly1305.encrypt(chunk, state.key, { aad: chunkAad });
    iv = result.iv; ciphertext = result.ciphertext; tag = result.tag;
  } else {
    const result = await aesGcm.encrypt(chunk, state.key, { aad: chunkAad });
    iv = result.iv; ciphertext = result.ciphertext; tag = result.tag;
  }

  return concatBytes(indexBytes, iv, ciphertext, tag);
}

// ── Public streaming API ──────────────────────────────────────────────────

export function createEncryptStream(options: StreamEncryptOptions): {
  update: (chunk: Uint8Array) => Promise<Uint8Array[]>;
  final: () => Promise<Uint8Array>;
} {
  const state: StreamEncryptState = {
    algorithm:  options.algorithm,
    key:        options.key,
    aad:        options.aad,
    chunkSize:  options.chunkSize ?? STREAM_CHUNK_SIZE,
    chunkIndex: 0,
    buffer:     new Uint8Array(0),
    finalised:  false,
  };

  return {
    /**
     * Feed data into the stream. Returns zero or more encrypted chunks.
     * Chunks are emitted as soon as a full chunkSize is accumulated.
     */
    async update(incoming: Uint8Array): Promise<Uint8Array[]> {
      if (state.finalised) {
        throw new LombokCryptoError(ErrorCode.STREAM_FINALISED, 'Stream already finalised');
      }

      state.buffer = concatBytes(state.buffer, incoming);
      const out: Uint8Array[] = [];

      while (state.buffer.length >= state.chunkSize) {
        const chunk = state.buffer.slice(0, state.chunkSize);
        state.buffer = state.buffer.slice(state.chunkSize);
        out.push(await encryptChunk(state, chunk, state.chunkIndex++));
      }
      return out;
    },

    /**
     * Flush remaining buffered data and emit the final sentinel chunk.
     * Must be called exactly once after all data has been fed.
     */
    async final(): Promise<Uint8Array> {
      if (state.finalised) {
        throw new LombokCryptoError(ErrorCode.STREAM_FINALISED, 'Stream already finalised');
      }
      state.finalised = true;

      const chunks: Uint8Array[] = [];

      // Encrypt any remaining bytes (partial last chunk)
      if (state.buffer.length > 0) {
        chunks.push(await encryptChunk(state, state.buffer, state.chunkIndex++));
      }

      // Final sentinel: 4-byte 0xFFFFFFFF index
      const sentinel = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]);
      chunks.push(sentinel);

      return concatBytes(...chunks);
    },
  };
}

// ── Async generator helper ────────────────────────────────────────────────

/**
 * Encrypt an async iterable of Uint8Arrays (e.g., fs.ReadStream, fetch body).
 *
 * @example
 * const encrypted = encryptStreamGen(fileStream, {
 *   algorithm: 'AES-256-GCM',
 *   key: randomKey256(),
 * });
 * for await (const chunk of encrypted) {
 *   await writeFile(outPath, chunk, { flag: 'a' });
 * }
 */
export async function* encryptStreamGen(
  source: AsyncIterable<Uint8Array>,
  options: StreamEncryptOptions,
): AsyncGenerator<Uint8Array> {
  const stream = createEncryptStream(options);

  for await (const chunk of source) {
    const encrypted = await stream.update(chunk);
    for (const enc of encrypted) yield enc;
  }

  yield await stream.final();
}
