/**
 * LombokEncryptDecrypt — Streaming Encrypt
 *
 * Chunk-by-chunk AEAD encryption for data of unlimited size.
 *
 * Record format (all integers big-endian):
 *
 *   [4  index]  chunk counter, 0-based, strictly increasing
 *   [1  flags]  0x00 = more chunks follow, 0x01 = LAST chunk
 *   [n  iv]     12 bytes (AES-GCM, ChaCha20-Poly1305) or 24 bytes (XChaCha20-Poly1305)
 *   [4  ctLen]  ciphertext length
 *   [ctLen]     ciphertext
 *   [16 tag]    authentication tag
 *
 * Per-chunk AAD = userAad || index(4) || flags(1).
 *
 * Binding the index prevents reordering and splicing; binding the LAST flag
 * prevents truncation (a stream cut short has no authenticated LAST record, so the
 * decryptor reports an integrity failure instead of returning a short plaintext).
 * The final record is always emitted, even for an empty stream.
 *
 * @module stream/encrypt_stream
 */

import type { StreamEncryptOptions } from '../types.js';
import { STREAM_CHUNK_SIZE } from '../constants.js';
import { aesGcm } from '../modes/gcm.js';
import { chaCha20Poly1305 } from '../core/chacha/chacha20.js';
import { xchaChaPoly1305 } from '../core/chacha/xchacha20.js';
import { concatBytes } from '../utils/encoding.js';
import { LombokCryptoError, ErrorCode } from '../errors.js';

export const STREAM_FLAG_MORE = 0x00;
export const STREAM_FLAG_LAST = 0x01;
const MAX_INDEX = 0xFFFFFFFE;

export interface StreamEncryptState {
  readonly algorithm: string;
  readonly key: Uint8Array;
  readonly aad: Uint8Array | undefined;
  readonly chunkSize: number;
  chunkIndex: number;
  buffer: Uint8Array;
  finalised: boolean;
}

function u32be(value: number): Uint8Array {
  return new Uint8Array([(value >>> 24) & 0xFF, (value >>> 16) & 0xFF, (value >>> 8) & 0xFF, value & 0xFF]);
}

async function sealChunk(
  state: StreamEncryptState,
  plaintext: Uint8Array,
  last: boolean,
): Promise<Uint8Array> {
  if (state.chunkIndex > MAX_INDEX) {
    throw new LombokCryptoError(ErrorCode.INVALID_INPUT, 'Stream exceeds the maximum number of chunks (2^32 - 1)');
  }
  const index = u32be(state.chunkIndex++);
  const flags = new Uint8Array([last ? STREAM_FLAG_LAST : STREAM_FLAG_MORE]);
  const aad = state.aad ? concatBytes(state.aad, index, flags) : concatBytes(index, flags);

  let result: { iv: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array };
  switch (state.algorithm) {
    case 'AES-256-GCM':
      result = await aesGcm.encrypt(plaintext, state.key, { aad });
      break;
    case 'CHACHA20-POLY1305':
      result = await chaCha20Poly1305.encrypt(plaintext, state.key, { aad });
      break;
    case 'XCHACHA20-POLY1305':
      result = await xchaChaPoly1305.encrypt(plaintext, state.key, { aad });
      break;
    default:
      throw new LombokCryptoError(ErrorCode.UNSUPPORTED_ALGORITHM, `Unsupported stream algorithm: ${state.algorithm}`);
  }
  return concatBytes(index, flags, result.iv, u32be(result.ciphertext.length), result.ciphertext, result.tag);
}

export function createEncryptStream(options: StreamEncryptOptions): {
  update: (chunk: Uint8Array) => Promise<Uint8Array[]>;
  final: () => Promise<Uint8Array>;
} {
  const chunkSize = options.chunkSize ?? STREAM_CHUNK_SIZE;
  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > 16 * 1024 * 1024) {
    throw new LombokCryptoError(ErrorCode.INVALID_PARAMETER, 'chunkSize must be an integer between 1 and 16 MiB');
  }
  const state: StreamEncryptState = {
    algorithm: options.algorithm,
    key: options.key,
    aad: options.aad,
    chunkSize,
    chunkIndex: 0,
    buffer: new Uint8Array(0),
    finalised: false,
  };

  return {
    /**
     * Feed data in. Returns zero or more encrypted records. At least one byte stays
     * buffered until final() so the last record can be flagged as LAST.
     */
    async update(incoming: Uint8Array): Promise<Uint8Array[]> {
      if (state.finalised) {
        throw new LombokCryptoError(ErrorCode.STREAM_FINALISED, 'Stream already finalised');
      }
      state.buffer = state.buffer.length === 0 ? incoming.slice() : concatBytes(state.buffer, incoming);
      const out: Uint8Array[] = [];
      let offset = 0;
      while (state.buffer.length - offset > state.chunkSize) {
        out.push(await sealChunk(state, state.buffer.subarray(offset, offset + state.chunkSize), false));
        offset += state.chunkSize;
      }
      state.buffer = state.buffer.slice(offset);
      return out;
    },

    /** Emit the LAST record (possibly empty). Call exactly once. */
    async final(): Promise<Uint8Array> {
      if (state.finalised) {
        throw new LombokCryptoError(ErrorCode.STREAM_FINALISED, 'Stream already finalised');
      }
      state.finalised = true;
      const record = await sealChunk(state, state.buffer, true);
      state.buffer = new Uint8Array(0);
      return record;
    },
  };
}

/**
 * Encrypt an async iterable of Uint8Arrays (fs.ReadStream, fetch body, ...).
 *
 * @example
 * for await (const record of encryptStreamGen(fileStream, { algorithm: 'AES-256-GCM', key })) {
 *   await writeFile(outPath, record, { flag: 'a' });
 * }
 */
export async function* encryptStreamGen(
  source: AsyncIterable<Uint8Array>,
  options: StreamEncryptOptions,
): AsyncGenerator<Uint8Array> {
  const stream = createEncryptStream(options);
  for await (const chunk of source) {
    for (const record of await stream.update(chunk)) yield record;
  }
  yield await stream.final();
}
