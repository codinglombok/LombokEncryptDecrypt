/**
 * LombokEncryptDecrypt — Streaming Decrypt
 * Decrypts output produced by encrypt_stream.ts.
 * @module stream/decrypt_stream
 */

import type { StreamDecryptOptions } from '../../types.js';
import { STREAM_CHUNK_SIZE } from '../../constants.js';
import { aesGcm } from '../../modes/gcm.js';
import { chaCha20Poly1305 } from '../core/chacha/chacha20.js';
import { concatBytes } from '../../utils/encoding.js';
import { LombokCryptoError, ErrorCode } from '../../errors.js';

const IV_LEN  = 12;
const TAG_LEN = 16;
const IDX_LEN = 4;

function readBE32(buf: Uint8Array, off: number): number {
  return (((buf[off]??0) << 24) | ((buf[off+1]??0) << 16) | ((buf[off+2]??0) << 8) | (buf[off+3]??0)) >>> 0;
}

// ── Chunk decrypt ─────────────────────────────────────────────────────────

async function decryptChunk(
  algorithm: string,
  key: Uint8Array,
  aad: Uint8Array | undefined,
  packed: Uint8Array,
  expectedIndex: number,
): Promise<Uint8Array> {
  if (packed.length < IDX_LEN + IV_LEN + TAG_LEN) {
    throw new LombokCryptoError(ErrorCode.INVALID_INPUT, 'Encrypted chunk too short');
  }

  const chunkIndex = readBE32(packed, 0);
  if (chunkIndex !== expectedIndex) {
    throw new LombokCryptoError(
      ErrorCode.INTEGRITY_CHECK_FAILED,
      `Stream chunk out of order: expected ${expectedIndex}, got ${chunkIndex}`,
    );
  }

  const iv         = packed.slice(IDX_LEN, IDX_LEN + IV_LEN);
  const ciphertext = packed.slice(IDX_LEN + IV_LEN, packed.length - TAG_LEN);
  const tag        = packed.slice(packed.length - TAG_LEN);

  const indexBytes = packed.slice(0, IDX_LEN);
  const chunkAad   = aad ? concatBytes(aad, indexBytes) : indexBytes;

  if (algorithm === 'CHACHA20-POLY1305') {
    return chaCha20Poly1305.decrypt(ciphertext, key, iv, tag, { aad: chunkAad });
  }
  return aesGcm.decrypt(ciphertext, key, iv, tag, { aad: chunkAad });
}

// ── Public streaming API ──────────────────────────────────────────────────

export function createDecryptStream(options: StreamDecryptOptions): {
  update: (encrypted: Uint8Array) => Promise<Uint8Array[]>;
  final: () => Promise<Uint8Array>;
} {
  const chunkSize  = options.chunkSize ?? STREAM_CHUNK_SIZE;
  const encChunkSize = IDX_LEN + IV_LEN + chunkSize + TAG_LEN;

  let buffer    = new Uint8Array(0);
  let chunkIdx  = 0;
  let finalised = false;

  return {
    async update(incoming: Uint8Array): Promise<Uint8Array[]> {
      if (finalised) throw new LombokCryptoError(ErrorCode.STREAM_FINALISED, 'Stream already finalised');
      buffer = concatBytes(buffer, incoming);
      const out: Uint8Array[] = [];

      while (buffer.length >= encChunkSize) {
        // Check for sentinel
        if (buffer[0] === 0xFF && buffer[1] === 0xFF && buffer[2] === 0xFF && buffer[3] === 0xFF) {
          finalised = true;
          buffer = buffer.slice(4);
          break;
        }
        const chunk = buffer.slice(0, encChunkSize);
        buffer = buffer.slice(encChunkSize);
        out.push(await decryptChunk(options.algorithm, options.key, options.aad, chunk, chunkIdx++));
      }
      return out;
    },

    async final(): Promise<Uint8Array> {
      // Flush any remaining partial chunk (smaller than chunkSize)
      const out: Uint8Array[] = [];
      while (buffer.length >= IDX_LEN + IV_LEN + TAG_LEN + 1) {
        if (buffer[0] === 0xFF && buffer[1] === 0xFF && buffer[2] === 0xFF && buffer[3] === 0xFF) {
          finalised = true;
          break;
        }
        const minLen = IDX_LEN + IV_LEN + TAG_LEN;
        if (buffer.length < minLen) break;
        out.push(await decryptChunk(options.algorithm, options.key, options.aad, buffer, chunkIdx++));
        buffer = new Uint8Array(0);
      }
      return concatBytes(...out);
    },
  };
}

/** Decrypt an async generator of encrypted chunks */
export async function* decryptStreamGen(
  source: AsyncIterable<Uint8Array>,
  options: StreamDecryptOptions,
): AsyncGenerator<Uint8Array> {
  const stream = createDecryptStream(options);
  for await (const chunk of source) {
    const decrypted = await stream.update(chunk);
    for (const d of decrypted) yield d;
  }
  const last = await stream.final();
  if (last.length > 0) yield last;
}
