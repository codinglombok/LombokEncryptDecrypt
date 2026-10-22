/**
 * LombokEncryptDecrypt — Streaming Decrypt
 * Decrypts output produced by encrypt_stream.ts (see that file for the record format).
 *
 * Guarantees: records must arrive in order (INTEGRITY_CHECK_FAILED otherwise), a
 * stream without an authenticated LAST record is rejected as truncated, and bytes
 * after the LAST record are rejected.
 *
 * @module stream/decrypt_stream
 */

import type { StreamDecryptOptions } from '../types.js';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { aesGcm } from '../modes/gcm.js';
import { chaCha20Poly1305 } from '../modes/chacha.js';
import { xchaChaPoly1305 } from '../core/chacha/xchacha20.js';
import { concatBytes } from '../utils/encoding.js';
import { LombokCryptoError, ErrorCode } from '../errors.js';
import { STREAM_FLAG_LAST, STREAM_FLAG_MORE } from './encrypt_stream.js';

const TAG_LEN = 16;
const MAX_CT_LEN = 16 * 1024 * 1024;

function readBE32(buf: Uint8Array, off: number): number {
  return ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0;
}

function ivLength(algorithm: string): number {
  switch (algorithm) {
    case 'AES-128-GCM':
    case 'AES-192-GCM':
    case 'AES-256-GCM':
    case 'CHACHA20-POLY1305':
      return 12;
    case 'XCHACHA20-POLY1305':
      return 24;
    default:
      throw new LombokCryptoError(
        ErrorCode.UNSUPPORTED_ALGORITHM,
        `Unsupported stream algorithm: ${algorithm}`,
      );
  }
}

async function open(
  algorithm: string,
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  switch (algorithm) {
    case 'AES-128-GCM':
    case 'AES-192-GCM':
    case 'AES-256-GCM':
      return aesGcm.decrypt(ciphertext, key, iv, tag, { aad });
    case 'CHACHA20-POLY1305':
      return chaCha20Poly1305.decrypt(ciphertext, key, iv, tag, { aad });
    case 'XCHACHA20-POLY1305':
      return xchaChaPoly1305.decrypt(ciphertext, key, iv, tag, { aad });
    default:
      throw new LombokCryptoError(
        ErrorCode.UNSUPPORTED_ALGORITHM,
        `Unsupported stream algorithm: ${algorithm}`,
      );
  }
}

/** Push-style decryptor: update() parses records, final() verifies the LAST record arrived. */
export interface DecryptStream {
  update(encrypted: Uint8Array): Promise<Uint8Array[]>;
  final(): Promise<Uint8Array>;
}

export function createDecryptStream(options: StreamDecryptOptions): DecryptStream {
  const ivLen = ivLength(options.algorithm);
  const headerLen = 4 + 1 + ivLen + 4;

  let buffer = new Uint8Array(0);
  let expectedIndex = 0;
  let sawLast = false;
  let finished = false;

  return {
    async update(incoming: Uint8Array): Promise<Uint8Array[]> {
      if (finished) {
        throw new LombokCryptoError(ErrorCode.STREAM_FINALISED, 'update() called after final()');
      }
      if (incoming.length > 0 && sawLast) {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          'Unexpected data after the final stream record',
        );
      }
      buffer = buffer.length === 0 ? incoming.slice() : concatBytes(buffer, incoming);
      const out: Uint8Array[] = [];
      let offset = 0;

      while (!sawLast && buffer.length - offset >= headerLen) {
        const index = readBE32(buffer, offset);
        const flags = buffer[offset + 4]!;
        const ctLen = readBE32(buffer, offset + 5 + ivLen);

        if (index !== expectedIndex) {
          throw new LombokCryptoError(
            ErrorCode.INTEGRITY_CHECK_FAILED,
            `Stream chunk out of order: expected ${expectedIndex}, got ${index}`,
          );
        }
        if (flags !== STREAM_FLAG_MORE && flags !== STREAM_FLAG_LAST) {
          throw new LombokCryptoError(ErrorCode.INVALID_INPUT, 'Invalid stream record flags');
        }
        if (ctLen > MAX_CT_LEN) {
          throw new LombokCryptoError(
            ErrorCode.INVALID_INPUT,
            'Stream record length exceeds the 16 MiB limit',
          );
        }
        const total = headerLen + ctLen + TAG_LEN;
        if (buffer.length - offset < total) break; // wait for more data

        const iv = buffer.slice(offset + 5, offset + 5 + ivLen);
        const ciphertext = buffer.slice(offset + headerLen, offset + headerLen + ctLen);
        const tag = buffer.slice(offset + headerLen + ctLen, offset + total);
        const aadSuffix = buffer.slice(offset, offset + 5); // index || flags
        const aad = options.aad ? concatBytes(options.aad, aadSuffix) : aadSuffix;

        out.push(await open(options.algorithm, options.key, iv, ciphertext, tag, aad));
        expectedIndex++;
        offset += total;
        if (flags === STREAM_FLAG_LAST) sawLast = true;
      }

      buffer = buffer.slice(offset);
      if (sawLast && buffer.length > 0) {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          'Unexpected data after the final stream record',
        );
      }
      return out;
    },

    /** Verifies the stream ended with an authenticated LAST record. Returns no extra plaintext. */
    async final(): Promise<Uint8Array> {
      if (finished) {
        throw new LombokCryptoError(ErrorCode.STREAM_FINALISED, 'final() called twice');
      }
      finished = true;
      if (!sawLast) {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          'Stream truncated: no authenticated final record',
        );
      }
      return new Uint8Array(0);
    },
  };
}

/** Decrypt an async iterable (or Web/node ReadableStream) of encrypted records. Throws if truncated. */
export async function* decryptStreamGen(
  source: AsyncIterable<Uint8Array> | WebReadableStream<Uint8Array> | ReadableStream<Uint8Array>,
  options: StreamDecryptOptions,
): AsyncGenerator<Uint8Array> {
  const stream = createDecryptStream(options);
  if ('getReader' in source) {
    const reader = source.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value !== undefined) {
          for (const plain of await stream.update(value)) yield plain;
        }
      }
    } finally {
      reader.releaseLock();
    }
  } else {
    for await (const chunk of source) {
      for (const plain of await stream.update(chunk)) yield plain;
    }
  }
  await stream.final();
}
