/**
 * LombokEncryptDecrypt — Authenticated streaming AEAD (frame format v2).
 *
 * Record format:
 *   [chunkIndex: u32 BE] [flags: u8] [iv] [ctLength: u32 BE] [ciphertext] [tag: 16]
 * flags: 0x00 = MORE (more records follow), 0x01 = LAST (final record).
 *
 * A stream ALWAYS ends with an authenticated LAST record — even for empty
 * plaintext — so truncation is always detectable (final() rejects with
 * INTEGRITY_CHECK_FAILED when the LAST record is missing). Record indices
 * start at 0 and increase without gaps; every record's AAD binds the caller
 * AAD (prefix) plus [index || flags], so reordering and flag forgery fail
 * authentication (INTEGRITY_CHECK_FAILED / AUTHENTICATION_FAILED).
 * IV length: 12 bytes for AES-GCM / ChaCha20-Poly1305, 24 bytes for XChaCha.
 * Decryption lives in ./decrypt_stream.ts.
 */

import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { aesGcmEncrypt } from '../modes/gcm.js';
import { chaCha20Poly1305 } from '../modes/chacha.js';
import { xchaChaPoly1305 } from '../core/chacha/xchacha20.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';
import { concatBytes } from '../utils/encoding.js';

/** Record flag: more records follow. */
export const STREAM_FLAG_MORE = 0x00;
/** Record flag: final record of the stream. */
export const STREAM_FLAG_LAST = 0x01;

export type StreamAlgorithm =
  'AES-128-GCM' | 'AES-192-GCM' | 'AES-256-GCM' | 'CHACHA20-POLY1305' | 'XCHACHA20-POLY1305';

export interface StreamOptions {
  algorithm: StreamAlgorithm;
  key: Uint8Array;
  aad?: Uint8Array;
  /** Chunk size in bytes (default 65536). */
  chunkSize?: number;
}

const DEFAULT_CHUNK_SIZE = 65536;
const MAX_CHUNK = 0x100000;

interface BaseState {
  algorithm: StreamAlgorithm;
  key: Uint8Array;
  aad: Uint8Array;
  chunkSize: number;
  finished: boolean;
}

const SUPPORTED_STREAM_ALGORITHMS: ReadonlySet<string> = new Set([
  'AES-128-GCM',
  'AES-192-GCM',
  'AES-256-GCM',
  'CHACHA20-POLY1305',
  'XCHACHA20-POLY1305',
]);

function ivLength(algorithm: StreamAlgorithm): number {
  return algorithm === 'XCHACHA20-POLY1305' ? 24 : 12;
}

function initBase(options: StreamOptions): BaseState {
  if (options.algorithm === undefined) {
    throw new LombokCryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      'stream algorithm is required',
      'stream',
    );
  }
  if (!SUPPORTED_STREAM_ALGORITHMS.has(options.algorithm)) {
    throw new LombokCryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `unsupported stream algorithm ${options.algorithm}`,
      'stream',
    );
  }
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_CHUNK) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_IV_SIZE,
      `chunkSize must be an integer between 1 and ${MAX_CHUNK}, got ${chunkSize}`,
      'stream',
    );
  }
  return {
    algorithm: options.algorithm,
    key: options.key,
    aad: options.aad ?? new Uint8Array(0),
    chunkSize,
    finished: false,
  };
}

/** AAD suffix bound into every record: [index: u32 BE][flags: u8]. */
function recordAad(base: BaseState, index: number, flags: number): Uint8Array {
  const suffix = new Uint8Array([
    (index >>> 24) & 0xff,
    (index >>> 16) & 0xff,
    (index >>> 8) & 0xff,
    index & 0xff,
    flags,
  ]);
  return base.aad.length > 0 ? concatBytes(base.aad, suffix) : suffix;
}

async function encryptRecord(
  base: BaseState,
  index: number,
  flags: number,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const aad = recordAad(base, index, flags);
  const result =
    base.algorithm === 'CHACHA20-POLY1305'
      ? await chaCha20Poly1305.encrypt(plaintext, base.key, { aad })
      : base.algorithm === 'XCHACHA20-POLY1305'
        ? await xchaChaPoly1305.encrypt(plaintext, base.key, { aad })
        : await aesGcmEncrypt(plaintext, base.key, { aad });
  const ivLen = ivLength(base.algorithm);
  const header = new Uint8Array(5 + ivLen + 4);
  header[0] = (index >>> 24) & 0xff;
  header[1] = (index >>> 16) & 0xff;
  header[2] = (index >>> 8) & 0xff;
  header[3] = index & 0xff;
  header[4] = flags;
  header.set(result.iv, 5);
  const ctLenPos = 5 + ivLen;
  header[ctLenPos] = (result.ciphertext.length >>> 24) & 0xff;
  header[ctLenPos + 1] = (result.ciphertext.length >>> 16) & 0xff;
  header[ctLenPos + 2] = (result.ciphertext.length >>> 8) & 0xff;
  header[ctLenPos + 3] = result.ciphertext.length & 0xff;
  // The IV is already embedded in the header (index || flags || iv || ctLen).
  return concatBytes(header, result.ciphertext, result.tag);
}

/** Push-style encryptor: update() buffers to full chunks, final() emits the LAST record. */
export interface EncryptStream {
  update(data: Uint8Array): Promise<Uint8Array[]>;
  final(): Promise<Uint8Array>;
}

export function createEncryptStream(options: StreamOptions): EncryptStream {
  const base = initBase(options);
  let buffer = new Uint8Array(0);
  let index = 0;

  return {
    async update(data: Uint8Array): Promise<Uint8Array[]> {
      if (base.finished) {
        throw new LombokCryptoError(
          ErrorCode.STREAM_FINALISED,
          'update() called after final()',
          'stream',
        );
      }
      buffer = concatBytes(buffer, data);
      const out: Uint8Array[] = [];
      while (buffer.length >= base.chunkSize) {
        out.push(
          await encryptRecord(base, index, STREAM_FLAG_MORE, buffer.subarray(0, base.chunkSize)),
        );
        index += 1;
        buffer = buffer.subarray(base.chunkSize);
      }
      return out;
    },

    async final(): Promise<Uint8Array> {
      if (base.finished) {
        throw new LombokCryptoError(ErrorCode.STREAM_FINALISED, 'final() called twice', 'stream');
      }
      base.finished = true;
      const record = await encryptRecord(base, index, STREAM_FLAG_LAST, buffer);
      buffer = new Uint8Array(0);
      return record;
    },
  };
}

/** Async generator over any async byte source (Web/node ReadableStream included). */
export async function* encryptStreamGen(
  source: AsyncIterable<Uint8Array> | WebReadableStream<Uint8Array> | ReadableStream<Uint8Array>,
  options: StreamOptions,
): AsyncGenerator<Uint8Array, void, unknown> {
  const stream = createEncryptStream(options);
  if ('getReader' in source) {
    const reader = source.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value !== undefined) {
          for (const piece of await stream.update(value)) yield piece;
        }
      }
    } finally {
      reader.releaseLock();
    }
  } else {
    for await (const chunk of source) {
      for (const piece of await stream.update(chunk)) yield piece;
    }
  }
  yield await stream.final();
}
