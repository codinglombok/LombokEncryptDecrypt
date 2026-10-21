/**
 * LombokEncryptDecrypt — Authenticated streaming AEAD.
 *
 * Frame format (v1 — refines SPEC §9.1 with an explicit length field so
 * receivers can frame variable-size chunks):
 *   [chunkIndex: u32 BE] [ctLength: u32 BE] [iv: 12] [ciphertext] [tag: 16]
 * End sentinel: chunkIndex = 0xFFFFFFFF.
 * Each chunk's AAD binds "LED1" and the chunk index so reordering and
 * truncation are detected (INTEGRITY_CHECK_FAILED).
 */

import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { aesGcmDecrypt, aesGcmEncrypt } from '../modes/gcm.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';
import { concatBytes, stringToBytes } from '../utils/encoding.js';

/**
 * Streaming uses the 12-byte-IV frame format (SPEC §9), which fits the
 * AES-GCM family. ChaCha20-Poly1305 / XChaCha are available through the
 * one-shot AEAD API.
 */
export type StreamAlgorithm = 'AES-256-GCM' | 'AES-128-GCM' | 'AES-192-GCM';

export interface StreamOptions {
  algorithm: StreamAlgorithm;
  key: Uint8Array;
  aad?: Uint8Array;
  /** Chunk size in bytes (default 65536). */
  chunkSize?: number;
}

const SENTINEL = 0xffffffff;
const DEFAULT_CHUNK_SIZE = 65536;
const MAX_CHUNK = 0x100000;
const FRAME_HEADER = 4 + 4 + 12;
const FRAME_TRAILER = 16;

interface BaseState {
  algorithm: StreamAlgorithm;
  key: Uint8Array;
  aad: Uint8Array;
  chunkSize: number;
  finished: boolean;
}

const SUPPORTED_STREAM_ALGORITHMS: ReadonlySet<string> = new Set([
  'AES-256-GCM',
  'AES-128-GCM',
  'AES-192-GCM',
]);

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

function chunkAad(base: BaseState, index: number): Uint8Array {
  return concatBytes(
    stringToBytes('LED1'),
    new Uint8Array([
      (index >>> 24) & 0xff,
      (index >>> 16) & 0xff,
      (index >>> 8) & 0xff,
      index & 0xff,
    ]),
    base.aad,
  );
}

async function encryptChunk(
  base: BaseState,
  index: number,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const { ciphertext, tag, iv } = await aesGcmEncrypt(plaintext, base.key, {
    aad: chunkAad(base, index),
  });
  const header = new Uint8Array(8);
  header[0] = (index >>> 24) & 0xff;
  header[1] = (index >>> 16) & 0xff;
  header[2] = (index >>> 8) & 0xff;
  header[3] = index & 0xff;
  header[4] = (ciphertext.length >>> 24) & 0xff;
  header[5] = (ciphertext.length >>> 16) & 0xff;
  header[6] = (ciphertext.length >>> 8) & 0xff;
  header[7] = ciphertext.length & 0xff;
  return concatBytes(header, iv, ciphertext, tag);
}

async function decryptFrame(
  base: BaseState,
  expectedIndex: number,
  frame: Uint8Array,
): Promise<Uint8Array> {
  /* istanbul ignore if -- defensive: tryParseFrames always slices exact frameLen */
  if (frame.length < FRAME_HEADER + FRAME_TRAILER) {
    throw new LombokCryptoError(
      ErrorCode.INTEGRITY_CHECK_FAILED,
      `frame too short (${frame.length} bytes)`,
      'stream',
    );
  }
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const index = view.getUint32(0);
  const ctLen = view.getUint32(4);
  if (index !== expectedIndex) {
    throw new LombokCryptoError(
      ErrorCode.INTEGRITY_CHECK_FAILED,
      `chunk index ${index} does not match expected ${expectedIndex}`,
      'stream',
    );
  }
  if (frame.length !== FRAME_HEADER + ctLen + FRAME_TRAILER) {
    throw new LombokCryptoError(
      ErrorCode.INTEGRITY_CHECK_FAILED,
      `frame length ${frame.length} does not match declared ciphertext length ${ctLen}`,
      'stream',
    );
  }
  const iv = frame.subarray(8, 20);
  const ciphertext = frame.subarray(20, 20 + ctLen);
  const tag = frame.subarray(20 + ctLen);
  try {
    return await aesGcmDecrypt(ciphertext, base.key, iv, tag, { aad: chunkAad(base, index) });
  } catch (e) {
    if (e instanceof LombokCryptoError && e.code === ErrorCode.AUTHENTICATION_FAILED) {
      throw new LombokCryptoError(
        ErrorCode.INTEGRITY_CHECK_FAILED,
        `chunk ${index} failed authentication`,
        'stream',
      );
    }
    throw e;
  }
}

/** Push-style encryptor: update() buffers to full chunks, final() emits the sentinel. */
export interface EncryptStream {
  update(data: Uint8Array): Promise<Uint8Array[]>;
  final(): Promise<Uint8Array>;
}

export interface DecryptStream {
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
        out.push(await encryptChunk(base, index, buffer.subarray(0, base.chunkSize)));
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
      const out: Uint8Array[] = [];
      if (buffer.length > 0) {
        out.push(await encryptChunk(base, index, buffer));
        index += 1;
      }
      const sentinel = new Uint8Array(4);
      sentinel[0] = (SENTINEL >>> 24) & 0xff;
      sentinel[1] = (SENTINEL >>> 16) & 0xff;
      sentinel[2] = (SENTINEL >>> 8) & 0xff;
      sentinel[3] = SENTINEL & 0xff;
      return concatBytes(...out, sentinel);
    },
  };
}

export function createDecryptStream(options: StreamOptions): DecryptStream {
  const base = initBase(options);
  let buffer = new Uint8Array(0);
  let expectedIndex = 0;
  let sawSentinel = false;

  const tryParseFrames = async (out: Uint8Array[]): Promise<void> => {
    // Parse as many complete frames as possible from the buffer.
    for (;;) {
      if (buffer.length < 4) return;
      const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      const index = view.getUint32(0);
      if (index === SENTINEL) {
        sawSentinel = true;
        buffer = buffer.subarray(4);
        continue;
      }
      if (buffer.length < FRAME_HEADER) return;
      const ctLen = view.getUint32(4);
      const frameLen = FRAME_HEADER + ctLen + FRAME_TRAILER;
      if (buffer.length < frameLen) return;
      const frame = buffer.subarray(0, frameLen);
      out.push(await decryptFrame(base, expectedIndex, frame));
      expectedIndex += 1;
      buffer = buffer.subarray(frameLen);
    }
  };

  return {
    async update(data: Uint8Array): Promise<Uint8Array[]> {
      if (base.finished) {
        throw new LombokCryptoError(
          ErrorCode.STREAM_FINALISED,
          'update() called after final()',
          'stream',
        );
      }
      if (sawSentinel) {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          'data found after end sentinel',
          'stream',
        );
      }
      buffer = concatBytes(buffer, data);
      const out: Uint8Array[] = [];
      await tryParseFrames(out);
      return out;
    },

    async final(): Promise<Uint8Array> {
      if (base.finished) {
        throw new LombokCryptoError(ErrorCode.STREAM_FINALISED, 'final() called twice', 'stream');
      }
      base.finished = true;
      const out: Uint8Array[] = [];
      await tryParseFrames(out);
      if (!sawSentinel) {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          'stream truncated: end sentinel missing',
          'stream',
        );
      }
      if (buffer.length !== 0) {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          `${buffer.length} trailing bytes after sentinel`,
          'stream',
        );
      }
      return concatBytes(...out);
    },
  };
}

/** Async generator over a ReadableStream (Web streams). */
export async function* encryptStreamGen(
  source: WebReadableStream<Uint8Array>,
  options: StreamOptions,
): AsyncGenerator<Uint8Array, void, unknown> {
  const stream = createEncryptStream(options);
  const reader = source.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value !== undefined) {
        for (const chunk of await stream.update(value)) yield chunk;
      }
    }
  } finally {
    reader.releaseLock();
  }
  yield await stream.final();
}

/** Async generator decryptor over a ReadableStream (Web streams). */
export async function* decryptStreamGen(
  source: WebReadableStream<Uint8Array>,
  options: StreamOptions,
): AsyncGenerator<Uint8Array, void, unknown> {
  const stream = createDecryptStream(options);
  const reader = source.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value !== undefined) {
        for (const chunk of await stream.update(value)) yield chunk;
      }
    }
  } finally {
    reader.releaseLock();
  }
  yield await stream.final();
}
