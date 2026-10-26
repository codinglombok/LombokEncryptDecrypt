/**
 * LombokEncryptDecrypt — Encrypted vector embeddings (LombokRAGFrameworks integration).
 *
 * RAG pipelines need embeddings at rest to be ciphertext, yet retrieval still
 * needs to rank them. This module pairs LED's AES-256-GCM with the published
 * `lombokvector` package (binary64 math, bit-identical across the Rust/TS/
 * Python/Go/PHP ports): vectors are encoded as explicit little-endian
 * binary64 lanes, sealed with AES-256-GCM, and ranked client-side after
 * decryption via `lombokvector.batchCosine`.
 *
 * `lombokvector` is an OPTIONAL dependency: every entry point that needs it
 * dynamic-imports it and fails closed with UNSUPPORTED_ALGORITHM when the
 * package is absent, so the crypto core keeps working without it.
 *
 * Security note: ranking happens on PLAINTEXT vectors in the client process.
 * Nothing about the vectors is exposed to storage beyond the ciphertext and
 * the declared dimension. The AAD binds each record to its declared
 * dimension so records cannot be swapped between slots undetected.
 *
 * @module integrations/vector
 */

import { ErrorCode, LombokCryptoError } from '../errors.js';
import { aesGcmDecrypt, aesGcmEncrypt } from '../modes/gcm.js';
import { randomBytes } from '../utils/random.js';

/** Any array-like of numbers: `number[]`, `Float64Array`, `Float32Array`, ... */
export type VectorInput = ArrayLike<number>;

/** Injectable loader for `lombokvector` — tests cover the failure path with it. */
export type LombokVectorLoader = () => Promise<unknown>;

/** Structural view of the `lombokvector` API surface this module relies on. */
interface LombokVectorApi {
  batchCosine(
    query: ArrayLike<number>,
    candidates: readonly ArrayLike<number>[],
  ): { index: number; score: number }[];
}

const FORMAT = 'lombok-encrypted-vector' as const;
const VERSION = 1 as const;

/** A vector sealed with AES-256-GCM; ciphertext is dim × 8 little-endian binary64 lanes. */
export interface EncryptedVectorRecord {
  format: typeof FORMAT;
  version: typeof VERSION;
  algorithm: 'AES-256-GCM';
  /** Declared component count; AAD-bound so it cannot be forged. */
  dimension: number;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

export interface VectorRanking {
  index: number;
  score: number;
}

export interface EncryptVectorOptions {
  /** Explicit IV (12 bytes); random when omitted. */
  iv?: Uint8Array;
  /** Additional authenticated data. */
  aad?: Uint8Array;
}

export interface DecryptVectorOptions {
  /** Additional authenticated data — must match the encryption call. */
  aad?: Uint8Array;
}

export interface RankOptions extends DecryptVectorOptions {
  /** Override the `lombokvector` resolution (tests inject failures here). */
  loader?: LombokVectorLoader;
}

async function loadLombokVector(loader?: LombokVectorLoader): Promise<LombokVectorApi> {
  let mod: unknown;
  try {
    mod = await (loader ? loader() : import('lombokvector'));
  } catch (importErr) {
    // lombokvector ships "type": "module" with no CJS export condition, so
    // this import() fails on CommonJS runtimes whose module registry cannot
    // require() ESM (jest/ts-jest patches even createRequire() bypasses).
    // Real ESM runtimes — node >= 22.12 via require(esm), Bun, Deno, tsx —
    // reach here only when the package is genuinely absent.
    throw new LombokCryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      'optional peer dependency "lombokvector" is not installed — run: npm install lombokvector',
      { cause: importErr },
    );
  }
  const api = (mod as { batchCosine?: unknown }).batchCosine;
  if (typeof api !== 'function') {
    throw new LombokCryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      'optional peer dependency "lombokvector" is not installed — run: npm install lombokvector',
      { cause: new Error('batchCosine export not found — lombokvector >= 0.1.0 required') },
    );
  }
  return mod as LombokVectorApi;
}

function encodeVector(vector: VectorInput): Uint8Array {
  const dim = vector.length;
  if (!Number.isInteger(dim) || dim <= 0) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_INPUT,
      `vector must have a positive integer dimension, got ${dim}`,
      'vector-embedding',
    );
  }
  for (let i = 0; i < dim; i++) {
    if (typeof vector[i] !== 'number' || !Number.isFinite(vector[i])) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_INPUT,
        `vector component ${i} is not a finite number`,
        'vector-embedding',
      );
    }
  }
  const out = new Uint8Array(dim * 8);
  const view = new DataView(out.buffer);
  // Explicit little-endian: identical bytes on every platform, matching the
  // lombokvector binary64 specification (bit-identical across ports).
  for (let i = 0; i < dim; i++) view.setFloat64(i * 8, vector[i], true);
  return out;
}

function decodeVector(bytes: Uint8Array): Float64Array {
  if (bytes.length === 0 || bytes.length % 8 !== 0) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_INPUT,
      `plaintext length ${bytes.length} is not a positive multiple of 8 (binary64 lanes)`,
      'vector-embedding',
    );
  }
  const out = new Float64Array(bytes.length / 8);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < out.length; i++) out[i] = view.getFloat64(i * 8, true);
  return out;
}

/** Seal one vector. Key must be 16/24/32 bytes (validated by AES-GCM). */
export async function encryptVector(
  vector: VectorInput,
  key: Uint8Array,
  options?: EncryptVectorOptions,
): Promise<EncryptedVectorRecord> {
  const plaintext = encodeVector(vector);
  const aad = options?.aad;
  const result = await aesGcmEncrypt(plaintext, key, {
    iv: options?.iv ?? randomBytes(12),
    aad,
  });
  return {
    format: FORMAT,
    version: VERSION,
    algorithm: 'AES-256-GCM',
    dimension: vector.length,
    iv: result.iv,
    ciphertext: result.ciphertext,
    tag: result.tag,
  };
}

function assertRecordShape(record: EncryptedVectorRecord): void {
  if (
    record === null ||
    typeof record !== 'object' ||
    record.format !== FORMAT ||
    record.version !== VERSION ||
    record.algorithm !== 'AES-256-GCM'
  ) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_INPUT,
      'not a lombok-encrypted-vector v1 AES-256-GCM record',
      'vector-embedding',
    );
  }
  if (!Number.isInteger(record.dimension) || record.dimension <= 0) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_INPUT,
      `record dimension must be a positive integer, got ${record.dimension}`,
      'vector-embedding',
    );
  }
  if (
    !(record.ciphertext instanceof Uint8Array) ||
    record.ciphertext.length !== record.dimension * 8
  ) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_INPUT,
      `ciphertext length ${record.ciphertext?.length} does not match declared dimension ${record.dimension} (dim × 8 bytes)`,
      'vector-embedding',
    );
  }
  if (!(record.iv instanceof Uint8Array) || !(record.tag instanceof Uint8Array)) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_INPUT,
      'record iv/tag must be Uint8Array',
      'vector-embedding',
    );
  }
}

/** Open one record back into its binary64 components. */
export async function decryptVector(
  record: EncryptedVectorRecord,
  key: Uint8Array,
  options?: DecryptVectorOptions,
): Promise<Float64Array> {
  assertRecordShape(record);
  const plaintext = await aesGcmDecrypt(record.ciphertext, key, record.iv, record.tag, {
    aad: options?.aad,
  });
  return decodeVector(plaintext);
}

/**
 * Decrypt every record and rank by cosine similarity against `query`
 * (descending) via `lombokvector.batchCosine` — zero-magnitude candidates
 * score 0, no exception. Throws INVALID_INPUT (wrapping the package's
 * stable VectorError) on dimension mismatches.
 */
export async function rankEncryptedVectors(
  query: VectorInput,
  records: readonly EncryptedVectorRecord[],
  key: Uint8Array,
  options?: RankOptions,
): Promise<VectorRanking[]> {
  const pkg = await loadLombokVector(options?.loader);
  const aad = options?.aad;
  const vectors = await Promise.all(records.map((record) => decryptVector(record, key, { aad })));
  try {
    return pkg.batchCosine(query, vectors);
  } catch (err) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_INPUT,
      `ranking failed: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  }
}
