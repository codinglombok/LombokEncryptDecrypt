/**
 * LombokEncryptDecrypt — Plaintext similarity fingerprints (LombokSimHash integration).
 *
 * For RAG ingestion pipelines: compute a SimHash-64 fingerprint of a document
 * BEFORE encryption, so the index layer can cluster near-duplicates without
 * ever seeing the ciphertext side. Uses the published `lomboksimhash`
 * package (pure TypeScript, BigInt 64-bit math, vectors pinned by its SPEC).
 *
 * `lomboksimhash` is an OPTIONAL dependency: dynamic-imported, failing closed
 * with UNSUPPORTED_ALGORITHM when absent.
 *
 * ⚠ SECURITY — opt-in leakage by design: a SimHash of PLAINTEXT is similarity
 * metadata. Publishing it alongside the ciphertext reveals "these two
 * documents are near-duplicates" to anyone who can read the index. Callers
 * must treat the fingerprint as sensitive as the plaintext itself (store it
 * encrypted, or in a trust boundary that already sees plaintexts).
 *
 * @module integrations/simhash
 */

import { ErrorCode, LombokCryptoError } from '../errors.js';

/** Injectable loader for `lomboksimhash` — tests cover the failure path with it. */
export type SimHashLoader = () => Promise<unknown>;

/** Structural view of the `lomboksimhash` API surface this module relies on. */
interface SimHashApi {
  simhash64Text(text: string): bigint;
  hamming64(a: bigint, b: bigint): number;
}

export interface SimHashOptions {
  /** Override the `lomboksimhash` resolution (tests inject failures here). */
  loader?: SimHashLoader;
}

async function loadSimHash(loader?: SimHashLoader): Promise<SimHashApi> {
  try {
    const mod = await (loader ? loader() : import('lomboksimhash'));
    const api = (mod as { simhash64Text?: unknown }).simhash64Text;
    if (typeof api !== 'function') {
      throw new Error('simhash64Text export not found — lomboksimhash >= 0.1.0 required');
    }
    return mod as SimHashApi;
  } catch (err) {
    throw new LombokCryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      'optional peer dependency "lomboksimhash" is not installed — run: npm install lomboksimhash',
      { cause: err },
    );
  }
}

/**
 * SimHash-64 of a plaintext document as fixed-width 16-char lowercase hex.
 * Cross-repo pinned vector: `fingerprintPlaintext('the fox')` returns
 * `54b080184441c10c` — the canonical LombokSimHash vector, bit-identical
 * across every language port.
 */
export async function fingerprintPlaintext(
  text: string,
  options?: SimHashOptions,
): Promise<string> {
  const { simhash64Text } = (await loadSimHash(options?.loader)) as {
    simhash64Text: (text: string) => bigint;
  };
  const bits = simhash64Text(text);
  return bits.toString(16).padStart(16, '0');
}

/**
 * Hamming distance between two fingerprints produced by
 * {@link fingerprintPlaintext} (0 = identical hashes; small values =
 * near-duplicates per LombokSimHash's LSH guidance).
 */
export async function hammingDistance(
  fingerprintA: string,
  fingerprintB: string,
  options?: SimHashOptions,
): Promise<number> {
  const pkg = await loadSimHash(options?.loader);
  let a: bigint;
  let b: bigint;
  try {
    a = BigInt(`0x${fingerprintA}`);
    b = BigInt(`0x${fingerprintB}`);
  } catch (err) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_INPUT,
      'fingerprints must be hexadecimal SimHash-64 strings (16 hex chars)',
      { cause: err },
    );
  }
  return pkg.hamming64(a, b);
}
