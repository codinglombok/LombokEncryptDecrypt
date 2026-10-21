/**
 * LombokEncryptDecrypt — HKDF (RFC 5869), pure TypeScript.
 */

import { hmacRaw } from '../mac/hmac.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';
import { SYNC_SHA256, SYNC_SHA384, SYNC_SHA512, type SyncHash } from '../core/sha/sha2.js';
import { concatBytes } from '../utils/encoding.js';

export type KdfHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

export interface HkdfOptions {
  hash?: KdfHash;
  salt?: Uint8Array;
  info?: Uint8Array;
  outputLength?: number;
}

function syncHashFor(name: KdfHash): SyncHash {
  if (name === 'SHA-256') return SYNC_SHA256;
  if (name === 'SHA-384') return SYNC_SHA384;
  if (name === 'SHA-512') return SYNC_SHA512;
  // Never silently fall back: an unknown hash name must fail loudly.
  throw new LombokCryptoError(
    ErrorCode.UNSUPPORTED_ALGORITHM,
    `unsupported HKDF hash "${String(name)}"`,
    'HKDF',
  );
}

function outputSizeFor(name: KdfHash): number {
  return syncHashFor(name).outputSize;
}

function extract(hashName: KdfHash, salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmacRaw(syncHashFor(hashName), salt, ikm);
}

function expand(hashName: KdfHash, prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const hash = syncHashFor(hashName);
  const blocks = Math.ceil(length / hash.outputSize);
  if (blocks > 255) {
    throw new Error(
      `HKDF output length ${length} exceeds the maximum for ${hashName} (${hash.outputSize * 255} bytes)`,
    );
  }
  let t = new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  for (let i = 1; i <= blocks; i++) {
    t = hmacRaw(hash, prk, concatBytes(t, info, new Uint8Array([i])));
    chunks.push(t);
  }
  const okm = concatBytes(...chunks);
  return okm.subarray(0, length);
}

/** HKDF-Extract+Expand with explicit options. */
export async function hkdfDerive(ikm: Uint8Array, options?: HkdfOptions): Promise<Uint8Array> {
  const hashName = options?.hash ?? 'SHA-256';
  const salt = options?.salt ?? new Uint8Array(outputSizeFor(hashName));
  const info = options?.info ?? new Uint8Array(0);
  const outputLength = options?.outputLength ?? 32;
  const prk = extract(hashName, salt, ikm);
  return expand(hashName, prk, info, outputLength);
}

function makeConvenience(hashName: KdfHash) {
  return async (
    ikm: Uint8Array,
    salt?: Uint8Array,
    info?: Uint8Array,
    outputLength = 32,
  ): Promise<Uint8Array> => hkdfDerive(ikm, { hash: hashName, salt, info, outputLength });
}

export const hkdf = {
  derive: hkdfDerive,
  sha256: makeConvenience('SHA-256'),
  sha384: makeConvenience('SHA-384'),
  sha512: makeConvenience('SHA-512'),
};
