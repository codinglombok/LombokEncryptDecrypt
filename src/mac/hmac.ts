/**
 * LombokEncryptDecrypt — HMAC-SHA2 (RFC 2104 / FIPS 198-1), pure TypeScript
 * over the synchronous SHA-2 implementation. Verification is constant-time
 * and never throws on mismatch.
 */

import { sha384Raw, SYNC_SHA256, SYNC_SHA512, type SyncHash } from '../core/sha/sha2.js';
import { concatBytes, timingSafeEqual, xorBytes } from '../utils/encoding.js';

type HashName = 'SHA-256' | 'SHA-384' | 'SHA-512';

function hashFor(name: HashName): SyncHash {
  if (name === 'SHA-256') return SYNC_SHA256;
  if (name === 'SHA-512') return SYNC_SHA512;
  return { blockSize: 128, outputSize: 48, digest: sha384Raw };
}

/** Raw HMAC over an arbitrary SyncHash (used internally by KDFs). */
export function hmacRaw(hash: SyncHash, key: Uint8Array, message: Uint8Array): Uint8Array {
  let k = key;
  if (k.length > hash.blockSize) {
    k = hash.digest(k);
  }
  const ipad = new Uint8Array(hash.blockSize);
  const opad = new Uint8Array(hash.blockSize);
  ipad.fill(0x36);
  opad.fill(0x5c);
  const kPadded = new Uint8Array(hash.blockSize);
  kPadded.set(k);
  const inner = hash.digest(concatBytes(xorBytes(kPadded, ipad), message));
  return hash.digest(concatBytes(xorBytes(kPadded, opad), inner));
}

function namedHash(name: HashName): (key: Uint8Array, message: Uint8Array) => Uint8Array {
  return (key: Uint8Array, message: Uint8Array) => hmacRaw(hashFor(name), key, message);
}

function makeHmac(algorithm: HashName): {
  verify(key: Uint8Array, message: Uint8Array, tag: Uint8Array): Promise<boolean>;
  compute(key: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
  sign(key: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
  outputSize: number;
} {
  const fn = namedHash(algorithm);
  const size = hashFor(algorithm).outputSize;
  return {
    /** Constant-time verification — returns false on mismatch, never throws. */
    async verify(key: Uint8Array, message: Uint8Array, tag: Uint8Array): Promise<boolean> {
      if (tag.length !== size) return false;
      return timingSafeEqual(fn(key, message), tag);
    },
    /** Raw MAC bytes. */
    async compute(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
      return fn(key, message);
    },
    /** Alias of compute. */
    async sign(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
      return fn(key, message);
    },
    outputSize: size,
  };
}

/** HMAC-SHA256 (32-byte MAC). */
export const hmacSha256 = makeHmac('SHA-256');
/** HMAC-SHA384 (48-byte MAC). */
export const hmacSha384 = makeHmac('SHA-384');
/** HMAC-SHA512 (64-byte MAC). */
export const hmacSha512 = makeHmac('SHA-512');

/** Generic HMAC by hash name (used by KeyStore and envelope internals). */
export const hmac = {
  compute(algorithm: HashName, key: Uint8Array, message: Uint8Array): Uint8Array {
    return namedHash(algorithm)(key, message);
  },
  verify(algorithm: HashName, key: Uint8Array, message: Uint8Array, tag: Uint8Array): boolean {
    const size = hashFor(algorithm).outputSize;
    if (tag.length !== size) return false;
    return timingSafeEqual(namedHash(algorithm)(key, message), tag);
  },
};
