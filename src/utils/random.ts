/**
 * LombokEncryptDecrypt — CSPRNG.
 *
 * Uses the platform WebCrypto `getRandomValues` (Node 19+/Deno/Bun/browser)
 * and falls back to node:crypto webcrypto on Node 18, where the global is
 * still behind a flag. Math.random() is banned by ESLint and never used.
 */

import { webcrypto } from 'node:crypto';

type Rng = {
  getRandomValues<T extends ArrayBufferView>(array: T): T;
};

function getGlobalRng(): Rng | undefined {
  const g = globalThis as { crypto?: Rng };
  return g.crypto;
}

/** WebCrypto caps getRandomValues at 64 KiB per call — larger requests are chunked. */
const MAX_CHUNK = 65536;

/** Fill `out` with cryptographically secure random bytes. */
export function getRandomInto(out: Uint8Array): Uint8Array {
  const rng = getGlobalRng();
  if (rng !== undefined) {
    for (let offset = 0; offset < out.length; offset += MAX_CHUNK) {
      rng.getRandomValues(out.subarray(offset, Math.min(offset + MAX_CHUNK, out.length)));
    }
    return out;
  }
  return randomViaNodeWebcrypto(out);
}

/* istanbul ignore next -- platform fallback: only reachable on Node 18 with the global WebCrypto flag disabled */
function randomViaNodeWebcrypto(out: Uint8Array): Uint8Array {
  for (let offset = 0; offset < out.length; offset += MAX_CHUNK) {
    webcrypto.getRandomValues(out.subarray(offset, Math.min(offset + MAX_CHUNK, out.length)));
  }
  return out;
}

/** Return `length` cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0) {
    throw new RangeError(`length must be a non-negative integer, got ${length}`);
  }
  return getRandomInto(new Uint8Array(length));
}

/** 16 random bytes — an AES-128 key. */
export function randomKey128(): Uint8Array {
  return randomBytes(16);
}

/** 32 random bytes — an AES-256 / ChaCha20-Poly1305 key. */
export function randomKey256(): Uint8Array {
  return randomBytes(32);
}

/** `length` random bytes (default 16) suitable for use as a KDF salt. */
export function randomSalt(length = 16): Uint8Array {
  return randomBytes(length);
}

/** `length` random bytes (default 12) suitable for use as a 96-bit IV. */
export function randomIv(length = 12): Uint8Array {
  return randomBytes(length);
}
