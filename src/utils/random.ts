/**
 * LombokEncryptDecrypt — CSPRNG (Cryptographically Secure Random)
 *
 * Cross-platform secure random bytes.
 * NEVER use Math.random() in cryptographic code.
 *
 * @module utils/random
 */

import { HAS_SUBTLE_CRYPTO, HAS_NODE_CRYPTO } from '../platform/detect.js';

/**
 * Fill a Uint8Array with cryptographically secure random bytes.
 * Uses the best available entropy source for the current platform.
 */
export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);

  if (HAS_SUBTLE_CRYPTO) {
    // Browser + Deno + Bun + Node.js 19+: WebCrypto
    globalThis.crypto.getRandomValues(buf);
    return buf;
  }

  if (HAS_NODE_CRYPTO) {
    // Node.js < 19 fallback (should rarely be needed)
    // Dynamic import to avoid bundler issues in browser
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { randomFillSync } = require('node:crypto') as typeof import('node:crypto');
    randomFillSync(buf);
    return buf;
  }

  throw new Error(
    'LombokEncryptDecrypt: No CSPRNG available. ' +
    'Ensure running in Node.js ≥ 18, browser with WebCrypto, Deno, or Bun.',
  );
}

/**
 * Generate a random IV/nonce of the given length.
 */
export function randomIv(length: number): Uint8Array {
  return randomBytes(length);
}

/**
 * Generate a random 256-bit (32-byte) symmetric key.
 */
export function randomKey256(): Uint8Array {
  return randomBytes(32);
}

/**
 * Generate a random 128-bit (16-byte) symmetric key.
 */
export function randomKey128(): Uint8Array {
  return randomBytes(16);
}

/**
 * Generate a random salt (16 bytes default).
 */
export function randomSalt(length: number = 16): Uint8Array {
  return randomBytes(length);
}
