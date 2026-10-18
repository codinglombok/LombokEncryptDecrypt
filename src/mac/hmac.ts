/**
 * LombokEncryptDecrypt — HMAC
 * Hash-based Message Authentication Code (RFC 2104, NIST FIPS 198-1)
 * @module mac/hmac
 */

import { LombokCryptoError, ErrorCode } from '../errors.js';
import { HAS_SUBTLE_CRYPTO, HAS_NODE_CRYPTO, PLATFORM } from '../platform/detect.js';
import { timingSafeEqual } from '../utils/timing.js';

type HmacHash = 'SHA-256' | 'SHA-384' | 'SHA-512' | 'SHA-1';

const NODE_HASH: Record<HmacHash, string> = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
  'SHA-1':   'sha1',
};

// ── Core HMAC ─────────────────────────────────────────────────────────────

async function hmacCompute(
  hash: HmacHash,
  key: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  if (HAS_SUBTLE_CRYPTO) {
    const ck = await globalThis.crypto.subtle.importKey(
      'raw', key, { name: 'HMAC', hash }, false, ['sign'],
    );
    return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', ck, message));
  }
  if (PLATFORM === 'node' && HAS_NODE_CRYPTO) {
    const { createHmac } = await import('node:crypto');
    return new Uint8Array(createHmac(NODE_HASH[hash]!, key).update(message).digest());
  }
  throw new LombokCryptoError(ErrorCode.UNSUPPORTED_ALGORITHM,
    'HMAC requires WebCrypto or node:crypto; no pure-TS fallback in v0.1.0', { algorithm: `HMAC-${hash}` });
}

function makeHmac(hash: HmacHash) {
  return {
    /**
     * Compute HMAC.
     * @returns raw MAC bytes
     */
    async compute(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
      return hmacCompute(hash, key, message);
    },

    /**
     * Verify HMAC — constant-time comparison.
     * @returns true if MAC matches
     */
    async verify(key: Uint8Array, message: Uint8Array, mac: Uint8Array): Promise<boolean> {
      const computed = await hmacCompute(hash, key, message);
      return timingSafeEqual(computed, mac);
    },

    /** Alias for compute() */
    async sign(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
      return hmacCompute(hash, key, message);
    },
  };
}

export const hmacSha256 = makeHmac('SHA-256');
export const hmacSha384 = makeHmac('SHA-384');
export const hmacSha512 = makeHmac('SHA-512');

/** Generic HMAC — choose hash at call time */
export const hmac = {
  async compute(hash: HmacHash, key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    return hmacCompute(hash, key, message);
  },
  async verify(hash: HmacHash, key: Uint8Array, message: Uint8Array, mac: Uint8Array): Promise<boolean> {
    const computed = await hmacCompute(hash, key, message);
    return timingSafeEqual(computed, mac);
  },
};
