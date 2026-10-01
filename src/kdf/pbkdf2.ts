/**
 * LombokEncryptDecrypt — PBKDF2
 * Password-Based Key Derivation Function 2 (RFC 8018, NIST SP 800-132)
 * @module kdf/pbkdf2
 */

import type { Pbkdf2Options } from '../../types.js';
import { HAS_SUBTLE_CRYPTO, HAS_NODE_CRYPTO, PLATFORM } from '../../platform/detect.js';
import { randomSalt } from '../../utils/random.js';
import { stringToBytes } from '../../utils/encoding.js';
import { timingSafeEqual } from '../../utils/timing.js';

const DEFAULT_SALT_LEN = 16;
const DEFAULT_DK_LEN   = 32;

async function pbkdf2Native(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  hash: 'SHA-256' | 'SHA-512',
  dkLen: number,
): Promise<Uint8Array> {
  if (HAS_SUBTLE_CRYPTO) {
    const baseKey = await globalThis.crypto.subtle.importKey(
      'raw', password, { name: 'PBKDF2' }, false, ['deriveBits'],
    );
    const bits = await globalThis.crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash }, baseKey, dkLen * 8,
    );
    return new Uint8Array(bits);
  }
  if (PLATFORM === 'node' && HAS_NODE_CRYPTO) {
    const { pbkdf2: nodePbkdf2 } = await import('node:crypto');
    const { promisify } = await import('node:util');
    const pbkdf2Async = promisify(nodePbkdf2);
    const nodeHash = hash.toLowerCase().replace('-', '');
    const result = await pbkdf2Async(password, salt, iterations, dkLen, nodeHash);
    return new Uint8Array(result);
  }
  // Pure HMAC-based PBKDF2
  const { hmacSha256, hmacSha512 } = await import('../mac/hmac.js');
  const mac = hash === 'SHA-256' ? hmacSha256 : hmacSha512;
  const hashLen = hash === 'SHA-256' ? 32 : 64;
  const blocks  = Math.ceil(dkLen / hashLen);
  const out     = new Uint8Array(dkLen);

  for (let i = 1; i <= blocks; i++) {
    const bi = new Uint8Array(4);
    bi[0]=(i>>>24)&0xFF; bi[1]=(i>>>16)&0xFF; bi[2]=(i>>>8)&0xFF; bi[3]=i&0xFF;
    let U = await mac.compute(password, new Uint8Array([...salt, ...bi]));
    const T = new Uint8Array(U);
    for (let c = 1; c < iterations; c++) {
      U = await mac.compute(password, U);
      for (let j = 0; j < T.length; j++) T[j]! ^= U[j]!;
    }
    out.set(T.slice(0, Math.min(hashLen, dkLen - (i-1)*hashLen)), (i-1)*hashLen);
  }
  return out;
}

// PHC-like format: $pbkdf2-sha256$i=<iter>$<salt_b64>$<hash_b64>
import { bytesToBase64Url, base64ToBytes } from '../../utils/encoding.js';

function encodePbkdf2Hash(hash: 'SHA-256'|'SHA-512', iterations: number, salt: Uint8Array, dk: Uint8Array): string {
  const id = hash === 'SHA-256' ? 'pbkdf2-sha256' : 'pbkdf2-sha512';
  return `$${id}$i=${iterations}$${bytesToBase64Url(salt)}$${bytesToBase64Url(dk)}`;
}

export const pbkdf2 = {
  /**
   * Derive a key using PBKDF2.
   * @example
   * const key = await pbkdf2.derive('my-password', { iterations: 600000, hash: 'SHA-256', dkLen: 32 });
   */
  async derive(
    password: string | Uint8Array,
    options: Pbkdf2Options,
  ): Promise<Uint8Array> {
    const pw   = typeof password === 'string' ? stringToBytes(password) : password;
    const salt = options.salt ?? randomSalt(DEFAULT_SALT_LEN);
    return pbkdf2Native(pw, salt, options.iterations, options.hash, options.dkLen ?? DEFAULT_DK_LEN);
  },

  /** Hash password to PHC-like string */
  async hash(
    password: string | Uint8Array,
    options: Partial<Pbkdf2Options> & { hash: 'SHA-256'|'SHA-512' },
  ): Promise<string> {
    const pw   = typeof password === 'string' ? stringToBytes(password) : password;
    const salt = options.salt ?? randomSalt(DEFAULT_SALT_LEN);
    const iter = options.iterations ?? 600_000;
    const dkLen = options.dkLen ?? DEFAULT_DK_LEN;
    const dk   = await pbkdf2Native(pw, salt, iter, options.hash, dkLen);
    return encodePbkdf2Hash(options.hash, iter, salt, dk);
  },

  /** Verify password against PHC-like hash string */
  async verify(phcHash: string, password: string | Uint8Array): Promise<boolean> {
    const pw = typeof password === 'string' ? stringToBytes(password) : password;
    const parts = phcHash.split('$');
    if (parts.length !== 5) return false;
    const [, id, params, saltB64, hashB64] = parts;
    const hash  = id!.includes('sha256') ? 'SHA-256' as const : 'SHA-512' as const;
    const iter  = parseInt((params ?? '').replace('i=', ''), 10);
    const salt  = base64ToBytes(saltB64 ?? '');
    const stored = base64ToBytes(hashB64 ?? '');
    const computed = await pbkdf2Native(pw, salt, iter, hash, stored.length);
    return timingSafeEqual(computed, stored);
  },

  sha256: {
    async derive(pw: string | Uint8Array, salt: Uint8Array, iter = 600_000, len = 32): Promise<Uint8Array> {
      const p = typeof pw === 'string' ? stringToBytes(pw) : pw;
      return pbkdf2Native(p, salt, iter, 'SHA-256', len);
    },
  },
  sha512: {
    async derive(pw: string | Uint8Array, salt: Uint8Array, iter = 600_000, len = 64): Promise<Uint8Array> {
      const p = typeof pw === 'string' ? stringToBytes(pw) : pw;
      return pbkdf2Native(p, salt, iter, 'SHA-512', len);
    },
  },
};
