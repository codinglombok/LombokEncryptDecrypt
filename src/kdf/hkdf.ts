/**
 * LombokEncryptDecrypt — HKDF
 * HMAC-based Key Derivation Function (RFC 5869)
 * @module kdf/hkdf
 */

import { LombokCryptoError, ErrorCode } from '../errors.js';
import type { HkdfOptions } from '../types.js';
import { HAS_SUBTLE_CRYPTO, HAS_NODE_CRYPTO, PLATFORM } from '../platform/detect.js';
import { concatBytes } from '../utils/encoding.js';

const MAX_OUTPUT_BYTES: Record<string, number> = {
  'SHA-256': 32 * 255,
  'SHA-384': 48 * 255,
  'SHA-512': 64 * 255,
};

const HASH_LEN: Record<string, number> = {
  'SHA-256': 32,
  'SHA-384': 48,
  'SHA-512': 64,
};

// ── HMAC (used internally) ────────────────────────────────────────────────

async function hmac(hash: string, key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  if (HAS_SUBTLE_CRYPTO) {
    const ck = await globalThis.crypto.subtle.importKey(
      'raw', key, { name: 'HMAC', hash }, false, ['sign'],
    );
    return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', ck, data));
  }
  if (PLATFORM === 'node' && HAS_NODE_CRYPTO) {
    const { createHmac } = await import('node:crypto');
    const nodeHash = hash.toLowerCase().replace('-', '');
    return new Uint8Array(createHmac(nodeHash, key).update(data).digest());
  }
  // LombokAlgoritma math fallback
  throw new LombokCryptoError(ErrorCode.UNSUPPORTED_ALGORITHM,
    'HKDF requires WebCrypto or node:crypto; no pure-TS fallback in v0.1.0', { algorithm: `HKDF-${hash}` });
}

// ── HKDF Extract ──────────────────────────────────────────────────────────

async function extract(hash: string, salt: Uint8Array | undefined, ikm: Uint8Array): Promise<Uint8Array> {
  const hashLen = HASH_LEN[hash] ?? 32;
  const saltBytes = salt && salt.length > 0 ? salt : new Uint8Array(hashLen);
  return hmac(hash, saltBytes, ikm);
}

// ── HKDF Expand ───────────────────────────────────────────────────────────

async function expand(
  hash: string,
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const hashLen = HASH_LEN[hash] ?? 32;
  const n = Math.ceil(length / hashLen);
  const okm = new Uint8Array(n * hashLen);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const input = concatBytes(prev, info, new Uint8Array([i]));
    prev = await hmac(hash, prk, input);
    okm.set(prev, (i - 1) * hashLen);
  }
  return okm.slice(0, length);
}

// ── Node native HKDF ──────────────────────────────────────────────────────

async function hkdfNode(
  ikm: Uint8Array,
  options: Required<HkdfOptions>,
): Promise<Uint8Array> {
  const { hkdf } = await import('node:crypto');
  const { promisify } = await import('node:util');
  const hkdfAsync = promisify(hkdf);
  const hash = options.hash.toLowerCase().replace('-', '') as 'sha256' | 'sha384' | 'sha512';
  const result = await hkdfAsync(
    hash, ikm,
    options.salt ?? new Uint8Array(HASH_LEN[options.hash] ?? 32),
    options.info ?? new Uint8Array(0),
    options.outputLength,
  );
  return new Uint8Array(result);
}

// ── SubtleCrypto HKDF ─────────────────────────────────────────────────────

async function hkdfSubtle(
  ikm: Uint8Array,
  options: Required<HkdfOptions>,
): Promise<Uint8Array> {
  const ck = await globalThis.crypto.subtle.importKey(
    'raw', ikm, 'HKDF', false, ['deriveBits'],
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: options.hash,
      salt: options.salt ?? new Uint8Array(HASH_LEN[options.hash] ?? 32),
      info: options.info ?? new Uint8Array(0),
    },
    ck,
    options.outputLength * 8,
  );
  return new Uint8Array(bits);
}

// ── Public API ────────────────────────────────────────────────────────────

export const hkdf = {
  /**
   * HKDF — derive keying material from IKM.
   *
   * @example
   * const key = await hkdf.derive(sharedSecret, {
   *   hash: 'SHA-256',
   *   salt: randomSalt(),
   *   info: stringToBytes('LombokEncryptDecrypt v1 encryption key'),
   *   outputLength: 32,
   * });
   */
  async derive(ikm: Uint8Array, options: HkdfOptions): Promise<Uint8Array> {
    const max = MAX_OUTPUT_BYTES[options.hash];
    if (options.outputLength > (max ?? 8160)) {
      throw new RangeError(`HKDF output too long: max ${max} bytes for ${options.hash}`);
    }
    const opts: Required<HkdfOptions> = {
      hash: options.hash,
      salt: options.salt ?? new Uint8Array(0),
      info: options.info ?? new Uint8Array(0),
      outputLength: options.outputLength,
    };

    if (PLATFORM === 'node' && HAS_NODE_CRYPTO) return hkdfNode(ikm, opts);
    if (HAS_SUBTLE_CRYPTO) return hkdfSubtle(ikm, opts);
    // Pure path
    const prk = await extract(opts.hash, opts.salt, ikm);
    return expand(opts.hash, prk, opts.info, opts.outputLength);
  },

  /** Convenience: HKDF-SHA256 */
  async sha256(ikm: Uint8Array, salt?: Uint8Array, info?: Uint8Array, length = 32): Promise<Uint8Array> {
    return hkdf.derive(ikm, { hash: 'SHA-256', salt, info, outputLength: length });
  },

  /** Convenience: HKDF-SHA512 */
  async sha512(ikm: Uint8Array, salt?: Uint8Array, info?: Uint8Array, length = 64): Promise<Uint8Array> {
    return hkdf.derive(ikm, { hash: 'SHA-512', salt, info, outputLength: length });
  },
};
