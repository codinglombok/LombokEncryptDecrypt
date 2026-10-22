/**
 * LombokEncryptDecrypt — PBKDF2 (RFC 8018) over HMAC-SHA2, pure TypeScript.
 */

import { hmacRaw } from '../mac/hmac.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';
import { sha384Raw, SYNC_SHA256, SYNC_SHA512, type SyncHash } from '../core/sha/sha2.js';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  concatBytes,
  timingSafeEqual,
} from '../utils/encoding.js';
import { randomBytes } from '../utils/random.js';

export type Pbkdf2Hash = 'SHA-256' | 'SHA-384' | 'SHA-512';

export interface Pbkdf2Options {
  iterations?: number;
  hash?: Pbkdf2Hash;
  salt?: Uint8Array;
  dkLen?: number;
}

function syncHashFor(name: Pbkdf2Hash): SyncHash {
  if (name === 'SHA-256') return SYNC_SHA256;
  if (name === 'SHA-384') return { blockSize: 128, outputSize: 48, digest: sha384Raw };
  if (name === 'SHA-512') return SYNC_SHA512;
  // Never silently fall back: an unknown hash name must fail loudly.
  throw new LombokCryptoError(
    ErrorCode.UNSUPPORTED_ALGORITHM,
    `unsupported PBKDF2 hash "${String(name)}"`,
    'PBKDF2',
  );
}

/** PBKDF2-HMAC-SHA2. */
export async function pbkdf2Derive(
  password: string | Uint8Array,
  options?: Pbkdf2Options,
): Promise<Uint8Array> {
  const pass = typeof password === 'string' ? new TextEncoder().encode(password) : password;
  const hash = syncHashFor(options?.hash ?? 'SHA-256');
  const salt = options?.salt ?? randomBytes(16);
  const iterations = options?.iterations ?? 600_000;
  const dkLen = options?.dkLen ?? 32;
  if (!Number.isInteger(iterations) || iterations < 1)
    throw new RangeError(`iterations must be a positive integer, got ${iterations}`);
  if (dkLen <= 0) throw new RangeError(`dkLen must be positive, got ${dkLen}`);

  const blocks = Math.ceil(dkLen / hash.outputSize);
  const out = new Uint8Array(dkLen);
  for (let block = 1; block <= blocks; block++) {
    const blockIndex = new Uint8Array(4);
    blockIndex[0] = (block >>> 24) & 0xff;
    blockIndex[1] = (block >>> 16) & 0xff;
    blockIndex[2] = (block >>> 8) & 0xff;
    blockIndex[3] = block & 0xff;
    let u = hmacRaw(hash, pass, concatBytes(salt, blockIndex));
    const t = new Uint8Array(hash.outputSize);
    t.set(u);
    for (let i = 1; i < iterations; i++) {
      u = hmacRaw(hash, pass, u);
      for (let j = 0; j < t.length; j++) t[j] ^= u[j];
    }
    const offset = (block - 1) * hash.outputSize;
    out.set(t.subarray(0, Math.min(hash.outputSize, dkLen - offset)), offset);
  }
  return out;
}

type Pbkdf2Convenience = {
  (
    password: string | Uint8Array,
    salt: Uint8Array,
    iterations: number,
    dkLen: number,
  ): Promise<Uint8Array>;
  derive(
    password: string | Uint8Array,
    salt: Uint8Array,
    iterations: number,
    dkLen: number,
  ): Promise<Uint8Array>;
};

function makeConvenience(hashName: Pbkdf2Hash): Pbkdf2Convenience {
  const fn = async (
    password: string | Uint8Array,
    salt: Uint8Array,
    iterations: number,
    dkLen: number,
  ): Promise<Uint8Array> => pbkdf2Derive(password, { hash: hashName, salt, iterations, dkLen });
  // Both call styles are supported: pbkdf2.sha256(...) and pbkdf2.sha256.derive(...).
  const withDerive = fn as unknown as Pbkdf2Convenience;
  withDerive.derive = fn;
  return withDerive;
}

export const pbkdf2 = {
  derive: pbkdf2Derive,
  sha256: makeConvenience('SHA-256'),
  sha512: makeConvenience('SHA-512'),
  /**
   * PHC-style hash with a random salt (verification via `verify`).
   * Format: $pbkdf2-sha256$i=...$<salt_b64url>$<hash_b64url>
   */
  async hash(password: string | Uint8Array, options?: Pbkdf2Options): Promise<string> {
    const hashName = options?.hash ?? 'SHA-256';
    if (hashName !== 'SHA-256' && hashName !== 'SHA-384' && hashName !== 'SHA-512') {
      throw new LombokCryptoError(
        ErrorCode.UNSUPPORTED_ALGORITHM,
        `unsupported PBKDF2 hash "${String(hashName)}"`,
        'PBKDF2',
      );
    }
    const iterations = options?.iterations ?? 600_000;
    const dkLen = options?.dkLen ?? 32;
    const salt = options?.salt ?? randomBytes(16);
    const dk = await pbkdf2Derive(password, { hash: hashName, iterations, dkLen, salt });
    // PHC naming: "pbkdf2-sha256" (no dash between sha and the size)
    const phcName = hashName.toLowerCase().replace('-', '');
    return `$pbkdf2-${phcName}$i=${iterations}$${bytesToBase64Url(salt)}$${bytesToBase64Url(dk)}`;
  },
  /** Constant-time PHC verification — returns false on mismatch, never throws. */
  async verify(phc: string, password: string | Uint8Array): Promise<boolean> {
    const parts = phc.split('$');
    if (parts.length !== 5 || parts[0] !== '') return false;
    const algo = parts[1];
    if (!algo.startsWith('pbkdf2-')) return false;
    // PHC name "sha256" → internal "SHA-256"
    const rawName = algo.slice('pbkdf2-'.length);
    const hashName = (
      rawName.startsWith('sha') ? `sha-${rawName.slice(3)}` : rawName
    ).toUpperCase() as Pbkdf2Hash;
    if (hashName !== 'SHA-256' && hashName !== 'SHA-384' && hashName !== 'SHA-512') return false;
    const iterParts = parts[2].split('=');
    if (iterParts[0] !== 'i' || iterParts.length !== 2) return false;
    const iterations = Number(iterParts[1]);
    if (!Number.isInteger(iterations) || iterations < 1) return false;
    const salt = base64UrlToBytes(parts[3]);
    const expected = base64UrlToBytes(parts[4]);
    const dk = await pbkdf2Derive(password, {
      hash: hashName,
      iterations,
      salt,
      dkLen: expected.length,
    });
    return timingSafeEqual(dk, expected);
  },
};
