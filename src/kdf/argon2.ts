/**
 * LombokEncryptDecrypt — Argon2id / Argon2i / Argon2d
 *
 * Memory-hard password hashing. Argon2id is recommended for password hashing.
 * Reference: RFC 9106, NIST SP 800-63B
 *
 * Default parameters (OWASP 2024):
 *   m=65536 (64MB), t=3 iterations, p=4 parallelism
 *
 * PHC string format: $argon2id$v=19$m=65536,t=3,p=4$<salt_b64>$<hash_b64>
 *
 * @module kdf/argon2
 */

import type { Argon2Options } from '../types.js';
import { LombokCryptoError, ErrorCode } from '../errors.js';
import { randomSalt } from '../utils/random.js';
import { bytesToBase64Url, base64ToBytes, stringToBytes } from '../utils/encoding.js';
import { timingSafeEqual } from '../utils/timing.js';
import { HAS_NODE_CRYPTO, PLATFORM } from '../platform/detect.js';

export type Argon2Type = 'argon2d' | 'argon2i' | 'argon2id';

const ARGON2_VERSION = 0x13;  // v19

const DEFAULTS: Required<Omit<Argon2Options, 'salt'>> = {
  m: 65536,    // 64 MB
  t: 3,
  p: 4,
  hashLength: 32,
};

/** PHC string format: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash> */
function encodePhc(type: Argon2Type, m: number, t: number, p: number, salt: Uint8Array, hash: Uint8Array): string {
  return `$${type}$v=${ARGON2_VERSION}$m=${m},t=${t},p=${p}$${bytesToBase64Url(salt)}$${bytesToBase64Url(hash)}`;
}

function parsePhc(phc: string): {
  type: Argon2Type; version: number;
  m: number; t: number; p: number;
  salt: Uint8Array; hash: Uint8Array;
} {
  const parts = phc.split('$');
  if (parts.length !== 6) throw new LombokCryptoError(ErrorCode.INVALID_PARAMETER, 'Invalid PHC string');
  const [, type, versionStr, paramsStr, saltB64, hashB64] = parts;
  const version = parseInt((versionStr ?? '').replace('v=', ''), 10);
  const params: Record<string, number> = {};
  for (const kv of (paramsStr ?? '').split(',')) {
    const [k, v] = kv.split('=');
    if (k && v) params[k] = parseInt(v, 10);
  }
  return {
    type: (type ?? 'argon2id') as Argon2Type,
    version,
    m: params['m'] ?? DEFAULTS.m,
    t: params['t'] ?? DEFAULTS.t,
    p: params['p'] ?? DEFAULTS.p,
    salt: base64ToBytes(saltB64 ?? ''),
    hash: base64ToBytes(hashB64 ?? ''),
  };
}

// ── Platform dispatch ─────────────────────────────────────────────────────

async function hashWithNode(
  type: Argon2Type,
  password: Uint8Array,
  salt: Uint8Array,
  options: Required<Omit<Argon2Options, 'salt'>>,
): Promise<Uint8Array> {
  // Node.js 22+ has built-in argon2 via crypto.hash (experimental)
  // Fall back to pure implementation for now
  return hashPure(type, password, salt, options);
}

/**
 * Argon2 has no backend in v0.1.0: Node 22 has no crypto.argon2 and the RFC 9106
 * pure-TS implementation is not written yet. Fail loudly rather than return a
 * hash that is not Argon2 (an earlier skeleton returned a BLAKE2b-derived value).
 */
async function hashPure(
  type: Argon2Type,
  _password: Uint8Array,
  _salt: Uint8Array,
  _options: Required<Omit<Argon2Options, 'salt'>>,
): Promise<Uint8Array> {
  throw new LombokCryptoError(ErrorCode.UNSUPPORTED_ALGORITHM,
    'Argon2 is not implemented in v0.1.0. Use scrypt or PBKDF2 until the RFC 9106 implementation lands.',
    { algorithm: type });
}

// ── Public API ────────────────────────────────────────────────────────────

function makeHasher(type: Argon2Type) {
  return {
    /**
     * Hash a password. Returns a PHC string.
     * @example
     * const hash = await argon2id.hash('my-password');
     * // $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
     */
    async hash(password: string | Uint8Array, options: Partial<Argon2Options> = {}): Promise<string> {
      const pw = typeof password === 'string' ? stringToBytes(password) : password;
      const salt = options.salt ?? randomSalt(16);
      const opts: Required<Omit<Argon2Options, 'salt'>> = {
        m: options.m ?? DEFAULTS.m,
        t: options.t ?? DEFAULTS.t,
        p: options.p ?? DEFAULTS.p,
        hashLength: options.hashLength ?? DEFAULTS.hashLength,
      };
      const hash = (PLATFORM === 'node' && HAS_NODE_CRYPTO)
        ? await hashWithNode(type, pw, salt, opts)
        : await hashPure(type, pw, salt, opts);
      return encodePhc(type, opts.m, opts.t, opts.p, salt, hash);
    },

    /**
     * Verify a password against a PHC string.
     * Constant-time comparison — safe against timing attacks.
     */
    async verify(phcHash: string, password: string | Uint8Array): Promise<boolean> {
      const pw = typeof password === 'string' ? stringToBytes(password) : password;
      const parsed = parsePhc(phcHash);
      const opts: Required<Omit<Argon2Options, 'salt'>> = {
        m: parsed.m, t: parsed.t, p: parsed.p, hashLength: parsed.hash.length,
      };
      const computed = (PLATFORM === 'node' && HAS_NODE_CRYPTO)
        ? await hashWithNode(parsed.type, pw, parsed.salt, opts)
        : await hashPure(parsed.type, pw, parsed.salt, opts);
      return timingSafeEqual(computed, parsed.hash);
    },

    /**
     * Raw hash — returns bytes only (no PHC wrapping).
     */
    async raw(password: string | Uint8Array, salt: Uint8Array, options: Partial<Argon2Options> = {}): Promise<Uint8Array> {
      const pw = typeof password === 'string' ? stringToBytes(password) : password;
      const opts: Required<Omit<Argon2Options, 'salt'>> = {
        m: options.m ?? DEFAULTS.m,
        t: options.t ?? DEFAULTS.t,
        p: options.p ?? DEFAULTS.p,
        hashLength: options.hashLength ?? DEFAULTS.hashLength,
      };
      return (PLATFORM === 'node' && HAS_NODE_CRYPTO)
        ? hashWithNode(type, pw, salt, opts)
        : hashPure(type, pw, salt, opts);
    },
  };
}

export const argon2id = makeHasher('argon2id');
export const argon2i  = makeHasher('argon2i');
export const argon2d  = makeHasher('argon2d');
