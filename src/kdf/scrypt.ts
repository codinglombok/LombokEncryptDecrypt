/**
 * LombokEncryptDecrypt — scrypt (RFC 7914), pure TypeScript.
 *
 * PBKDF2-HMAC-SHA256 → ROMix (BlockMix with Salsa20/8 core) → PBKDF2 again.
 * Verified against the RFC 7914 §12 test vectors.
 */

import { pbkdf2Derive } from './pbkdf2.js';
import { hmacRaw } from '../mac/hmac.js';
import { SYNC_SHA256 } from '../core/sha/sha2.js';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  concatBytes,
  timingSafeEqual,
} from '../utils/encoding.js';
import { randomBytes } from '../utils/random.js';

export interface ScryptOptions {
  /** CPU/memory cost — must be a power of two greater than 1 (default 16384). */
  N?: number;
  /** Block size in 1 KiB units (default 8). */
  r?: number;
  /** Parallelisation factor (default 1). */
  p?: number;
  /** Derived key length in bytes (default 32). */
  dkLen?: number;
}

function salsa20Eight(block: Uint8Array, offset: number): void {
  // Operates on a 64-byte block in place; words are little-endian.
  const w = new Uint32Array(16);
  for (let i = 0; i < 16; i++) {
    const o = offset + i * 4;
    w[i] = (block[o] | (block[o + 1] << 8) | (block[o + 2] << 16) | (block[o + 3] << 24)) >>> 0;
  }
  const initial = Uint32Array.from(w);

  // Salsa20/8 = 8 rounds = 4 double-rounds (column round + row round each).
  for (let round = 0; round < 4; round++) {
    salsaQuarter(w, 0, 4, 8, 12);
    salsaQuarter(w, 5, 9, 13, 1);
    salsaQuarter(w, 10, 14, 2, 6);
    salsaQuarter(w, 15, 3, 7, 11);
    salsaQuarter(w, 0, 1, 2, 3);
    salsaQuarter(w, 5, 6, 7, 4);
    salsaQuarter(w, 10, 11, 8, 9);
    salsaQuarter(w, 15, 12, 13, 14);
  }

  for (let i = 0; i < 16; i++) {
    const v = (w[i] + initial[i]) >>> 0;
    const o = offset + i * 4;
    block[o] = v & 0xff;
    block[o + 1] = (v >>> 8) & 0xff;
    block[o + 2] = (v >>> 16) & 0xff;
    block[o + 3] = (v >>> 24) & 0xff;
  }
}

function salsaQuarter(w: Uint32Array, a: number, b: number, c: number, d: number): void {
  // Salsa20 quarter-round (Bernstein): the SUM is rotated, then XORed in —
  // y1 ^= rotl(y0 + y3, 7); y2 ^= rotl(y1 + y0, 9); … (NOT ChaCha's pattern).
  const rotl = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;
  w[b] = (w[b] ^ rotl((w[a] + w[d]) >>> 0, 7)) >>> 0;
  w[c] = (w[c] ^ rotl((w[b] + w[a]) >>> 0, 9)) >>> 0;
  w[d] = (w[d] ^ rotl((w[c] + w[b]) >>> 0, 13)) >>> 0;
  w[a] = (w[a] ^ rotl((w[d] + w[c]) >>> 0, 18)) >>> 0;
}

function blockMix(b: Uint8Array, r: number): Uint8Array {
  // RFC 7914 §2.3: X ← B_{2r−1}; Y_i ← Salsa(X ⊕ B_i) for i = 0..2r−1;
  // output B' = (Y_0, Y_2, …, Y_{2r−2}, Y_1, Y_3, …, Y_{2r−1}).
  const x = new Uint8Array(64);
  x.set(b.subarray((2 * r - 1) * 64, 2 * r * 64));
  const y = new Uint8Array(2 * r * 64);
  for (let i = 0; i < 2 * r; i++) {
    for (let j = 0; j < 64; j++) x[j] ^= b[i * 64 + j];
    salsa20Eight(x, 0);
    const destIndex = i % 2 === 0 ? (i / 2) * 64 : (r + (i - 1) / 2) * 64;
    y.set(x, destIndex);
  }
  return y;
}

function integerify(b: Uint8Array, r: number): bigint {
  // little-endian 64-byte → BigInt (only the first 8 bytes matter for N < 2^512)
  let v = 0n;
  for (let i = 7; i >= 0; i--) {
    v = (v << 8n) | BigInt(b[(2 * r - 1) * 64 + i]);
  }
  return v;
}

function romix(block: Uint8Array, N: number, r: number): Uint8Array {
  const v = new Uint8Array(N * 128 * r);
  let b = Uint8Array.from(block);
  // 1: X ← B; 2: for i = 0 to N−1 do V_i ← X; X ← BlockMix(X)
  for (let i = 0; i < N; i++) {
    v.set(b, i * 128 * r);
    b = blockMix(b, r);
  }
  // 3: for i = 0 to N−1 do j ← Integerify(X) mod N; X ← BlockMix(X ⊕ V_j)
  for (let i = 0; i < N; i++) {
    const j = Number(integerify(b, r) % BigInt(N));
    for (let k = 0; k < b.length; k++) b[k] ^= v[j * 128 * r + k];
    b = blockMix(b, r);
  }
  return b;
}

/** scrypt KDF (RFC 7914). */
export async function scryptDerive(
  password: string | Uint8Array,
  salt: string | Uint8Array,
  options?: ScryptOptions,
): Promise<Uint8Array> {
  const pass = typeof password === 'string' ? new TextEncoder().encode(password) : password;
  const salty = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;
  const N = options?.N ?? 16384;
  const r = options?.r ?? 8;
  const p = options?.p ?? 1;
  const dkLen = options?.dkLen ?? 32;
  if (N <= 1 || (N & (N - 1)) !== 0)
    throw new RangeError(`scrypt N must be a power of two greater than 1, got ${N}`);
  if (r < 1 || p < 1) throw new RangeError('scrypt r and p must be at least 1');
  const maxMemory = Math.floor((Number.MAX_SAFE_INTEGER - 1024) / (128 * r));
  if (N * p > maxMemory) throw new RangeError('scrypt parameters exceed memory limits');

  const b = await pbkdf2Derive(pass, {
    hash: 'SHA-256',
    salt: salty,
    iterations: 1,
    dkLen: p * 128 * r,
  });
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < p; i++) {
    chunks.push(romix(b.subarray(i * 128 * r, (i + 1) * 128 * r), N, r));
  }
  const mixed = concatBytes(...chunks);
  return pbkdf2Derive(pass, { hash: 'SHA-256', salt: mixed, iterations: 1, dkLen });
}

/** PBKDF2-HMAC-SHA256 exposed for KeyStore's KDF chain. */
export { pbkdf2Derive as pbkdf2Sha256Raw, hmacRaw, SYNC_SHA256 };

// ── scrypt object API (options-style) + PHC strings ─────────────────────

/** Ceiling for the scrypt cost factor (N = 2^20 with r = 8 costs 1 GiB). */
const MAX_SCRYPT_N_LIMIT = 2 ** 20;

function assertScryptCost(N: number, r: number, p: number, dkLen: number): void {
  if (!Number.isInteger(N) || N < 2 || N > MAX_SCRYPT_N_LIMIT || (N & (N - 1)) !== 0) {
    throw new RangeError(
      `scrypt N must be a power of two between 2 and ${MAX_SCRYPT_N_LIMIT}, got ${N}`,
    );
  }
  if (!Number.isInteger(r) || r < 1) {
    throw new RangeError(`scrypt r must be a positive integer, got ${r}`);
  }
  if (!Number.isInteger(p) || p < 1) {
    throw new RangeError(`scrypt p must be a positive integer, got ${p}`);
  }
  if (!Number.isInteger(dkLen) || dkLen < 1) {
    throw new RangeError(`scrypt dkLen must be a positive integer, got ${dkLen}`);
  }
}

/** Options-style scrypt: derive(password, { N, r, p, dkLen, salt }) plus PHC hash/verify. */
export const scrypt = {
  async derive(
    password: string | Uint8Array,
    options: ScryptOptions & { salt?: Uint8Array },
  ): Promise<Uint8Array> {
    const N = options.N ?? 16384;
    const r = options.r ?? 8;
    const p = options.p ?? 1;
    const dkLen = options.dkLen ?? 32;
    assertScryptCost(N, r, p, dkLen);
    const salt = options.salt ?? randomBytes(16);
    return scryptDerive(password, salt, { N, r, p, dkLen });
  },

  /** PHC-style hash: $scrypt$ln=<log2N>,r=<r>,p=<p>$<salt_b64url>$<hash_b64url> */
  async hash(
    password: string | Uint8Array,
    options?: { N?: number; r?: number; p?: number; dkLen?: number },
  ): Promise<string> {
    const N = options?.N ?? 16384;
    const r = options?.r ?? 8;
    const p = options?.p ?? 1;
    const dkLen = options?.dkLen ?? 32;
    assertScryptCost(N, r, p, dkLen);
    const salt = randomBytes(16);
    const dk = await scryptDerive(password, salt, { N, r, p, dkLen });
    const ln = Math.log2(N);
    return `$scrypt$ln=${ln},r=${r},p=${p}$${bytesToBase64Url(salt)}$${bytesToBase64Url(dk)}`;
  },

  /** Constant-time PHC verification — returns false on mismatch, never throws. */
  async verify(phc: string, password: string | Uint8Array): Promise<boolean> {
    try {
      const parts = phc.split('$');
      if (parts.length !== 5 || parts[0] !== '' || parts[1] !== 'scrypt') return false;
      const params = new Map(parts[2]!.split(',').map((kv) => kv.split('=') as [string, string]));
      const ln = Number(params.get('ln'));
      const r = Number(params.get('r'));
      const p = Number(params.get('p'));
      if (!Number.isInteger(ln) || ln < 1 || ln > 20) return false;
      if (!Number.isInteger(r) || r < 1 || !Number.isInteger(p) || p < 1) return false;
      const N = 2 ** ln;
      const salt = base64UrlToBytes(parts[3]!);
      const expected = base64UrlToBytes(parts[4]!);
      if (expected.length < 1) return false;
      const dk = await scryptDerive(password, salt, { N, r, p, dkLen: expected.length });
      return timingSafeEqual(dk, expected);
    } catch {
      return false;
    }
  },
};

/** Positional pure-TS scrypt (conformance tests compare it against OpenSSL). */
export function scryptPureInternal(
  password: Uint8Array,
  salt: Uint8Array,
  N: number,
  r: number,
  p: number,
  dkLen: number,
): Promise<Uint8Array> {
  assertScryptCost(N, r, p, dkLen);
  return scryptDerive(password, salt, { N, r, p, dkLen });
}
