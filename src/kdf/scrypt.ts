/**
 * LombokEncryptDecrypt — scrypt (RFC 7914)
 * Memory-hard password-based key derivation.
 *
 * Backends:
 *   1. node:crypto scryptSync (Node.js, when importable)
 *   2. Pure TypeScript fallback (browser / Deno / Bun / Workers),
 *      using WebCrypto PBKDF2-SHA256 for the outer PBKDF2 steps.
 *
 * Both backends must produce identical output; the RFC 7914 §12 vectors
 * are checked in tests/unit/scrypt.test.ts.
 *
 * @module kdf/scrypt
 */

export interface ScryptParams {
  /** CPU/memory cost. Power of two, > 1. Default 2^16 (OWASP 2024). */
  N?: number;
  /** Block size. Default 8. */
  r?: number;
  /** Parallelization. Default 1. */
  p?: number;
  /** Output length in bytes. Default 32. */
  dkLen?: number;
  /** Salt. A random 16-byte salt is generated when omitted. */
  salt?: Uint8Array;
}

const DEFAULTS = { N: 65536, r: 8, p: 1, dkLen: 32 } as const;
const encoder = new TextEncoder();

function toBytes(value: string | Uint8Array): Uint8Array {
  return typeof value === 'string' ? encoder.encode(value) : value;
}

function randomSalt(length = 16): Uint8Array {
  const salt = new Uint8Array(length);
  globalThis.crypto.getRandomValues(salt);
  return salt;
}

function validate(N: number, r: number, p: number, dkLen: number): void {
  if (!Number.isInteger(N) || N < 2 || N > 2 ** 30 || (N & (N - 1)) !== 0) {
    throw new RangeError('scrypt: N must be a power of two greater than 1');
  }
  if (!Number.isInteger(r) || r < 1) throw new RangeError('scrypt: r must be a positive integer');
  if (!Number.isInteger(p) || p < 1) throw new RangeError('scrypt: p must be a positive integer');
  if (r * p >= 2 ** 30) throw new RangeError('scrypt: r * p is too large');
  if (!Number.isInteger(dkLen) || dkLen < 1 || dkLen > 2 ** 20) {
    throw new RangeError('scrypt: dkLen must be between 1 and 2^20 bytes');
  }
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// ── Base64url (no padding) for PHC strings ────────────────────────────────

function b64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(text: string): Uint8Array {
  const std = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// ── PBKDF2-SHA256 via WebCrypto ───────────────────────────────────────────

async function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('scrypt: WebCrypto (crypto.subtle) is not available');
  const key = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

// ── Salsa20/8 core (RFC 7914 §3) ──────────────────────────────────────────

function rotl(a: number, b: number): number {
  return (a << b) | (a >>> (32 - b));
}

/** In-place Salsa20/8 on a 16-word block. */
function salsa208(B: Uint32Array): void {
  const x = new Uint32Array(B);
  for (let i = 0; i < 8; i += 2) {
    // Column round
    x[4]! ^= rotl(x[0]! + x[12]!, 7);   x[8]!  ^= rotl(x[4]! + x[0]!, 9);
    x[12]! ^= rotl(x[8]! + x[4]!, 13);  x[0]!  ^= rotl(x[12]! + x[8]!, 18);
    x[9]! ^= rotl(x[5]! + x[1]!, 7);    x[13]! ^= rotl(x[9]! + x[5]!, 9);
    x[1]! ^= rotl(x[13]! + x[9]!, 13);  x[5]!  ^= rotl(x[1]! + x[13]!, 18);
    x[14]! ^= rotl(x[10]! + x[6]!, 7);  x[2]!  ^= rotl(x[14]! + x[10]!, 9);
    x[6]! ^= rotl(x[2]! + x[14]!, 13);  x[10]! ^= rotl(x[6]! + x[2]!, 18);
    x[3]! ^= rotl(x[15]! + x[11]!, 7);  x[7]!  ^= rotl(x[3]! + x[15]!, 9);
    x[11]! ^= rotl(x[7]! + x[3]!, 13);  x[15]! ^= rotl(x[11]! + x[7]!, 18);
    // Row round
    x[1]! ^= rotl(x[0]! + x[3]!, 7);    x[2]!  ^= rotl(x[1]! + x[0]!, 9);
    x[3]! ^= rotl(x[2]! + x[1]!, 13);   x[0]!  ^= rotl(x[3]! + x[2]!, 18);
    x[6]! ^= rotl(x[5]! + x[4]!, 7);    x[7]!  ^= rotl(x[6]! + x[5]!, 9);
    x[4]! ^= rotl(x[7]! + x[6]!, 13);   x[5]!  ^= rotl(x[4]! + x[7]!, 18);
    x[11]! ^= rotl(x[10]! + x[9]!, 7);  x[8]!  ^= rotl(x[11]! + x[10]!, 9);
    x[9]! ^= rotl(x[8]! + x[11]!, 13);  x[10]! ^= rotl(x[9]! + x[8]!, 18);
    x[12]! ^= rotl(x[15]! + x[14]!, 7); x[13]! ^= rotl(x[12]! + x[15]!, 9);
    x[14]! ^= rotl(x[13]! + x[12]!, 13); x[15]! ^= rotl(x[14]! + x[13]!, 18);
  }
  for (let i = 0; i < 16; i++) B[i] = (B[i]! + x[i]!) >>> 0;
}

// ── BlockMix / ROMix (RFC 7914 §4) ────────────────────────────────────────

/** Input: 2r blocks of 16 words. Output: 2r blocks, even-indexed first. */
function blockMix(B: Uint32Array, r: number): Uint32Array {
  const out = new Uint32Array(B.length);
  const X = new Uint32Array(16);
  X.set(B.subarray((2 * r - 1) * 16, 2 * r * 16));
  for (let i = 0; i < 2 * r; i++) {
    for (let j = 0; j < 16; j++) X[j] = (X[j]! ^ B[i * 16 + j]!) >>> 0;
    salsa208(X);
    const slot = i % 2 === 0 ? i / 2 : r + (i - 1) / 2;
    out.set(X, slot * 16);
  }
  return out;
}

function roMix(B: Uint32Array, N: number, r: number): Uint32Array {
  const words = 32 * r;
  const V = new Uint32Array(N * words);
  let X = B.slice();
  for (let i = 0; i < N; i++) {
    V.set(X, i * words);
    X = blockMix(X, r);
  }
  for (let i = 0; i < N; i++) {
    // Integerify: first word of the last block, reduced mod N (N is a power of two).
    const j = X[(2 * r - 1) * 16]! % N;
    const Vj = V.subarray(j * words, (j + 1) * words);
    for (let k = 0; k < words; k++) X[k] = (X[k]! ^ Vj[k]!) >>> 0;
    X = blockMix(X, r);
  }
  return X;
}

// ── Backends ──────────────────────────────────────────────────────────────

async function scryptPure(
  password: Uint8Array,
  salt: Uint8Array,
  N: number,
  r: number,
  p: number,
  dkLen: number,
): Promise<Uint8Array> {
  const blockBytes = 128 * r;
  const words = 32 * r;
  const B = await pbkdf2Sha256(password, salt, 1, p * blockBytes);
  const view = new DataView(B.buffer, B.byteOffset, B.byteLength);

  for (let i = 0; i < p; i++) {
    const base = i * blockBytes;
    const chunk = new Uint32Array(words);
    for (let w = 0; w < words; w++) chunk[w] = view.getUint32(base + w * 4, true);
    const mixed = roMix(chunk, N, r);
    for (let w = 0; w < words; w++) view.setUint32(base + w * 4, mixed[w]!, true);
  }
  return pbkdf2Sha256(password, B, 1, dkLen);
}

async function loadNodeCrypto(): Promise<typeof import('node:crypto') | null> {
  if (typeof process === 'undefined' || !process.versions?.node) return null;
  try {
    return await import('node:crypto');
  } catch {
    return null;
  }
}

// ── Public API ────────────────────────────────────────────────────────────

export const scrypt = {
  /**
   * Derive a key with scrypt.
   *
   * @example
   * const key = await scrypt.derive('correct horse', { N: 65536, r: 8, p: 1 });
   */
  async derive(password: string | Uint8Array, params: ScryptParams = {}): Promise<Uint8Array> {
    const pw = toBytes(password);
    const N = params.N ?? DEFAULTS.N;
    const r = params.r ?? DEFAULTS.r;
    const p = params.p ?? DEFAULTS.p;
    const dkLen = params.dkLen ?? DEFAULTS.dkLen;
    const salt = params.salt ?? randomSalt();
    validate(N, r, p, dkLen);

    const nodeCrypto = await loadNodeCrypto();
    if (nodeCrypto) {
      return new Uint8Array(
        nodeCrypto.scryptSync(pw, salt, dkLen, { N, r, p, maxmem: 256 * N * r }),
      );
    }
    return scryptPure(pw, salt, N, r, p, dkLen);
  },

  /**
   * Hash a password to a PHC string:
   * `$scrypt$ln=16,r=8,p=1$<salt b64url>$<hash b64url>`
   */
  async hash(password: string | Uint8Array, params: ScryptParams = {}): Promise<string> {
    const N = params.N ?? DEFAULTS.N;
    const r = params.r ?? DEFAULTS.r;
    const p = params.p ?? DEFAULTS.p;
    const dkLen = params.dkLen ?? DEFAULTS.dkLen;
    const salt = params.salt ?? randomSalt();
    const hash = await scrypt.derive(password, { N, r, p, dkLen, salt });
    return `$scrypt$ln=${Math.round(Math.log2(N))},r=${r},p=${p}$${b64url(salt)}$${b64url(hash)}`;
  },

  /** Verify a password against a PHC string produced by {@link scrypt.hash}. Never throws. */
  async verify(phcHash: string, password: string | Uint8Array): Promise<boolean> {
    try {
      const parts = phcHash.split('$');
      if (parts.length !== 5 || parts[0] !== '' || parts[1] !== 'scrypt') return false;
      const fields: Record<string, number> = {};
      for (const pair of parts[2]!.split(',')) {
        const [key, value] = pair.split('=');
        if (key && value) fields[key] = Number.parseInt(value, 10);
      }
      const ln = fields['ln'];
      const r = fields['r'];
      const p = fields['p'];
      if (ln === undefined || r === undefined || p === undefined) return false;
      const salt = unb64url(parts[3]!);
      const expected = unb64url(parts[4]!);
      const computed = await scrypt.derive(password, {
        N: 2 ** ln,
        r,
        p,
        salt,
        dkLen: expected.length,
      });
      return constantTimeEqual(computed, expected);
    } catch {
      return false;
    }
  },
};

/** @internal exposed for conformance tests */
export { scryptPure as scryptPureInternal };
