/**
 * LombokEncryptDecrypt — SHA-224/256/384/512 (FIPS 180-4), pure TypeScript.
 *
 * The round constants and initial hash values are NOT transcribed from a
 * table: FIPS 180-4 defines them as the fractional parts of the cube roots
 * (K) and square roots (H) of the first 80 primes, so they are derived at
 * module init with exact BigInt integer-root arithmetic. A transcription
 * typo is therefore impossible, and the unit vectors ("abc", the 56-byte
 * block-boundary message, …) pin the transform itself.
 */

/** First `count` prime numbers (sieve of Eratosthenes, generous bound). */
function firstPrimes(count: number): number[] {
  const limit = 512; // 512nd prime is 3671 — far above the 80 we need
  const sieve = new Uint8Array(limit);
  const primes: number[] = [];
  for (let n = 2; n < limit && primes.length < count; n++) {
    if (sieve[n] === 0) {
      primes.push(n);
      for (let m = n * n; m < limit; m += n) sieve[m] = 1;
    }
  }
  return primes;
}

/** floor(n^(1/k)) via Newton iteration on BigInt — exact. */
function iroot(n: bigint, k: bigint): bigint {
  /* istanbul ignore if -- defensive: constants derivation always passes n >= 2 */
  if (n < 2n) return n;
  let x = 1n << (BigInt(n.toString(2).length) / k + 1n);
  let y = ((k - 1n) * x + n / x ** (k - 1n)) / k;
  while (y < x) {
    x = y;
    y = ((k - 1n) * x + n / x ** (k - 1n)) / k;
  }
  return x;
}

/**
 * floor(frac(p^(1/root)) * 2^bits) — the FIPS 180-4 constant derivation.
 * p * 2^(root*bits) has the integer root floor(p^(1/root) * 2^bits); masking
 * the low `bits` bits extracts the fractional part.
 */
function fracBitsRoot(p: number, bits: bigint, root: bigint): bigint {
  const scaled = BigInt(p) << (bits * root);
  return iroot(scaled, root) & ((1n << bits) - 1n);
}

const PRIMES_80 = firstPrimes(80);

// ── SHA-256 family (32-bit words) ────────────────────────────────────────────

const K256 = Uint32Array.from(PRIMES_80.slice(0, 64).map((p) => Number(fracBitsRoot(p, 32n, 3n))));
const H256 = Uint32Array.from(PRIMES_80.slice(0, 8).map((p) => Number(fracBitsRoot(p, 32n, 2n))));
// SHA-224 IV: published explicitly in FIPS 180-4 §5.3.2 (unlike SHA-256/384/512
// these eight words are specified as a table, not via the root derivation).
const H224 = Uint32Array.from([
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
]);

function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function sha256Compress(state: Uint32Array, block: Uint8Array, blockStart: number): void {
  const w = new Uint32Array(64);
  for (let i = 0; i < 16; i++) {
    const o = blockStart + i * 4;
    w[i] = ((block[o] << 24) | (block[o + 1] << 16) | (block[o + 2] << 8) | block[o + 3]) >>> 0;
  }
  for (let t = 16; t < 64; t++) {
    const s0 = rotr32(w[t - 15], 7) ^ rotr32(w[t - 15], 18) ^ (w[t - 15] >>> 3);
    const s1 = rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19) ^ (w[t - 2] >>> 10);
    w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
  }
  let a = state[0];
  let b = state[1];
  let c = state[2];
  let d = state[3];
  let e = state[4];
  let f = state[5];
  let g = state[6];
  let h = state[7];
  for (let t = 0; t < 64; t++) {
    const bigS1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + bigS1 + ch + K256[t] + w[t]) >>> 0;
    const bigS0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (bigS0 + maj) >>> 0;
    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }
  state[0] = (state[0] + a) >>> 0;
  state[1] = (state[1] + b) >>> 0;
  state[2] = (state[2] + c) >>> 0;
  state[3] = (state[3] + d) >>> 0;
  state[4] = (state[4] + e) >>> 0;
  state[5] = (state[5] + f) >>> 0;
  state[6] = (state[6] + g) >>> 0;
  state[7] = (state[7] + h) >>> 0;
}

function padSha256(data: Uint8Array): Uint8Array {
  const bitLenHi = Math.floor(data.length / 0x20000000); // data.length * 8 / 2^32
  const bitLenLo = (data.length << 3) >>> 0;
  const zeroCount = (((55 - data.length) % 64) + 64) % 64;
  const total = data.length + 1 + 8 + zeroCount;
  const padded = new Uint8Array(total);
  padded.set(data);
  padded[data.length] = 0x80;
  const lenOffset = total - 8;
  padded[lenOffset] = (bitLenHi >>> 24) & 0xff;
  padded[lenOffset + 1] = (bitLenHi >>> 16) & 0xff;
  padded[lenOffset + 2] = (bitLenHi >>> 8) & 0xff;
  padded[lenOffset + 3] = bitLenHi & 0xff;
  padded[lenOffset + 4] = (bitLenLo >>> 24) & 0xff;
  padded[lenOffset + 5] = (bitLenLo >>> 16) & 0xff;
  padded[lenOffset + 6] = (bitLenLo >>> 8) & 0xff;
  padded[lenOffset + 7] = bitLenLo & 0xff;
  return padded;
}

function sha256Core(data: Uint8Array, initialState: Uint32Array, truncateTo: number): Uint8Array {
  const padded = padSha256(data);
  const state = Uint32Array.from(initialState);
  for (let off = 0; off < padded.length; off += 64) sha256Compress(state, padded, off);
  const out = new Uint8Array(truncateTo);
  for (let i = 0; i < truncateTo; i++) out[i] = (state[i >> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  return out;
}

/** SHA-256 — 32-byte digest. */
export function sha256Raw(data: Uint8Array): Uint8Array {
  return sha256Core(data, H256, 32);
}

/** SHA-224 — 28-byte digest. */
export function sha224Raw(data: Uint8Array): Uint8Array {
  return sha256Core(data, H224, 28);
}

// ── SHA-512 family (64-bit words via BigInt) ─────────────────────────────────

const M64 = (1n << 64n) - 1n;
const K512: bigint[] = PRIMES_80.map((p) => fracBitsRoot(p, 64n, 3n));
const H512: bigint[] = PRIMES_80.slice(0, 8).map((p) => fracBitsRoot(p, 64n, 2n));
const H384: bigint[] = PRIMES_80.slice(8, 16).map((p) => fracBitsRoot(p, 64n, 2n));

function rotr64(x: bigint, n: bigint): bigint {
  return ((x >> n) | (x << (64n - n))) & M64;
}

function sha512Compress(state: bigint[], block: Uint8Array, blockStart: number): void {
  const w = new Array<bigint>(80).fill(0n);
  for (let i = 0; i < 16; i++) {
    let v = 0n;
    for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(block[blockStart + i * 8 + j]);
    w[i] = v;
  }
  for (let t = 16; t < 80; t++) {
    const s0 = rotr64(w[t - 15], 1n) ^ rotr64(w[t - 15], 8n) ^ (w[t - 15] >> 7n);
    const s1 = rotr64(w[t - 2], 19n) ^ rotr64(w[t - 2], 61n) ^ (w[t - 2] >> 6n);
    w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & M64;
  }
  let a = state[0];
  let b = state[1];
  let c = state[2];
  let d = state[3];
  let e = state[4];
  let f = state[5];
  let g = state[6];
  let h = state[7];
  for (let t = 0; t < 80; t++) {
    const bigS1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + bigS1 + ch + K512[t] + w[t]) & M64;
    const bigS0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (bigS0 + maj) & M64;
    h = g;
    g = f;
    f = e;
    e = (d + temp1) & M64;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) & M64;
  }
  state[0] = (state[0] + a) & M64;
  state[1] = (state[1] + b) & M64;
  state[2] = (state[2] + c) & M64;
  state[3] = (state[3] + d) & M64;
  state[4] = (state[4] + e) & M64;
  state[5] = (state[5] + f) & M64;
  state[6] = (state[6] + g) & M64;
  state[7] = (state[7] + h) & M64;
}

function padSha512(data: Uint8Array): Uint8Array {
  const bitLen = BigInt(data.length) * 8n;
  const zeroCount = (((111 - data.length) % 128) + 128) % 128;
  const total = data.length + 1 + 16 + zeroCount;
  const padded = new Uint8Array(total);
  padded.set(data);
  padded[data.length] = 0x80;
  const lenOffset = total - 16;
  for (let i = 0; i < 16; i++) {
    padded[lenOffset + i] = Number((bitLen >> BigInt((15 - i) * 8)) & 0xffn);
  }
  return padded;
}

function sha512Core(data: Uint8Array, initialState: bigint[], truncateTo: number): Uint8Array {
  const padded = padSha512(data);
  const state = initialState.slice();
  for (let off = 0; off < padded.length; off += 128) sha512Compress(state, padded, off);
  const out = new Uint8Array(truncateTo);
  let written = 0;
  for (let lane = 0; lane < 8 && written < truncateTo; lane++) {
    let v = state[lane];
    const chunk = new Uint8Array(8);
    for (let j = 7; j >= 0; j--) {
      chunk[j] = Number(v & 0xffn);
      v >>= 8n;
    }
    const take = Math.min(8, truncateTo - written);
    out.set(chunk.subarray(0, take), written);
    written += take;
  }
  return out;
}

/** SHA-512 — 64-byte digest. */
export function sha512Raw(data: Uint8Array): Uint8Array {
  return sha512Core(data, H512, 64);
}

/** SHA-384 — 48-byte digest. */
export function sha384Raw(data: Uint8Array): Uint8Array {
  return sha512Core(data, H384, 48);
}

/** Synchronous hash abstraction used by HMAC/CMAC/PBKDF2/scrypt. */
export interface SyncHash {
  readonly blockSize: number;
  readonly outputSize: number;
  digest(data: Uint8Array): Uint8Array;
}

function makeSyncHash(
  blockSize: number,
  outputSize: number,
  fn: (data: Uint8Array) => Uint8Array,
): SyncHash {
  return {
    blockSize,
    outputSize,
    digest: fn,
  };
}

/** SyncHash handle for SHA-256. */
export const SYNC_SHA256: SyncHash = makeSyncHash(64, 32, sha256Raw);
/** SyncHash handle for SHA-224. */
export const SYNC_SHA224: SyncHash = makeSyncHash(64, 28, sha224Raw);
/** SyncHash handle for SHA-512. */
export const SYNC_SHA512: SyncHash = makeSyncHash(128, 64, sha512Raw);
/** SyncHash handle for SHA-384. */
export const SYNC_SHA384: SyncHash = makeSyncHash(128, 48, sha384Raw);
