/**
 * LombokEncryptDecrypt — SM3 (GM/T 0004-2012), pure TypeScript, synchronous.
 *
 * 32-bit Merkle–Damgård hash with the GB/T message expansion. Verified
 * against the published GB/T test vectors and cross-checked with OpenSSL's
 * SM3 (node:crypto) on random inputs during development.
 */

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

const IV = Uint32Array.from([
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
]);
const T0 = 0x79cc4519;
const T1 = 0x7a879d8a;

function p0(x: number): number {
  return (x ^ rotl(x, 9) ^ rotl(x, 17)) >>> 0;
}

function p1(x: number): number {
  return (x ^ rotl(x, 15) ^ rotl(x, 23)) >>> 0;
}

function compress(state: Uint32Array, block: Uint8Array, blockStart: number): void {
  const w = new Uint32Array(68);
  for (let i = 0; i < 16; i++) {
    const o = blockStart + i * 4;
    w[i] = ((block[o] << 24) | (block[o + 1] << 16) | (block[o + 2] << 8) | block[o + 3]) >>> 0;
  }
  for (let j = 16; j < 68; j++) {
    w[j] = (p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) ^ rotl(w[j - 13], 7) ^ w[j - 6]) >>> 0;
  }

  let a = state[0];
  let b = state[1];
  let c = state[2];
  let d = state[3];
  let e = state[4];
  let f = state[5];
  let g = state[6];
  let h = state[7];

  for (let j = 0; j < 64; j++) {
    const t = j < 16 ? T0 : T1;
    const rotatedT = rotl(t, j % 32);
    const ss1 = rotl((rotl(a, 12) + e + rotatedT) >>> 0, 7);
    const ss2 = (ss1 ^ rotl(a, 12)) >>> 0;
    const ff = j < 16 ? a ^ b ^ c : (a & b) | (a & c) | (b & c);
    const gg = j < 16 ? e ^ f ^ g : (e & f) | (~e & g);
    const tt1 = (ff + d + ss2 + (w[j] ^ w[j + 4])) >>> 0;
    const tt2 = (gg + h + ss1 + w[j]) >>> 0;
    d = c;
    c = rotl(b, 9);
    b = a;
    a = tt1;
    h = g;
    g = rotl(f, 19);
    f = e;
    e = p0(tt2);
  }

  state[0] = (state[0] ^ a) >>> 0;
  state[1] = (state[1] ^ b) >>> 0;
  state[2] = (state[2] ^ c) >>> 0;
  state[3] = (state[3] ^ d) >>> 0;
  state[4] = (state[4] ^ e) >>> 0;
  state[5] = (state[5] ^ f) >>> 0;
  state[6] = (state[6] ^ g) >>> 0;
  state[7] = (state[7] ^ h) >>> 0;
}

function padSm3(data: Uint8Array): Uint8Array {
  const bitLenLo = (data.length << 3) >>> 0;
  const bitLenHi = Math.floor(data.length / 0x20000000);
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

/** SM3 — 32-byte digest (synchronous, per the documented API). */
export function sm3Raw(data: Uint8Array): Uint8Array {
  const padded = padSm3(data);
  const state = Uint32Array.from(IV);
  for (let off = 0; off < padded.length; off += 64) compress(state, padded, off);
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (state[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (state[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (state[i] >>> 8) & 0xff;
    out[i * 4 + 3] = state[i] & 0xff;
  }
  return out;
}

/** SM3 public hash object (synchronous, per the documented API). */
export const sm3 = {
  hash(data: Uint8Array): Uint8Array {
    return sm3Raw(data);
  },
};
