/**
 * LombokEncryptDecrypt — AES Core (Pure TypeScript)
 *
 * AES-128/192/256 key schedule and block cipher.
 * This is the pure TS fallback. Node.js and NAPI paths use native AES-NI.
 *
 * Reference: NIST FIPS 197
 * Test vectors: NIST FIPS 197 Appendix A + B
 *
 * @module core/aes
 */

import { LombokCryptoError, ErrorCode } from '../../errors.js';

// ── AES S-box and inverse S-box ───────────────────────────────────────────

const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);

// Rcon table for key schedule
const RCON = new Uint8Array([
  0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
]);

// ── Key Expansion ──────────────────────────────────────────────────────────

function subWord(word: number): number {
  return (
    (SBOX[(word >>> 24) & 0xff]! << 24) |
    (SBOX[(word >>> 16) & 0xff]! << 16) |
    (SBOX[(word >>> 8) & 0xff]! << 8) |
    SBOX[word & 0xff]!
  );
}

function rotWord(word: number): number {
  return ((word << 8) | (word >>> 24)) >>> 0;
}

/** Expand an AES key into round keys. Returns Uint32Array of round key words. */
export function expandKey(key: Uint8Array): Uint32Array {
  const keyLen = key.length;
  if (keyLen !== 16 && keyLen !== 24 && keyLen !== 32) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `AES key must be 16, 24, or 32 bytes; got ${keyLen}`,
      { algorithm: 'AES' },
    );
  }

  const nk = keyLen / 4;       // Number of 32-bit words in key
  const nr = nk + 6;            // Number of rounds
  const totalWords = 4 * (nr + 1);
  const w = new Uint32Array(totalWords);

  // Copy key into w
  for (let i = 0; i < nk; i++) {
    w[i] =
      ((key[i * 4] ?? 0) << 24) |
      ((key[i * 4 + 1] ?? 0) << 16) |
      ((key[i * 4 + 2] ?? 0) << 8) |
      (key[i * 4 + 3] ?? 0);
  }

  // Key schedule core
  for (let i = nk; i < totalWords; i++) {
    let temp = w[i - 1]!;
    if (i % nk === 0) {
      temp = (subWord(rotWord(temp)) ^ ((RCON[(i / nk) - 1] ?? 0) << 24)) >>> 0;
    } else if (nk > 6 && i % nk === 4) {
      temp = subWord(temp) >>> 0;
    }
    w[i] = (w[i - nk]! ^ temp) >>> 0;
  }

  return w;
}

/** AES block encrypt (16 bytes). Pure TS, no hardware acceleration. */
export function aesEncryptBlock(block: Uint8Array, roundKeys: Uint32Array): Uint8Array {
  const nr = (roundKeys.length / 4) - 1;
  const state = new Uint32Array(4);

  // AddRoundKey (round 0)
  for (let i = 0; i < 4; i++) {
    state[i] = (
      ((block[i * 4] ?? 0) << 24) |
      ((block[i * 4 + 1] ?? 0) << 16) |
      ((block[i * 4 + 2] ?? 0) << 8) |
      (block[i * 4 + 3] ?? 0)
    ) ^ roundKeys[i]!;
  }

  // Rounds 1 .. nr-1
  for (let round = 1; round < nr; round++) {
    const s0 = state[0]!;
    const s1 = state[1]!;
    const s2 = state[2]!;
    const s3 = state[3]!;

    state[0] = mixColsSubShift(s0, s1, s2, s3, 0) ^ roundKeys[round * 4]!;
    state[1] = mixColsSubShift(s1, s2, s3, s0, 1) ^ roundKeys[round * 4 + 1]!;
    state[2] = mixColsSubShift(s2, s3, s0, s1, 2) ^ roundKeys[round * 4 + 2]!;
    state[3] = mixColsSubShift(s3, s0, s1, s2, 3) ^ roundKeys[round * 4 + 3]!;
  }

  // Final round (no MixColumns)
  const fs0 = state[0]!; const fs1 = state[1]!;
  const fs2 = state[2]!; const fs3 = state[3]!;
  state[0] = subShiftNoMix(fs0, fs1, fs2, fs3) ^ roundKeys[nr * 4]!;
  state[1] = subShiftNoMix(fs1, fs2, fs3, fs0) ^ roundKeys[nr * 4 + 1]!;
  state[2] = subShiftNoMix(fs2, fs3, fs0, fs1) ^ roundKeys[nr * 4 + 2]!;
  state[3] = subShiftNoMix(fs3, fs0, fs1, fs2) ^ roundKeys[nr * 4 + 3]!;

  const out = new Uint8Array(16);
  for (let i = 0; i < 4; i++) {
    const w = state[i]!;
    out[i * 4] = (w >>> 24) & 0xff;
    out[i * 4 + 1] = (w >>> 16) & 0xff;
    out[i * 4 + 2] = (w >>> 8) & 0xff;
    out[i * 4 + 3] = w & 0xff;
  }
  return out;
}

// GF(2^8) multiply by 2 (xtime)
function xtime(a: number): number {
  return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
}

function mixColsSubShift(a: number, b: number, c: number, d: number, _col: number): number {
  const s0 = SBOX[(a >>> 24) & 0xff]!;
  const s1 = SBOX[(b >>> 16) & 0xff]!;
  const s2 = SBOX[(c >>> 8) & 0xff]!;
  const s3 = SBOX[d & 0xff]!;

  const m0 = xtime(s0);
  const m1 = xtime(s1);
  const m2 = xtime(s2);
  const m3 = xtime(s3);

  return (
    (((m0 ^ m1 ^ s1 ^ s2 ^ s3) & 0xff) << 24) |
    (((s0 ^ m1 ^ m2 ^ s2 ^ s3) & 0xff) << 16) |
    (((s0 ^ s1 ^ m2 ^ m3 ^ s3) & 0xff) << 8) |
    ((m0 ^ s0 ^ s1 ^ s2 ^ m3) & 0xff)
  ) >>> 0;
}

function subShiftNoMix(a: number, b: number, c: number, d: number): number {
  return (
    ((SBOX[(a >>> 24) & 0xff]! & 0xff) << 24) |
    ((SBOX[(b >>> 16) & 0xff]! & 0xff) << 16) |
    ((SBOX[(c >>> 8) & 0xff]! & 0xff) << 8) |
    (SBOX[d & 0xff]! & 0xff)
  ) >>> 0;
}

// ── Public AES ECB interface ──────────────────────────────────────────────

// ── Inverse cipher (FIPS 197 §5.3) ────────────────────────────────────────

const INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]!] = i;

function gmul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

const MUL9 = new Uint8Array(256);
const MUL11 = new Uint8Array(256);
const MUL13 = new Uint8Array(256);
const MUL14 = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  MUL9[i] = gmul(i, 9); MUL11[i] = gmul(i, 11); MUL13[i] = gmul(i, 13); MUL14[i] = gmul(i, 14);
}

/** AES block decrypt (16 bytes) with the round keys from {@link expandKey}. Pure TS. */
export function aesDecryptBlock(block: Uint8Array, roundKeys: Uint32Array): Uint8Array {
  if (block.length !== 16) {
    throw new LombokCryptoError(ErrorCode.INVALID_INPUT, `AES block must be 16 bytes; got ${block.length}`, { algorithm: 'AES' });
  }
  const nr = roundKeys.length / 4 - 1;
  const s = new Uint8Array(16);
  const addRoundKey = (round: number): void => {
    for (let c = 0; c < 4; c++) {
      const w = roundKeys[round * 4 + c]!;
      s[c * 4] = s[c * 4]! ^ (w >>> 24);
      s[c * 4 + 1] = s[c * 4 + 1]! ^ ((w >>> 16) & 0xff);
      s[c * 4 + 2] = s[c * 4 + 2]! ^ ((w >>> 8) & 0xff);
      s[c * 4 + 3] = s[c * 4 + 3]! ^ (w & 0xff);
    }
  };
  const invShiftSub = (): void => {
    const t = Uint8Array.from(s);
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) s[((c + r) % 4) * 4 + r] = INV_SBOX[t[c * 4 + r]!]!;
    }
  };
  s.set(block);
  addRoundKey(nr);
  for (let round = nr - 1; round >= 1; round--) {
    invShiftSub();
    addRoundKey(round);
    for (let c = 0; c < 4; c++) {
      const a0 = s[c * 4]!, a1 = s[c * 4 + 1]!, a2 = s[c * 4 + 2]!, a3 = s[c * 4 + 3]!;
      s[c * 4] = MUL14[a0]! ^ MUL11[a1]! ^ MUL13[a2]! ^ MUL9[a3]!;
      s[c * 4 + 1] = MUL9[a0]! ^ MUL14[a1]! ^ MUL11[a2]! ^ MUL13[a3]!;
      s[c * 4 + 2] = MUL13[a0]! ^ MUL9[a1]! ^ MUL14[a2]! ^ MUL11[a3]!;
      s[c * 4 + 3] = MUL11[a0]! ^ MUL13[a1]! ^ MUL9[a2]! ^ MUL14[a3]!;
    }
  }
  invShiftSub();
  addRoundKey(0);
  return s;
}

export interface AesCore {
  readonly keyLength: 16 | 24 | 32;
  readonly rounds: 10 | 12 | 14;
  encryptBlock(block: Uint8Array): Uint8Array;
  decryptBlock(block: Uint8Array): Uint8Array;
}

export function createAes(key: Uint8Array): AesCore {
  const roundKeys = expandKey(key);
  const keyLen = key.length as 16 | 24 | 32;
  const rounds = (roundKeys.length / 4 - 1) as 10 | 12 | 14;
  return {
    keyLength: keyLen,
    rounds,
    encryptBlock: (block: Uint8Array) => aesEncryptBlock(block, roundKeys),
    decryptBlock: (block: Uint8Array) => aesDecryptBlock(block, roundKeys),
  };
}
