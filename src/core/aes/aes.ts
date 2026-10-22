/**
 * LombokEncryptDecrypt — AES block cipher (FIPS 197), pure TypeScript.
 *
 * Byte-oriented implementation with column-major state layout
 * (flat index i = row + 4·column, identical to the FIPS input ordering).
 * The inverse S-box is derived by inverting the forward table, so no second
 * table can drift. Verified against the FIPS-197 appendix C vectors and
 * cross-checked with node:crypto for every key size.
 */

import { LombokCryptoError, ErrorCode } from '../../errors.js';

// prettier-ignore
const SBOX = Uint8Array.from([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

const INVSBOX = (() => {
  const inv = new Uint8Array(256);
  for (let i = 0; i < 256; i++) inv[SBOX[i]] = i;
  return inv;
})();

const RCON = Uint8Array.from([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

export interface AesExpandedKey {
  readonly rounds: number;
  readonly roundKeys: Uint8Array[]; // each 16 bytes, column-major
}

export const AES_BLOCK_SIZE = 16;

/** Convenience block-cipher handle over one expanded key. */
export function createAes(key: Uint8Array): {
  encryptBlock(block: Uint8Array): Uint8Array;
  decryptBlock(block: Uint8Array): Uint8Array;
} {
  const expanded = aesExpandKey(key);
  return {
    encryptBlock: (block: Uint8Array): Uint8Array => aesEncryptBlock(expanded, block),
    decryptBlock: (block: Uint8Array): Uint8Array => aesDecryptBlock(expanded, block),
  };
}

function xtime(x: number): number {
  return ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff;
}

function keySizeToRounds(size: number): number {
  if (size === 16) return 10;
  if (size === 24) return 12;
  if (size === 32) return 14;
  throw new LombokCryptoError(
    ErrorCode.INVALID_KEY_SIZE,
    `AES key must be 16, 24 or 32 bytes, got ${size}`,
    'AES',
  );
}

/** Expand a 128/192/256-bit key into the round key schedule. */
export function aesExpandKey(key: Uint8Array): AesExpandedKey {
  const rounds = keySizeToRounds(key.length);
  const nk = key.length / 4;
  const words = new Uint8Array(16 * (rounds + 1));
  words.set(key);
  let rconIndex = 0;
  for (let i = nk; i < (rounds + 1) * 4; i++) {
    let t0 = words[(i - 1) * 4];
    let t1 = words[(i - 1) * 4 + 1];
    let t2 = words[(i - 1) * 4 + 2];
    let t3 = words[(i - 1) * 4 + 3];
    if (i % nk === 0) {
      // RotWord + SubWord + Rcon
      const tmp = t0;
      t0 = SBOX[t1] ^ RCON[rconIndex];
      t1 = SBOX[t2];
      t2 = SBOX[t3];
      t3 = SBOX[tmp];
      rconIndex += 1;
    } else if (nk > 6 && i % nk === 4) {
      t0 = SBOX[t0];
      t1 = SBOX[t1];
      t2 = SBOX[t2];
      t3 = SBOX[t3];
    }
    words[i * 4] = words[(i - nk) * 4] ^ t0;
    words[i * 4 + 1] = words[(i - nk) * 4 + 1] ^ t1;
    words[i * 4 + 2] = words[(i - nk) * 4 + 2] ^ t2;
    words[i * 4 + 3] = words[(i - nk) * 4 + 3] ^ t3;
  }
  const roundKeys: Uint8Array[] = [];
  for (let r = 0; r <= rounds; r++) roundKeys.push(words.slice(r * 16, r * 16 + 16));
  return { rounds, roundKeys };
}

function addRoundKey(state: Uint8Array, roundKey: Uint8Array): void {
  for (let i = 0; i < 16; i++) state[i] ^= roundKey[i];
}

function subBytes(state: Uint8Array): void {
  for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

function invSubBytes(state: Uint8Array): void {
  for (let i = 0; i < 16; i++) state[i] = INVSBOX[state[i]];
}

/** ShiftRows with flat column-major indexing: row r rotates left by r. */
function shiftRows(state: Uint8Array): void {
  const copy = Uint8Array.from(state);
  for (let r = 1; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      state[r + 4 * c] = copy[r + 4 * ((c + r) % 4)];
    }
  }
}

function invShiftRows(state: Uint8Array): void {
  const copy = Uint8Array.from(state);
  for (let r = 1; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      state[r + 4 * ((c + r) % 4)] = copy[r + 4 * c];
    }
  }
}

function mixColumn(col: Uint8Array): Uint8Array {
  const a0 = col[0];
  const a1 = col[1];
  const a2 = col[2];
  const a3 = col[3];
  const t = (a0 ^ a1 ^ a2 ^ a3) & 0xff;
  const out = new Uint8Array(4);
  out[0] = (a0 ^ t ^ xtime(a0 ^ a1)) & 0xff;
  out[1] = (a1 ^ t ^ xtime(a1 ^ a2)) & 0xff;
  out[2] = (a2 ^ t ^ xtime(a2 ^ a3)) & 0xff;
  out[3] = (a3 ^ t ^ xtime(a3 ^ a0)) & 0xff;
  return out;
}

function invMixColumn(col: Uint8Array): Uint8Array {
  const mul = (x: number, factor: number): number => {
    let acc = 0;
    let base = x;
    let f = factor;
    while (f > 0) {
      if (f & 1) acc ^= base;
      base = xtime(base);
      f >>= 1;
    }
    return acc & 0xff;
  };
  const out = new Uint8Array(4);
  out[0] = mul(col[0], 14) ^ mul(col[1], 11) ^ mul(col[2], 13) ^ mul(col[3], 9);
  out[1] = mul(col[1], 14) ^ mul(col[2], 11) ^ mul(col[3], 13) ^ mul(col[0], 9);
  out[2] = mul(col[2], 14) ^ mul(col[3], 11) ^ mul(col[0], 13) ^ mul(col[1], 9);
  out[3] = mul(col[3], 14) ^ mul(col[0], 11) ^ mul(col[1], 13) ^ mul(col[2], 9);
  return out;
}

function mixColumns(state: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const col = mixColumn(state.subarray(c * 4, c * 4 + 4));
    state.set(col, c * 4);
  }
}

function invMixColumns(state: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const col = invMixColumn(state.subarray(c * 4, c * 4 + 4));
    state.set(col, c * 4);
  }
}

/** Encrypt a single 16-byte block (input/output column-major). */
export function aesEncryptBlock(expanded: AesExpandedKey, block: Uint8Array): Uint8Array {
  if (block.length !== AES_BLOCK_SIZE) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_INPUT,
      `AES block must be 16 bytes, got ${block.length}`,
      'AES',
    );
  }
  const state = Uint8Array.from(block);
  addRoundKey(state, expanded.roundKeys[0]);
  for (let round = 1; round < expanded.rounds; round++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, expanded.roundKeys[round]);
  }
  subBytes(state);
  shiftRows(state);
  addRoundKey(state, expanded.roundKeys[expanded.rounds]);
  return state;
}

/** Decrypt a single 16-byte block (input/output column-major). */
export function aesDecryptBlock(expanded: AesExpandedKey, block: Uint8Array): Uint8Array {
  if (block.length !== AES_BLOCK_SIZE) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_INPUT,
      `AES block must be 16 bytes, got ${block.length}`,
      'AES',
    );
  }
  const state = Uint8Array.from(block);
  addRoundKey(state, expanded.roundKeys[expanded.rounds]);
  for (let round = expanded.rounds - 1; round >= 1; round--) {
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, expanded.roundKeys[round]);
    invMixColumns(state);
  }
  invShiftRows(state);
  invSubBytes(state);
  addRoundKey(state, expanded.roundKeys[0]);
  return state;
}
