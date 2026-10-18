/**
 * LombokEncryptDecrypt — SHA-3 (Keccak-p[1600]) + SHAKE-128/256
 * Reference: NIST FIPS 202
 * @module core/sha/sha3
 */

import { HAS_SUBTLE_CRYPTO, HAS_NODE_CRYPTO, PLATFORM } from '../../platform/detect.js';

// Keccak round constants (64-bit via BigInt pairs stored as [lo, hi])
const RC: bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808An, 0x8000000080008000n,
  0x000000000000808Bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008An, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000An,
  0x000000008000808Bn, 0x800000000000008Bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800An, 0x800000008000000An,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rho rotation offsets r[x][y] from FIPS 202 Table 2, laid out by lane index x + 5*y.
const ROT: number[] = [
  0,  1,  62, 28, 27,
  36, 44, 6,  55, 20,
  3,  10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2,  61, 56, 14,
];

function rotl64(x: bigint, n: number): bigint {
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & 0xFFFFFFFFFFFFFFFFn;
}

function keccakF(state: bigint[]): void {
  for (let round = 0; round < 24; round++) {
    // θ
    const C = [0,1,2,3,4].map(x => state[x]! ^ state[x+5]! ^ state[x+10]! ^ state[x+15]! ^ state[x+20]!);
    const D = [0,1,2,3,4].map(x => C[(x+4)%5]! ^ rotl64(C[(x+1)%5]!, 1));
    for (let i = 0; i < 25; i++) state[i] = state[i]! ^ D[i%5]!;
    // ρ + π
    const B: bigint[] = new Array(25).fill(0n);
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        // B[y, 2x + 3y] = rot(A[x, y], r[x, y])
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y]!, ROT[x + 5 * y]!);
      }
    }
    // χ
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        state[x + 5*y] = B[x + 5*y]! ^ ((~B[(x+1)%5 + 5*y]!) & B[(x+2)%5 + 5*y]!);
        state[x + 5*y]! &= 0xFFFFFFFFFFFFFFFFn;
      }
    }
    // ι
    state[0] = state[0]! ^ RC[round]!;
  }
}

export function keccakSponge(data: Uint8Array, rate: number, outputLen: number, domain: number): Uint8Array {
  const state: bigint[] = new Array(25).fill(0n);
  const rateBytes = rate / 8;
  // Absorb
  const padded = new Uint8Array(Math.ceil((data.length + 1) / rateBytes) * rateBytes);
  padded.set(data);
  padded[data.length] = domain;
  padded[padded.length - 1]! |= 0x80;
  for (let i = 0; i < padded.length; i += rateBytes) {
    for (let j = 0; j < rateBytes / 8; j++) {
      let word = 0n;
      for (let b = 0; b < 8; b++) word |= BigInt(padded[i + j*8 + b] ?? 0) << BigInt(b*8);
      state[j] = (state[j]! ^ word) & 0xFFFFFFFFFFFFFFFFn;
    }
    keccakF(state);
  }
  // Squeeze
  const out: number[] = [];
  while (out.length < outputLen) {
    for (let j = 0; j < rateBytes / 8 && out.length < outputLen; j++) {
      for (let b = 0; b < 8 && out.length < outputLen; b++) {
        out.push(Number((state[j]! >> BigInt(b*8)) & 0xFFn));
      }
    }
    if (out.length < outputLen) keccakF(state);
  }
  return new Uint8Array(out.slice(0, outputLen));
}

async function sha3Native(data: Uint8Array, bits: 224|256|384|512): Promise<Uint8Array> {
  if (HAS_SUBTLE_CRYPTO) {
    try {
      return new Uint8Array(await globalThis.crypto.subtle.digest(`SHA-3-${bits}`, data));
    } catch { /* SubtleCrypto may not support SHA-3 in all browsers */ }
  }
  if (PLATFORM === 'node' && HAS_NODE_CRYPTO) {
    const { createHash } = await import('node:crypto');
    try {
      return new Uint8Array(createHash(`sha3-${bits}`).update(data).digest());
    } catch { /* Node < 18 fallback */ }
  }
  return keccakSponge(data, 1600 - bits * 2, bits / 8, 0x06);
}

export const sha3_256 = { async hash(d: Uint8Array): Promise<Uint8Array> { return sha3Native(d, 256); } };
export const sha3_512 = { async hash(d: Uint8Array): Promise<Uint8Array> { return sha3Native(d, 512); } };
export const sha3_224 = { async hash(d: Uint8Array): Promise<Uint8Array> { return sha3Native(d, 224); } };
export const sha3_384 = { async hash(d: Uint8Array): Promise<Uint8Array> { return sha3Native(d, 384); } };

export const shake128 = {
  async hash(data: Uint8Array, outputLen: number): Promise<Uint8Array> {
    return keccakSponge(data, 1344, outputLen, 0x1F);
  },
};
export const shake256 = {
  async hash(data: Uint8Array, outputLen: number): Promise<Uint8Array> {
    return keccakSponge(data, 1088, outputLen, 0x1F);
  },
};
