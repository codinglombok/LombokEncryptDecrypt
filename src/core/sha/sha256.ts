/**
 * LombokEncryptDecrypt — SHA-224 / SHA-256
 * Reference: NIST FIPS 180-4
 * Test vectors: NIST CAVP
 * @module core/sha/sha256
 */

import { HAS_SUBTLE_CRYPTO, HAS_NODE_CRYPTO, PLATFORM } from '../../platform/detect.js';

// SHA-256 initial hash values (first 32 bits of fractional parts of sqrt of first 8 primes)
const H0_256 = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
const H0_224 = new Uint32Array([
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
  0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
]);

// SHA-256 round constants
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function sha256Block(H: Uint32Array, block: Uint8Array): void {
  const W = new Uint32Array(64);
  for (let i = 0; i < 16; i++) {
    W[i] = ((block[i*4]!<<24)|(block[i*4+1]!<<16)|(block[i*4+2]!<<8)|block[i*4+3]!) >>> 0;
  }
  for (let i = 16; i < 64; i++) {
    const s0 = rotr32(W[i-15]!,7) ^ rotr32(W[i-15]!,18) ^ (W[i-15]! >>> 3);
    const s1 = rotr32(W[i-2]!,17) ^ rotr32(W[i-2]!,19)  ^ (W[i-2]!  >>> 10);
    W[i] = (W[i-16]! + s0 + W[i-7]! + s1) >>> 0;
  }
  let [a,b,c,d,e,f,g,h] = [H[0]!,H[1]!,H[2]!,H[3]!,H[4]!,H[5]!,H[6]!,H[7]!];
  for (let i = 0; i < 64; i++) {
    const S1   = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
    const ch   = (e & f) ^ (~e & g);
    const temp1 = (h + S1 + ch + K256[i]! + W[i]!) >>> 0;
    const S0   = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
    const maj  = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (S0 + maj) >>> 0;
    h=g; g=f; f=e; e=(d+temp1)>>>0; d=c; c=b; b=a; a=(temp1+temp2)>>>0;
  }
  H[0]=(H[0]!+a)>>>0; H[1]=(H[1]!+b)>>>0; H[2]=(H[2]!+c)>>>0; H[3]=(H[3]!+d)>>>0;
  H[4]=(H[4]!+e)>>>0; H[5]=(H[5]!+f)>>>0; H[6]=(H[6]!+g)>>>0; H[7]=(H[7]!+h)>>>0;
}

function sha256Pure(data: Uint8Array, is224 = false): Uint8Array {
  const H = new Uint32Array(is224 ? H0_224 : H0_256);
  const bitLen = BigInt(data.length * 8);
  // Padding
  const padded = new Uint8Array(Math.ceil((data.length + 9) / 64) * 64);
  padded.set(data);
  padded[data.length] = 0x80;
  for (let i = 0; i < 8; i++) padded[padded.length - 1 - i] = Number((bitLen >> BigInt(i*8)) & 0xFFn);
  for (let i = 0; i < padded.length; i += 64) sha256Block(H, padded.subarray(i, i+64));
  const out = new Uint8Array(is224 ? 28 : 32);
  for (let i = 0; i < (is224?7:8); i++) {
    out[i*4]=H[i]!>>>24; out[i*4+1]=(H[i]!>>>16)&0xFF; out[i*4+2]=(H[i]!>>>8)&0xFF; out[i*4+3]=H[i]!&0xFF;
  }
  return out;
}

async function hashNative(data: Uint8Array, alg: 'SHA-256'|'SHA-224'): Promise<Uint8Array> {
  if (HAS_SUBTLE_CRYPTO) {
    return new Uint8Array(await globalThis.crypto.subtle.digest(alg, data));
  }
  if (PLATFORM === 'node' && HAS_NODE_CRYPTO) {
    const { createHash } = await import('node:crypto');
    return new Uint8Array(createHash(alg.toLowerCase().replace('-','') as 'sha256').update(data).digest());
  }
  return sha256Pure(data, alg === 'SHA-224');
}

export const sha256 = {
  async hash(data: Uint8Array): Promise<Uint8Array> { return hashNative(data, 'SHA-256'); },
  hashSync(data: Uint8Array): Uint8Array { return sha256Pure(data, false); },
};
export const sha224 = {
  async hash(data: Uint8Array): Promise<Uint8Array> { return hashNative(data, 'SHA-224'); },
  hashSync(data: Uint8Array): Uint8Array { return sha256Pure(data, true); },
};
