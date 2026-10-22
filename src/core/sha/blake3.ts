/**
 * LombokEncryptDecrypt — BLAKE3 (hash, keyed hash, derive_key, XOF), pure TypeScript.
 *
 * Follows the BLAKE3 specification (O'Connor, Aumasson, Neves, Wilcox-O'Hearn).
 * Verified against the reference implementation in tests/unit/blake3.test.ts.
 * Not constant-time audited (BLAKE3 has no secret-dependent branches or lookups,
 * but the JS engine gives no timing guarantees).
 *
 * @module core/sha/blake3
 */

import { LombokCryptoError, ErrorCode } from '../../errors.js';

const IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const CHUNK_START = 1;
const CHUNK_END = 2;
const PARENT = 4;
const ROOT = 8;
const KEYED_HASH = 16;
const DERIVE_KEY_CONTEXT = 32;
const DERIVE_KEY_MATERIAL = 64;

const BLOCK_LEN = 64;
const CHUNK_LEN = 1024;

const rotr = (x: number, n: number): number => ((x >>> n) | (x << (32 - n))) >>> 0;

function g(
  s: Uint32Array,
  a: number,
  b: number,
  c: number,
  d: number,
  mx: number,
  my: number,
): void {
  s[a] = (s[a]! + s[b]! + mx) >>> 0;
  s[d] = rotr(s[d]! ^ s[a]!, 16);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = rotr(s[b]! ^ s[c]!, 12);
  s[a] = (s[a]! + s[b]! + my) >>> 0;
  s[d] = rotr(s[d]! ^ s[a]!, 8);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = rotr(s[b]! ^ s[c]!, 7);
}

function round(s: Uint32Array, m: Uint32Array): void {
  g(s, 0, 4, 8, 12, m[0]!, m[1]!);
  g(s, 1, 5, 9, 13, m[2]!, m[3]!);
  g(s, 2, 6, 10, 14, m[4]!, m[5]!);
  g(s, 3, 7, 11, 15, m[6]!, m[7]!);
  g(s, 0, 5, 10, 15, m[8]!, m[9]!);
  g(s, 1, 6, 11, 12, m[10]!, m[11]!);
  g(s, 2, 7, 8, 13, m[12]!, m[13]!);
  g(s, 3, 4, 9, 14, m[14]!, m[15]!);
}

/** Returns the full 16-word compression output. */
function compress(
  cv: Uint32Array,
  block: Uint32Array,
  counter: number,
  blockLen: number,
  flags: number,
): Uint32Array {
  const s = new Uint32Array(16);
  s.set(cv.subarray(0, 8), 0);
  s[8] = IV[0]!;
  s[9] = IV[1]!;
  s[10] = IV[2]!;
  s[11] = IV[3]!;
  s[12] = counter >>> 0;
  s[13] = Math.floor(counter / 4294967296) >>> 0;
  s[14] = blockLen;
  s[15] = flags;
  let m = Uint32Array.from(block);
  for (let r = 0; r < 7; r++) {
    round(s, m);
    if (r < 6) {
      const p = new Uint32Array(16);
      for (let i = 0; i < 16; i++) p[i] = m[PERM[i]!]!;
      m = p;
    }
  }
  for (let i = 0; i < 8; i++) {
    s[i] = (s[i]! ^ s[i + 8]!) >>> 0;
    s[i + 8] = (s[i + 8]! ^ cv[i]!) >>> 0;
  }
  return s;
}

function wordsFromBytes(bytes: Uint8Array, len: number): Uint32Array {
  const w = new Uint32Array(16);
  for (let i = 0; i < len; i++) w[i >> 2] = (w[i >> 2]! | (bytes[i]! << ((i & 3) * 8))) >>> 0;
  return w;
}

interface Output {
  cv: Uint32Array;
  block: Uint32Array;
  counter: number;
  blockLen: number;
  flags: number;
}

const chainingValue = (o: Output): Uint32Array =>
  compress(o.cv, o.block, o.counter, o.blockLen, o.flags).slice(0, 8);

function rootBytes(o: Output, outLen: number): Uint8Array {
  const out = new Uint8Array(outLen);
  let counter = 0;
  let pos = 0;
  while (pos < outLen) {
    const words = compress(o.cv, o.block, counter, o.blockLen, o.flags | ROOT);
    for (let i = 0; i < 64 && pos < outLen; i++, pos++)
      out[pos] = (words[i >> 2]! >>> ((i & 3) * 8)) & 0xff;
    counter++;
  }
  return out;
}

function parentOutput(
  left: Uint32Array,
  right: Uint32Array,
  key: Uint32Array,
  flags: number,
): Output {
  const block = new Uint32Array(16);
  block.set(left, 0);
  block.set(right, 8);
  return { cv: key, block, counter: 0, blockLen: BLOCK_LEN, flags: flags | PARENT };
}

function chunkOutput(
  data: Uint8Array,
  chunkCounter: number,
  key: Uint32Array,
  flags: number,
): Output {
  let cv = key;
  const nBlocks = Math.max(1, Math.ceil(data.length / BLOCK_LEN));
  for (let b = 0; b < nBlocks; b++) {
    const start = b * BLOCK_LEN;
    const len = Math.min(BLOCK_LEN, data.length - start);
    const block = wordsFromBytes(data.subarray(start, start + len), len);
    let f = flags;
    if (b === 0) f |= CHUNK_START;
    if (b === nBlocks - 1) {
      return { cv, block, counter: chunkCounter, blockLen: len, flags: f | CHUNK_END };
    }
    cv = compress(cv, block, chunkCounter, len, f).slice(0, 8);
  }
  throw new Error('unreachable');
}

function hashInternal(
  data: Uint8Array,
  key: Uint32Array,
  flags: number,
  outLen: number,
): Uint8Array {
  if (!Number.isInteger(outLen) || outLen < 1 || outLen > 2 ** 32) {
    throw new LombokCryptoError(ErrorCode.INVALID_PARAMETER, 'BLAKE3: invalid output length');
  }
  const nChunks = Math.max(1, Math.ceil(data.length / CHUNK_LEN));
  const stack: Uint32Array[] = [];
  let total = 0; // chunks pushed to the stack so far
  for (let c = 0; c < nChunks - 1; c++) {
    let cv = chainingValue(
      chunkOutput(data.subarray(c * CHUNK_LEN, (c + 1) * CHUNK_LEN), c, key, flags),
    );
    total++;
    let t = total;
    while ((t & 1) === 0) {
      cv = chainingValue(parentOutput(stack.pop()!, cv, key, flags));
      t >>= 1;
    }
    stack.push(cv);
  }
  let out = chunkOutput(data.subarray((nChunks - 1) * CHUNK_LEN), nChunks - 1, key, flags);
  while (stack.length > 0) {
    out = parentOutput(stack.pop()!, chainingValue(out), key, flags);
  }
  return rootBytes(out, outLen);
}

const IV_KEY = Uint32Array.from(IV);

function keyWords(key: Uint8Array): Uint32Array {
  if (key.length !== 32) {
    throw new LombokCryptoError(ErrorCode.INVALID_KEY_SIZE, 'BLAKE3 key must be 32 bytes');
  }
  return wordsFromBytes(key, 32).slice(0, 8);
}

export const blake3 = {
  /** Hash (default 32-byte output; any length is allowed, i.e. XOF). */
  hashSync(data: Uint8Array, outLen = 32): Uint8Array {
    return hashInternal(data, IV_KEY, 0, outLen);
  },
  async hash(data: Uint8Array, outLen = 32): Promise<Uint8Array> {
    return hashInternal(data, IV_KEY, 0, outLen);
  },
  /** Keyed hash (a MAC). `key` must be 32 bytes. */
  keyedHashSync(key: Uint8Array, data: Uint8Array, outLen = 32): Uint8Array {
    return hashInternal(data, keyWords(key), KEYED_HASH, outLen);
  },
  /** Derive a key from a context string and key material. */
  deriveKeySync(context: string, material: Uint8Array, outLen = 32): Uint8Array {
    const ctxKey = hashInternal(new TextEncoder().encode(context), IV_KEY, DERIVE_KEY_CONTEXT, 32);
    return hashInternal(
      material,
      wordsFromBytes(ctxKey, 32).slice(0, 8),
      DERIVE_KEY_MATERIAL,
      outLen,
    );
  },
};
