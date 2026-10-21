/**
 * LombokEncryptDecrypt — BLAKE3, pure TypeScript.
 *
 * Faithful port of the reference algorithm: 1 KiB chunks, 64-byte blocks,
 * 7-round compression, binary tree chunk chaining, keyed hash / derive_key
 * modes and extendable output (XOF). Verified against the official test
 * vectors and cross-checked with Bun's native BLAKE3 on random inputs.
 */

const OUT_LEN = 32;
const KEY_LEN = 32;
const BLOCK_LEN = 64;
const CHUNK_LEN = 1024;

const CHUNK_START = 0x01;
const CHUNK_END = 0x02;
const PARENT = 0x04;
const ROOT = 0x08;
const KEYED_HASH = 0x10;
const DERIVE_KEY_CONTEXT = 0x20;
const DERIVE_KEY_MATERIAL = 0x40;

const IV = Uint32Array.from([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function g(
  state: number[],
  a: number,
  b: number,
  c: number,
  d: number,
  mx: number,
  my: number,
): void {
  state[a] = (state[a] + state[b] + mx) >>> 0;
  state[d] = rotr32(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotr32(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b] + my) >>> 0;
  state[d] = rotr32(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotr32(state[b] ^ state[c], 7);
}

function round(state: number[], m: number[]): void {
  g(state, 0, 4, 8, 12, m[0], m[1]);
  g(state, 1, 5, 9, 13, m[2], m[3]);
  g(state, 2, 6, 10, 14, m[4], m[5]);
  g(state, 3, 7, 11, 15, m[6], m[7]);
  g(state, 0, 5, 10, 15, m[8], m[9]);
  g(state, 1, 6, 11, 12, m[10], m[11]);
  g(state, 2, 7, 8, 13, m[12], m[13]);
  g(state, 3, 4, 9, 14, m[14], m[15]);
}

function permute(m: number[]): number[] {
  const out = new Array<number>(16);
  for (let i = 0; i < 16; i++) out[i] = m[MSG_PERMUTATION[i]];
  return out;
}

function compress(
  chainingValue: Uint32Array,
  blockWords: Uint32Array,
  counter: number,
  blockLen: number,
  flags: number,
): Uint32Array {
  const counterHigh = Math.floor(counter / 0x100000000) >>> 0;
  const counterLow = counter >>> 0;
  const state: number[] = [
    chainingValue[0],
    chainingValue[1],
    chainingValue[2],
    chainingValue[3],
    chainingValue[4],
    chainingValue[5],
    chainingValue[6],
    chainingValue[7],
    IV[0],
    IV[1],
    IV[2],
    IV[3],
    counterLow,
    counterHigh,
    blockLen,
    flags,
  ];
  let block = Array.from(blockWords);
  for (let r = 0; r < 7; r++) {
    round(state, block);
    block = permute(block);
  }
  const out = new Uint32Array(16);
  for (let i = 0; i < 8; i++) {
    out[i] = (state[i] ^ state[i + 8]) >>> 0;
    out[i + 8] = (state[i + 8] ^ chainingValue[i]) >>> 0;
  }
  return out;
}

interface Output {
  inputChainingValue: Uint32Array;
  blockWords: Uint32Array;
  counter: number;
  blockLen: number;
  flags: number;
}

function outputChainingValue(o: Output): Uint32Array {
  return compress(o.inputChainingValue, o.blockWords, o.counter, o.blockLen, o.flags).subarray(
    0,
    8,
  );
}

function rootOutputBytes(o: Output, out: Uint8Array): void {
  let produced = 0;
  let outputCounter = o.counter;
  while (produced < out.length) {
    const wide = compress(
      o.inputChainingValue,
      o.blockWords,
      outputCounter,
      o.blockLen,
      o.flags | ROOT,
    );
    const take = Math.min(64, out.length - produced);
    for (let i = 0; i < take; i++) {
      const word = wide[i >> 2];
      out[produced + i] = (word >>> ((i & 3) * 8)) & 0xff;
    }
    produced += take;
    outputCounter += 1;
  }
}

function wordsFromBytes(bytes: Uint8Array): Uint32Array {
  const words = new Uint32Array(Math.ceil(bytes.length / 4));
  for (let i = 0; i < bytes.length; i++) {
    words[i >> 2] |= bytes[i] << ((i & 3) * 8);
  }
  return words;
}

class ChunkState {
  public chainingValue: Uint32Array;
  public chunkCounter: number;
  public blockBuffer = new Uint8Array(BLOCK_LEN);
  public blockLen = 0;
  public blocksCompressed = 0;
  private readonly flags: number;

  public constructor(keyWords: Uint32Array, chunkCounter: number, flags: number) {
    this.chainingValue = keyWords;
    this.chunkCounter = chunkCounter;
    this.flags = flags;
  }

  public length(): number {
    return BLOCK_LEN * this.blocksCompressed + this.blockLen;
  }

  public startFlag(): number {
    return this.blocksCompressed === 0 ? CHUNK_START : 0;
  }

  public update(input: Uint8Array): void {
    let offset = 0;
    while (offset < input.length) {
      if (this.blockLen === BLOCK_LEN) {
        const blockWords = wordsFromBytes(this.blockBuffer);
        this.chainingValue = compress(
          this.chainingValue,
          blockWords,
          this.chunkCounter,
          BLOCK_LEN,
          this.flags | this.startFlag(),
        ).subarray(0, 8);
        this.blocksCompressed += 1;
        this.blockBuffer.fill(0);
        this.blockLen = 0;
      }
      const want = BLOCK_LEN - this.blockLen;
      const take = Math.min(want, input.length - offset);
      this.blockBuffer.set(input.subarray(offset, offset + take), this.blockLen);
      this.blockLen += take;
      offset += take;
    }
  }

  public output(): Output {
    return {
      inputChainingValue: this.chainingValue,
      blockWords: wordsFromBytes(this.blockBuffer),
      counter: this.chunkCounter,
      blockLen: this.blockLen,
      flags: this.flags | this.startFlag() | CHUNK_END,
    };
  }
}

function parentOutput(
  leftChildCv: Uint32Array,
  rightChildCv: Uint32Array,
  keyWords: Uint32Array,
  flags: number,
): Output {
  const blockWords = new Uint32Array(16);
  blockWords.set(leftChildCv, 0);
  blockWords.set(rightChildCv, 8);
  return {
    inputChainingValue: keyWords,
    blockWords,
    counter: 0,
    blockLen: BLOCK_LEN,
    flags: flags | PARENT,
  };
}

export class Blake3Hasher {
  private chunkState: ChunkState;
  private readonly keyWords: Uint32Array;
  private readonly flags: number;
  private readonly cvStack: Uint32Array[] = [];
  private cvStackLen = 0;

  private constructor(keyWords: Uint32Array, flags: number) {
    this.keyWords = keyWords;
    this.flags = flags;
    this.chunkState = new ChunkState(keyWords, 0, flags);
  }

  /** New hasher in plain hash mode. */
  public static create(): Blake3Hasher {
    return new Blake3Hasher(IV, 0);
  }

  /** New hasher in keyed-hash mode with a 32-byte key. */
  public static createKeyed(key: Uint8Array): Blake3Hasher {
    if (key.length !== KEY_LEN)
      throw new Error(`BLAKE3 keyed hash requires a ${KEY_LEN}-byte key, got ${key.length}`);
    return new Blake3Hasher(wordsFromBytes(key), KEYED_HASH);
  }

  /** New hasher in derive_key mode (context string is hashed to the key). */
  public static createDeriveKey(context: string): Blake3Hasher {
    const contextHasher = new Blake3Hasher(IV, DERIVE_KEY_CONTEXT);
    contextHasher.update(new TextEncoder().encode(context));
    const contextKey = new Uint8Array(32);
    rootOutputBytes(contextHasher.finalizeOutput(), contextKey);
    return new Blake3Hasher(wordsFromBytes(contextKey), DERIVE_KEY_MATERIAL);
  }

  public update(data: Uint8Array): void {
    let offset = 0;
    while (offset < data.length) {
      if (this.chunkState.length() === CHUNK_LEN) {
        const chunkCv = outputChainingValue(this.chunkState.output());
        const totalChunks = this.chunkState.chunkCounter + 1;
        this.addChunkChainingValue(chunkCv, totalChunks);
        this.chunkState = new ChunkState(this.keyWords, totalChunks, this.flags);
      }
      const want = CHUNK_LEN - this.chunkState.length();
      const take = Math.min(want, data.length - offset);
      this.chunkState.update(data.subarray(offset, offset + take));
      offset += take;
    }
  }

  private addChunkChainingValue(newCv: Uint32Array, totalChunks: number): void {
    let cv = newCv;
    let total = totalChunks;
    // Fold left siblings into the new CV while the chunk count is even, then
    // push. This keeps the stack holding one CV per set bit of total_chunks.
    while ((total & 1) === 0) {
      this.cvStackLen -= 1;
      cv = outputChainingValue(
        parentOutput(this.cvStack[this.cvStackLen], cv, this.keyWords, this.flags),
      );
      total >>= 1;
    }
    this.cvStack[this.cvStackLen] = cv;
    this.cvStackLen += 1;
  }

  private finalizeOutput(): Output {
    let output = this.chunkState.output();
    let parentNodesRemaining = this.cvStackLen;
    while (parentNodesRemaining > 0) {
      parentNodesRemaining -= 1;
      const rightChildCv = outputChainingValue(output);
      output = parentOutput(
        this.cvStack[parentNodesRemaining],
        rightChildCv,
        this.keyWords,
        this.flags,
      );
    }
    return output;
  }

  /** Emit `length` output bytes (XOF — any length is valid). */
  public finalize(length = OUT_LEN): Uint8Array {
    const out = new Uint8Array(length);
    rootOutputBytes(this.finalizeOutput(), out);
    return out;
  }
}

/** One-shot BLAKE3 hash (32-byte digest by default, XOF when longer). */
export function blake3Raw(data: Uint8Array, outputLength = OUT_LEN): Uint8Array {
  const hasher = Blake3Hasher.create();
  hasher.update(data);
  return hasher.finalize(outputLength);
}

/** One-shot keyed BLAKE3. */
export function blake3KeyedRaw(
  key: Uint8Array,
  data: Uint8Array,
  outputLength = OUT_LEN,
): Uint8Array {
  const hasher = Blake3Hasher.createKeyed(key);
  hasher.update(data);
  return hasher.finalize(outputLength);
}

/** One-shot BLAKE3 derive_key (output usable as a symmetric key). */
export function blake3DeriveKeyRaw(
  context: string,
  material: Uint8Array,
  outputLength = OUT_LEN,
): Uint8Array {
  const hasher = Blake3Hasher.createDeriveKey(context);
  hasher.update(material);
  return hasher.finalize(outputLength);
}

/** BLAKE3 public hash object (hash / keyed / derive_key / XOF). */
export const blake3 = {
  async hash(data: Uint8Array, outputLength?: number): Promise<Uint8Array> {
    return blake3Raw(data, outputLength ?? OUT_LEN);
  },
  async keyed(key: Uint8Array, data: Uint8Array, outputLength?: number): Promise<Uint8Array> {
    return blake3KeyedRaw(key, data, outputLength ?? OUT_LEN);
  },
  async deriveKey(
    context: string,
    material: Uint8Array,
    outputLength?: number,
  ): Promise<Uint8Array> {
    return blake3DeriveKeyRaw(context, material, outputLength ?? OUT_LEN);
  },
};
