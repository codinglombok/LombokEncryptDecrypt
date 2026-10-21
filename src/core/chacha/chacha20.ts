/**
 * LombokEncryptDecrypt — ChaCha20 stream cipher & HChaCha20 (RFC 8439 /
 * draft-irtf-cfrg-xchacha), pure TypeScript.
 */

const CHACHA_CONST = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function quarterRound(s: number[], a: number, b: number, c: number, d: number): void {
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl32(s[b] ^ s[c], 7);
}

/** Key as 8 little-endian words; nonce as 3 little-endian words. */
export function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint32Array {
  const keyWords = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    keyWords[i] =
      (key[i * 4] | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24)) >>> 0;
  }
  const nonceWords = new Uint32Array(3);
  for (let i = 0; i < 3; i++) {
    nonceWords[i] =
      (nonce[i * 4] |
        (nonce[i * 4 + 1] << 8) |
        (nonce[i * 4 + 2] << 16) |
        (nonce[i * 4 + 3] << 24)) >>>
      0;
  }
  const state: number[] = [
    CHACHA_CONST[0],
    CHACHA_CONST[1],
    CHACHA_CONST[2],
    CHACHA_CONST[3],
    keyWords[0],
    keyWords[1],
    keyWords[2],
    keyWords[3],
    keyWords[4],
    keyWords[5],
    keyWords[6],
    keyWords[7],
    counter >>> 0,
    nonceWords[0],
    nonceWords[1],
    nonceWords[2],
  ];
  const working = state.slice();
  for (let i = 0; i < 10; i++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  const out = new Uint32Array(16);
  for (let i = 0; i < 16; i++) out[i] = (working[i] + state[i]) >>> 0;
  return out;
}

/**
 * HChaCha20 — XChaCha20 subkey derivation from a 16-byte nonce prefix.
 * Runs 20 rounds without feed-forward and outputs words 0–3 and 12–15.
 */
export function hchacha20(key: Uint8Array, nonce16: Uint8Array): Uint8Array {
  const keyWords = new Uint32Array(8);
  for (let i = 0; i < 8; i++) {
    keyWords[i] =
      (key[i * 4] | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24)) >>> 0;
  }
  const nonceWords = new Uint32Array(4);
  for (let i = 0; i < 4; i++) {
    nonceWords[i] =
      (nonce16[i * 4] |
        (nonce16[i * 4 + 1] << 8) |
        (nonce16[i * 4 + 2] << 16) |
        (nonce16[i * 4 + 3] << 24)) >>>
      0;
  }
  const state: number[] = [
    CHACHA_CONST[0],
    CHACHA_CONST[1],
    CHACHA_CONST[2],
    CHACHA_CONST[3],
    keyWords[0],
    keyWords[1],
    keyWords[2],
    keyWords[3],
    keyWords[4],
    keyWords[5],
    keyWords[6],
    keyWords[7],
    nonceWords[0],
    nonceWords[1],
    nonceWords[2],
    nonceWords[3],
  ];
  const working = state.slice();
  for (let i = 0; i < 10; i++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  const out = new Uint8Array(32);
  // HChaCha20 has NO feed-forward: the output words are the raw working
  // state (draft-irtf-cfrg-xchacha §2.2), serialized little-endian.
  const pick = [0, 1, 2, 3, 12, 13, 14, 15];
  for (let w = 0; w < 8; w++) {
    const word = working[pick[w]] >>> 0;
    out[w * 4] = word & 0xff;
    out[w * 4 + 1] = (word >>> 8) & 0xff;
    out[w * 4 + 2] = (word >>> 16) & 0xff;
    out[w * 4 + 3] = (word >>> 24) & 0xff;
  }
  return out;
}

/** XOR `data` with the ChaCha20 keystream starting at `counter`. */
export function chacha20Xor(
  key: Uint8Array,
  counter: number,
  nonce: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(data.length);
  let blockCounter = counter;
  for (let off = 0; off < data.length; off += 64) {
    const block = chacha20Block(key, blockCounter, nonce);
    const take = Math.min(64, data.length - off);
    for (let i = 0; i < take; i++) {
      const word = block[i >> 2];
      out[off + i] = (data[off + i] ^ ((word >>> ((i & 3) * 8)) & 0xff)) & 0xff;
    }
    blockCounter += 1;
  }
  return out;
}
