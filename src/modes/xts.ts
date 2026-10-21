/**
 * LombokEncryptDecrypt — AES-XTS (IEEE 1619 / NIST SP 800-38E), pure TypeScript.
 *
 * Key = two independent AES keys concatenated (32 bytes → AES-128-XTS,
 * 64 bytes → AES-256-XTS; AES-192-XTS is disallowed by SP 800-38E).
 * Tweak = data-unit number as a little-endian 128-bit integer, encrypted
 * with the second key. Ciphertext stealing handles partial final blocks.
 */

import { aesDecryptBlock, aesEncryptBlock, aesExpandKey } from '../core/aes/aes.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';

export interface AesXtsKeyPair {
  dataKey: Uint8Array;
  tweakKey: Uint8Array;
}

function splitKey(key: Uint8Array): AesXtsKeyPair {
  if (key.length !== 32 && key.length !== 64) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `AES-XTS key must be 32 or 64 bytes (two AES keys), got ${key.length}`,
      'AES-XTS',
    );
  }
  const half = key.length / 2;
  return { dataKey: key.subarray(0, half), tweakKey: key.subarray(half) };
}

function expandPair(pair: AesXtsKeyPair): {
  data: ReturnType<typeof aesExpandKey>;
  tweak: ReturnType<typeof aesExpandKey>;
} {
  return { data: aesExpandKey(pair.dataKey), tweak: aesExpandKey(pair.tweakKey) };
}

function tweakFromNumber(dataUnitNumber: bigint): Uint8Array {
  const tweak = new Uint8Array(16);
  // IEEE 1619 serializes the data-unit number little-endian
  let v = dataUnitNumber;
  for (let i = 0; i < 16; i++) {
    tweak[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return tweak;
}

function multiplyTweak(tweak: Uint8Array): void {
  // T ← T · α in GF(2^128) with x^128 + x^7 + x^2 + x + 1, LE byte order
  let carry = 0;
  for (let i = 0; i < 16; i++) {
    const nextCarry = (tweak[i] >>> 7) & 1;
    tweak[i] = ((tweak[i] << 1) | carry) & 0xff;
    carry = nextCarry;
  }
  if (carry === 1) tweak[0] ^= 0x87;
}

function xtsEncryptBlocks(
  data: ReturnType<typeof aesExpandKey>,
  tweakInit: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const tweak = Uint8Array.from(tweakInit);
  const n = plaintext.length;
  const full = Math.floor(n / 16);
  const b = n % 16;
  const out = new Uint8Array(n);
  const numFull = b === 0 ? full : full - 1; // last two units handled specially when b != 0

  let i = 0;
  for (; i < numFull; i++) {
    const block = new Uint8Array(16);
    for (let j = 0; j < 16; j++) block[j] = plaintext[i * 16 + j] ^ tweak[j];
    const enc = aesEncryptBlock(data, block);
    for (let j = 0; j < 16; j++) out[i * 16 + j] = enc[j] ^ tweak[j];
    multiplyTweak(tweak);
  }

  if (b === 0 && full > 0) {
    // final full block
    const block = new Uint8Array(16);
    for (let j = 0; j < 16; j++) block[j] = plaintext[i * 16 + j] ^ tweak[j];
    const enc = aesEncryptBlock(data, block);
    for (let j = 0; j < 16; j++) out[i * 16 + j] = enc[j] ^ tweak[j];
    return out;
  }

  // ciphertext stealing: PP = enc(P_{m-1} ^ T_{m-1}) ^ T_{m-1} (full block),
  // CC = P_m || PP[b..15], C_{m-1} = enc(CC ^ T_m) ^ T_m (full 16),
  // C_m = first b bytes of PP.
  const lastFull = new Uint8Array(16);
  for (let j = 0; j < 16; j++) lastFull[j] = plaintext[i * 16 + j] ^ tweak[j];
  const pp = new Uint8Array(16);
  const ppEnc = aesEncryptBlock(data, lastFull);
  for (let j = 0; j < 16; j++) pp[j] = ppEnc[j] ^ tweak[j];

  multiplyTweak(tweak);
  const cc = new Uint8Array(16);
  for (let j = 0; j < b; j++) cc[j] = plaintext[(i + 1) * 16 + j];
  for (let j = b; j < 16; j++) cc[j] = pp[j];
  const ccXored = new Uint8Array(16);
  for (let j = 0; j < 16; j++) ccXored[j] = cc[j] ^ tweak[j];
  const ccEnc = aesEncryptBlock(data, ccXored);
  for (let j = 0; j < 16; j++) out[i * 16 + j] = ccEnc[j] ^ tweak[j];
  for (let j = 0; j < b; j++) out[(i + 1) * 16 + j] = pp[j];
  return out;
}

function xtsDecryptBlocks(
  data: ReturnType<typeof aesExpandKey>,
  tweakInit: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const tweak = Uint8Array.from(tweakInit);
  const n = ciphertext.length;
  const full = Math.floor(n / 16);
  const b = n % 16;
  const out = new Uint8Array(n);
  const numFull = b === 0 ? full : full - 1;

  let i = 0;
  for (; i < numFull; i++) {
    const block = new Uint8Array(16);
    for (let j = 0; j < 16; j++) block[j] = ciphertext[i * 16 + j] ^ tweak[j];
    const dec = aesDecryptBlock(data, block);
    for (let j = 0; j < 16; j++) out[i * 16 + j] = dec[j] ^ tweak[j];
    multiplyTweak(tweak);
  }

  if (b === 0 && full > 0) {
    const block = new Uint8Array(16);
    for (let j = 0; j < 16; j++) block[j] = ciphertext[i * 16 + j] ^ tweak[j];
    const dec = aesDecryptBlock(data, block);
    for (let j = 0; j < 16; j++) out[i * 16 + j] = dec[j] ^ tweak[j];
    return out;
  }

  // Stealing section. Tweak bookkeeping mirrors the encryptor:
  //   PP (block m-1) was encrypted under T_{m-1} = T_1 (current state)
  //   CC (block m)   was encrypted under T_m     = T_2 (one multiply ahead)
  const tweakM1 = Uint8Array.from(tweak); // T_{m-1}
  multiplyTweak(tweak);
  const tweakM = Uint8Array.from(tweak); // T_m

  // CC = Dec(C_{m-1} ⊕ T_m) ⊕ T_m
  const ccEnc = new Uint8Array(16);
  for (let j = 0; j < 16; j++) ccEnc[j] = ciphertext[i * 16 + j] ^ tweakM[j];
  const ccXored = aesDecryptBlock(data, ccEnc);
  const cc = new Uint8Array(16);
  for (let j = 0; j < 16; j++) cc[j] = ccXored[j] ^ tweakM[j];

  // PP = C_m || CC[b..15]
  const pp = new Uint8Array(16);
  for (let j = 0; j < b; j++) pp[j] = ciphertext[(i + 1) * 16 + j];
  for (let j = b; j < 16; j++) pp[j] = cc[j];

  // P_{m-1} = Dec(PP ⊕ T_{m-1}) ⊕ T_{m-1}
  const ppXored = new Uint8Array(16);
  for (let j = 0; j < 16; j++) ppXored[j] = pp[j] ^ tweakM1[j];
  const dec = aesDecryptBlock(data, ppXored);
  for (let j = 0; j < 16; j++) out[i * 16 + j] = dec[j] ^ tweakM1[j];

  // P_m = CC[0..b)
  for (let j = 0; j < b; j++) out[(i + 1) * 16 + j] = cc[j];
  return out;
}

const MIN_DATA_UNIT = 16;

/** AES-XTS encrypt one data unit (min 16 bytes). */
export async function aesXtsEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  dataUnitNumber: number | bigint,
): Promise<Uint8Array> {
  if (plaintext.length < MIN_DATA_UNIT) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_IV_SIZE,
      `XTS data unit must be at least ${MIN_DATA_UNIT} bytes, got ${plaintext.length}`,
      'AES-XTS',
    );
  }
  const pair = splitKey(key);
  const expanded = expandPair(pair);
  const tweak = tweakFromNumber(BigInt(dataUnitNumber));
  return xtsEncryptBlocks(expanded.data, aesEncryptBlock(expanded.tweak, tweak), plaintext);
}

/** AES-XTS decrypt one data unit (min 16 bytes). */
export async function aesXtsDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  dataUnitNumber: number | bigint,
): Promise<Uint8Array> {
  if (ciphertext.length < MIN_DATA_UNIT) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_IV_SIZE,
      `XTS data unit must be at least ${MIN_DATA_UNIT} bytes, got ${ciphertext.length}`,
      'AES-XTS',
    );
  }
  const pair = splitKey(key);
  const expanded = expandPair(pair);
  const tweak = tweakFromNumber(BigInt(dataUnitNumber));
  return xtsDecryptBlocks(expanded.data, aesEncryptBlock(expanded.tweak, tweak), ciphertext);
}
