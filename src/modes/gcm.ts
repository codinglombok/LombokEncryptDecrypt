/**
 * LombokEncryptDecrypt — AES-GCM (NIST SP 800-38D), pure TypeScript.
 *
 * GHASH is a bit-serial GF(2^128) multiply (MSB-first, reduction polynomial
 * R = 0xe1000…0), CTR mode uses the standard 96-bit-IV J0 construction.
 * Verified against the published NIST GCM test cases and cross-checked with
 * node:crypto (OpenSSL) for all three key sizes and truncated tags.
 */

import { aesEncryptBlock, aesExpandKey, AES_BLOCK_SIZE } from '../core/aes/aes.js';
import { LombokCryptoError, ErrorCode } from '../errors.js';
import { concatBytes, timingSafeEqual, xorBytes } from '../utils/encoding.js';
import { randomBytes } from '../utils/random.js';

export interface AesGcmOptions {
  /** 12-byte IV. Randomly generated when omitted. */
  iv?: Uint8Array;
  /** Additional authenticated data. */
  aad?: Uint8Array;
  /** Tag length in bytes: 4 | 6 | 8 | 10 | 12 | 14 | 16 (default 16). */
  tagLength?: 4 | 6 | 8 | 10 | 12 | 14 | 16;
}

export interface AeadEncryptResult {
  ciphertext: Uint8Array;
  tag: Uint8Array;
  iv: Uint8Array;
}

const GCM_IV_LENGTH = 12;
const GCM_TAG_LENGTHS = [4, 6, 8, 10, 12, 14, 16];

function validateKeySize(key: Uint8Array): void {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `AES-GCM key must be 16, 24 or 32 bytes, got ${key.length}`,
      'AES-GCM',
    );
  }
}

function validateIv(iv: Uint8Array): void {
  if (iv.length !== GCM_IV_LENGTH) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_IV_SIZE,
      `AES-GCM IV must be ${GCM_IV_LENGTH} bytes, got ${iv.length}`,
      'AES-GCM',
    );
  }
}

function xor16(a: Uint8Array, b: Uint8Array, aOffset = 0, bOffset = 0): void {
  for (let i = 0; i < 16; i++) a[aOffset + i] ^= b[bOffset + i];
}

function gf128Multiply(x: Uint8Array, y: Uint8Array): Uint8Array {
  const z = new Uint8Array(16);
  const v = Uint8Array.from(y);
  for (let bit = 0; bit < 128; bit++) {
    if ((x[bit >> 3] & (0x80 >> (bit & 7))) !== 0) xor16(z, v);
    const lsb = v[15] & 1;
    for (let i = 15; i > 0; i--) {
      v[i] = ((v[i] >>> 1) | (v[i - 1] << 7)) & 0xff;
    }
    v[0] = v[0] >>> 1;
    if (lsb === 1) v[0] ^= 0xe1;
  }
  return z;
}

function ghash(h: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  let y = new Uint8Array(16);
  const process = (data: Uint8Array): void => {
    for (let off = 0; off < data.length; off += 16) {
      const block = new Uint8Array(16);
      block.set(data.subarray(off, Math.min(off + 16, data.length)));
      xor16(y, block);
      y = gf128Multiply(y, h);
    }
  };
  process(aad);
  process(ciphertext);
  const aadBits = BigInt(aad.length) * 8n;
  const ctBits = BigInt(ciphertext.length) * 8n;
  const lenBlock = new Uint8Array(16);
  for (let i = 0; i < 8; i++) lenBlock[i] = Number((aadBits >> BigInt((7 - i) * 8)) & 0xffn);
  for (let i = 0; i < 8; i++) lenBlock[8 + i] = Number((ctBits >> BigInt((7 - i) * 8)) & 0xffn);
  xor16(y, lenBlock);
  return gf128Multiply(y, h);
}

function inc32(counterBlock: Uint8Array): void {
  for (let i = 15; i >= 12; i--) {
    counterBlock[i] = (counterBlock[i] + 1) & 0xff;
    if (counterBlock[i] !== 0) break;
  }
}

/** GCTR over `data` starting from `icb` (must be 16 bytes). */
function gctr(
  expanded: ReturnType<typeof aesExpandKey>,
  icb: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  if (data.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(data.length);
  const cb = Uint8Array.from(icb);
  for (let off = 0; off < data.length; off += 16) {
    const stream = aesEncryptBlock(expanded, cb);
    const take = Math.min(16, data.length - off);
    out.set(xorBytes(data.subarray(off, off + take), stream.subarray(0, take)), off);
    if (off + 16 < data.length) inc32(cb);
  }
  return out;
}

function computeTag(
  expanded: ReturnType<typeof aesExpandKey>,
  h: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const j0 = concatBytes(iv, new Uint8Array([0, 0, 0, 1]));
  const s = ghash(h, aad, ciphertext);
  const tagMask = aesEncryptBlock(expanded, j0);
  return xorBytes(s, tagMask);
}

function deriveTagLength(options?: AesGcmOptions): number {
  const tagLength = options?.tagLength ?? 16;
  if (!GCM_TAG_LENGTHS.includes(tagLength)) {
    throw new LombokCryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `unsupported GCM tag length ${tagLength}`,
      'AES-GCM',
    );
  }
  return tagLength;
}

/** AES-GCM authenticated encryption (SP 800-38D). */
export async function aesGcmEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  options?: AesGcmOptions,
): Promise<AeadEncryptResult> {
  validateKeySize(key);
  const iv = options?.iv ?? randomBytes(GCM_IV_LENGTH);
  validateIv(iv);
  const tagLength = deriveTagLength(options);
  const aad = options?.aad ?? new Uint8Array(0);
  const expanded = aesExpandKey(key);
  const h = aesEncryptBlock(expanded, new Uint8Array(16));
  const j0 = concatBytes(iv, new Uint8Array([0, 0, 0, 1]));
  const cb = Uint8Array.from(j0);
  inc32(cb);
  const ciphertext = gctr(expanded, cb, plaintext);
  const tag = computeTag(expanded, h, iv, aad, ciphertext).subarray(0, tagLength);
  return { ciphertext, tag, iv };
}

/** AES-GCM authenticated decryption. Throws AUTHENTICATION_FAILED on tag mismatch. */
export async function aesGcmDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  options?: AesGcmOptions,
): Promise<Uint8Array> {
  validateKeySize(key);
  validateIv(iv);
  // The expected tag length comes from the options when present; otherwise it
  // is inferred from the provided tag (mirrors WebCrypto behaviour).
  const tagLength = options?.tagLength ?? tag.length;
  if (!GCM_TAG_LENGTHS.includes(tagLength)) {
    throw new LombokCryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `unsupported GCM tag length ${tagLength}`,
      'AES-GCM',
    );
  }
  if (tag.length !== tagLength) {
    throw new LombokCryptoError(
      ErrorCode.AUTHENTICATION_FAILED,
      `tag length ${tag.length} does not match expected ${tagLength}`,
      'AES-GCM',
    );
  }
  const aad = options?.aad ?? new Uint8Array(0);
  const expanded = aesExpandKey(key);
  const h = aesEncryptBlock(expanded, new Uint8Array(16));
  const expectedTag = computeTag(expanded, h, iv, aad, ciphertext).subarray(0, tagLength);
  if (!timingSafeEqual(expectedTag, tag)) {
    throw new LombokCryptoError(
      ErrorCode.AUTHENTICATION_FAILED,
      'GCM tag verification failed',
      'AES-GCM',
    );
  }
  const j0 = concatBytes(iv, new Uint8Array([0, 0, 0, 1]));
  const cb = Uint8Array.from(j0);
  inc32(cb);
  return gctr(expanded, cb, ciphertext);
}

export { AES_BLOCK_SIZE };

/**
 * Public `aesGcm` facade (encrypt/decrypt/generateKey/generateIv).
 */
export const aesGcm = {
  async encrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    options?: AesGcmOptions,
  ): Promise<AeadEncryptResult> {
    return aesGcmEncrypt(plaintext, key, options);
  },
  async decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    tag: Uint8Array,
    options?: AesGcmOptions,
  ): Promise<Uint8Array> {
    return aesGcmDecrypt(ciphertext, key, iv, tag, options);
  },
  /** 16/24/32-byte random key for AES-128/192/256. */
  generateKey(bits: 128 | 192 | 256 = 256): Uint8Array {
    if (bits !== 128 && bits !== 192 && bits !== 256)
      throw new RangeError(`bits must be 128, 192 or 256, got ${bits as number}`);
    return randomBytes(bits / 8);
  },
  /** 12 random bytes — a fresh 96-bit IV. */
  generateIv(): Uint8Array {
    return randomBytes(12);
  },
};
