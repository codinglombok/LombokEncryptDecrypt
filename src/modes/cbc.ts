/**
 * LombokEncryptDecrypt — AES-CBC with PKCS#7 padding, pure TypeScript.
 */

import { aesDecryptBlock, aesEncryptBlock, aesExpandKey } from '../core/aes/aes.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';
import { timingSafeEqual } from '../utils/encoding.js';
import { randomBytes } from '../utils/random.js';

export interface AesCbcOptions {
  /** Prepend the IV to the ciphertext (default false). */
  includeIv?: boolean;
}

function validate(key: Uint8Array, iv: Uint8Array): void {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `AES-CBC key must be 16, 24 or 32 bytes, got ${key.length}`,
      'AES-CBC',
    );
  }
  if (iv.length !== 16) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_IV_SIZE,
      `AES-CBC IV must be 16 bytes, got ${iv.length}`,
      'AES-CBC',
    );
  }
}

function pkcs7Pad(data: Uint8Array): Uint8Array {
  const padLen = 16 - (data.length % 16);
  const out = new Uint8Array(data.length + padLen);
  out.set(data);
  out.fill(padLen, data.length);
  return out;
}

function pkcs7Unpad(data: Uint8Array): Uint8Array {
  if (data.length === 0 || data.length % 16 !== 0) {
    throw new LombokCryptoError(
      ErrorCode.INTEGRITY_CHECK_FAILED,
      'ciphertext length is not a multiple of the block size',
      'AES-CBC',
    );
  }
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > 16) {
    throw new LombokCryptoError(
      ErrorCode.INTEGRITY_CHECK_FAILED,
      `invalid PKCS#7 padding length ${padLen}`,
      'AES-CBC',
    );
  }
  // constant-time padding check
  let diff = 0;
  for (let i = data.length - padLen; i < data.length; i++) {
    diff |= (data[i] ^ padLen) & 0xff;
  }
  if (!timingSafeEqual(new Uint8Array([diff === 0 ? 0 : 1]), new Uint8Array([0]))) {
    throw new LombokCryptoError(
      ErrorCode.INTEGRITY_CHECK_FAILED,
      'invalid PKCS#7 padding bytes',
      'AES-CBC',
    );
  }
  return data.subarray(0, data.length - padLen);
}

/** AES-CBC encrypt with PKCS#7 padding. */
export async function aesCbcEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv?: Uint8Array,
  options?: AesCbcOptions,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const actualIv = iv ?? randomBytes(16);
  validate(key, actualIv);
  const expanded = aesExpandKey(key);
  const padded = pkcs7Pad(plaintext);
  const out = new Uint8Array(padded.length);
  let prev = actualIv;
  for (let off = 0; off < padded.length; off += 16) {
    const block = new Uint8Array(16);
    for (let i = 0; i < 16; i++) block[i] = padded[off + i] ^ prev[i];
    const enc = aesEncryptBlock(expanded, block);
    out.set(enc, off);
    prev = enc;
  }
  const includeIv = options?.includeIv ?? false;
  const ciphertext = includeIv ? new Uint8Array([...actualIv, ...out]) : out;
  return { ciphertext, iv: actualIv };
}

/** AES-CBC decrypt with PKCS#7 padding. */
export async function aesCbcDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv?: Uint8Array,
  options?: AesCbcOptions,
): Promise<Uint8Array> {
  const includeIv = options?.includeIv ?? false;
  let actualIv: Uint8Array;
  let body: Uint8Array;
  if (includeIv) {
    if (ciphertext.length < 32) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_IV_SIZE,
        'ciphertext too short to contain IV + one block',
        'AES-CBC',
      );
    }
    actualIv = ciphertext.subarray(0, 16);
    body = ciphertext.subarray(16);
  } else {
    if (iv === undefined) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_IV_SIZE,
        'IV is required when includeIv is false',
        'AES-CBC',
      );
    }
    actualIv = iv;
    body = ciphertext;
  }
  validate(key, actualIv);
  const expanded = aesExpandKey(key);
  const out = new Uint8Array(body.length);
  let prev = actualIv;
  for (let off = 0; off < body.length; off += 16) {
    const dec = aesDecryptBlock(expanded, body.subarray(off, off + 16));
    const block = new Uint8Array(16);
    for (let i = 0; i < 16; i++) block[i] = dec[i] ^ prev[i];
    out.set(block, off);
    prev = body.subarray(off, off + 16);
  }
  return pkcs7Unpad(out);
}
