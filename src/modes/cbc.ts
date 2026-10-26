/**
 * LombokEncryptDecrypt — AES-CBC with PKCS#7 padding, pure TypeScript.
 */

import { aesDecryptBlock, aesEncryptBlock, aesExpandKey } from '../core/aes/aes.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';
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
  // Constant-time padding check: a single accumulated XOR difference is
  // compared without touching any comparator that an engine could polyfill
  // differently (a Bun CI leg once resolved where a reject was required —
  // every conditional in this path is now pure TypeScript with no escape
  // hatch into runtime-provided primitives).
  if (diff !== 0) {
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

// ── Synchronous block-mode facade (SP 800-38A known-answer shape) ─────────

export interface AesBlockPaddingOptions {
  /** Padding policy — 'pkcs7' (default for CBC) or 'none' for exact-block I/O. */
  padding?: 'none' | 'pkcs7';
}

function validateKeyOnly(key: Uint8Array): void {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `AES key must be 16, 24 or 32 bytes, got ${key.length}`,
      'AES-CBC',
    );
  }
}

/** AES-ECB (raw block mode). Insecure for real data — kept for legacy formats and PDF primitives. */
export const aesEcb = {
  encrypt(key: Uint8Array, plaintext: Uint8Array, options?: AesBlockPaddingOptions): Uint8Array {
    validateKeyOnly(key);
    const padding = options?.padding ?? 'none';
    const data = padding === 'pkcs7' ? pkcs7Pad(plaintext) : plaintext;
    if (data.length === 0 || data.length % 16 !== 0) {
      throw new LombokCryptoError(
        data.length === 0 ? ErrorCode.INTEGRITY_CHECK_FAILED : ErrorCode.INVALID_INPUT,
        'plaintext length must be a positive multiple of the block size',
        'AES-ECB',
      );
    }
    const expanded = aesExpandKey(key);
    const out = new Uint8Array(data.length);
    for (let off = 0; off < data.length; off += 16) {
      out.set(aesEncryptBlock(expanded, data.subarray(off, off + 16)), off);
    }
    return out;
  },
  decrypt(key: Uint8Array, ciphertext: Uint8Array, options?: AesBlockPaddingOptions): Uint8Array {
    validateKeyOnly(key);
    const padding = options?.padding ?? 'none';
    if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
      throw new LombokCryptoError(
        ciphertext.length === 0 ? ErrorCode.INTEGRITY_CHECK_FAILED : ErrorCode.INVALID_INPUT,
        'ciphertext length must be a positive multiple of the block size',
        'AES-ECB',
      );
    }
    const expanded = aesExpandKey(key);
    const out = new Uint8Array(ciphertext.length);
    for (let off = 0; off < ciphertext.length; off += 16) {
      out.set(aesDecryptBlock(expanded, ciphertext.subarray(off, off + 16)), off);
    }
    return padding === 'pkcs7' ? pkcs7Unpad(out) : out;
  },
};

/** Synchronous AES-CBC (key-first signature, SP 800-38A known-answer shape). */
export const aesCbc = {
  encrypt(
    key: Uint8Array,
    iv: Uint8Array,
    plaintext: Uint8Array,
    options?: AesBlockPaddingOptions,
  ): Uint8Array {
    validate(key, iv);
    const padding = options?.padding ?? 'pkcs7';
    const data = padding === 'pkcs7' ? pkcs7Pad(plaintext) : plaintext;
    if (data.length === 0 || data.length % 16 !== 0) {
      throw new LombokCryptoError(
        data.length === 0 ? ErrorCode.INTEGRITY_CHECK_FAILED : ErrorCode.INVALID_INPUT,
        'plaintext length must be a positive multiple of the block size',
        'AES-CBC',
      );
    }
    const expanded = aesExpandKey(key);
    const out = new Uint8Array(data.length);
    let prev = iv;
    for (let off = 0; off < data.length; off += 16) {
      const block = new Uint8Array(16);
      for (let i = 0; i < 16; i++) block[i] = data[off + i]! ^ prev[i]!;
      const enc = aesEncryptBlock(expanded, block);
      out.set(enc, off);
      prev = enc;
    }
    return out;
  },
  decrypt(
    key: Uint8Array,
    iv: Uint8Array,
    ciphertext: Uint8Array,
    options?: AesBlockPaddingOptions,
  ): Uint8Array {
    validate(key, iv);
    if (ciphertext.length === 0) {
      throw new LombokCryptoError(
        ErrorCode.INTEGRITY_CHECK_FAILED,
        'ciphertext is empty',
        'AES-CBC',
      );
    }
    if (ciphertext.length % 16 !== 0) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_INPUT,
        'ciphertext length must be a multiple of the block size',
        'AES-CBC',
      );
    }
    const padding = options?.padding ?? 'pkcs7';
    const expanded = aesExpandKey(key);
    const out = new Uint8Array(ciphertext.length);
    let prev = iv;
    for (let off = 0; off < ciphertext.length; off += 16) {
      const dec = aesDecryptBlock(expanded, ciphertext.subarray(off, off + 16));
      const block = new Uint8Array(16);
      for (let i = 0; i < 16; i++) block[i] = dec[i]! ^ prev[i]!;
      out.set(block, off);
      prev = ciphertext.subarray(off, off + 16);
    }
    return padding === 'pkcs7' ? pkcs7Unpad(out) : out;
  },
};
