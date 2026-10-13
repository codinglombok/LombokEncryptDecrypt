/**
 * LombokEncryptDecrypt — AES-CBC and AES-ECB (NIST SP 800-38A)
 *
 * CBC and ECB give confidentiality only, without integrity. Use them to read and
 * write formats that require them (for example PDF encryption, ISO 32000-2 §7.6);
 * for new designs use AES-GCM or ChaCha20-Poly1305.
 *
 * Padding: 'pkcs7' (RFC 5652 §6.3, default) or 'none' (input must be a multiple of 16 bytes).
 * Decryption with 'pkcs7' rejects malformed padding with INTEGRITY_CHECK_FAILED.
 *
 * @module modes/cbc
 */

import { LombokCryptoError, ErrorCode } from '../errors.js';
import { createAes, type AesCore } from '../core/aes/aes.js';

export type BlockPadding = 'pkcs7' | 'none';

export interface CbcOptions {
  /** Padding scheme (default 'pkcs7'). */
  padding?: BlockPadding;
}

const BLOCK = 16;

function checkIv(iv: Uint8Array, algorithm: string): void {
  if (iv.length !== BLOCK) {
    throw new LombokCryptoError(ErrorCode.INVALID_IV_SIZE, `${algorithm} IV must be 16 bytes; got ${iv.length}`, { algorithm });
  }
}

function pad(data: Uint8Array, padding: BlockPadding, algorithm: string): Uint8Array {
  if (padding === 'none') {
    if (data.length % BLOCK !== 0) {
      throw new LombokCryptoError(ErrorCode.INVALID_INPUT, `${algorithm} without padding needs a multiple of 16 bytes; got ${data.length}`, { algorithm });
    }
    return data;
  }
  const n = BLOCK - (data.length % BLOCK);
  const out = new Uint8Array(data.length + n);
  out.set(data);
  out.fill(n, data.length);
  return out;
}

function unpad(data: Uint8Array, padding: BlockPadding, algorithm: string): Uint8Array {
  if (padding === 'none') return data;
  const n = data.length > 0 ? data[data.length - 1]! : 0;
  // Check every padding byte without an early exit
  let bad = n === 0 || n > BLOCK || n > data.length ? 1 : 0;
  for (let i = 0; i < BLOCK && i < data.length; i++) {
    const inPad = i < n ? 1 : 0;
    bad |= inPad & (data[data.length - 1 - i]! !== n ? 1 : 0);
  }
  if (bad) throw new LombokCryptoError(ErrorCode.INTEGRITY_CHECK_FAILED, `${algorithm}: invalid PKCS#7 padding`, { algorithm });
  return data.subarray(0, data.length - n);
}

function checkCiphertext(data: Uint8Array, algorithm: string): void {
  if (data.length % BLOCK !== 0) {
    throw new LombokCryptoError(ErrorCode.INVALID_INPUT, `${algorithm} ciphertext must be a multiple of 16 bytes; got ${data.length}`, { algorithm });
  }
}

function cbcEncrypt(aes: AesCore, iv: Uint8Array, plaintext: Uint8Array, padding: BlockPadding): Uint8Array {
  const data = pad(plaintext, padding, 'AES-CBC');
  const out = new Uint8Array(data.length);
  let prev = iv;
  const block = new Uint8Array(BLOCK);
  for (let off = 0; off < data.length; off += BLOCK) {
    for (let i = 0; i < BLOCK; i++) block[i] = data[off + i]! ^ prev[i]!;
    const c = aes.encryptBlock(block);
    out.set(c, off);
    prev = c;
  }
  return out;
}

function cbcDecrypt(aes: AesCore, iv: Uint8Array, ciphertext: Uint8Array, padding: BlockPadding): Uint8Array {
  checkCiphertext(ciphertext, 'AES-CBC');
  const out = new Uint8Array(ciphertext.length);
  let prev = iv;
  for (let off = 0; off < ciphertext.length; off += BLOCK) {
    const c = ciphertext.subarray(off, off + BLOCK);
    const p = aes.decryptBlock(c);
    for (let i = 0; i < BLOCK; i++) out[off + i] = p[i]! ^ prev[i]!;
    prev = c;
  }
  return unpad(out, padding, 'AES-CBC');
}

/** AES-CBC with a caller-supplied 16-byte IV. Key: 16, 24 or 32 bytes. */
export const aesCbc = {
  encrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array, options: CbcOptions = {}): Uint8Array {
    checkIv(iv, 'AES-CBC');
    return cbcEncrypt(createAes(key), iv, plaintext, options.padding ?? 'pkcs7');
  },
  decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, options: CbcOptions = {}): Uint8Array {
    checkIv(iv, 'AES-CBC');
    return cbcDecrypt(createAes(key), iv, ciphertext, options.padding ?? 'pkcs7');
  },
};

/** AES-ECB. Only for formats that require it (for example the PDF 2.0 Perms entry); leaks equal blocks. */
export const aesEcb = {
  encrypt(key: Uint8Array, plaintext: Uint8Array, options: CbcOptions = {}): Uint8Array {
    const aes = createAes(key);
    const data = pad(plaintext, options.padding ?? 'none', 'AES-ECB');
    const out = new Uint8Array(data.length);
    for (let off = 0; off < data.length; off += BLOCK) out.set(aes.encryptBlock(data.subarray(off, off + BLOCK)), off);
    return out;
  },
  decrypt(key: Uint8Array, ciphertext: Uint8Array, options: CbcOptions = {}): Uint8Array {
    checkCiphertext(ciphertext, 'AES-ECB');
    const aes = createAes(key);
    const out = new Uint8Array(ciphertext.length);
    for (let off = 0; off < ciphertext.length; off += BLOCK) out.set(aes.decryptBlock(ciphertext.subarray(off, off + BLOCK)), off);
    return unpad(out, options.padding ?? 'none', 'AES-ECB');
  },
};
