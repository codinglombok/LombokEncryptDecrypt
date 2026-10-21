/**
 * LombokEncryptDecrypt — Legacy namespace (old formats only).
 *
 * MD5, RC4 and AES-ECB are broken primitives kept strictly for reading
 * historical data. Every function requires `{ legacy: true }` and throws
 * LEGACY_DISABLED otherwise, so accidental use is impossible.
 */

import { createHash } from 'node:crypto';
import { aesDecryptBlock, aesEncryptBlock, aesExpandKey } from '../core/aes/aes.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';

export interface LegacyGate {
  legacy: true;
}

function assertLegacy(gate?: LegacyGate): void {
  if (gate?.legacy !== true) {
    throw new LombokCryptoError(
      ErrorCode.LEGACY_DISABLED,
      'legacy algorithms require { legacy: true } and are broken — do not use for new data',
      'legacy',
    );
  }
}

/** MD5 digest (broken — legacy gate required). */
export async function md5(data: Uint8Array, gate?: LegacyGate): Promise<Uint8Array> {
  assertLegacy(gate);
  return new Uint8Array(createHash('md5').update(new Uint8Array(data)).digest());
}

/** RC4 keystream XOR (broken — legacy gate required). Pure TS. */
export function rc4(key: Uint8Array, data: Uint8Array, gate?: LegacyGate): Uint8Array {
  assertLegacy(gate);
  if (key.length < 1 || key.length > 256) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `RC4 key length must be 1..256 bytes, got ${key.length}`,
      'RC4',
    );
  }
  // KSA
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    const tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
  }
  // PRGA
  const out = new Uint8Array(data.length);
  let i = 0;
  j = 0;
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    const tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
    out[k] = data[k] ^ s[(s[i] + s[j]) & 0xff];
  }
  return out;
}

function ecb(key: Uint8Array, data: Uint8Array, decrypt: boolean): Uint8Array {
  const expanded = aesExpandKey(key);
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += 16) {
    const block = decrypt
      ? aesDecryptBlock(expanded, data.subarray(off, off + 16))
      : aesEncryptBlock(expanded, data.subarray(off, off + 16));
    out.set(block, off);
  }
  return out;
}

function validateEcbInput(key: Uint8Array, data: Uint8Array): void {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `AES-ECB key must be 16, 24 or 32 bytes, got ${key.length}`,
      'AES-ECB',
    );
  }
  if (data.length % 16 !== 0 || data.length === 0) {
    throw new LombokCryptoError(
      ErrorCode.INTEGRITY_CHECK_FAILED,
      `AES-ECB data length must be a positive multiple of 16, got ${data.length}`,
      'AES-ECB',
    );
  }
}

/** AES-ECB encryption WITHOUT padding (broken — legacy gate required). */
export async function aesEcbEncrypt(
  key: Uint8Array,
  data: Uint8Array,
  gate?: LegacyGate,
): Promise<Uint8Array> {
  assertLegacy(gate);
  validateEcbInput(key, data);
  return ecb(key, data, false);
}

/** AES-ECB decryption WITHOUT padding (broken — legacy gate required). */
export async function aesEcbDecrypt(
  key: Uint8Array,
  data: Uint8Array,
  gate?: LegacyGate,
): Promise<Uint8Array> {
  assertLegacy(gate);
  validateEcbInput(key, data);
  return ecb(key, data, true);
}

/** Legacy namespace. */
export const legacy = { md5, rc4, aesEcbEncrypt, aesEcbDecrypt };
