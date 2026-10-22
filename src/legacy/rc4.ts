/**
 * LombokEncryptDecrypt — RC4 / ARCFOUR. LEGACY.
 *
 * RC4 has known biases (RFC 7465 prohibits it in TLS). It is provided only to read
 * legacy formats that require it (for example PDF standard security handler R2-R4).
 * Never use it to protect new data.
 *
 * Test vectors: RFC 6229.
 *
 * @module legacy/rc4
 */

import { LombokCryptoError, ErrorCode } from '../errors.js';

/** RC4 keystream XOR. Encryption and decryption are the same operation. Key: 1-256 bytes. */
export function rc4(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (key.length < 1 || key.length > 256) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `RC4 key must be 1-256 bytes; got ${key.length}`,
      { algorithm: 'RC4' },
    );
  }
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  for (let i = 0, j = 0; i < 256; i++) {
    j = (j + s[i]! + key[i % key.length]!) & 0xff;
    const t = s[i]!;
    s[i] = s[j]!;
    s[j] = t;
  }
  const out = new Uint8Array(data.length);
  for (let n = 0, i = 0, j = 0; n < data.length; n++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]!) & 0xff;
    const t = s[i]!;
    s[i] = s[j]!;
    s[j] = t;
    out[n] = data[n]! ^ s[(s[i]! + s[j]!) & 0xff]!;
  }
  return out;
}
