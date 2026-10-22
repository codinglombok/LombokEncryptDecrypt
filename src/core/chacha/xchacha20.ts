/**
 * LombokEncryptDecrypt — XChaCha20-Poly1305
 *
 * Extended-nonce variant of ChaCha20-Poly1305.
 * 192-bit nonce = 24 bytes (vs 96-bit for ChaCha20).
 * Safe for random nonce generation (no nonce collision concerns at 2^32 messages).
 *
 * Construction: subkey = HChaCha20(key, nonce[0:16]);
 *               then ChaCha20-Poly1305(subkey, nonce[16:24])
 *
 * @module core/chacha/xchacha20
 */

import type { AeadEncryptOptions, AeadDecryptOptions, AeadResult } from '../../types.js';
import { LombokCryptoError, ErrorCode } from '../../errors.js';
import { randomIv } from '../../utils/random.js';
import { chacha20Crypt, poly1305KeyGen, constructAeadMsg } from './chacha20.js';
import { poly1305Mac } from './poly1305.js';
import { timingSafeEqual } from '../../utils/timing.js';

const KEY_SIZE = 32;
const NONCE_SIZE = 24;

// ── HChaCha20 — derive subkey from first 16 bytes of nonce ────────────────

function hRotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function hQuarter(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a]! + s[b]!) >>> 0;
  s[d] = hRotl(s[d]! ^ s[a]!, 16);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = hRotl(s[b]! ^ s[c]!, 12);
  s[a] = (s[a]! + s[b]!) >>> 0;
  s[d] = hRotl(s[d]! ^ s[a]!, 8);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = hRotl(s[b]! ^ s[c]!, 7);
}

/**
 * HChaCha20 (draft-irtf-cfrg-xchacha §2.2): 20 ChaCha rounds over
 * constants | key | 16-byte nonce, output words 0-3 and 12-15, NO feed-forward addition.
 */
function hChaCha20(key: Uint8Array, nonce16: Uint8Array): Uint8Array {
  const s = new Uint32Array(16);
  s[0] = 0x61707865;
  s[1] = 0x3320646e;
  s[2] = 0x79622d32;
  s[3] = 0x6b206574;
  const kv = new DataView(key.buffer, key.byteOffset, 32);
  for (let i = 0; i < 8; i++) s[4 + i] = kv.getUint32(i * 4, true);
  const nv = new DataView(nonce16.buffer, nonce16.byteOffset, 16);
  for (let i = 0; i < 4; i++) s[12 + i] = nv.getUint32(i * 4, true);
  for (let i = 0; i < 10; i++) {
    hQuarter(s, 0, 4, 8, 12);
    hQuarter(s, 1, 5, 9, 13);
    hQuarter(s, 2, 6, 10, 14);
    hQuarter(s, 3, 7, 11, 15);
    hQuarter(s, 0, 5, 10, 15);
    hQuarter(s, 1, 6, 11, 12);
    hQuarter(s, 2, 7, 8, 13);
    hQuarter(s, 3, 4, 9, 14);
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 4; i++) {
    ov.setUint32(i * 4, s[i]!, true);
    ov.setUint32(16 + i * 4, s[12 + i]!, true);
  }
  return out;
}

// ── XChaCha20-Poly1305 encrypt/decrypt (pure TS) ──────────────────────────

function encryptPure(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce24: Uint8Array,
  aad?: Uint8Array,
): AeadResult {
  const subkey = hChaCha20(key, nonce24.slice(0, 16));
  const nonce12 = new Uint8Array(12);
  nonce12.set(nonce24.slice(16, 24), 4); // last 8 bytes placed at offset 4

  const ciphertext = chacha20Crypt(subkey, nonce12, 1, plaintext);
  const macKey = poly1305KeyGen(subkey, nonce12);
  const macInput = constructAeadMsg(aad, ciphertext);
  const tag = poly1305Mac(macKey, macInput);
  return { ciphertext, tag, iv: nonce24 };
}

function decryptPure(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce24: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  const subkey = hChaCha20(key, nonce24.slice(0, 16));
  const nonce12 = new Uint8Array(12);
  nonce12.set(nonce24.slice(16, 24), 4);

  const macKey = poly1305KeyGen(subkey, nonce12);
  const macInput = constructAeadMsg(aad, ciphertext);
  const computed = poly1305Mac(macKey, macInput);
  if (!timingSafeEqual(computed, tag)) {
    throw LombokCryptoError.authenticationFailed('XChaCha20-Poly1305');
  }
  return chacha20Crypt(subkey, nonce12, 1, ciphertext);
}

// ── Public API ────────────────────────────────────────────────────────────

export const xchaChaPoly1305 = {
  /**
   * Encrypt with XChaCha20-Poly1305 (192-bit nonce).
   * Recommended when nonces are randomly generated (safe up to 2^64 messages).
   */
  async encrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    options: AeadEncryptOptions = {},
  ): Promise<AeadResult> {
    if (key.length !== KEY_SIZE) {
      throw LombokCryptoError.invalidKeySize(KEY_SIZE, key.length, 'XChaCha20-Poly1305');
    }
    const nonce = options.iv ?? randomIv(NONCE_SIZE);
    if (nonce.length !== NONCE_SIZE) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_IV_SIZE,
        `XChaCha20-Poly1305 nonce must be ${NONCE_SIZE} bytes (got ${nonce.length})`,
      );
    }
    return encryptPure(plaintext, key, nonce, options.aad);
  },

  async decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    tag: Uint8Array,
    options: AeadDecryptOptions = {},
  ): Promise<Uint8Array> {
    if (key.length !== KEY_SIZE) {
      throw LombokCryptoError.invalidKeySize(KEY_SIZE, key.length, 'XChaCha20-Poly1305');
    }
    if (iv.length !== NONCE_SIZE) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_IV_SIZE,
        `XChaCha20-Poly1305 nonce must be ${NONCE_SIZE} bytes`,
      );
    }
    return decryptPure(ciphertext, key, iv, tag, options.aad);
  },

  generateKey(): Uint8Array {
    return randomIv(KEY_SIZE);
  },
  generateNonce(): Uint8Array {
    return randomIv(NONCE_SIZE);
  },
};

/** @internal exposed for conformance tests */
export { hChaCha20, encryptPure as xchachaEncryptPure, decryptPure as xchachaDecryptPure };
