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
import { chacha20Block, chacha20Crypt, poly1305Mac, poly1305KeyGen, constructAeadMsg } from './chacha20.js';
import { timingSafeEqual } from '../../utils/timing.js';

const KEY_SIZE    = 32;
const NONCE_SIZE  = 24;

// ── HChaCha20 — derive subkey from first 16 bytes of nonce ────────────────

function hChaCha20(key: Uint8Array, nonce16: Uint8Array): Uint8Array {
  // Run ChaCha20 block with counter=0 and nonce=nonce16 (padded to 12 bytes)
  // HChaCha20 uses the first and last 4 words of the output
  const nonce12 = new Uint8Array(12);
  nonce12.set(nonce16.slice(0, 12)); // first 12 bytes as "nonce"
  const block = chacha20Block(key, 0, nonce12);
  // HChaCha20 output = words 0–3 and 12–15 of the block
  const subkey = new Uint8Array(32);
  subkey.set(block.slice(0, 16));
  subkey.set(block.slice(48, 64), 16);
  return subkey;
}

// ── XChaCha20-Poly1305 encrypt/decrypt (pure TS) ──────────────────────────

function encryptPure(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce24: Uint8Array,
  aad?: Uint8Array,
): AeadResult {
  const subkey  = hChaCha20(key, nonce24.slice(0, 16));
  const nonce12 = new Uint8Array(12);
  nonce12.set(nonce24.slice(16, 24), 4); // last 8 bytes placed at offset 4

  const ciphertext = chacha20Crypt(subkey, nonce12, 1, plaintext);
  const macKey     = poly1305KeyGen(subkey, nonce12);
  const macInput   = constructAeadMsg(aad, ciphertext);
  const tag        = poly1305Mac(macKey, macInput);
  return { ciphertext, tag, iv: nonce24 };
}

function decryptPure(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce24: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  const subkey  = hChaCha20(key, nonce24.slice(0, 16));
  const nonce12 = new Uint8Array(12);
  nonce12.set(nonce24.slice(16, 24), 4);

  const macKey   = poly1305KeyGen(subkey, nonce12);
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

  generateKey():   Uint8Array { return randomIv(KEY_SIZE); },
  generateNonce(): Uint8Array { return randomIv(NONCE_SIZE); },
};
