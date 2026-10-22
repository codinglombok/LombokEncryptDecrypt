/**
 * LombokEncryptDecrypt — Envelope Encryption
 *
 * KEK/DEK (Key Encryption Key / Data Encryption Key) pattern.
 * Compatible with AWS KMS, GCP Cloud KMS, Azure Key Vault API patterns.
 *
 * Flow:
 *   1. Generate random DEK (AES-256 key)
 *   2. Encrypt plaintext with DEK (AES-256-GCM)
 *   3. Wrap DEK with KEK (AES-256-GCM or asymmetric)
 *   4. Store: wrappedDek + encryptedData
 *
 * Decrypt flow:
 *   1. Unwrap DEK with KEK
 *   2. Decrypt data with DEK
 *
 * @module hybrid/envelope
 */

import type { EnvelopeEncryptedKey } from '../types.js';
import { randomKey256 } from '../utils/random.js';
import { aesGcm } from '../modes/gcm.js';
import { concatBytes } from '../utils/encoding.js';
import { LombokCryptoError, ErrorCode } from '../errors.js';

export interface EnvelopeEncryptResult {
  /** Encrypted payload (contains IV + ciphertext + tag inline) */
  readonly encryptedData: Uint8Array;
  /** Wrapped DEK */
  readonly encryptedKey: EnvelopeEncryptedKey;
}

// ── Packed format: 12-byte IV || ciphertext || 16-byte tag ────────────────

function packAeadResult(iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  return concatBytes(iv, ciphertext, tag);
}

function unpackAeadResult(
  packed: Uint8Array,
  ivLen = 12,
  tagLen = 16,
): { iv: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array } {
  if (packed.length < ivLen + tagLen) {
    throw new LombokCryptoError(ErrorCode.INVALID_INPUT, 'Packed AEAD data too short');
  }
  return {
    iv: packed.slice(0, ivLen),
    ciphertext: packed.slice(ivLen, packed.length - tagLen),
    tag: packed.slice(packed.length - tagLen),
  };
}

// ── Symmetric KEK wrapping ────────────────────────────────────────────────

async function wrapDekWithKek(
  dek: Uint8Array,
  kek: Uint8Array,
  kemId: string,
): Promise<EnvelopeEncryptedKey> {
  const { ciphertext, tag, iv } = await aesGcm.encrypt(dek, kek);
  return { wrappedDek: ciphertext, dekIv: iv, dekTag: tag, kemId, algorithm: 'AES-256-GCM' };
}

async function unwrapDekWithKek(
  encKey: EnvelopeEncryptedKey,
  kek: Uint8Array,
): Promise<Uint8Array> {
  return aesGcm.decrypt(encKey.wrappedDek, kek, encKey.dekIv, encKey.dekTag);
}

// ── Public API ────────────────────────────────────────────────────────────

export const envelopeEncrypt = {
  /**
   * Encrypt plaintext using a fresh DEK, wrapped with the provided KEK.
   *
   * @param plaintext - Data to encrypt
   * @param kek       - Key Encryption Key (32-byte AES-256 key or asymmetric public key)
   * @param kemId     - Identifier for the KEK (for key rotation tracking)
   * @param aad       - Optional additional authenticated data
   *
   * @example
   * const kek = randomKey256(); // or load from KMS
   * const { encryptedData, encryptedKey } = await envelopeEncrypt.encrypt(plaintext, kek, 'my-kek-id');
   * // Store encryptedKey alongside encryptedData
   */
  async encrypt(
    plaintext: Uint8Array,
    kek: Uint8Array,
    kemId: string,
    aad?: Uint8Array,
  ): Promise<EnvelopeEncryptResult> {
    // 1. Generate fresh random DEK
    const dek = randomKey256();

    // 2. Encrypt plaintext with DEK
    const { ciphertext, tag, iv } = await aesGcm.encrypt(plaintext, dek, { aad });
    const encryptedData = packAeadResult(iv, ciphertext, tag);

    // 3. Wrap DEK with KEK
    const encryptedKey = await wrapDekWithKek(dek, kek, kemId);

    // 4. Zero out DEK from memory
    dek.fill(0);

    return { encryptedData, encryptedKey };
  },

  /**
   * Decrypt envelope-encrypted data.
   *
   * @param encryptedData - Output from envelopeEncrypt.encrypt()
   * @param encryptedKey  - Wrapped DEK from envelopeEncrypt.encrypt()
   * @param kek           - Key Encryption Key to unwrap the DEK
   * @param aad           - Must match AAD used during encryption
   */
  async decrypt(
    encryptedData: Uint8Array,
    encryptedKey: EnvelopeEncryptedKey,
    kek: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    // 1. Unwrap DEK
    const dek = await unwrapDekWithKek(encryptedKey, kek);

    // 2. Unpack and decrypt
    const { iv, ciphertext, tag } = unpackAeadResult(encryptedData);
    const plaintext = await aesGcm.decrypt(ciphertext, dek, iv, tag, { aad });

    // 3. Zero out DEK
    dek.fill(0);

    return plaintext;
  },

  /**
   * Re-wrap the DEK with a new KEK (key rotation without re-encrypting data).
   *
   * @example
   * // Rotate KEK without touching the encrypted data
   * const rotated = await envelopeEncrypt.rewrap(encryptedKey, oldKek, newKek, 'new-kek-id');
   */
  async rewrap(
    encryptedKey: EnvelopeEncryptedKey,
    oldKek: Uint8Array,
    newKek: Uint8Array,
    newKemId: string,
  ): Promise<EnvelopeEncryptedKey> {
    const dek = await unwrapDekWithKek(encryptedKey, oldKek);
    const rewrapped = await wrapDekWithKek(dek, newKek, newKemId);
    dek.fill(0);
    return rewrapped;
  },
};
