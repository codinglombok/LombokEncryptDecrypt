/**
 * LombokEncryptDecrypt — Envelope encryption (KEK/DEK, KMS-compatible).
 *
 * Format per docs/SPEC.md §8:
 *   encryptedData = IV(12) || ciphertext || tag(16)   — AES-256-GCM under the DEK
 *   encryptedKey  = { wrappedDek, dekIv, dekTag, kemId, algorithm }
 * rewrap() changes only the wrapped key, never the data.
 */

import { aesGcmDecrypt, aesGcmEncrypt } from '../modes/gcm.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';
import { concatBytes, stringToBytes, zeroize } from '../utils/encoding.js';
import { randomBytes } from '../utils/random.js';

export interface EncryptedKey {
  /** AES-GCM ciphertext of the DEK. */
  wrappedDek: Uint8Array;
  dekIv: Uint8Array;
  dekTag: Uint8Array;
  /** Key-encryption-key identifier. */
  kemId: string;
  /** Always "AES-256-GCM" in v0.1.0. */
  algorithm: string;
}

export interface EnvelopeEncryptResult {
  encryptedData: Uint8Array;
  encryptedKey: EncryptedKey;
}

const WRAP_AAD = stringToBytes('LEDL-envelope-v1');

function assertKek(kek: Uint8Array): void {
  if (kek.length !== 32) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `envelope KEK must be 32 bytes (AES-256), got ${kek.length}`,
      'envelope',
    );
  }
}

async function sealData(data: Uint8Array, dek: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const { ciphertext, tag, iv } = await aesGcmEncrypt(data, dek, { aad });
  return concatBytes(iv, ciphertext, tag);
}

async function openData(
  encryptedData: Uint8Array,
  dek: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (encryptedData.length < 28) {
    throw new LombokCryptoError(
      ErrorCode.INTEGRITY_CHECK_FAILED,
      `encryptedData too short (${encryptedData.length} bytes)`,
      'envelope',
    );
  }
  const iv = encryptedData.subarray(0, 12);
  const tag = encryptedData.subarray(encryptedData.length - 16);
  const ciphertext = encryptedData.subarray(12, encryptedData.length - 16);
  return aesGcmDecrypt(ciphertext, dek, iv, tag, { aad });
}

export const envelopeEncrypt = {
  /** Encrypt with a fresh random DEK wrapped under the KEK. */
  async encrypt(
    plaintext: Uint8Array,
    kek: Uint8Array,
    kemId: string,
    aad?: Uint8Array,
  ): Promise<EnvelopeEncryptResult> {
    assertKek(kek);
    const dataAad = aad ?? new Uint8Array(0);
    const dek = randomBytes(32);
    try {
      const encryptedData = await sealData(plaintext, dek, dataAad);
      const wrap = await aesGcmEncrypt(dek, kek, {
        aad: concatBytes(WRAP_AAD, stringToBytes(kemId)),
      });
      return {
        encryptedData,
        encryptedKey: {
          wrappedDek: wrap.ciphertext,
          dekIv: wrap.iv,
          dekTag: wrap.tag,
          kemId,
          algorithm: 'AES-256-GCM',
        },
      };
    } finally {
      zeroize(dek);
    }
  },

  /** Decrypt by unwrapping the DEK with the KEK. */
  async decrypt(
    encryptedData: Uint8Array,
    encryptedKey: EncryptedKey,
    kek: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    assertKek(kek);
    if (encryptedKey.algorithm !== 'AES-256-GCM') {
      throw new LombokCryptoError(
        ErrorCode.UNSUPPORTED_ALGORITHM,
        `unsupported envelope key algorithm ${encryptedKey.algorithm}`,
        'envelope',
      );
    }
    const dataAad = aad ?? new Uint8Array(0);
    const dek = await aesGcmDecrypt(
      encryptedKey.wrappedDek,
      kek,
      encryptedKey.dekIv,
      encryptedKey.dekTag,
      {
        aad: concatBytes(WRAP_AAD, stringToBytes(encryptedKey.kemId)),
      },
    );
    try {
      return await openData(encryptedData, dek, dataAad);
    } finally {
      zeroize(dek);
    }
  },

  /** Rotate the KEK: only the wrapped DEK changes, encryptedData stays put. */
  async rewrap(
    encryptedKey: EncryptedKey,
    oldKek: Uint8Array,
    newKek: Uint8Array,
    newKemId?: string,
  ): Promise<EncryptedKey> {
    assertKek(oldKek);
    assertKek(newKek);
    const kemId = newKemId ?? encryptedKey.kemId;
    const dek = await aesGcmDecrypt(
      encryptedKey.wrappedDek,
      oldKek,
      encryptedKey.dekIv,
      encryptedKey.dekTag,
      {
        aad: concatBytes(WRAP_AAD, stringToBytes(encryptedKey.kemId)),
      },
    );
    try {
      const wrap = await aesGcmEncrypt(dek, newKek, {
        aad: concatBytes(WRAP_AAD, stringToBytes(kemId)),
      });
      return {
        wrappedDek: wrap.ciphertext,
        dekIv: wrap.iv,
        dekTag: wrap.tag,
        kemId,
        algorithm: encryptedKey.algorithm,
      };
    } finally {
      zeroize(dek);
    }
  },
};
