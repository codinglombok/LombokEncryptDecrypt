/**
 * LombokEncryptDecrypt — ML-KEM-768 (Kyber768), NIST FIPS 203
 *
 * STATUS (v0.1.0): API surface and size checks only. There is NO pure-TypeScript
 * ML-KEM implementation yet, and Node.js 22 has no built-in ML-KEM. The functions
 * delegate to an optional native backend (`./kyber768_napi.js`, built from
 * src-rust/ via NAPI-RS) and throw UNSUPPORTED_ALGORITHM when it is absent.
 *
 * An earlier skeleton returned zeroed keys/ciphertexts and a random shared secret
 * from decapsulate(); that was removed because a KEM that silently returns
 * non-matching secrets is worse than one that refuses to run.
 *
 * @module pq/kyber/kyber768
 */

import type { KEMKeyPair, KEMResult } from '../../types.js';
import { LombokCryptoError, ErrorCode } from '../../errors.js';
import { PQC_SIZES } from '../../constants.js';

interface NativeKyber {
  kyber768_keygen(): KEMKeyPair | Promise<KEMKeyPair>;
  kyber768_encapsulate(publicKey: Uint8Array): KEMResult | Promise<KEMResult>;
  kyber768_decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

async function loadNative(): Promise<NativeKyber> {
  const modulePath = './kyber768_napi.js'; // variable specifier: optional, built separately
  try {
    return (await import(/* @vite-ignore */ modulePath)) as NativeKyber;
  } catch (cause) {
    throw new LombokCryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      'ML-KEM-768 needs the native backend (kyber768_napi), which is not built in this environment',
      { algorithm: 'ML-KEM-768', cause },
    );
  }
}

export const kyber768 = {
  /** Generate an ML-KEM-768 key pair (publicKey 1184 B, secretKey 2400 B). */
  async generateKeyPair(): Promise<KEMKeyPair> {
    const native = await loadNative();
    return native.kyber768_keygen();
  },

  /** Encapsulate to a recipient public key (ciphertext 1088 B, sharedSecret 32 B). */
  async encapsulate(publicKey: Uint8Array): Promise<KEMResult> {
    if (publicKey.length !== PQC_SIZES.KYBER768_PK) {
      throw LombokCryptoError.invalidKeySize(PQC_SIZES.KYBER768_PK, publicKey.length, 'ML-KEM-768');
    }
    const native = await loadNative();
    return native.kyber768_encapsulate(publicKey);
  },

  /** Recover the shared secret from a ciphertext with the secret key. */
  async decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    if (ciphertext.length !== PQC_SIZES.KYBER768_CT) {
      throw new LombokCryptoError(ErrorCode.INVALID_INPUT,
        `ML-KEM-768 ciphertext must be ${PQC_SIZES.KYBER768_CT} bytes`, { algorithm: 'ML-KEM-768' });
    }
    if (secretKey.length !== PQC_SIZES.KYBER768_SK) {
      throw LombokCryptoError.invalidKeySize(PQC_SIZES.KYBER768_SK, secretKey.length, 'ML-KEM-768');
    }
    const native = await loadNative();
    return native.kyber768_decapsulate(ciphertext, secretKey);
  },

  PK_SIZE: PQC_SIZES.KYBER768_PK,
  SK_SIZE: PQC_SIZES.KYBER768_SK,
  CT_SIZE: PQC_SIZES.KYBER768_CT,
  SS_SIZE: PQC_SIZES.KYBER768_SS,
};

export const mlKem768 = kyber768; // NIST FIPS 203 alias
