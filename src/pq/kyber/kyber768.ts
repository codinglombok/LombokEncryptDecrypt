/**
 * LombokEncryptDecrypt — ML-KEM-768 / Kyber768 (NIST FIPS 203) — FAILS CLOSED.
 *
 * v0.1.0 does not ship a post-quantum KEM: every operation throws
 * UNSUPPORTED_ALGORITHM. The module is intentionally NOT re-exported from
 * the package barrels; importing the deep path is only useful for tools
 * that must fail predictably.
 */

import { ErrorCode, LombokCryptoError } from '../../errors.js';

function fail(method: string): never {
  throw new LombokCryptoError(
    ErrorCode.UNSUPPORTED_ALGORITHM,
    `ML-KEM-768 ${method} is not implemented in v0.1.0 and fails closed`,
    'ML-KEM-768',
  );
}

/** Fail-closed ML-KEM-768 stub — see IMPLEMENTATION_STATUS.md. */
export const kyber768 = {
  async generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    fail('generateKeyPair');
  },
  async encapsulate(
    publicKey: Uint8Array,
  ): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
    void publicKey;
    fail('encapsulate');
  },
  async decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    void ciphertext;
    void secretKey;
    fail('decapsulate');
  },
};

/** NIST alias for kyber768 — also fails closed. */
export const mlKem768 = kyber768;
