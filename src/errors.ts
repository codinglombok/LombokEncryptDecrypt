/**
 * LombokEncryptDecrypt — Error taxonomy.
 *
 * Error codes mirror docs/API.md exactly. Every algorithm-level failure raises
 * a LombokCryptoError carrying a machine-readable code so callers can branch
 * on `err.code` instead of parsing messages.
 */

export const ErrorCode = {
  /** Key has wrong byte length for the selected algorithm. */
  INVALID_KEY_SIZE: 'INVALID_KEY_SIZE',
  /** IV / nonce has wrong byte length. */
  INVALID_IV_SIZE: 'INVALID_IV_SIZE',
  /** GCM / Poly1305 / HMAC tag mismatch (verified in constant time). */
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
  /** KeyStore lookup miss. */
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  /** KeyStore entry is past its TTL. */
  KEY_EXPIRED: 'KEY_EXPIRED',
  /** get() called on a locked KeyStore. */
  KEYSTORE_LOCKED: 'KEYSTORE_LOCKED',
  /** Wrong password or tampered KeyStore blob. */
  KEYSTORE_CORRUPT: 'KEYSTORE_CORRUPT',
  /** Legacy algorithm (MD5 / RC4 / AES-ECB) called without `{ legacy: true }`. */
  LEGACY_DISABLED: 'LEGACY_DISABLED',
  /** Non-FIPS algorithm requested while FIPS mode is on. */
  FIPS_VIOLATION: 'FIPS_VIOLATION',
  /** update() called after final() on a stream. */
  STREAM_FINALISED: 'STREAM_FINALISED',
  /** Stream chunk out of order / truncated / corrupted. */
  INTEGRITY_CHECK_FAILED: 'INTEGRITY_CHECK_FAILED',
  /** Unknown algorithm string, or feature that fails closed (Argon2, ML-KEM). */
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
} as const;

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode];

/**
 * Base error for every cryptographic failure raised by this library.
 * `code` is one of the ErrorCode values, `algorithm` (when present) names the
 * algorithm that rejected the input.
 */
export class LombokCryptoError extends Error {
  public readonly code: ErrorCodeValue;
  public readonly algorithm?: string;

  public constructor(code: ErrorCodeValue, message: string, algorithm?: string) {
    super(`[${code}] ${message}`);
    // Keeps `instanceof` reliable when the class is transpiled to CommonJS.
    Object.setPrototypeOf(this, LombokCryptoError.prototype);
    this.name = 'LombokCryptoError';
    this.code = code;
    if (algorithm !== undefined) {
      this.algorithm = algorithm;
    }
  }
}
