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
  /** Malformed input that cannot be processed at all (lengths, encodings, flags). */
  INVALID_INPUT: 'INVALID_INPUT',
  /** Semantically invalid parameter value (e.g. non-power-of-two scrypt cost). */
  INVALID_PARAMETER: 'INVALID_PARAMETER',
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
 * Optional details attached to a LombokCryptoError.
 * Pass a plain string as shorthand for `{ algorithm: string }`.
 */
export interface LombokCryptoErrorDetails {
  /** Algorithm that rejected the input. */
  readonly algorithm?: string;
  /** Underlying error (e.g. a WebCrypto DataError) preserved for diagnostics. */
  readonly cause?: unknown;
}

/**
 * Base error for every cryptographic failure raised by this library.
 * `code` is one of the ErrorCode values, `algorithm` (when present) names the
 * algorithm that rejected the input.
 */
export class LombokCryptoError extends Error {
  public readonly code: ErrorCodeValue;
  public readonly algorithm?: string;

  public constructor(
    code: ErrorCodeValue,
    message: string,
    details?: string | LombokCryptoErrorDetails,
  ) {
    const normalized: LombokCryptoErrorDetails | undefined =
      typeof details === 'string' ? { algorithm: details } : details;
    const cause = normalized?.cause;
    super(`[${code}] ${message}`, cause !== undefined ? { cause } : undefined);
    // Keeps `instanceof` reliable when the class is transpiled to CommonJS.
    Object.setPrototypeOf(this, LombokCryptoError.prototype);
    this.name = 'LombokCryptoError';
    this.code = code;
    if (normalized?.algorithm !== undefined) {
      this.algorithm = normalized.algorithm;
    }
  }

  /** AUTHENTICATION_FAILED factory — tag mismatch on AEAD/MAC verification. */
  public static authenticationFailed(algorithm: string): LombokCryptoError {
    return new LombokCryptoError(
      ErrorCode.AUTHENTICATION_FAILED,
      'authentication failed',
      algorithm,
    );
  }

  /** INVALID_KEY_SIZE factory — expected vs actual byte length. */
  public static invalidKeySize(
    expected: number,
    actual: number,
    algorithm: string,
  ): LombokCryptoError {
    return new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `key must be ${expected} bytes, got ${actual}`,
      algorithm,
    );
  }
}
