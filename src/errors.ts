/**
 * LombokEncryptDecrypt — Error Classes
 * @module errors
 */

export const enum ErrorCode {
  // General
  INVALID_KEY_SIZE = 'INVALID_KEY_SIZE',
  INVALID_IV_SIZE = 'INVALID_IV_SIZE',
  INVALID_TAG_SIZE = 'INVALID_TAG_SIZE',
  INVALID_INPUT = 'INVALID_INPUT',
  INVALID_PARAMETER = 'INVALID_PARAMETER',
  UNSUPPORTED_ALGORITHM = 'UNSUPPORTED_ALGORITHM',

  // Authentication
  AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED',
  INTEGRITY_CHECK_FAILED = 'INTEGRITY_CHECK_FAILED',
  MAC_VERIFICATION_FAILED = 'MAC_VERIFICATION_FAILED',

  // Key management
  KEY_NOT_FOUND = 'KEY_NOT_FOUND',
  KEY_EXPIRED = 'KEY_EXPIRED',
  KEY_IMPORT_FAILED = 'KEY_IMPORT_FAILED',
  KEY_EXPORT_FAILED = 'KEY_EXPORT_FAILED',
  KEYSTORE_LOCKED = 'KEYSTORE_LOCKED',
  KEYSTORE_CORRUPT = 'KEYSTORE_CORRUPT',

  // Post-quantum
  PQC_ENCAPSULATION_FAILED = 'PQC_ENCAPSULATION_FAILED',
  PQC_DECAPSULATION_FAILED = 'PQC_DECAPSULATION_FAILED',
  PQC_KEYGEN_FAILED = 'PQC_KEYGEN_FAILED',

  // Certificate / X.509
  CERT_PARSE_FAILED = 'CERT_PARSE_FAILED',
  CERT_CHAIN_INVALID = 'CERT_CHAIN_INVALID',
  CERT_EXPIRED = 'CERT_EXPIRED',
  CERT_REVOKED = 'CERT_REVOKED',
  CERT_SIGNATURE_INVALID = 'CERT_SIGNATURE_INVALID',

  // Format
  PEM_PARSE_FAILED = 'PEM_PARSE_FAILED',
  DER_PARSE_FAILED = 'DER_PARSE_FAILED',
  JWK_PARSE_FAILED = 'JWK_PARSE_FAILED',
  PKCS12_PARSE_FAILED = 'PKCS12_PARSE_FAILED',

  // Hardware
  HSM_NOT_AVAILABLE = 'HSM_NOT_AVAILABLE',
  HSM_OPERATION_FAILED = 'HSM_OPERATION_FAILED',
  TPM_NOT_AVAILABLE = 'TPM_NOT_AVAILABLE',
  TPM_OPERATION_FAILED = 'TPM_OPERATION_FAILED',
  SECURE_ENCLAVE_NOT_AVAILABLE = 'SECURE_ENCLAVE_NOT_AVAILABLE',

  // Policy
  LEGACY_DISABLED = 'LEGACY_DISABLED',
  FIPS_VIOLATION = 'FIPS_VIOLATION',
  ALGORITHM_DEPRECATED = 'ALGORITHM_DEPRECATED',

  // Streaming
  STREAM_FINALISED = 'STREAM_FINALISED',
  STREAM_NOT_FINALISED = 'STREAM_NOT_FINALISED',

  // Audit
  AUDIT_LOG_CORRUPT = 'AUDIT_LOG_CORRUPT',
  AUDIT_LOG_WRITE_FAILED = 'AUDIT_LOG_WRITE_FAILED',
}

export class LombokCryptoError extends Error {
  public readonly code: ErrorCode;
  public readonly algorithm?: string;
  public readonly cause?: unknown;

  constructor(code: ErrorCode, message: string, options?: { algorithm?: string; cause?: unknown }) {
    super(message);
    this.name = 'LombokCryptoError';
    this.code = code;
    this.algorithm = options?.algorithm;
    this.cause = options?.cause;

    // Maintain proper prototype chain in transpiled environments
    Object.setPrototypeOf(this, LombokCryptoError.prototype);
  }

  static invalidKeySize(expected: number | number[], got: number, algorithm?: string): LombokCryptoError {
    const exp = Array.isArray(expected) ? expected.join('/') : String(expected);
    return new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `Invalid key size: expected ${exp} bytes, got ${got} bytes`,
      { algorithm },
    );
  }

  static authenticationFailed(algorithm?: string): LombokCryptoError {
    return new LombokCryptoError(
      ErrorCode.AUTHENTICATION_FAILED,
      'Authentication tag verification failed — ciphertext may be tampered',
      { algorithm },
    );
  }

  static legacyDisabled(algorithm: string): LombokCryptoError {
    return new LombokCryptoError(
      ErrorCode.LEGACY_DISABLED,
      `Algorithm ${algorithm} is disabled. Pass { legacy: true } to enable legacy algorithms.`,
      { algorithm },
    );
  }

  static fipsViolation(algorithm: string): LombokCryptoError {
    return new LombokCryptoError(
      ErrorCode.FIPS_VIOLATION,
      `Algorithm ${algorithm} is not permitted in FIPS mode.`,
      { algorithm },
    );
  }

  static unsupportedAlgorithm(algorithm: string): LombokCryptoError {
    return new LombokCryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `Unsupported algorithm: ${algorithm}`,
      { algorithm },
    );
  }
}
