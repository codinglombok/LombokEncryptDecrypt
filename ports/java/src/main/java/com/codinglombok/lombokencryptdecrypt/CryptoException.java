package com.codinglombok.lombokencryptdecrypt;

/**
 * CryptoException — wraps all LombokEncryptDecrypt errors with a machine-readable code.
 *
 * <p>Error codes follow the same naming convention as the TypeScript and Rust implementations,
 * allowing unified error handling across all language ports.
 */
public class CryptoException extends RuntimeException {

    private final String code;

    public CryptoException(String code, String message) {
        super("[" + code + "] " + message);
        this.code = code;
    }

    public CryptoException(String code, String message, Throwable cause) {
        super("[" + code + "] " + message, cause);
        this.code = code;
    }

    /** Machine-readable error code (e.g. "AUTHENTICATION_FAILED", "INVALID_KEY_SIZE"). */
    public String getCode() { return code; }

    // Well-known codes
    public static final String INVALID_KEY_SIZE     = "INVALID_KEY_SIZE";
    public static final String INVALID_IV_SIZE      = "INVALID_IV_SIZE";
    public static final String AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED";
    public static final String INVALID_INPUT        = "INVALID_INPUT";
    public static final String UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM";
    public static final String KEY_NOT_FOUND        = "KEY_NOT_FOUND";
    public static final String INTERNAL             = "INTERNAL";
}
