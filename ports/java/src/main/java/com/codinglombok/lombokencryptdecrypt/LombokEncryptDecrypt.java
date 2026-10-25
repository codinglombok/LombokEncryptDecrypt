package com.codinglombok.lombokencryptdecrypt;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

/**
 * LombokEncryptDecrypt — Java Port
 * Universal encrypt/decrypt library for Java 17+
 *
 * <p>All cryptographic operations use the JCA/JCE provider.
 * Constant-time MAC comparisons use MessageDigest.isEqual().
 *
 * @version 0.1.0
 * @author  codinglombok
 * Licensed under the Apache License, Version 2.0.
 */
public final class LombokEncryptDecrypt {

    public static final String VERSION = "0.1.0";

    private LombokEncryptDecrypt() {}

    // ── AES-GCM ──────────────────────────────────────────────────────────

    /** Result of an AES-GCM encryption operation. */
    public record AesGcmResult(byte[] ciphertext, byte[] tag, byte[] iv) {}

    /**
     * AES-GCM encrypt (NIST SP 800-38D).
     *
     * @param plaintext Data to encrypt
     * @param key       16, 24, or 32 byte AES key
     * @param iv        12-byte IV (randomly generated if null)
     * @param aad       Additional authenticated data (may be null)
     * @return {@link AesGcmResult} containing ciphertext, 16-byte tag, and IV
     * @throws CryptoException on invalid key size or encryption failure
     */
    public static AesGcmResult aesGcmEncrypt(byte[] plaintext, byte[] key, byte[] iv, byte[] aad) {
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new CryptoException("INVALID_KEY_SIZE",
                "AES key must be 16, 24, or 32 bytes; got " + key.length);
        }
        if (iv == null) {
            iv = new byte[12];
            new SecureRandom().nextBytes(iv);
        }
        if (iv.length != 12) {
            throw new CryptoException("INVALID_IV_SIZE", "AES-GCM IV must be 12 bytes");
        }

        try {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
            if (aad != null && aad.length > 0) cipher.updateAAD(aad);

            final byte[] combined = cipher.doFinal(plaintext);
            // Java GCM appends tag to ciphertext
            final byte[] ciphertext = Arrays.copyOfRange(combined, 0, combined.length - 16);
            final byte[] tag        = Arrays.copyOfRange(combined, combined.length - 16, combined.length);
            return new AesGcmResult(ciphertext, tag, iv);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CryptoException("UNSUPPORTED_ALGORITHM", "AES/GCM not available: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            throw new CryptoException("ENCRYPTION_FAILED", e.getMessage());
        }
    }

    /** Convenience: AES-GCM encrypt with random IV and no AAD. */
    public static AesGcmResult aesGcmEncrypt(byte[] plaintext, byte[] key) {
        return aesGcmEncrypt(plaintext, key, null, null);
    }

    /**
     * AES-GCM decrypt and verify authentication tag.
     *
     * @throws CryptoException with code AUTHENTICATION_FAILED if tag does not match
     */
    public static byte[] aesGcmDecrypt(byte[] ciphertext, byte[] key, byte[] iv, byte[] tag, byte[] aad) {
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new CryptoException("INVALID_KEY_SIZE", "AES key must be 16/24/32 bytes");
        }
        try {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            if (aad != null && aad.length > 0) cipher.updateAAD(aad);

            final byte[] combined = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
            System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
            return cipher.doFinal(combined);

        } catch (AEADBadTagException e) {
            throw new CryptoException("AUTHENTICATION_FAILED",
                "AES-GCM authentication tag verification failed");
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AUTHENTICATION_FAILED", e.getMessage());
        }
    }

    public static byte[] aesGcmDecrypt(AesGcmResult result, byte[] key, byte[] aad) {
        return aesGcmDecrypt(result.ciphertext(), key, result.iv(), result.tag(), aad);
    }

    /** Generate a random AES key. @param bits 128, 192, or 256 */
    public static byte[] generateAesKey(int bits) {
        try {
            final KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(bits, new SecureRandom());
            return kg.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("INTERNAL", "AES key generation failed");
        }
    }

    /** Generate a random 12-byte GCM IV. */
    public static byte[] generateGcmIv() {
        final byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // ── HMAC ────────────────────────────────────────────────────────────

    /**
     * HMAC-SHA256 (RFC 2104, NIST FIPS 198-1).
     *
     * @return 32-byte MAC
     */
    public static byte[] hmacSha256(byte[] key, byte[] message) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("INTERNAL", "HMAC-SHA256 failed: " + e.getMessage());
        }
    }

    /**
     * HMAC-SHA512.
     * @return 64-byte MAC
     */
    public static byte[] hmacSha512(byte[] key, byte[] message) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(key, "HmacSHA512"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("INTERNAL", "HMAC-SHA512 failed: " + e.getMessage());
        }
    }

    /**
     * Constant-time HMAC-SHA256 verification.
     * Uses MessageDigest.isEqual() which is constant-time.
     */
    public static boolean hmacVerify(byte[] key, byte[] message, byte[] expected) {
        final byte[] computed = hmacSha256(key, message);
        return MessageDigest.isEqual(computed, expected);
    }

    // ── Hash ─────────────────────────────────────────────────────────────

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("INTERNAL", "SHA-256 not available");
        }
    }

    public static byte[] sha512(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("INTERNAL", "SHA-512 not available");
        }
    }

    public static byte[] sha3_256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA3-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("INTERNAL", "SHA3-256 not available (requires Java 9+)");
        }
    }

    // ── PBKDF2 ───────────────────────────────────────────────────────────

    /**
     * PBKDF2-SHA256 key derivation (RFC 8018).
     *
     * @param password   Password bytes
     * @param salt       Salt (recommend ≥ 16 random bytes)
     * @param iterations Iteration count (≥ 600,000 per OWASP 2024)
     * @param keyLength  Desired output length in bytes
     */
    public static byte[] pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int keyLength) {
        try {
            final SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            final PBEKeySpec spec = new PBEKeySpec(
                new String(password, java.nio.charset.StandardCharsets.ISO_8859_1).toCharArray(),
                salt, iterations, keyLength * 8);
            try {
                return skf.generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException("INTERNAL", "PBKDF2-SHA256 failed: " + e.getMessage());
        }
    }

    // ── HKDF ─────────────────────────────────────────────────────────────

    /**
     * HKDF-SHA256 (RFC 5869).
     *
     * @param ikm    Input keying material
     * @param salt   Salt (use new byte[32] if empty)
     * @param info   Context info
     * @param length Output length in bytes (max 32*255 = 8160)
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (length > 32 * 255) throw new CryptoException("INVALID_INPUT", "HKDF output too long");
        if (salt == null || salt.length == 0) salt = new byte[32];

        // Extract
        final byte[] prk = hmacSha256(salt, ikm);

        // Expand
        final byte[] out = new byte[length];
        byte[] prev = new byte[0];
        int offset = 0;
        for (int i = 1; offset < length; i++) {
            final byte[] input = new byte[prev.length + info.length + 1];
            System.arraycopy(prev, 0, input, 0, prev.length);
            System.arraycopy(info, 0, input, prev.length, info.length);
            input[input.length - 1] = (byte) i;
            prev = hmacSha256(prk, input);
            final int copy = Math.min(32, length - offset);
            System.arraycopy(prev, 0, out, offset, copy);
            offset += copy;
        }
        return out;
    }

    // ── Random ───────────────────────────────────────────────────────────

    /** Generate n cryptographically secure random bytes. */
    public static byte[] randomBytes(int n) {
        final byte[] buf = new byte[n];
        new SecureRandom().nextBytes(buf);
        return buf;
    }

    // ── Constant-time comparison ─────────────────────────────────────────

    /** Constant-time byte array comparison (prevents timing attacks). */
    public static boolean timingSafeEqual(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
}
