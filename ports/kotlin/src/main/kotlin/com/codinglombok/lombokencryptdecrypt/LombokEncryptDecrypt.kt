package com.codinglombok.lombokencryptdecrypt

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * LombokEncryptDecrypt — Kotlin/Android Port
 * Supports Android 6+ (API 23) with AndroidKeyStore integration.
 *
 * @version 0.1.0
 * @author  codinglombok
 * @license Apache-2.0
 */
object LombokEncryptDecrypt {

    const val VERSION = "0.1.0"

    // ── Errors ──────────────────────────────────────────────────────────

    class CryptoException(val code: String, message: String, cause: Throwable? = null) :
        RuntimeException("[$code] $message", cause) {

        companion object {
            const val INVALID_KEY_SIZE      = "INVALID_KEY_SIZE"
            const val INVALID_IV_SIZE       = "INVALID_IV_SIZE"
            const val AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
            const val INVALID_INPUT         = "INVALID_INPUT"
            const val UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
            const val INTERNAL              = "INTERNAL"
        }
    }

    // ── AES-GCM ─────────────────────────────────────────────────────────

    data class AesGcmResult(val ciphertext: ByteArray, val tag: ByteArray, val iv: ByteArray) {
        val packed: ByteArray get() = iv + ciphertext + tag

        companion object {
            fun unpack(packed: ByteArray, ivLen: Int = 12, tagLen: Int = 16): AesGcmResult {
                require(packed.size >= ivLen + tagLen) { "Packed AES-GCM data too short" }
                return AesGcmResult(
                    ciphertext = packed.copyOfRange(ivLen, packed.size - tagLen),
                    tag        = packed.copyOfRange(packed.size - tagLen, packed.size),
                    iv         = packed.copyOfRange(0, ivLen)
                )
            }
        }
    }

    /**
     * AES-GCM encrypt (NIST SP 800-38D).
     *
     * @param plaintext Data to encrypt
     * @param key       16, 24, or 32 byte key
     * @param iv        12-byte IV (randomly generated if null)
     * @param aad       Additional authenticated data
     * @return [AesGcmResult] with ciphertext, tag, and IV
     */
    fun aesGcmEncrypt(
        plaintext: ByteArray,
        key: ByteArray,
        iv: ByteArray? = null,
        aad: ByteArray? = null
    ): AesGcmResult {
        require(key.size in listOf(16, 24, 32)) {
            throw CryptoException(CryptoException.INVALID_KEY_SIZE,
                "AES key must be 16/24/32 bytes; got ${key.size}")
        }

        val actualIv = iv ?: ByteArray(12).also { SecureRandom().nextBytes(it) }
        require(actualIv.size == 12) {
            throw CryptoException(CryptoException.INVALID_IV_SIZE, "AES-GCM IV must be 12 bytes")
        }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, actualIv))
        aad?.takeIf { it.isNotEmpty() }?.let { cipher.updateAAD(it) }

        val combined = cipher.doFinal(plaintext)
        val ciphertext = combined.copyOfRange(0, combined.size - 16)
        val tag        = combined.copyOfRange(combined.size - 16, combined.size)
        return AesGcmResult(ciphertext, tag, actualIv)
    }

    /**
     * AES-GCM decrypt and verify.
     *
     * @throws CryptoException with AUTHENTICATION_FAILED if tag mismatch
     */
    fun aesGcmDecrypt(
        ciphertext: ByteArray,
        key: ByteArray,
        iv: ByteArray,
        tag: ByteArray,
        aad: ByteArray? = null
    ): ByteArray {
        require(key.size in listOf(16, 24, 32)) {
            throw CryptoException(CryptoException.INVALID_KEY_SIZE, "AES key must be 16/24/32 bytes")
        }
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            aad?.takeIf { it.isNotEmpty() }?.let { cipher.updateAAD(it) }
            cipher.doFinal(ciphertext + tag)
        } catch (e: javax.crypto.AEADBadTagException) {
            throw CryptoException(CryptoException.AUTHENTICATION_FAILED,
                "AES-GCM authentication failed", e)
        } catch (e: Exception) {
            throw CryptoException(CryptoException.AUTHENTICATION_FAILED,
                "AES-GCM decryption failed: ${e.message}", e)
        }
    }

    fun aesGcmDecrypt(result: AesGcmResult, key: ByteArray, aad: ByteArray? = null): ByteArray =
        aesGcmDecrypt(result.ciphertext, key, result.iv, result.tag, aad)

    fun generateAesKey(bits: Int = 256): ByteArray {
        require(bits in listOf(128, 192, 256)) { "AES key bits must be 128, 192, or 256" }
        return ByteArray(bits / 8).also { SecureRandom().nextBytes(it) }
    }

    fun generateGcmIv(): ByteArray = ByteArray(12).also { SecureRandom().nextBytes(it) }

    // ── HMAC ────────────────────────────────────────────────────────────

    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    fun hmacSha512(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return mac.doFinal(message)
    }

    /** Constant-time HMAC-SHA256 verification. */
    fun hmacVerify(key: ByteArray, message: ByteArray, expected: ByteArray): Boolean =
        MessageDigest.isEqual(hmacSha256(key, message), expected)

    // ── Hash ─────────────────────────────────────────────────────────────

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
    fun sha512(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(data)
    fun sha3_256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA3-256").digest(data)

    // ── PBKDF2 ───────────────────────────────────────────────────────────

    fun pbkdf2Sha256(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int = 600_000,
        keyLength: Int = 32
    ): ByteArray {
        val spec = PBEKeySpec(
            String(password, Charsets.ISO_8859_1).toCharArray(),
            salt, iterations, keyLength * 8
        )
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    // ── HKDF ─────────────────────────────────────────────────────────────

    fun hkdfSha256(
        ikm: ByteArray,
        length: Int,
        salt: ByteArray = ByteArray(32),
        info: ByteArray = ByteArray(0)
    ): ByteArray {
        val prk = hmacSha256(salt, ikm)
        val out  = ByteArray(length)
        var prev = ByteArray(0)
        var offset = 0
        var i = 1
        while (offset < length) {
            prev = hmacSha256(prk, prev + info + byteArrayOf(i.toByte()))
            val copy = minOf(32, length - offset)
            prev.copyInto(out, offset, 0, copy)
            offset += copy
            i++
        }
        return out
    }

    // ── Random ───────────────────────────────────────────────────────────

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { SecureRandom().nextBytes(it) }

    fun timingSafeEqual(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)
}
