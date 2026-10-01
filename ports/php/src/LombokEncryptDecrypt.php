<?php

declare(strict_types=1);

namespace CodingLombok\LombokEncryptDecrypt;

use RuntimeException;
use SodiumException;

/**
 * LombokEncryptDecrypt — PHP Port
 * Universal encrypt/decrypt library for PHP 8.2+
 *
 * @version 0.1.0
 * @license Apache-2.0
 * @author  codinglombok
 */
final class LombokEncryptDecrypt
{
    public const VERSION = '0.1.0';

    // Prevent instantiation — use static methods only
    private function __construct() {}

    /**
     * AES-256-GCM encrypt.
     *
     * @param  string      $plaintext Data to encrypt
     * @param  string      $key       32-byte AES-256 key (or 16/24 for AES-128/192)
     * @param  string|null $iv        12-byte IV (random if null)
     * @param  string      $aad       Additional authenticated data
     * @return array{ciphertext: string, tag: string, iv: string}
     * @throws CryptoException On invalid key size or encryption failure
     */
    public static function aesGcmEncrypt(
        string $plaintext,
        string $key,
        ?string $iv = null,
        string $aad = '',
    ): array {
        $keyLen = strlen($key);
        if (! in_array($keyLen, [16, 24, 32], true)) {
            throw new CryptoException('INVALID_KEY_SIZE', "AES key must be 16, 24, or 32 bytes; got {$keyLen}");
        }

        if ($iv === null) {
            $iv = random_bytes(12);
        }
        if (strlen($iv) !== 12) {
            throw new CryptoException('INVALID_IV_SIZE', 'AES-GCM IV must be 12 bytes');
        }

        $tag        = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            "aes-{$keyLen}-gcm-aead", // Wait, correct cipher string
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
            16, // tag length
        );

        // openssl_encrypt with GCM: use the correct cipher name
        $cipherName = match ($keyLen) {
            16 => 'aes-128-gcm',
            24 => 'aes-192-gcm',
            32 => 'aes-256-gcm',
        };

        $tag        = '';
        $ciphertext = openssl_encrypt($plaintext, $cipherName, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);

        if ($ciphertext === false) {
            throw new CryptoException('ENCRYPTION_FAILED', 'AES-GCM encryption failed');
        }

        return [
            'ciphertext' => $ciphertext,
            'tag'        => $tag,
            'iv'         => $iv,
        ];
    }

    /**
     * AES-256-GCM decrypt.
     *
     * @throws CryptoException On authentication failure
     */
    public static function aesGcmDecrypt(
        string $ciphertext,
        string $key,
        string $iv,
        string $tag,
        string $aad = '',
    ): string {
        $keyLen     = strlen($key);
        $cipherName = match ($keyLen) {
            16 => 'aes-128-gcm',
            24 => 'aes-192-gcm',
            32 => 'aes-256-gcm',
            default => throw new CryptoException('INVALID_KEY_SIZE', "AES key must be 16/24/32 bytes; got {$keyLen}"),
        };

        $plaintext = openssl_decrypt($ciphertext, $cipherName, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);

        if ($plaintext === false) {
            throw new CryptoException('AUTHENTICATION_FAILED', 'AES-GCM authentication tag verification failed');
        }

        return $plaintext;
    }

    /**
     * ChaCha20-Poly1305 encrypt (uses libsodium).
     *
     * @throws CryptoException On failure
     */
    public static function chaCha20Poly1305Encrypt(
        string $plaintext,
        string $key,
        ?string $nonce = null,
        string $aad = '',
    ): array {
        if (strlen($key) !== SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES) {
            throw new CryptoException('INVALID_KEY_SIZE', 'ChaCha20 key must be 32 bytes');
        }
        if ($nonce === null) {
            $nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
        }

        try {
            $combined   = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
            $ciphertext = substr($combined, 0, -SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES);
            $tag        = substr($combined, -SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES);
        } catch (SodiumException $e) {
            throw new CryptoException('ENCRYPTION_FAILED', $e->getMessage());
        }

        return ['ciphertext' => $ciphertext, 'tag' => $tag, 'nonce' => $nonce];
    }

    /**
     * ChaCha20-Poly1305 decrypt.
     *
     * @throws CryptoException On authentication failure
     */
    public static function chaCha20Poly1305Decrypt(
        string $ciphertext,
        string $key,
        string $nonce,
        string $tag,
        string $aad = '',
    ): string {
        try {
            $result = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
                $ciphertext . $tag,
                $aad,
                $nonce,
                $key,
            );
        } catch (SodiumException $e) {
            throw new CryptoException('AUTHENTICATION_FAILED', 'ChaCha20-Poly1305 authentication failed');
        }

        if ($result === false) {
            throw new CryptoException('AUTHENTICATION_FAILED', 'ChaCha20-Poly1305 authentication failed');
        }

        return $result;
    }

    /**
     * Ed25519 key pair generation.
     *
     * @return array{private_key: string, public_key: string}
     */
    public static function ed25519GenerateKeyPair(): array
    {
        $keypair = sodium_crypto_sign_keypair();
        return [
            'private_key' => sodium_crypto_sign_secretkey($keypair),
            'public_key'  => sodium_crypto_sign_publickey($keypair),
        ];
    }

    /**
     * Ed25519 sign.
     *
     * @param  string $message    Message to sign
     * @param  string $privateKey 64-byte Ed25519 private key (seed + public)
     * @return string 64-byte signature
     */
    public static function ed25519Sign(string $message, string $privateKey): string
    {
        return sodium_crypto_sign_detached($message, $privateKey);
    }

    /**
     * Ed25519 verify.
     */
    public static function ed25519Verify(string $message, string $signature, string $publicKey): bool
    {
        try {
            return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
        } catch (SodiumException) {
            return false;
        }
    }

    /**
     * HMAC-SHA256.
     */
    public static function hmacSha256(string $key, string $message): string
    {
        return hash_hmac('sha256', $message, $key, true);
    }

    /**
     * HMAC-SHA512.
     */
    public static function hmacSha512(string $key, string $message): string
    {
        return hash_hmac('sha512', $message, $key, true);
    }

    /**
     * Constant-time HMAC verification.
     */
    public static function hmacVerify(string $key, string $message, string $expected): bool
    {
        $computed = self::hmacSha256($key, $message);
        return hash_equals($computed, $expected);
    }

    /**
     * PBKDF2-SHA256 key derivation (RFC 8018).
     */
    public static function pbkdf2Sha256(
        string $password,
        string $salt,
        int $iterations = 600_000,
        int $keyLength = 32,
    ): string {
        return hash_pbkdf2('sha256', $password, $salt, $iterations, $keyLength, true);
    }

    /**
     * Argon2id hash (RFC 9106, PHP 7.2+).
     */
    public static function argon2idHash(
        string $password,
        int $memoryCost = 65536,
        int $timeCost = 3,
        int $threads = 4,
    ): string {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => $memoryCost,
            'time_cost'   => $timeCost,
            'threads'     => $threads,
        ]);
    }

    /**
     * Argon2id verify.
     */
    public static function argon2idVerify(string $hash, string $password): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * SHA-256 hash.
     */
    public static function sha256(string $data): string
    {
        return hash('sha256', $data, true);
    }

    /**
     * SHA3-256 hash.
     */
    public static function sha3_256(string $data): string
    {
        return hash('sha3-256', $data, true);
    }

    /**
     * SM3 hash (GM/T 0004). Requires OpenSSL ≥ 3.0 with SM support.
     *
     * @throws CryptoException If SM3 is not supported by the OpenSSL build
     */
    public static function sm3(string $data): string
    {
        $result = hash('sm3', $data, true);
        if ($result === false) {
            throw new CryptoException('UNSUPPORTED_ALGORITHM', 'SM3 requires OpenSSL ≥ 3.0 with SM support');
        }
        return $result;
    }

    /**
     * Generate cryptographically secure random bytes.
     */
    public static function randomBytes(int $length): string
    {
        return random_bytes($length);
    }

    /**
     * Constant-time string comparison (prevents timing attacks).
     */
    public static function timingSafeEqual(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }

    /**
     * HKDF-SHA256 (RFC 5869).
     */
    public static function hkdfSha256(string $ikm, int $length, string $salt = '', string $info = ''): string
    {
        // Extract
        if ($salt === '') {
            $salt = str_repeat("\x00", 32);
        }
        $prk = hash_hmac('sha256', $ikm, $salt, true);

        // Expand
        $out  = '';
        $prev = '';
        for ($i = 1; strlen($out) < $length; $i++) {
            $prev = hash_hmac('sha256', $prev . $info . chr($i), $prk, true);
            $out .= $prev;
        }

        return substr($out, 0, $length);
    }
}

/**
 * CryptoException — wraps cryptographic errors with a code.
 */
class CryptoException extends RuntimeException
{
    public function __construct(
        public readonly string $code,
        string $message,
    ) {
        parent::__construct("[{$code}] {$message}");
    }
}
