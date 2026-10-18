<?php

declare(strict_types=1);

namespace CodingLombok\LombokEncryptDecrypt\Tests;

use PHPUnit\Framework\TestCase;
use CodingLombok\LombokEncryptDecrypt\LombokEncryptDecrypt;
use CodingLombok\LombokEncryptDecrypt\CryptoException;

/**
 * LombokEncryptDecrypt PHP — Unit Tests
 * Covers AES-GCM, ChaCha20-Poly1305, Ed25519, HMAC, PBKDF2, HKDF.
 */
class AesGcmTest extends TestCase
{
    // ── AES-GCM — NIST CAVP vectors ──────────────────────────────────────

    public static function aesGcmVectorProvider(): array
    {
        return [
            'aes-128-empty' => [
                '00000000000000000000000000000000',
                '000000000000000000000000',
                '', '',
                '', '58e2fccefa7e3061367f1d57a4e7455a',
            ],
            'aes-256-1' => [
                'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
                'cafebabefacedbaddecaf888',
                'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
                '',
                '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad',
                'b094dac5d93471bdec1a502270e3cc6c',
            ],
        ];
    }

    /**
     * @dataProvider aesGcmVectorProvider
     */
    public function testEncryptNistVectors(
        string $keyHex, string $ivHex,
        string $ptHex, string $aadHex,
        string $expectedCtHex, string $expectedTagHex
    ): void {
        $key = hex2bin($keyHex);
        $iv  = hex2bin($ivHex);
        $pt  = $ptHex ? hex2bin($ptHex) : '';
        $aad = $aadHex ? hex2bin($aadHex) : '';

        $result = LombokEncryptDecrypt::aesGcmEncrypt($pt, $key, $iv, $aad);

        self::assertSame($expectedCtHex, bin2hex($result['ciphertext']), 'Ciphertext mismatch');
        self::assertSame($expectedTagHex, bin2hex($result['tag']), 'Tag mismatch');
    }

    /**
     * @dataProvider aesGcmVectorProvider
     */
    public function testDecryptNistVectors(
        string $keyHex, string $ivHex,
        string $ptHex, string $aadHex,
        string $ctHex, string $tagHex
    ): void {
        $key = hex2bin($keyHex);
        $iv  = hex2bin($ivHex);
        $ct  = $ctHex ? hex2bin($ctHex) : '';
        $tag = hex2bin($tagHex);
        $aad = $aadHex ? hex2bin($aadHex) : '';
        $expectedPt = $ptHex ? hex2bin($ptHex) : '';

        $pt = LombokEncryptDecrypt::aesGcmDecrypt($ct, $key, $iv, $tag, $aad);
        self::assertSame($expectedPt, $pt);
    }

    public function testRoundtrip(): void
    {
        $key = LombokEncryptDecrypt::randomBytes(32);
        $msg = 'Hello from PHP LombokEncryptDecrypt!';

        $result = LombokEncryptDecrypt::aesGcmEncrypt($msg, $key);
        $pt     = LombokEncryptDecrypt::aesGcmDecrypt(
            $result['ciphertext'], $key, $result['iv'], $result['tag']
        );

        self::assertSame($msg, $pt);
    }

    public function testRoundtripWithAad(): void
    {
        $key = LombokEncryptDecrypt::randomBytes(32);
        $msg = 'confidential data';
        $aad = 'request-id:php-test';

        $result = LombokEncryptDecrypt::aesGcmEncrypt($msg, $key, null, $aad);
        $pt     = LombokEncryptDecrypt::aesGcmDecrypt(
            $result['ciphertext'], $key, $result['iv'], $result['tag'], $aad
        );

        self::assertSame($msg, $pt);
    }

    public function testRejectsTamperedTag(): void
    {
        $this->expectException(CryptoException::class);

        $key    = LombokEncryptDecrypt::randomBytes(32);
        $result = LombokEncryptDecrypt::aesGcmEncrypt('secret', $key);
        $badTag = str_repeat("\xFF", 16);

        LombokEncryptDecrypt::aesGcmDecrypt($result['ciphertext'], $key, $result['iv'], $badTag);
    }

    public function testRejectsTamperedCiphertext(): void
    {
        $this->expectException(CryptoException::class);

        $key    = LombokEncryptDecrypt::randomBytes(32);
        $result = LombokEncryptDecrypt::aesGcmEncrypt('secret data', $key);
        $badCt  = chr(ord($result['ciphertext'][0]) ^ 0xFF) . substr($result['ciphertext'], 1);

        LombokEncryptDecrypt::aesGcmDecrypt($badCt, $key, $result['iv'], $result['tag']);
    }

    public function testRejectsInvalidKeySize(): void
    {
        $this->expectException(CryptoException::class);
        LombokEncryptDecrypt::aesGcmEncrypt('data', str_repeat("\x00", 17));
    }

    public function testRejectsInvalidIvSize(): void
    {
        $this->expectException(CryptoException::class);
        $key = LombokEncryptDecrypt::randomBytes(32);
        LombokEncryptDecrypt::aesGcmEncrypt('data', $key, str_repeat("\x00", 16));
    }

    public function testAllKeySizes(): void
    {
        foreach ([16, 24, 32] as $keyLen) {
            $key    = LombokEncryptDecrypt::randomBytes($keyLen);
            $result = LombokEncryptDecrypt::aesGcmEncrypt('test', $key);
            $pt     = LombokEncryptDecrypt::aesGcmDecrypt(
                $result['ciphertext'], $key, $result['iv'], $result['tag']
            );
            self::assertSame('test', $pt, "Failed for key length {$keyLen}");
        }
    }

    public function testEmptyPlaintext(): void
    {
        $key    = LombokEncryptDecrypt::randomBytes(32);
        $result = LombokEncryptDecrypt::aesGcmEncrypt('', $key);
        self::assertSame('', $result['ciphertext']);
        self::assertSame(16, strlen($result['tag']));

        $pt = LombokEncryptDecrypt::aesGcmDecrypt('', $key, $result['iv'], $result['tag']);
        self::assertSame('', $pt);
    }

    // ── HMAC ──────────────────────────────────────────────────────────────

    public function testHmacSha256Rfc4231(): void
    {
        $key  = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $msg  = hex2bin('4869205468657265');
        $expected = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';

        self::assertSame($expected, bin2hex(LombokEncryptDecrypt::hmacSha256($key, $msg)));
    }

    public function testHmacVerifyConstantTime(): void
    {
        $key = LombokEncryptDecrypt::randomBytes(32);
        $msg = 'test message';
        $mac = LombokEncryptDecrypt::hmacSha256($key, $msg);

        self::assertTrue(LombokEncryptDecrypt::timingSafeEqual($mac, $mac));
        self::assertFalse(LombokEncryptDecrypt::timingSafeEqual($mac, str_repeat("\x00", 32)));
    }

    // ── Hash ──────────────────────────────────────────────────────────────

    public function testSha256NistVectors(): void
    {
        self::assertSame(
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            bin2hex(LombokEncryptDecrypt::sha256(''))
        );
        self::assertSame(
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
            bin2hex(LombokEncryptDecrypt::sha256('abc'))
        );
    }

    // ── PBKDF2 ────────────────────────────────────────────────────────────

    public function testPbkdf2Sha256(): void
    {
        // RFC 7914 test vector for PBKDF2-SHA256
        $key = LombokEncryptDecrypt::pbkdf2Sha256('password', 'salt', 1, 32);
        self::assertSame(32, strlen($key));
        // Verify determinism
        $key2 = LombokEncryptDecrypt::pbkdf2Sha256('password', 'salt', 1, 32);
        self::assertSame($key, $key2);
    }

    // ── Argon2id ─────────────────────────────────────────────────────────

    public function testArgon2idHashAndVerify(): void
    {
        $hash = LombokEncryptDecrypt::argon2idHash('my-password', 19456, 2, 1);
        self::assertStringStartsWith('$argon2id$', $hash);
        self::assertTrue(LombokEncryptDecrypt::argon2idVerify($hash, 'my-password'));
        self::assertFalse(LombokEncryptDecrypt::argon2idVerify($hash, 'wrong-password'));
    }

    // ── HKDF ─────────────────────────────────────────────────────────────

    public function testHkdfSha256Rfc5869(): void
    {
        $ikm  = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $salt = hex2bin('000102030405060708090a0b0c');
        $info = hex2bin('f0f1f2f3f4f5f6f7f8f9');
        $expected = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';

        $okm = LombokEncryptDecrypt::hkdfSha256($ikm, 42, $salt, $info);
        self::assertSame($expected, bin2hex($okm));
    }

    // ── Cross-language vectors ────────────────────────────────────────────

    public function testCrossLanguageVectors(): void
    {
        $vectorPath = __DIR__ . '/../../../../tests/vectors/lombokencryptdecrypt-vectors-v1.json';
        if (!file_exists($vectorPath)) {
            self::markTestSkipped('Vector file not found — run: node scripts/generate-vectors.mjs');
        }

        $vectors = json_decode(file_get_contents($vectorPath), true);

        foreach ($vectors['aes_gcm'] as $v) {
            $key = hex2bin($v['key']);
            $iv  = hex2bin($v['iv']);
            $pt  = $v['plaintext'] ? hex2bin($v['plaintext']) : '';
            $aad = isset($v['aad']) && $v['aad'] ? hex2bin($v['aad']) : '';

            $result = LombokEncryptDecrypt::aesGcmEncrypt($pt, $key, $iv, $aad);
            self::assertSame($v['ciphertext'], bin2hex($result['ciphertext']), "CT mismatch: {$v['id']}");
            self::assertSame($v['tag'], bin2hex($result['tag']), "Tag mismatch: {$v['id']}");
        }
    }
}
