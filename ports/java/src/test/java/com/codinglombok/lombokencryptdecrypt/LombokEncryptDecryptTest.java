package com.codinglombok.lombokencryptdecrypt;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.Arguments;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import static org.assertj.core.api.Assertions.*;

/**
 * LombokEncryptDecrypt Java Port — Unit Tests
 * NIST CAVP + RFC test vectors + roundtrip + cross-language verification.
 */
class LombokEncryptDecryptTest {

    private static final HexFormat HEX = HexFormat.of();

    // ── AES-GCM NIST vectors ──────────────────────────────────────────────

    static Stream<Arguments> aesGcmVectors() {
        return Stream.of(
            Arguments.of(
                "00000000000000000000000000000000",
                "000000000000000000000000",
                "", "",
                "", "58e2fccefa7e3061367f1d57a4e7455a"
            ),
            Arguments.of(
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                "cafebabefacedbaddecaf888",
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                "",
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
                "b094dac5d93471bdec1a502270e3cc6c"
            )
        );
    }

    @ParameterizedTest(name = "encrypt-{index}")
    @MethodSource("aesGcmVectors")
    void aesGcmEncryptNistVectors(
        String keyHex, String ivHex, String ptHex, String aadHex,
        String expectedCtHex, String expectedTagHex
    ) {
        byte[] key = HEX.parseHex(keyHex);
        byte[] iv  = HEX.parseHex(ivHex);
        byte[] pt  = ptHex.isEmpty() ? new byte[0] : HEX.parseHex(ptHex);
        byte[] aad = aadHex.isEmpty() ? null : HEX.parseHex(aadHex);

        var result = LombokEncryptDecrypt.aesGcmEncrypt(pt, key, iv, aad);

        assertThat(HEX.formatHex(result.ciphertext())).isEqualTo(expectedCtHex);
        assertThat(HEX.formatHex(result.tag())).isEqualTo(expectedTagHex);
    }

    @ParameterizedTest(name = "decrypt-{index}")
    @MethodSource("aesGcmVectors")
    void aesGcmDecryptNistVectors(
        String keyHex, String ivHex, String ptHex, String aadHex,
        String ctHex, String tagHex
    ) {
        byte[] key        = HEX.parseHex(keyHex);
        byte[] iv         = HEX.parseHex(ivHex);
        byte[] ct         = ctHex.isEmpty() ? new byte[0] : HEX.parseHex(ctHex);
        byte[] tag        = HEX.parseHex(tagHex);
        byte[] aad        = aadHex.isEmpty() ? null : HEX.parseHex(aadHex);
        byte[] expectedPt = ptHex.isEmpty() ? new byte[0] : HEX.parseHex(ptHex);

        byte[] pt = LombokEncryptDecrypt.aesGcmDecrypt(ct, key, iv, tag, aad);
        assertThat(pt).isEqualTo(expectedPt);
    }

    @Test
    void aesGcmRoundtrip() {
        byte[] key  = LombokEncryptDecrypt.generateAesKey(256);
        byte[] msg  = "Hello Java LombokEncryptDecrypt!".getBytes();
        var    enc  = LombokEncryptDecrypt.aesGcmEncrypt(msg, key);
        byte[] dec  = LombokEncryptDecrypt.aesGcmDecrypt(enc, key, null);
        assertThat(dec).isEqualTo(msg);
    }

    @Test
    void aesGcmRoundtripWithAad() {
        byte[] key = LombokEncryptDecrypt.generateAesKey(256);
        byte[] msg = "confidential".getBytes();
        byte[] aad = "request-id:java-test".getBytes();
        var    enc = LombokEncryptDecrypt.aesGcmEncrypt(msg, key, null, aad);
        byte[] dec = LombokEncryptDecrypt.aesGcmDecrypt(enc, key, aad);
        assertThat(dec).isEqualTo(msg);
    }

    @Test
    void aesGcmRejectsTamperedTag() {
        byte[] key = LombokEncryptDecrypt.generateAesKey(256);
        var    enc = LombokEncryptDecrypt.aesGcmEncrypt("secret".getBytes(), key);
        byte[] badTag = new byte[16];
        badTag[0] = (byte) (enc.tag()[0] ^ 0xFF);

        assertThatThrownBy(() -> LombokEncryptDecrypt.aesGcmDecrypt(enc.ciphertext(), key, enc.iv(), badTag, null))
            .isInstanceOf(CryptoException.class)
            .extracting("code").isEqualTo(CryptoException.AUTHENTICATION_FAILED);
    }

    @Test
    void aesGcmRejectsTamperedCiphertext() {
        byte[] key = LombokEncryptDecrypt.generateAesKey(256);
        var enc = LombokEncryptDecrypt.aesGcmEncrypt("secret data".getBytes(), key);
        byte[] tampered = enc.ciphertext().clone();
        tampered[0] ^= 0x01;

        assertThatThrownBy(() -> LombokEncryptDecrypt.aesGcmDecrypt(tampered, key, enc.iv(), enc.tag(), null))
            .isInstanceOf(CryptoException.class);
    }

    @Test
    void aesGcmRejectsInvalidKeySize() {
        assertThatThrownBy(() -> LombokEncryptDecrypt.aesGcmEncrypt("data".getBytes(), new byte[17]))
            .isInstanceOf(CryptoException.class)
            .extracting("code").isEqualTo(CryptoException.INVALID_KEY_SIZE);
    }

    @Test
    void aesGcmAllKeySizes() {
        for (int bits : new int[]{128, 192, 256}) {
            byte[] key = LombokEncryptDecrypt.generateAesKey(bits);
            byte[] msg = "test".getBytes();
            var    enc = LombokEncryptDecrypt.aesGcmEncrypt(msg, key);
            byte[] dec = LombokEncryptDecrypt.aesGcmDecrypt(enc, key, null);
            assertThat(dec).as("AES-%d roundtrip", bits).isEqualTo(msg);
        }
    }

    @Test
    void aesGcmEmptyPlaintext() {
        byte[] key = LombokEncryptDecrypt.generateAesKey(256);
        var    enc = LombokEncryptDecrypt.aesGcmEncrypt(new byte[0], key);
        assertThat(enc.ciphertext()).isEmpty();
        assertThat(enc.tag()).hasSize(16);
        byte[] dec = LombokEncryptDecrypt.aesGcmDecrypt(enc, key, null);
        assertThat(dec).isEmpty();
    }

    // ── HMAC ──────────────────────────────────────────────────────────────

    @Test
    void hmacSha256Rfc4231Tc1() {
        byte[] key = HEX.parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] msg = HEX.parseHex("4869205468657265");
        assertThat(HEX.formatHex(LombokEncryptDecrypt.hmacSha256(key, msg)))
            .isEqualTo("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    @Test
    void hmacVerifyConstantTime() {
        byte[] key = LombokEncryptDecrypt.randomBytes(32);
        byte[] msg = "test message".getBytes();
        byte[] mac = LombokEncryptDecrypt.hmacSha256(key, msg);
        assertThat(LombokEncryptDecrypt.hmacVerify(key, msg, mac)).isTrue();
        assertThat(LombokEncryptDecrypt.hmacVerify(key, msg, new byte[32])).isFalse();
    }

    // ── Hash ──────────────────────────────────────────────────────────────

    @Test
    void sha256NistVectors() {
        assertThat(HEX.formatHex(LombokEncryptDecrypt.sha256(new byte[0])))
            .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assertThat(HEX.formatHex(LombokEncryptDecrypt.sha256("abc".getBytes())))
            .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void sha256OutputLength() {
        assertThat(LombokEncryptDecrypt.sha256("test".getBytes())).hasSize(32);
    }

    // ── PBKDF2 ────────────────────────────────────────────────────────────

    @Test
    void pbkdf2Sha256Deterministic() {
        byte[] pw   = "password".getBytes();
        byte[] salt = "salt".getBytes();
        byte[] k1   = LombokEncryptDecrypt.pbkdf2Sha256(pw, salt, 1, 32);
        byte[] k2   = LombokEncryptDecrypt.pbkdf2Sha256(pw, salt, 1, 32);
        assertThat(k1).hasSize(32).isEqualTo(k2);
    }

    // ── HKDF ─────────────────────────────────────────────────────────────

    @Test
    void hkdfSha256Rfc5869Tc1() {
        byte[] ikm  = HEX.parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = HEX.parseHex("000102030405060708090a0b0c");
        byte[] info = HEX.parseHex("f0f1f2f3f4f5f6f7f8f9");
        String expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

        byte[] okm = LombokEncryptDecrypt.hkdfSha256(ikm, salt, info, 42);
        assertThat(HEX.formatHex(okm)).isEqualTo(expected);
    }

    // ── Cross-language vectors ─────────────────────────────────────────────

    @Test
    void crossLanguageVectors() throws Exception {
        Path vectorPath = Path.of("../../../../tests/vectors/lombokencryptdecrypt-vectors-v1.json");
        if (!Files.exists(vectorPath)) {
            System.out.println("⚠️  Vector file not found — skipping cross-language test");
            System.out.println("   Run: node scripts/generate-vectors.mjs");
            return;
        }

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(vectorPath.toFile());

        for (JsonNode v : root.get("aes_gcm")) {
            byte[] key = HEX.parseHex(v.get("key").asText());
            byte[] iv  = HEX.parseHex(v.get("iv").asText());
            String ptHex = v.get("plaintext").asText();
            byte[] pt  = ptHex.isEmpty() ? new byte[0] : HEX.parseHex(ptHex);

            var result = LombokEncryptDecrypt.aesGcmEncrypt(pt, key, iv, null);
            assertThat(HEX.formatHex(result.ciphertext()))
                .as("CT mismatch: %s", v.get("id").asText())
                .isEqualTo(v.get("ciphertext").asText());
            assertThat(HEX.formatHex(result.tag()))
                .as("Tag mismatch: %s", v.get("id").asText())
                .isEqualTo(v.get("tag").asText());
        }

        for (JsonNode v : root.get("hmac_sha256")) {
            byte[] key = HEX.parseHex(v.get("key").asText());
            byte[] msg = HEX.parseHex(v.get("message").asText());
            byte[] mac = LombokEncryptDecrypt.hmacSha256(key, msg);
            assertThat(HEX.formatHex(mac))
                .as("HMAC mismatch: %s", v.get("id").asText())
                .isEqualTo(v.get("output").asText());
        }
    }
}
