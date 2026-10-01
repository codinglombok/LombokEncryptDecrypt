"""
LombokEncryptDecrypt — Python port tests: AES-GCM + ChaCha20 + Ed25519 + HMAC
"""

import pytest
import os
import json
from pathlib import Path

from lombokencryptdecrypt import (
    AesGcm, ChaCha20Poly1305, Ed25519, Argon2id,
    sha256, sha3_256, hmac_sha256, hkdf_sha256,
    LombokCryptoError,
)


def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def bytes_to_hex(b: bytes) -> str:
    return b.hex()


# ── AES-GCM — NIST CAVP vectors ───────────────────────────────────────────

AES_GCM_VECTORS = [
    {
        "key":        "00000000000000000000000000000000",
        "iv":         "000000000000000000000000",
        "plaintext":  "",
        "aad":        "",
        "ciphertext": "",
        "tag":        "58e2fccefa7e3061367f1d57a4e7455a",
    },
    {
        "key":        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "iv":         "cafebabefacedbaddecaf888",
        "plaintext":  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "aad":        "",
        "ciphertext": "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        "tag":        "b094dac5d93471bdec1a502270e3cc6c",
    },
]

class TestAesGcm:
    @pytest.mark.parametrize("v", AES_GCM_VECTORS)
    def test_encrypt_nist_vectors(self, v):
        key = hex_to_bytes(v["key"])
        iv  = hex_to_bytes(v["iv"])
        pt  = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
        aad = bytes.fromhex(v["aad"]) if v["aad"] else None

        ct, tag, actual_iv = AesGcm.encrypt(pt, key, iv=iv, aad=aad)
        assert ct.hex() == v["ciphertext"], f"Ciphertext mismatch"
        assert tag.hex() == v["tag"], f"Tag mismatch"
        assert actual_iv == iv

    @pytest.mark.parametrize("v", AES_GCM_VECTORS)
    def test_decrypt_nist_vectors(self, v):
        key = hex_to_bytes(v["key"])
        iv  = hex_to_bytes(v["iv"])
        ct  = bytes.fromhex(v["ciphertext"]) if v["ciphertext"] else b""
        tag = bytes.fromhex(v["tag"])
        aad = bytes.fromhex(v["aad"]) if v["aad"] else None
        expected_pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""

        pt = AesGcm.decrypt(ct, key, iv, tag, aad=aad)
        assert pt == expected_pt

    def test_roundtrip_random(self):
        key = AesGcm.generate_key(bits=256)
        assert len(key) == 32
        message = b"Hello from Python LombokEncryptDecrypt!"
        ct, tag, iv = AesGcm.encrypt(message, key)
        pt = AesGcm.decrypt(ct, key, iv, tag)
        assert pt == message

    def test_roundtrip_with_aad(self):
        key = AesGcm.generate_key()
        msg = b"confidential"
        aad = b"user-id:42"
        ct, tag, iv = AesGcm.encrypt(msg, key, aad=aad)
        pt = AesGcm.decrypt(ct, key, iv, tag, aad=aad)
        assert pt == msg

    def test_reject_tampered_tag(self):
        key = AesGcm.generate_key()
        ct, tag, iv = AesGcm.encrypt(b"secret", key)
        bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        with pytest.raises(LombokCryptoError) as exc:
            AesGcm.decrypt(ct, key, iv, bad_tag)
        assert exc.value.code == "AUTHENTICATION_FAILED"

    def test_reject_invalid_key_size(self):
        with pytest.raises(LombokCryptoError) as exc:
            AesGcm.encrypt(b"data", b"\x00" * 17)
        assert exc.value.code == "INVALID_KEY_SIZE"

    def test_random_iv_uniqueness(self):
        iv1 = AesGcm.generate_iv()
        iv2 = AesGcm.generate_iv()
        assert iv1 != iv2
        assert len(iv1) == 12

    def test_all_key_sizes(self):
        for bits in [128, 192, 256]:
            key = AesGcm.generate_key(bits=bits)
            assert len(key) == bits // 8
            ct, tag, iv = AesGcm.encrypt(b"test", key)
            pt = AesGcm.decrypt(ct, key, iv, tag)
            assert pt == b"test"


# ── Ed25519 ───────────────────────────────────────────────────────────────

class TestEd25519:
    def test_generate_keypair(self):
        priv, pub = Ed25519.generate_keypair()
        assert len(priv) == 32 or len(priv) == 64  # seed or full key
        assert len(pub) == 32

    def test_sign_verify_roundtrip(self):
        priv, pub = Ed25519.generate_keypair()
        msg = b"LombokEncryptDecrypt Ed25519 test"
        sig = Ed25519.sign(msg, priv)
        assert len(sig) == 64
        assert Ed25519.verify(msg, sig, pub) is True

    def test_reject_tampered_signature(self):
        priv, pub = Ed25519.generate_keypair()
        msg = b"test"
        sig = Ed25519.sign(msg, priv)
        bad = bytes([sig[0] ^ 0x01]) + sig[1:]
        assert Ed25519.verify(msg, bad, pub) is False

    def test_reject_wrong_public_key(self):
        priv1, _    = Ed25519.generate_keypair()
        _,     pub2 = Ed25519.generate_keypair()
        msg = b"test"
        sig = Ed25519.sign(msg, priv1)
        assert Ed25519.verify(msg, sig, pub2) is False


# ── Hash ──────────────────────────────────────────────────────────────────

class TestHash:
    def test_sha256_empty(self):
        h = sha256(b"")
        assert h.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_sha256_abc(self):
        h = sha256(b"abc")
        assert h.hex() == "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f490f67c94c0ca2b"

    def test_sha256_output_length(self):
        assert len(sha256(b"test")) == 32

    def test_hmac_sha256_rfc4231_tc1(self):
        key = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        msg = bytes.fromhex("4869205468657265")
        mac = hmac_sha256(key, msg)
        assert mac.hex() == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

    def test_hkdf_sha256_rfc5869_tc1(self):
        ikm  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm  = hkdf_sha256(ikm, 42, salt=salt, info=info)
        expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        assert okm.hex() == expected


# ── Cross-language vectors ────────────────────────────────────────────────

class TestCrossLanguageVectors:
    VECTORS_PATH = Path(__file__).parent.parent.parent.parent / "tests/vectors/lombokencryptdecrypt-vectors-v1.json"

    @pytest.fixture(autouse=True)
    def load_vectors(self):
        if self.VECTORS_PATH.exists():
            with open(self.VECTORS_PATH) as f:
                self.vectors = json.load(f)
        else:
            pytest.skip("Vector file not found — run: node scripts/generate-vectors.mjs")

    def test_aes_gcm_vectors(self):
        for v in self.vectors.get("aes_gcm", []):
            key = hex_to_bytes(v["key"])
            iv  = hex_to_bytes(v["iv"])
            pt  = hex_to_bytes(v["plaintext"]) if v["plaintext"] else b""
            aad = hex_to_bytes(v["aad"]) if v.get("aad") else None
            ct, tag, _ = AesGcm.encrypt(pt, key, iv=iv, aad=aad)
            assert ct.hex() == v["ciphertext"], f"AES-GCM CT mismatch for {v['id']}"
            assert tag.hex() == v["tag"], f"AES-GCM tag mismatch for {v['id']}"

    def test_hmac_sha256_vectors(self):
        for v in self.vectors.get("hmac_sha256", []):
            key = hex_to_bytes(v["key"])
            msg = hex_to_bytes(v["message"])
            mac = hmac_sha256(key, msg)
            assert mac.hex() == v["output"], f"HMAC mismatch for {v['id']}"
