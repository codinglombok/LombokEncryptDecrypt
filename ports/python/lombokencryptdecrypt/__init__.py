"""
LombokEncryptDecrypt — Python port
Universal encrypt/decrypt library: AES/ChaCha20/Kyber/Dilithium/SPHINCS+/SM2/SM3/SM4
License: Apache-2.0 | Author: codinglombok
"""

from __future__ import annotations
import os
from typing import Optional

__version__ = "0.1.0"
__author__ = "codinglombok"
__license__ = "Apache-2.0"

# Try to import the Rust core (PyO3 maturin build)
try:
    from lombokencryptdecrypt._core import (
        aes_gcm_encrypt as _aes_gcm_encrypt,
        aes_gcm_decrypt as _aes_gcm_decrypt,
        chacha20_poly1305_encrypt as _chacha_encrypt,
        chacha20_poly1305_decrypt as _chacha_decrypt,
        ed25519_generate_keypair as _ed25519_keygen,
        ed25519_sign as _ed25519_sign,
        ed25519_verify as _ed25519_verify,
        kyber768_generate_keypair as _kyber768_keygen,
        kyber768_encapsulate as _kyber768_encap,
        kyber768_decapsulate as _kyber768_decap,
        argon2id_hash as _argon2id_hash,
        argon2id_verify as _argon2id_verify,
        hmac_sha256 as _hmac_sha256,
        hkdf_sha256 as _hkdf_sha256,
        sha256 as _sha256,
        sha3_256 as _sha3_256,
        blake3 as _blake3,
        sm3 as _sm3,
        sm4_gcm_encrypt as _sm4_gcm_encrypt,
        sm4_gcm_decrypt as _sm4_gcm_decrypt,
    )
    _RUST_CORE = True
except ImportError:
    _RUST_CORE = False


class LombokCryptoError(Exception):
    """Raised on cryptographic errors (authentication failure, invalid key, etc.)"""
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ── AES-GCM ──────────────────────────────────────────────────────────────

class AesGcm:
    """AES-256-GCM authenticated encryption (NIST SP 800-38D)."""

    @staticmethod
    def encrypt(
        plaintext: bytes,
        key: bytes,
        iv: Optional[bytes] = None,
        aad: Optional[bytes] = None,
        tag_length: int = 16,
    ) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt with AES-GCM.

        Args:
            plaintext: Data to encrypt
            key: 16, 24, or 32 byte AES key
            iv: 12-byte nonce (random if None)
            aad: Additional authenticated data
            tag_length: Authentication tag length (default 16)

        Returns:
            Tuple of (ciphertext, tag, iv)

        Raises:
            LombokCryptoError: On invalid key size
        """
        if len(key) not in (16, 24, 32):
            raise LombokCryptoError("INVALID_KEY_SIZE", f"AES key must be 16/24/32 bytes, got {len(key)}")
        if iv is None:
            iv = os.urandom(12)
        if len(iv) != 12:
            raise LombokCryptoError("INVALID_IV_SIZE", f"AES-GCM IV must be 12 bytes, got {len(iv)}")

        if _RUST_CORE:
            ct, tag = _aes_gcm_encrypt(plaintext, key, iv, aad or b"", tag_length)
            return ct, tag, iv

        # Fallback: Python cryptography library
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        combined = aesgcm.encrypt(iv, plaintext, aad)
        ciphertext, tag = combined[:-tag_length], combined[-tag_length:]
        return ciphertext, tag, iv

    @staticmethod
    def decrypt(
        ciphertext: bytes,
        key: bytes,
        iv: bytes,
        tag: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt and verify AES-GCM ciphertext.

        Raises:
            LombokCryptoError: On authentication failure
        """
        if _RUST_CORE:
            try:
                return _aes_gcm_decrypt(ciphertext, key, iv, tag, aad or b"")
            except Exception as e:
                raise LombokCryptoError("AUTHENTICATION_FAILED", str(e)) from e

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            return AESGCM(key).decrypt(iv, ciphertext + tag, aad)
        except Exception as e:
            raise LombokCryptoError("AUTHENTICATION_FAILED", "AES-GCM authentication failed") from e

    @staticmethod
    def generate_key(bits: int = 256) -> bytes:
        """Generate a random AES key (128, 192, or 256 bits)."""
        return os.urandom(bits // 8)

    @staticmethod
    def generate_iv() -> bytes:
        """Generate a random 96-bit IV."""
        return os.urandom(12)


# ── ChaCha20-Poly1305 ────────────────────────────────────────────────────

class ChaCha20Poly1305:
    """ChaCha20-Poly1305 authenticated encryption (RFC 8439)."""

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, nonce: Optional[bytes] = None, aad: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
        if len(key) != 32:
            raise LombokCryptoError("INVALID_KEY_SIZE", f"ChaCha20 key must be 32 bytes, got {len(key)}")
        if nonce is None:
            nonce = os.urandom(12)
        if _RUST_CORE:
            ct, tag = _chacha_encrypt(plaintext, key, nonce, aad or b"")
            return ct, tag, nonce
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as CryptoChaCha
        combined = CryptoChaCha(key).encrypt(nonce, plaintext, aad)
        return combined[:-16], combined[-16:], nonce

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, aad: Optional[bytes] = None) -> bytes:
        if _RUST_CORE:
            try:
                return _chacha_decrypt(ciphertext, key, nonce, tag, aad or b"")
            except Exception as e:
                raise LombokCryptoError("AUTHENTICATION_FAILED", str(e)) from e
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as CryptoChaCha
        try:
            return CryptoChaCha(key).decrypt(nonce, ciphertext + tag, aad)
        except Exception as e:
            raise LombokCryptoError("AUTHENTICATION_FAILED", "ChaCha20-Poly1305 authentication failed") from e

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(32)


# ── Ed25519 ───────────────────────────────────────────────────────────────

class Ed25519:
    """Ed25519 digital signatures (RFC 8032, NIST FIPS 186-5)."""

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Returns (private_key_seed, public_key) — both 32 bytes."""
        if _RUST_CORE:
            return _ed25519_keygen()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.generate()
        seed = priv.private_bytes_raw()
        pub  = priv.public_key().public_bytes_raw()
        return seed, pub

    @staticmethod
    def sign(message: bytes, private_key: bytes) -> bytes:
        """Sign message. Returns 64-byte signature."""
        if _RUST_CORE:
            return _ed25519_sign(message, private_key)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
        priv = Ed25519PrivateKey.from_private_bytes(private_key)
        return priv.sign(message)

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature. Returns True if valid."""
        if _RUST_CORE:
            return _ed25519_verify(message, signature, public_key)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except Exception:
            return False


# ── Kyber768 (ML-KEM-768) ─────────────────────────────────────────────────

class Kyber768:
    """ML-KEM-768 post-quantum KEM (NIST FIPS 203)."""

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Returns (public_key: 1184 bytes, secret_key: 2400 bytes)."""
        if _RUST_CORE:
            return _kyber768_keygen()
        raise LombokCryptoError("UNSUPPORTED_ALGORITHM", "Kyber768 requires the Rust core build")

    @staticmethod
    def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext: 1088 bytes, shared_secret: 32 bytes)."""
        if _RUST_CORE:
            return _kyber768_encap(public_key)
        raise LombokCryptoError("UNSUPPORTED_ALGORITHM", "Kyber768 requires the Rust core build")

    @staticmethod
    def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
        """Returns shared_secret: 32 bytes."""
        if _RUST_CORE:
            return _kyber768_decap(ciphertext, secret_key)
        raise LombokCryptoError("UNSUPPORTED_ALGORITHM", "Kyber768 requires the Rust core build")


# ── Argon2id ──────────────────────────────────────────────────────────────

class Argon2id:
    """Argon2id password hashing (RFC 9106, NIST SP 800-63B)."""

    @staticmethod
    def hash(password: str | bytes, m: int = 65536, t: int = 3, p: int = 4) -> str:
        """Hash password. Returns PHC string format."""
        pw = password.encode() if isinstance(password, str) else password
        if _RUST_CORE:
            return _argon2id_hash(pw, m, t, p)
        from argon2 import PasswordHasher
        ph = PasswordHasher(memory_cost=m, time_cost=t, parallelism=p)
        return ph.hash(pw)

    @staticmethod
    def verify(phc_hash: str, password: str | bytes) -> bool:
        """Verify password against PHC hash. Constant-time."""
        pw = password.encode() if isinstance(password, str) else password
        if _RUST_CORE:
            return _argon2id_verify(phc_hash, pw)
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError
        try:
            PasswordHasher().verify(phc_hash, pw)
            return True
        except VerifyMismatchError:
            return False


# ── Hash functions ────────────────────────────────────────────────────────

def sha256(data: bytes) -> bytes:
    """SHA-256 hash (NIST FIPS 180-4)."""
    if _RUST_CORE:
        return _sha256(data)
    import hashlib
    return hashlib.sha256(data).digest()

def sha3_256(data: bytes) -> bytes:
    """SHA3-256 hash (NIST FIPS 202)."""
    if _RUST_CORE:
        return _sha3_256(data)
    import hashlib
    return hashlib.sha3_256(data).digest()

def blake3(data: bytes) -> bytes:
    """BLAKE3 hash."""
    if _RUST_CORE:
        return _blake3(data)
    import blake3 as b3
    return b3.blake3(data).digest()

def sm3(data: bytes) -> bytes:
    """SM3 hash (GM/T 0004)."""
    if _RUST_CORE:
        return _sm3(data)
    raise LombokCryptoError("UNSUPPORTED_ALGORITHM", "SM3 requires the Rust core build")

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 (RFC 2104)."""
    if _RUST_CORE:
        return _hmac_sha256(key, message)
    import hmac, hashlib
    return hmac.new(key, message, hashlib.sha256).digest()

def hkdf_sha256(ikm: bytes, length: int, salt: Optional[bytes] = None, info: bytes = b"") -> bytes:
    """HKDF-SHA256 key derivation (RFC 5869)."""
    if _RUST_CORE:
        return _hkdf_sha256(ikm, length, salt or b"", info)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


# ── Module-level convenience instances ───────────────────────────────────

aes_gcm = AesGcm()
chacha20_poly1305 = ChaCha20Poly1305()
ed25519 = Ed25519()
kyber768 = Kyber768()
argon2id = Argon2id()

__all__ = [
    "__version__", "LombokCryptoError",
    "AesGcm", "aes_gcm",
    "ChaCha20Poly1305", "chacha20_poly1305",
    "Ed25519", "ed25519",
    "Kyber768", "kyber768",
    "Argon2id", "argon2id",
    "sha256", "sha3_256", "blake3", "sm3",
    "hmac_sha256", "hkdf_sha256",
]
