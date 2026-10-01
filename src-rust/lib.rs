// LombokEncryptDecrypt — Rust Core
// Reference implementation + SIMD-accelerated inner loops
// License: Apache-2.0

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
)]
#![allow(clippy::module_name_repetitions)]

//! # LombokEncryptDecrypt
//!
//! Universal encrypt/decrypt library — AES/ChaCha20/Kyber/Dilithium/SPHINCS+/SM2/SM3/SM4.
//! Post-quantum ready, FIPS 140-3 algorithm set, 12 language ports.
//!
//! ## Feature flags
//!
//! - `std` (default): enable standard library
//! - `no_std`: embedded / bare-metal targets
//! - `aes-ni`: AES-NI intrinsics (x86/x86_64)
//! - `sha-ni`: SHA-NI intrinsics (x86/x86_64)
//! - `avx2`: AVX2 SIMD (ChaCha20, BLAKE3, Kyber NTT)
//! - `neon`: ARM NEON SIMD
//! - `post_quantum`: ML-KEM, ML-DSA, SLH-DSA, FALCON
//! - `napi`: Node.js NAPI-RS bindings
//! - `wasm`: wasm-pack browser bindings
//! - `python`: PyO3 Python bindings
//! - `fips`: enforce FIPS 140-3 algorithm set
//! - `legacy`: enable legacy algorithms (MD5, SHA-1, RC4)
//! - `full`: all stable features

#[cfg(not(any(feature = "std", feature = "no_std")))]
compile_error!("Either 'std' or 'no_std' feature must be enabled");

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc;

// ── Public modules ────────────────────────────────────────────────────────

/// AES-128/192/256 (FIPS 197) with optional AES-NI acceleration
pub mod aes;

/// ChaCha20-Poly1305 and XChaCha20-Poly1305 (RFC 8439)
pub mod chacha20;

/// SHA-2 (FIPS 180-4) with optional SHA-NI acceleration
pub mod sha2;

/// SHA-3 / SHAKE (FIPS 202) — Keccak sponge
pub mod sha3;

/// BLAKE2b, BLAKE2s (RFC 7693), BLAKE3
pub mod blake;

/// SM2 ECC (GM/T 0003), SM3 hash (GM/T 0004), SM4 (GM/T 0002)
pub mod sm;

/// ZUC stream cipher (ETSI TS 135 222, 3GPP LTE/5G)
pub mod zuc;

/// SNOW 3G stream cipher (ETSI TS 135 202)
pub mod snow3g;

/// Camellia-128/192/256 (RFC 3713)
pub mod camellia;

/// AES modes: GCM, CCM, EAX, OCB3, SIV, XTS, FPE-FF1, FPE-FF3
pub mod modes;

/// HMAC, CMAC, Poly1305, GMAC, SipHash, BLAKE3-MAC, KMAC
pub mod mac;

/// PBKDF2, scrypt, Argon2id/i/d, bcrypt, HKDF, X9.63, SP800-56C, BIP32
pub mod kdf;

/// RSA-OAEP, RSA-PSS, RSA key generation
pub mod rsa;

/// ECDH (P-256/384/521/X25519/X448), ECDSA, Ed25519, Ed448
pub mod ecc;

/// ECIES, HPKE (RFC 9180), IES, Envelope Encryption
pub mod hybrid;

#[cfg(feature = "post_quantum")]
#[cfg_attr(docsrs, doc(cfg(feature = "post_quantum")))]
/// ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), FALCON, BIKE, HQC
pub mod pq;

/// Key Management: KeyStore, KeyRing, JWK, PEM, PKCS#12, X.509
pub mod keystore;

/// Streaming AEAD encrypt/decrypt (unlimited file size)
pub mod stream;

/// Constant-time utilities: timingSafeEqual, zeroize, blinding
pub mod ct;

/// Random number generation (getrandom + DRBG)
pub mod rng;

/// Platform detection and SIMD capability probing
pub mod platform;

/// Audit logging with LombokECC RS(255,239) integrity
pub mod audit;

// ── NAPI-RS bindings (Node.js) ────────────────────────────────────────────
#[cfg(feature = "napi")]
#[cfg_attr(docsrs, doc(cfg(feature = "napi")))]
mod napi_bindings;

// ── WASM bindings ─────────────────────────────────────────────────────────
#[cfg(feature = "wasm")]
#[cfg_attr(docsrs, doc(cfg(feature = "wasm")))]
mod wasm_bindings;

// ── Python bindings ───────────────────────────────────────────────────────
#[cfg(feature = "python")]
#[cfg_attr(docsrs, doc(cfg(feature = "python")))]
mod python_bindings;

// ── Version ───────────────────────────────────────────────────────────────

/// Library version string
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const LIBRARY_NAME: &str = "LombokEncryptDecrypt";

// ── Capability detection ──────────────────────────────────────────────────

/// Returns true if AES-NI is available and enabled
#[must_use]
pub fn has_aes_ni() -> bool {
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    {
        is_x86_feature_detected!("aes") && is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(not(all(feature = "aes-ni", target_arch = "x86_64")))]
    false
}

/// Returns true if SHA-NI is available and enabled
#[must_use]
pub fn has_sha_ni() -> bool {
    #[cfg(all(feature = "sha-ni", target_arch = "x86_64"))]
    { is_x86_feature_detected!("sha") }
    #[cfg(not(all(feature = "sha-ni", target_arch = "x86_64")))]
    false
}

/// Returns true if AVX2 is available
#[must_use]
pub fn has_avx2() -> bool {
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    { is_x86_feature_detected!("avx2") }
    #[cfg(not(all(feature = "avx2", target_arch = "x86_64")))]
    false
}

/// Returns true if ARM NEON is available
#[must_use]
pub fn has_neon() -> bool {
    #[cfg(all(feature = "neon", target_arch = "aarch64"))]
    { std::arch::is_aarch64_feature_detected!("neon") }
    #[cfg(not(all(feature = "neon", target_arch = "aarch64")))]
    false
}
