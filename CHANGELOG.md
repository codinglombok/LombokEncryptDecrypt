# CHANGELOG — LombokEncryptDecrypt

All notable changes to this project will be documented in this file.  
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — SemVer.

---

## [Unreleased]

### Added
- ECDSA P-256/384/521 via WebCrypto (fails closed without it), interop-tested with OpenSSL both directions.
- BLAKE3 (pure TS, verified against the reference implementation, incl. multi-chunk trees, keyed, derive_key, XOF).
- AES block decrypt, AES-CBC/ECB, SHA-384/512, `legacy` namespace (MD5, RC4, AES-ECB); `tests/unit/pdf_primitives.test.ts`; vectors for them (OpenSSL / published). Merged from the GitHub main branch and completed (`decryptBlock` was missing there, so it did not compile).

### Corrected (honesty pass, supersedes the 0.1.0 "Initial Release" claims below)
- Only the items in docs/IMPLEMENTATION_STATUS.md are implemented; the 0.1.0 list below describes planned scope.
- Removed fake crypto (Argon2, Kyber, audit parity); they now fail closed with UNSUPPORTED_ALGORITHM.
- Fixed XChaCha20 (HChaCha20), SHA-3 rotation/padding, streaming (ordering, truncation), KeyStore (v2 format, scrypt KDF).
- Added scrypt, CMAC; real exports in src/index.ts and subpath entry points; vectors now generated from OpenSSL.
- Fixed mistyped SHA-256/HMAC vectors in Go/PHP/Java/Python port tests (ports still not run).

## [0.1.0] — 2026-09-18

### Added — Initial Release

#### Core Engine (TypeScript-first, Rust-core)
- **Symmetric Ciphers:** AES-128/192/256-GCM, AES-CBC/CTR, ChaCha20-Poly1305, XChaCha20-Poly1305, Salsa20, Camellia-256, SM4
- **Asymmetric Cryptography:** RSA-OAEP (2048/4096), ECDH (P-256/P-384/P-521/X25519/X448), ECIES, SM2
- **Digital Signatures:** ECDSA (P-256/P-384/P-521), Ed25519, Ed448, RSA-PSS, RSA-PKCS1v15, SM2-Sign
- **Post-Quantum Cryptography (NIST PQC):** Kyber-512/768/1024 (ML-KEM), Dilithium-2/3/5 (ML-DSA), SPHINCS+, FALCON-512/1024, BIKE, HQC, Classic McEliece
- **Key Derivation:** PBKDF2 (SHA-256/512), scrypt, Argon2id/Argon2i/Argon2d, bcrypt, HKDF, X9.42, SP 800-56C
- **MAC / Integrity:** HMAC (SHA-1/256/512), CMAC (AES), Poly1305, GMAC, SipHash-2-4/4-8, BLAKE3-MAC
- **Hash Functions:** SHA-2 (224/256/384/512), SHA-3 (224/256/384/512), SHAKE-128/256, BLAKE2b/2s, BLAKE3, SM3, Whirlpool, MD5 (legacy), SHA-1 (legacy)
- **Stream Ciphers:** RC4 (legacy-only), ChaCha20 (standalone), ZUC (LTE/5G), SNOW 3G
- **Block Cipher Modes:** ECB, CBC, CFB (8/128), OFB, CTR, GCM, CCM, EAX, OCB3, SIV, XTS (disk encryption)
- **Hybrid Encryption:** ECIES, IES, HPKE (RFC 9180), RSA-KEM
- **Format-Preserving Encryption:** FF1 (NIST SP 800-38G), FF3-1
- **Authenticated Encryption with Key Wrap:** AES-KEYWRAP (RFC 3394), AES-KEYWRAP-PAD (RFC 5649)
- **Envelope Encryption:** Multi-layer KEK/DEK pattern, AWS-KMS/GCP-KMS/Azure-KV compatible API
- **Hardware Security Module (HSM) Interface:** PKCS#11 bridge, TPM 2.0 bridge, Secure Enclave (Apple), Android Keystore, Intel SGX stub
- **Side-Channel Resistance:** Constant-time comparison, masked arithmetic, blinding, timing-safe implementations
- **Audit Logging:** Every crypto operation logged with timestamp, algorithm, key-id, result — immutable append-only via LombokECC RS(255,239)
- **ECC Data Integrity:** All key material and cipher output protected by Reed-Solomon (LombokECC)
- **Streaming API:** Chunk-by-chunk encrypt/decrypt for files of unlimited size
- **Key Management:** KeyStore, KeyRing, KeyRotation, KeyDerivationTree (BIP32-style), key import/export (PKCS#8, JWK, PEM, DER, raw)
- **Certificate Support:** X.509 parse/validate/chain-verify, PKCS#7/CMS, PKCS#12

#### Platform Support
- Node.js ≥ 18 (pure TypeScript primary implementation)
- Browser (ESM/WASM build)
- Deno ≥ 1.40
- Bun ≥ 1.0
- Rust core crate (crates.io)
- Python binding (PyO3 + maturin, PyPI)
- Go port (go module)
- PHP port (Packagist)
- Java port (Maven Central)
- .NET port (NuGet)
- C++ port (vcpkg/CMake)
- Perl port (CPAN)
- Swift port (Swift Package Manager — iOS/macOS)
- Kotlin port (Maven Central — Android)
- SQL port (PostgreSQL extension — PGXN)

#### Standards Compliance
- NIST FIPS 140-3 algorithm set
- NIST SP 800-38 (block cipher modes)
- NIST SP 800-56 (key agreement)
- NIST SP 800-90A/B/C (DRBG / entropy)
- NIST PQC Round 4 final standards (ML-KEM, ML-DSA, SLH-DSA)
- RFC 8018 (PBKDF2), RFC 7914 (scrypt), RFC 9106 (Argon2)
- RFC 9180 (HPKE)
- RFC 3394 / RFC 5649 (AES Key Wrap)
- RFC 4055 (RSA), RFC 8032 (Ed25519/Ed448)
- GM/T standards (SM2, SM3, SM4) — Chinese national standard
- ETSI TS 135 202 (SNOW 3G / 3GPP), ZUC (LTE/5G)
- ISO/IEC 18033 (Encryption algorithms)
- ISO/IEC 9797 (MAC algorithms)
- PKCS series (#1, #5, #7, #8, #10, #11, #12)

#### Ecosystem Integration
- LombokECC: RS(255,239) integrity on all stored key material and cipher output
- LombokFuzzer: Full fuzz corpus for all ciphers, parsers, and key derivation
- LombokQRCode: QR-encoded encrypted payload export/import
- LombokMarkDown: Documentation rendering
- LombokCSV: Audit log export in CSV format
- LombokStorybook: UI component showcase for web demo

#### CI / Quality
- GitHub Actions: Test matrix (Node 18/20/22, Python 3.11/3.12, Go 1.22/1.23, PHP 8.2/8.3, Rust stable/nightly)
- Cargo audit, npm audit, safety (Python), govulncheck (Go) — zero known CVE at release
- LombokFuzzer integration test (7-day seed corpus)
- 100% test vector coverage against NIST CAVP/ACVP test vectors
- Minimum 95% line coverage per module
- Constant-time verification via `dudect` statistical testing

---

*Author: @codinglombok*  
*License: Apache-2.0*
