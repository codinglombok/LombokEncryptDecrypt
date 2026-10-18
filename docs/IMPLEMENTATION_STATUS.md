# Implementation Status — v0.1.0 (pre-release)

Source of truth for what works. Anything not marked **Verified** must not be relied on.

## Verified (TypeScript, tested; pure-TS fallbacks cross-checked against OpenSSL)

| Area | Items |
|---|---|
| AEAD | AES-128/192/256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 |
| Block / modes | AES block, AES-XTS, SM4 block |
| Hash | SHA-224/256, SHA3-224/256/384/512, SHAKE128/256, SM3 |
| MAC | HMAC-SHA256/384/512, CMAC-AES-128/256 |
| KDF | HKDF, PBKDF2, scrypt (RFC 7914 vectors) |
| Asymmetric | Ed25519, ECDH (P-256/384/521, X25519, X448) — via platform crypto (node:crypto / WebCrypto) |
| Streaming | Authenticated chunked AEAD (ordered, truncation-detecting) |
| KeyStore | v2 format: scrypt → HKDF → AES-GCM per entry + HMAC trailer |
| Audit | `AuditLogger` (no Reed-Solomon parity yet) |

## Fail closed (source exists, throws `UNSUPPORTED_ALGORITHM`, NOT exported)

Argon2 (RFC 9106), ML-KEM-768 / Kyber (needs optional native module).

## Not written yet

BLAKE2/BLAKE3, ECDSA, RSA, SM2, FF1/FF3-1, ML-DSA, SLH-DSA, FALCON, HQC, BIKE, McEliece,
HPKE, ZUC, JWK/PEM/X.509, PKCS#11, Reed-Solomon parity in audit logs.

## Unverified

- Rust crate and the Go, Python, PHP, Java, Kotlin, C#, Swift ports have **never been compiled or run**.
- Pure-TS fallbacks are not constant-time audited.
- No third-party audit has been performed.
