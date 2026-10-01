# LombokEncryptDecrypt

**Universal Encrypt/Decrypt Library — The Most Complete in the Lombok Ecosystem**

[![npm](https://img.shields.io/npm/v/lombokencryptdecrypt.svg)](https://www.npmjs.com/package/lombokencryptdecrypt)
[![crates.io](https://img.shields.io/crates/v/lombokencryptdecrypt.svg)](https://crates.io/crates/lombokencryptdecrypt)
[![PyPI](https://img.shields.io/pypi/v/lombokencryptdecrypt.svg)](https://pypi.org/project/lombokencryptdecrypt/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/codinglombok/LombokEncryptDecrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/codinglombok/LombokEncryptDecrypt/actions)
[![codecov](https://codecov.io/gh/codinglombok/LombokEncryptDecrypt/branch/main/graph/badge.svg)](https://codecov.io/gh/codinglombok/LombokEncryptDecrypt)

---

## Why LombokEncryptDecrypt?

| Feature | OpenSSL | libsodium | WebCrypto | **LombokEncryptDecrypt** |
|---------|---------|-----------|-----------|--------------------------|
| Post-Quantum (ML-KEM/ML-DSA/SPHINCS+) | ❌ | ❌ | ❌ | ✅ |
| Chinese standards (SM2/SM3/SM4) | Plugin | ❌ | ❌ | ✅ |
| Telecom (ZUC/SNOW3G/5G) | ❌ | ❌ | ❌ | ✅ |
| 12 language idiomatic ports | ❌ | ❌ | ❌ | ✅ |
| Built-in audit logging | ❌ | ❌ | ❌ | ✅ |
| ECC data integrity on cipher output | ❌ | ❌ | ❌ | ✅ |
| HSM/TPM/SGX bridge | External | ❌ | ❌ | ✅ |
| Envelope Encryption (KMS-compat) | ❌ | ❌ | ❌ | ✅ |
| Format-Preserving Encryption (FF1/FF3-1) | ❌ | ❌ | ❌ | ✅ |
| Streaming (unlimited file size) | ❌ | ❌ | ❌ | ✅ |
| SQL extension (PostgreSQL UDF) | ❌ | ❌ | ❌ | ✅ |
| HPKE (RFC 9180) | ❌ | ❌ | ❌ | ✅ |
| Disk encryption (XTS-AES) | ❌ | ❌ | ❌ | ✅ |
| Zero external deps | ❌ | ❌ | Browser-only | ✅ |
| License | OpenSSL | ISC | N/A | **Apache 2.0** |

---

## Install

```bash
# npm (TypeScript / Node.js / Browser / Deno / Bun)
npm install lombokencryptdecrypt

# Rust
cargo add lombokencryptdecrypt

# Python
pip install lombokencryptdecrypt

# PHP
composer require codinglombok/lombokencryptdecrypt

# Go
go get github.com/codinglombok/lombokencryptdecrypt-go

# Java / Kotlin (Maven)
# com.codinglombok:lombokencryptdecrypt:0.1.0

# .NET
dotnet add package CodingLombok.LombokEncryptDecrypt

# Swift (Package.swift)
# .package(url: "https://github.com/codinglombok/LombokEncryptDecrypt", from: "0.1.0")

# PostgreSQL extension
CREATE EXTENSION lombokencryptdecrypt_ext;
```

---

## Quick Start

```typescript
import {
  aesGcm,
  chaCha20Poly1305,
  ed25519,
  kyber768,
  argon2id,
  hmacSha256,
  encryptStream,
  KeyStore,
} from 'lombokencryptdecrypt';

// ── AES-256-GCM ──────────────────────────────────────────────────────────
const key = crypto.getRandomValues(new Uint8Array(32));
const { ciphertext, tag, iv } = await aesGcm.encrypt(plaintext, key, { aad });
const recovered = await aesGcm.decrypt(ciphertext, key, iv, tag, { aad });

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────
const encrypted = await chaCha20Poly1305.encrypt(message, key32);
const decrypted = await chaCha20Poly1305.decrypt(encrypted, key32);

// ── Ed25519 Sign / Verify ─────────────────────────────────────────────────
const { privateKey, publicKey } = await ed25519.generateKeyPair();
const signature = await ed25519.sign(message, privateKey);
const valid = await ed25519.verify(message, signature, publicKey);

// ── Post-Quantum: ML-KEM-768 (Kyber) ─────────────────────────────────────
const { publicKey: pk, secretKey: sk } = await kyber768.generateKeyPair();
const { ciphertext: ct, sharedSecret: ss1 } = await kyber768.encapsulate(pk);
const ss2 = await kyber768.decapsulate(ct, sk);
// ss1 === ss2 (32-byte shared secret)

// ── Argon2id Password Hashing ─────────────────────────────────────────────
const hash = await argon2id.hash('my-password', { m: 65536, t: 3, p: 4 });
const ok = await argon2id.verify(hash, 'my-password');

// ── HMAC-SHA256 ───────────────────────────────────────────────────────────
const mac = await hmacSha256(message, key);

// ── Streaming (large file encryption) ────────────────────────────────────
const stream = encryptStream({ algorithm: 'AES-256-GCM', key });
for await (const chunk of inputStream) {
  yield stream.update(chunk);
}
yield stream.final();

// ── KeyStore (persistent encrypted key management) ───────────────────────
const ks = await KeyStore.open('/path/to/keystore.lked', { password: 'vault-password' });
await ks.set('my-key', key);
const retrieved = await ks.get('my-key');
```

```python
# Python
from lombokencryptdecrypt import aes_gcm, ed25519, kyber768, argon2id

key = bytes(32)
encrypted = aes_gcm.encrypt(b"hello", key)
decrypted = aes_gcm.decrypt(encrypted, key)

kp = ed25519.generate_keypair()
sig = ed25519.sign(b"message", kp.private_key)
assert ed25519.verify(b"message", sig, kp.public_key)
```

```go
// Go
import led "github.com/codinglombok/lombokencryptdecrypt-go"

encrypted, err := led.AesGcm.Encrypt(plaintext, key, nil)
decrypted, err := led.AesGcm.Decrypt(encrypted, key, nil)

kp, _ := led.Ed25519.GenerateKeyPair()
sig, _ := led.Ed25519.Sign(msg, kp.PrivateKey)
ok, _ := led.Ed25519.Verify(msg, sig, kp.PublicKey)
```

```php
<?php
// PHP
use CodingLombok\LombokEncryptDecrypt\AesGcm;
use CodingLombok\LombokEncryptDecrypt\Ed25519;

$encrypted = AesGcm::encrypt($plaintext, $key);
$decrypted = AesGcm::decrypt($encrypted, $key);

$kp = Ed25519::generateKeyPair();
$sig = Ed25519::sign($message, $kp->privateKey);
$ok = Ed25519::verify($message, $sig, $kp->publicKey);
```

```sql
-- PostgreSQL
SELECT lombok_crypto.aes_gcm_encrypt(
    'secret data'::bytea,
    encode(gen_random_bytes(32), 'hex')
);

SELECT lombok_crypto.argon2id_hash('my-password', encode(gen_random_bytes(16), 'hex'));
```

---

## Algorithm Coverage

| Category | Algorithms |
|----------|-----------|
| **Symmetric** | AES-128/192/256 (GCM/CCM/EAX/OCB3/SIV/CBC/CTR/CFB/OFB/XTS), ChaCha20-Poly1305, XChaCha20, Salsa20, Camellia-256-GCM, SM4-GCM, ZUC, SNOW 3G |
| **Asymmetric** | RSA-OAEP/PSS (2048/4096), ECDH (P-256/384/521/X25519/X448), ECDSA, Ed25519, Ed448, SM2, ECIES, RSA-KEM |
| **Post-Quantum** | ML-KEM-512/768/1024 (Kyber), ML-DSA-44/65/87 (Dilithium), SLH-DSA (SPHINCS+), FALCON-512/1024, BIKE, HQC, Classic McEliece |
| **Hash** | SHA-2 (224/256/384/512), SHA-3 (224/256/384/512), SHAKE-128/256, BLAKE2b/2s, BLAKE3, SM3, Whirlpool |
| **MAC** | HMAC-SHA256/512, CMAC-AES, Poly1305, GMAC, SipHash-2-4, BLAKE3-MAC, KMAC-128/256 |
| **KDF** | PBKDF2, scrypt, Argon2id/i/d, bcrypt, HKDF, X9.63, SP 800-56C, BIP32 |
| **Special** | FF1/FF3-1 (FPE), XTS-AES (disk), AES Key Wrap (RFC 3394/5649), HPKE (RFC 9180), Envelope Encryption |
| **Key Mgmt** | KeyStore, KeyRing, key rotation, JWK, PEM, DER, PKCS#12, X.509 chain verify |
| **Hardware** | PKCS#11 HSM, TPM 2.0, Apple Secure Enclave, Android Keystore, Intel SGX stub |
| **Protocols** | HPKE (RFC 9180), ECIES, IES, Hybrid X25519+ML-KEM-768 |

---

## Standards

NIST FIPS 197/180-4/202/203/204/205 | SP 800-38(A/B/C/D/E/G) | SP 800-56(A/B/C) | SP 800-90A  
RFC 8018/7914/9106/5869/8032/9180/3394/5649/7517 | PKCS#1/5/7/8/10/11/12  
GM/T 0002/0003/0004 (SM2/SM3/SM4) | ETSI TS 135 (ZUC/SNOW3G/3GPP) | IEEE 1619 (XTS)  
ISO/IEC 18033 | ISO/IEC 9797 | Wycheproof test vectors | NIST CAVP/ACVP

---

## Documentation

- [API Reference](docs/API.md)
- [Post-Quantum Guide](docs/PQC_GUIDE.md)
- [Envelope Encryption Guide](docs/ENVELOPE_GUIDE.md)
- [Hardware / HSM Guide](docs/HARDWARE_GUIDE.md)
- [Streaming Guide](docs/STREAMING_GUIDE.md)
- [FIPS Mode](docs/FIPS_MODE.md)
- [Compliance (GDPR/HIPAA/PCI-DSS)](docs/COMPLIANCE.md)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

---

## Part of Lombok Ecosystem

LombokEncryptDecrypt is **Tier 2 — Security & Compliance** in [@codinglombok](https://github.com/codinglombok).  
It uses [LombokECC](https://github.com/codinglombok/LombokECC) for Reed-Solomon integrity on key material and cipher output, and [LombokAlgoritma](https://github.com/codinglombok/LombokAlgoritma) for math primitives.

---

**License:** Apache-2.0 © 2026 [@codinglombok](https://github.com/codinglombok)
