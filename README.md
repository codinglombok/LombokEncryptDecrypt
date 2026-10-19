# LombokEncryptDecrypt

**Encrypt/decrypt toolkit for TypeScript — pre-release (v0.1.0)**

> ⚠️ Pre-release, not security-audited. Only the items marked *Verified* in [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) are implemented. The Rust core and non-TypeScript ports have not been compiled or run. No third-party runtime dependencies.

[![npm](https://img.shields.io/npm/v/lombokencryptdecrypt.svg)](https://www.npmjs.com/package/lombokencryptdecrypt)
[![crates.io](https://img.shields.io/crates/v/lombokencryptdecrypt.svg)](https://crates.io/crates/lombokencryptdecrypt)
[![PyPI](https://img.shields.io/pypi/v/lombokencryptdecrypt.svg)](https://pypi.org/project/lombokencryptdecrypt/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/codinglombok/LombokEncryptDecrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/codinglombok/LombokEncryptDecrypt/actions)
[![codecov](https://codecov.io/gh/codinglombok/LombokEncryptDecrypt/branch/main/graph/badge.svg)](https://codecov.io/gh/codinglombok/LombokEncryptDecrypt)

---

## Install

```bash
npm install lombokencryptdecrypt   # not yet published; build from source for now
```

## Quick Start

```ts
import { aesGcm, randomKey256, stringToBytes, bytesToString } from 'lombokencryptdecrypt';

const key = randomKey256();
const aad = stringToBytes('ctx');
const { ciphertext, tag, iv } = await aesGcm.encrypt(stringToBytes('halo lombok'), key, { aad });
const plain = await aesGcm.decrypt(ciphertext, key, iv, tag, { aad });
console.log(bytesToString(plain)); // "halo lombok"
```

Subpath imports: `/symmetric`, `/asymmetric`, `/hash`, `/mac`, `/kdf`, `/keystore`, `/stream`, `/audit`.

## What is implemented

AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-XTS, SM3/SM4, SHA-2, SHA-3/SHAKE, HMAC, CMAC,
HKDF, PBKDF2, scrypt, Ed25519, ECDH, authenticated streaming, password-protected KeyStore.
Argon2 and ML-KEM fail closed (`UNSUPPORTED_ALGORITHM`). Everything else is planned — see
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md).

## Develop

```bash
npm install
npm run typecheck && npm test && npm run build:ts
```

## Documentation

- [Implementation status](docs/IMPLEMENTATION_STATUS.md)
- [API Reference](docs/API.md), [Architecture](docs/architecture_repo.md), [Masterplan](docs/masterplan_repo.md), [Spec](docs/SPEC.md) — *design documents; describe planned scope, may exceed what is implemented*
- [Security Policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Part of Lombok Ecosystem

Tier 2 — Security & Compliance in [@codinglombok](https://github.com/codinglombok).

---

**License:** Apache-2.0 © 2026 [@codinglombok](https://github.com/codinglombok)
