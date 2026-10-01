---
name: Bug Report
about: Report a bug or incorrect cryptographic output
title: '[BUG] '
labels: ['bug']
assignees: []
---

## Describe the bug

A clear and concise description of what the bug is.

## Algorithm / Module

- [ ] AES-GCM / AES-CBC / AES-CTR
- [ ] ChaCha20-Poly1305 / XChaCha20
- [ ] SHA-2 / SHA-3 / BLAKE2 / BLAKE3
- [ ] SM2 / SM3 / SM4
- [ ] ZUC / SNOW 3G
- [ ] RSA-OAEP / RSA-PSS
- [ ] ECDH / ECDSA / Ed25519
- [ ] Post-Quantum (Kyber / Dilithium / SPHINCS+ / FALCON)
- [ ] HKDF / Argon2 / scrypt / PBKDF2
- [ ] HMAC / CMAC / Poly1305
- [ ] FPE (FF1 / FF3-1)
- [ ] XTS (disk encryption)
- [ ] HPKE
- [ ] KeyStore / Key Management
- [ ] Streaming API
- [ ] Audit Logging
- [ ] Hardware (HSM / TPM / SGX)
- [ ] Port: Python / Go / PHP / Java / Rust / .NET / Swift / Kotlin / Perl / SQL (C++)

## Language / Environment

- Language: [TypeScript / Python / Go / PHP / Java / Rust / .NET / Swift / Kotlin / Perl / SQL]
- Runtime: [Node.js version / Python version / etc.]
- Platform: [Linux x86_64 / macOS ARM64 / Windows / WASM / Embedded]
- Library version: [e.g. 0.1.0]

## To Reproduce

```typescript
import { aesGcm } from 'lombokencryptdecrypt';

// Minimal code to reproduce
```

## Expected behavior

Expected output (hex, base64, or description).

## Actual behavior

Actual output or error received.

## NIST Test Vector (if applicable)

If this is a correctness bug, please provide the NIST CAVP/ACVP test vector or RFC reference.

## Additional context

Any other context about the problem here.

## Security impact

- [ ] This bug has a security impact (timing side-channel, incorrect MAC verification, etc.)

If this is a security vulnerability, please use the Security Vulnerability template instead.
