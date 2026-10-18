> **Status:** design document. Describes planned scope; see [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for what is actually implemented in v0.1.0.

# LombokEncryptDecrypt — Behavioral Specification

**Version:** 0.1.0 | **Date:** 2026-09-18 | **Author:** @codinglombok

This document is the **normative cross-language contract**. Every language port MUST produce
byte-identical output for all specified inputs. Deviations from this specification are bugs.

---

## 1. AES-GCM

### 1.1 Parameters

| Parameter | Value |
|-----------|-------|
| Block size | 128 bits |
| Key sizes | 128 / 192 / 256 bits |
| IV size | 96 bits (12 bytes) — **REQUIRED** |
| Tag size | 128 bits (16 bytes) default; 32/48/64/80/96/112/128 optional |
| Max plaintext | 2^39 − 256 bits ≈ 64 GiB |
| Max AAD | 2^64 − 1 bits |

### 1.2 Encoding

```
EncryptResult {
  ciphertext: bytes  -- same length as plaintext
  tag:        bytes  -- tagLength bytes (default 16)
  iv:         bytes  -- 12 bytes
}
```

### 1.3 Algorithm

1. If IV is omitted: generate 12 bytes from CSPRNG
2. Encrypt using AES-GCM (NIST SP 800-38D): `(C, T) = AES-GCM-Encrypt(K, IV, P, AAD)`
3. Return `(ciphertext=C, tag=T, iv=IV)`

### 1.4 Decrypt contract

- MUST verify tag before returning plaintext
- MUST use constant-time comparison for tag verification
- MUST raise `AUTHENTICATION_FAILED` error (not a generic error) on tag mismatch
- MUST NOT return partial plaintext if tag verification fails
- Empty plaintext is valid → returns empty ciphertext, 16-byte tag

### 1.5 Error codes

| Condition | Error code |
|-----------|-----------|
| `len(key) ∉ {16, 24, 32}` | `INVALID_KEY_SIZE` |
| `len(iv) ≠ 12` | `INVALID_IV_SIZE` |
| Tag mismatch | `AUTHENTICATION_FAILED` |

---

## 2. ChaCha20-Poly1305

### 2.1 Parameters (RFC 8439)

| Parameter | Value |
|-----------|-------|
| Key size | 256 bits (32 bytes) |
| Nonce size | 96 bits (12 bytes) |
| Tag size | 128 bits (16 bytes) — fixed |

### 2.2 Algorithm

1. Generate Poly1305 key: first 32 bytes of `ChaCha20(key, nonce, counter=0)`
2. Encrypt: `ChaCha20(key, nonce, counter=1, plaintext)`
3. Compute tag: `Poly1305(mac_key, AAD || pad(AAD) || CT || pad(CT) || len(AAD) || len(CT))`
4. The length encoding is two 64-bit little-endian unsigned integers

### 2.3 XChaCha20-Poly1305 extension

- Nonce size: **192 bits (24 bytes)**
- Subkey derivation: `subkey = HChaCha20(key, nonce[0:16])`
- Remaining nonce: `nonce[16:24]` placed at bytes 4-11 of a 12-byte nonce
- Otherwise identical to ChaCha20-Poly1305

---

## 3. Ed25519

### 3.1 Parameters (RFC 8032)

| Parameter | Value |
|-----------|-------|
| Private key | 32-byte seed (expanded internally to 64 bytes) |
| Public key | 32-byte compressed Edwards point |
| Signature | 64 bytes |
| Hash | SHA-512 |
| Curve | Edwards25519 |

### 3.2 Sign contract

- Deterministic: same (message, seed) → always same signature
- Prehash: NO — Ed25519 signs the message directly (not prehashed)
- Input: any-length byte array

### 3.3 Verify contract

- Returns `true` (valid) or `false` (invalid) — NEVER throws on invalid signature
- Performs cofactor check
- Rejects small-order public keys

---

## 4. ML-KEM-768 (NIST FIPS 203)

### 4.1 Sizes

| Item | Bytes |
|------|-------|
| Public key | 1184 |
| Secret key | 2400 |
| Ciphertext | 1088 |
| Shared secret | 32 |

### 4.2 Contract

- `generateKeyPair()` → `(pk, sk)` — random
- `encapsulate(pk)` → `(ct, ss)` — random; generates fresh shared secret
- `decapsulate(ct, sk)` → `ss` — deterministic
- `decapsulate` MUST use implicit rejection (Fujisaki-Okamoto transform)
- Shared secret MUST NOT be used directly as a symmetric key — run through HKDF first

---

## 5. Argon2id

### 5.1 Default parameters (OWASP 2024)

| Parameter | Default | Minimum |
|-----------|---------|---------|
| m (memory) | 65536 KiB (64 MB) | 19456 KiB |
| t (time) | 3 | 1 |
| p (parallelism) | 4 | 1 |
| Output length | 32 bytes | 16 bytes |

### 5.2 PHC string format

```
$argon2id$v=19$m=65536,t=3,p=4$<salt_base64url>$<hash_base64url>
```

- Salt: minimum 16 random bytes
- Version: always 19 (0x13)
- Base64url encoding: no padding characters

### 5.3 Verify contract

- MUST use constant-time comparison for hash verification
- MUST return `false` (not throw) on mismatch

---

## 6. HMAC

### 6.1 Algorithm

`HMAC-SHA256(key, message)`:
1. `k0 = key` if `len(key) ≤ 64`, else `SHA-256(key)`
2. `k0_padded = k0 || 0x00...(64 - len(k0))`
3. Inner: `SHA-256((k0_padded XOR 0x363636...) || message)`
4. Outer: `SHA-256((k0_padded XOR 0x5c5c5c...) || inner)`

### 6.2 Verify contract

- MUST use constant-time comparison (not `===` or `==`)
- Returns `boolean` — NEVER throws on mismatch

---

## 7. HKDF-SHA256

### 7.1 Algorithm (RFC 5869)

**Extract:** `PRK = HMAC-SHA256(salt, IKM)`
- `salt` defaults to `0x00 × 32` if omitted or empty

**Expand:** for `i = 1, 2, ...`:
- `T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)`
- `OKM = T(1) || T(2) || ...` truncated to `L` bytes

### 7.2 Limits

- Max output length: `32 × 255 = 8160` bytes for SHA-256

---

## 8. Envelope Encryption (KEK/DEK)

### 8.1 Format

```
EnvelopeEncryptResult {
  encryptedData: bytes  -- IV(12) || ciphertext || tag(16)
  encryptedKey: {
    wrappedDek:  bytes  -- AES-256-GCM(dek, kek)
    dekIv:       bytes  -- 12 bytes
    dekTag:      bytes  -- 16 bytes
    kemId:       string -- KEK identifier
    algorithm:   string -- "AES-256-GCM"
  }
}
```

### 8.2 Contract

1. Generate random 256-bit DEK
2. Encrypt data with DEK → `encryptedData`
3. Encrypt DEK with KEK → `encryptedKey`
4. Zero DEK from memory after use
5. `rewrap(oldKek, newKek)` changes only `encryptedKey` — `encryptedData` is unchanged

---

## 9. Streaming AEAD

### 9.1 Chunk format

Each chunk: `[4-byte big-endian chunk index] || [12-byte IV] || [ciphertext] || [16-byte tag]`

End sentinel: `[0xFF 0xFF 0xFF 0xFF]`

### 9.2 Contract

- Each chunk's AAD includes the chunk index to prevent reordering
- Out-of-order chunks MUST be rejected with `INTEGRITY_CHECK_FAILED`
- Truncation MUST be rejected (missing sentinel)
- Default chunk size: 65536 bytes

---

## 10. Audit Log

### 10.1 Block format

```
MAGIC(4='LEDL') || VERSION(1) || BLOCK_LEN(2,BE) || TIMESTAMP(8,BE,ms) ||
PAYLOAD(N,UTF-8 JSON) || RS_PARITY(16, LombokECC RS-255-239)
```

### 10.2 Log entry JSON schema

```json
{
  "timestamp": 1726643200000,
  "operation": "encrypt",
  "algorithm": "AES-256-GCM",
  "keyId": "optional-key-id",
  "inputLength": 1024,
  "outputLength": 1024,
  "success": true,
  "platform": "node/v22.0.0"
}
```

---

## 11. Cross-Language Guarantees

All ports MUST:
1. Pass all vectors in `tests/vectors/lombokencryptdecrypt-vectors-v1.json`
2. Produce byte-identical output for the same inputs
3. Use constant-time comparison for all MAC/tag verification
4. Reject invalid inputs with error codes matching this spec exactly
5. Not return partial plaintext on authentication failure

---

*Document version: 0.1.0 | License: Apache-2.0 | Author: @codinglombok*
