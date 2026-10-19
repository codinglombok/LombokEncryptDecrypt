> **Status:** design document. Describes planned scope; see [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for what is actually implemented in v0.1.0.

# LombokEncryptDecrypt — API Reference

**Version:** 0.1.0 | **License:** Apache-2.0

---

## Installation

```bash
npm install lombokencryptdecrypt      # Node.js / Deno / Bun / browser
cargo add lombokencryptdecrypt        # Rust
pip install lombokencryptdecrypt      # Python
composer require codinglombok/lombokencryptdecrypt   # PHP
go get github.com/codinglombok/lombokencryptdecrypt-go  # Go
# Maven: com.codinglombok:lombokencryptdecrypt:0.1.0
# NuGet: CodingLombok.LombokEncryptDecrypt
```

---

## Quick Start

```typescript
import {
  aesGcm, chaCha20Poly1305, xchaChaPoly1305,
  ed25519, ecdh, ecdhX25519,
  kyber768, mlKem768,
  argon2id, pbkdf2, hkdf,
  hmacSha256, hmacSha512,
  sha256, sha3_256, blake3,
  sm3, sm4,
  KeyStore, envelopeEncrypt,
  encryptStreamGen, decryptStreamGen,
  randomKey256, randomBytes,
  LombokCryptoError, ErrorCode,
} from 'lombokencryptdecrypt';
```

---

## Symmetric Encryption (AEAD)

### `aesGcm` — AES-256-GCM

```typescript
// Encrypt
const { ciphertext, tag, iv } = await aesGcm.encrypt(
  plaintext: Uint8Array,
  key:       Uint8Array,       // 16 / 24 / 32 bytes
  options?:  {
    iv?:        Uint8Array,    // 12-byte nonce (random if omitted)
    aad?:       Uint8Array,    // additional authenticated data
    tagLength?: 4|6|8|10|12|14|16,  // default 16
  }
): Promise<{ ciphertext, tag, iv }>

// Decrypt
const plaintext = await aesGcm.decrypt(
  ciphertext: Uint8Array,
  key:        Uint8Array,
  iv:         Uint8Array,
  tag:        Uint8Array,
  options?:   { aad?, tagLength? }
): Promise<Uint8Array>
// Throws: LombokCryptoError(AUTHENTICATION_FAILED) on tag mismatch

// Helpers
const key = aesGcm.generateKey(256);  // 128 | 192 | 256
const iv  = aesGcm.generateIv();      // 12 random bytes
```

### `chaCha20Poly1305` — ChaCha20-Poly1305 (RFC 8439)

```typescript
const { ciphertext, tag, iv } = await chaCha20Poly1305.encrypt(pt, key32, options?);
const pt = await chaCha20Poly1305.decrypt(ct, key32, nonce12, tag, options?);
const key   = chaCha20Poly1305.generateKey();   // 32 bytes
const nonce = chaCha20Poly1305.generateNonce(); // 12 bytes
```

### `xchaChaPoly1305` — XChaCha20-Poly1305 (192-bit nonce)

```typescript
const { ciphertext, tag, iv } = await xchaChaPoly1305.encrypt(pt, key32, options?);
const pt    = await xchaChaPoly1305.decrypt(ct, key32, nonce24, tag, options?);
const nonce = xchaChaPoly1305.generateNonce(); // 24 bytes — safe for random nonce
```

---

## Digital Signatures

### `ed25519` — Ed25519 (RFC 8032, NIST FIPS 186-5)

```typescript
// Generate key pair
const { privateKey, publicKey } = await ed25519.generateKeyPair();
// privateKey: 32-byte seed | publicKey: 32-byte compressed point

// From seed (deterministic)
const kp = await ed25519.fromSeed(seed32: Uint8Array);

// Sign
const sig = await ed25519.sign(message: Uint8Array, privateKey: Uint8Array);
// sig: 64 bytes

// Verify (never throws — returns false on invalid)
const valid = await ed25519.verify(message, signature, publicKey);
```

---

## Key Agreement (ECDH)

### `ecdhX25519`, `ecdhP256`, `ecdhP384`, `ecdhP521`, `ecdhX448`

```typescript
// Generate
const { privateKey, publicKey } = await ecdhX25519.generateKeyPair();

// Compute shared secret (run through HKDF before use as symmetric key)
const sharedSecret = await ecdhX25519.computeSharedSecret(privateKey, theirPublicKey);

// Generic
const ss = await ecdh.computeSharedSecret('X25519', myPriv, theirPub);
```

---

## Post-Quantum Cryptography

### `kyber768` / `mlKem768` — ML-KEM-768 (NIST FIPS 203)

```typescript
// Key generation
const { publicKey, secretKey } = await kyber768.generateKeyPair();
// publicKey: 1184 bytes | secretKey: 2400 bytes

// Encapsulate (sender → recipient)
const { ciphertext, sharedSecret } = await kyber768.encapsulate(recipientPublicKey);
// ciphertext: 1088 bytes | sharedSecret: 32 bytes

// Decapsulate (recipient)
const sharedSecret = await kyber768.decapsulate(ciphertext, secretKey);
// → same 32-byte shared secret

// Use HKDF on shared secret before use as AES key:
const aesKey = await hkdf.sha256(sharedSecret, undefined, stringToBytes('context'), 32);
```

---

## Key Derivation

### `argon2id` — Argon2id (RFC 9106, OWASP recommended)

```typescript
// Hash password → PHC string
const phcHash = await argon2id.hash('password', { m: 65536, t: 3, p: 4 });
// "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>"

// Verify
const ok = await argon2id.verify(phcHash, 'password');

// Raw key material
const key = await argon2id.raw('password', salt, { m: 65536, t: 3, p: 4, hashLength: 32 });
```

### `pbkdf2` — PBKDF2-SHA256/512 (RFC 8018)

```typescript
// Derive key
const key = await pbkdf2.derive('password', { iterations: 600_000, hash: 'SHA-256', salt, dkLen: 32 });

// Hash to PHC string
const hash = await pbkdf2.hash('password', { hash: 'SHA-256', iterations: 600_000 });
const ok   = await pbkdf2.verify(hash, 'password');

// Convenience
const key = await pbkdf2.sha256.derive('password', salt, 600_000, 32);
const key = await pbkdf2.sha512.derive('password', salt, 600_000, 64);
```

### `hkdf` — HKDF-SHA256/384/512 (RFC 5869)

```typescript
const key = await hkdf.derive(ikm, { hash: 'SHA-256', salt, info, outputLength: 32 });
const key = await hkdf.sha256(ikm, salt?, info?, length?);
const key = await hkdf.sha512(ikm, salt?, info?, length?);
```

---

## MAC / Message Authentication

### `hmacSha256`, `hmacSha384`, `hmacSha512`

```typescript
const mac   = await hmacSha256.compute(key, message);       // 32 bytes
const valid = await hmacSha256.verify(key, message, mac);   // constant-time
const mac   = await hmacSha256.sign(key, message);          // alias

const mac   = await hmac.compute('SHA-256', key, message);  // generic
```

---

## Hash Functions

```typescript
const hash = await sha256.hash(data);      // 32 bytes — SHA-256
const hash = await sha512.hash(data);      // 64 bytes — SHA-512
const hash = await sha3_256.hash(data);    // 32 bytes — SHA3-256
const hash = await sha3_512.hash(data);    // 64 bytes — SHA3-512
const hash = await shake128.hash(data, 64); // variable — SHAKE-128
const hash = await blake3.hash(data);      // 32 bytes — BLAKE3
const hash = sm3.hash(data);               // 32 bytes — SM3 (GM/T 0004, sync)
```

---

## Hybrid / Protocol

### `envelopeEncrypt` — Envelope Encryption (KMS-compatible)

```typescript
// Encrypt with auto-generated DEK, wrapped with KEK
const { encryptedData, encryptedKey } = await envelopeEncrypt.encrypt(
  plaintext, kek, kemId, aad?
);

// Decrypt
const plaintext = await envelopeEncrypt.decrypt(encryptedData, encryptedKey, kek, aad?);

// Key rotation (rewrap DEK without re-encrypting data)
const rotated = await envelopeEncrypt.rewrap(encryptedKey, oldKek, newKek, newKemId);
```

---

## Streaming (Unlimited File Size)

```typescript
import { encryptStreamGen, decryptStreamGen } from 'lombokencryptdecrypt';

// Encrypt
const encrypted = encryptStreamGen(readableStream, {
  algorithm: 'AES-256-GCM', key, aad?, chunkSize?: 65536,
});
for await (const chunk of encrypted) { /* write to output */ }

// Decrypt
const decrypted = decryptStreamGen(encryptedStream, {
  algorithm: 'AES-256-GCM', key,
});

// Manual control
const enc = createEncryptStream({ algorithm: 'AES-256-GCM', key });
const chunks = await enc.update(incoming);  // may return 0 or more encrypted chunks
const final  = await enc.final();           // flush + sentinel
```

---

## Key Management

### `KeyStore`

```typescript
// Create
const ks = await KeyStore.create({ password: 'vault-password', m: 65536, t: 3, p: 4 });

// Store / retrieve
await ks.set('my-key-id', keyBytes, 'AES-256-GCM');
const key = await ks.get('my-key-id');    // Uint8Array

// Generate and store
const newKey = await ks.generateKey('enc-key-2026', 'AES-256-GCM');

// List / delete
const ids = ks.list();
ks.delete('my-key-id');

// Serialize (encrypted)
const blob = await ks.serialize();        // store to file / DB
const ks2  = await KeyStore.open(blob, { password: 'vault-password' });

// Lock (zeroizes all key material in memory)
ks.lock();
```

---

## Random Number Generation

```typescript
import { randomBytes, randomKey256, randomKey128, randomSalt, randomIv } from 'lombokencryptdecrypt';

const rnd  = randomBytes(64);
const key  = randomKey256();    // 32 random bytes
const key  = randomKey128();    // 16 random bytes
const salt = randomSalt(16);    // 16 random bytes
const iv   = randomIv(12);      // 12 random bytes
```

---

## Encoding Utilities

```typescript
import {
  bytesToHex, hexToBytes,
  bytesToBase64, bytesToBase64Url, base64ToBytes,
  stringToBytes, bytesToString,
  concatBytes, xorBytes,
} from 'lombokencryptdecrypt';
```

---

## Constant-Time Utilities

```typescript
import { timingSafeEqual, zeroize } from 'lombokencryptdecrypt';

timingSafeEqual(a, b);  // boolean — always runs in O(n)
zeroize(buffer);        // securely fill with zeros (resistant to dead-code elimination)
```

---

## Error Handling

```typescript
import { LombokCryptoError, ErrorCode } from 'lombokencryptdecrypt';

try {
  await aesGcm.decrypt(ct, key, iv, tamperedTag);
} catch (e) {
  if (e instanceof LombokCryptoError) {
    console.log(e.code);       // 'AUTHENTICATION_FAILED'
    console.log(e.algorithm);  // 'AES-GCM'
    console.log(e.message);    // human-readable
  }
}
```

**Error codes:**

| Code | When |
|------|------|
| `INVALID_KEY_SIZE` | Key has wrong byte length |
| `INVALID_IV_SIZE` | IV/nonce has wrong byte length |
| `AUTHENTICATION_FAILED` | GCM/Poly1305 tag mismatch |
| `KEY_NOT_FOUND` | KeyStore lookup miss |
| `KEY_EXPIRED` | KeyStore entry past TTL |
| `KEYSTORE_LOCKED` | get() on locked KeyStore |
| `KEYSTORE_CORRUPT` | Wrong password or tampered KeyStore |
| `LEGACY_DISABLED` | MD5/SHA-1/RC4 called without `{ legacy: true }` |
| `FIPS_VIOLATION` | Non-FIPS algorithm in FIPS mode |
| `STREAM_FINALISED` | update() after final() |
| `INTEGRITY_CHECK_FAILED` | Stream chunk out of order |
| `UNSUPPORTED_ALGORITHM` | Unknown algorithm string |

---

## Platform Capabilities

```typescript
import { getPlatformCapabilities, PLATFORM } from 'lombokencryptdecrypt';

const caps = await getPlatformCapabilities();
// {
//   platform:          'node' | 'browser' | 'deno' | 'bun' | 'wasm' | 'embedded',
//   hasAesNi:          boolean,
//   hasShaExtensions:  boolean,
//   hasAvx2:           boolean,
//   hasNeon:           boolean,
//   hasSubtleCrypto:   boolean,
//   hasHardwareRng:    boolean,
//   hasHsm:            boolean,
//   hasTpm:            boolean,
//   hasSecureEnclave:  boolean,
// }
```

---

## Algorithm Aliases (NIST official names)

| NIST FIPS name | LombokEncryptDecrypt export |
|----------------|---------------------------|
| ML-KEM-768 | `kyber768` / `mlKem768` |
| ML-DSA-65 | `dilithium3` / `mlDsa65` |
| SLH-DSA-SHAKE-256f | `sphincsPlus` |
| AES-GCM | `aesGcm` |
| ChaCha20-Poly1305 | `chaCha20Poly1305` |

---

*Full docs: https://github.com/codinglombok/LombokEncryptDecrypt/blob/main/docs/API.md*
*License: Apache-2.0 © 2026 @codinglombok*
