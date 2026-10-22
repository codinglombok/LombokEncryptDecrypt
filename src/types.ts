/**
 * LombokEncryptDecrypt — Shared TypeScript Types
 * @module types
 */

// ── Byte types ─────────────────────────────────────────────────────────────

export type Bytes = Uint8Array;
export type HexString = string;
export type Base64String = string;
export type PemString = string;

// ── Algorithm identifiers ──────────────────────────────────────────────────

export type SymmetricAlgorithm =
  | 'AES-128-GCM'
  | 'AES-192-GCM'
  | 'AES-256-GCM'
  | 'AES-128-CBC'
  | 'AES-256-CBC'
  | 'AES-128-CTR'
  | 'AES-256-CTR'
  | 'AES-128-CCM'
  | 'AES-256-CCM'
  | 'AES-128-EAX'
  | 'AES-256-EAX'
  | 'AES-256-SIV'
  | 'AES-256-XTS'
  | 'CHACHA20-POLY1305'
  | 'XCHACHA20-POLY1305'
  | 'SM4-GCM'
  | 'SM4-CBC'
  | 'SM4-CTR'
  | 'CAMELLIA-256-GCM';

export type HashAlgorithm =
  | 'SHA-224'
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512'
  | 'SHA-512/224'
  | 'SHA-512/256'
  | 'SHA3-224'
  | 'SHA3-256'
  | 'SHA3-384'
  | 'SHA3-512'
  | 'SHAKE-128'
  | 'SHAKE-256'
  | 'BLAKE2b'
  | 'BLAKE2s'
  | 'BLAKE3'
  | 'SM3'
  | 'WHIRLPOOL';

export type MacAlgorithm =
  | 'HMAC-SHA256'
  | 'HMAC-SHA384'
  | 'HMAC-SHA512'
  | 'HMAC-SHA3-256'
  | 'HMAC-SHA3-512'
  | 'CMAC-AES-128'
  | 'CMAC-AES-256'
  | 'POLY1305'
  | 'GMAC-AES-256'
  | 'SIPHASH-2-4'
  | 'SIPHASH-4-8'
  | 'BLAKE3-MAC'
  | 'KMAC-128'
  | 'KMAC-256';

export type KdfAlgorithm =
  | 'PBKDF2-SHA256'
  | 'PBKDF2-SHA512'
  | 'SCRYPT'
  | 'ARGON2ID'
  | 'ARGON2I'
  | 'ARGON2D'
  | 'BCRYPT'
  | 'HKDF-SHA256'
  | 'HKDF-SHA512'
  | 'X963-SHA256'
  | 'X963-SHA512'
  | 'SP800-56C';

export type AsymmetricAlgorithm =
  | 'RSA-OAEP-SHA256'
  | 'RSA-OAEP-SHA512'
  | 'RSA-PSS-SHA256'
  | 'RSA-PSS-SHA512'
  | 'ECDH-P256'
  | 'ECDH-P384'
  | 'ECDH-P521'
  | 'ECDH-X25519'
  | 'ECDH-X448'
  | 'ECDSA-P256'
  | 'ECDSA-P384'
  | 'ECDSA-P521'
  | 'ED25519'
  | 'ED448'
  | 'SM2-ENCRYPT'
  | 'SM2-SIGN'
  | 'ECIES-P256'
  | 'ECIES-X25519';

export type PQCAlgorithm =
  | 'ML-KEM-512'
  | 'ML-KEM-768'
  | 'ML-KEM-1024'
  | 'ML-DSA-44'
  | 'ML-DSA-65'
  | 'ML-DSA-87'
  | 'SLH-DSA-SHAKE-128S'
  | 'SLH-DSA-SHAKE-128F'
  | 'SLH-DSA-SHAKE-256S'
  | 'SLH-DSA-SHAKE-256F'
  | 'FALCON-512'
  | 'FALCON-1024'
  | 'BIKE-L1'
  | 'BIKE-L3'
  | 'BIKE-L5'
  | 'HQC-128'
  | 'HQC-192'
  | 'HQC-256'
  | 'MCELIECE-348864'
  | 'MCELIECE-6688128'
  | 'HYBRID-X25519-ML-KEM-768'
  | 'HYBRID-P256-ML-KEM-768';

// ── Options ────────────────────────────────────────────────────────────────

export interface GlobalCryptoOptions {
  /** Enable legacy algorithms (MD5, SHA-1, RC4, RSA-PKCS1v1.5). Default: false */
  readonly legacy?: boolean;
  /** Enforce FIPS 140-3 algorithm set. Disables all non-FIPS algorithms. Default: false */
  readonly fips?: boolean;
  /** Audit every operation to LombokEncryptDecrypt audit log. Default: true */
  readonly audit?: boolean;
}

export interface AeadEncryptOptions {
  /** Additional authenticated data (not encrypted, but authenticated) */
  readonly aad?: Bytes;
  /** Authentication tag length in bytes. Default: 16 (GCM), 16 (CCM), variable (OCB) */
  readonly tagLength?: 4 | 6 | 8 | 10 | 12 | 14 | 16;
  /** Nonce/IV. If omitted, generated randomly */
  readonly iv?: Bytes;
}

export interface AeadDecryptOptions {
  readonly aad?: Bytes;
  readonly tagLength?: 4 | 6 | 8 | 10 | 12 | 14 | 16;
}

export interface AeadResult {
  readonly ciphertext: Bytes;
  readonly tag: Bytes;
  readonly iv: Bytes;
}

export interface Argon2Options {
  readonly m: number; // Memory cost in KiB
  readonly t: number; // Time cost (iterations)
  readonly p: number; // Parallelism
  readonly hashLength?: number; // Output length in bytes. Default: 32
  readonly salt?: Bytes; // Random salt if omitted
}

export interface ScryptOptions {
  readonly N: number; // CPU/memory cost. Must be power of 2
  readonly r: number; // Block size
  readonly p: number; // Parallelization
  readonly dkLen?: number;
  readonly salt?: Bytes;
}

export interface Pbkdf2Options {
  readonly iterations: number;
  readonly hash: 'SHA-256' | 'SHA-512';
  readonly dkLen?: number;
  readonly salt?: Bytes;
}

export interface HkdfOptions {
  readonly hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
  readonly info?: Bytes;
  readonly salt?: Bytes;
  readonly outputLength: number;
}

// ── Key types ──────────────────────────────────────────────────────────────

export interface KeyPair {
  readonly publicKey: Bytes;
  readonly privateKey: Bytes;
}

export interface KEMKeyPair {
  readonly publicKey: Bytes;
  readonly secretKey: Bytes;
}

export interface KEMResult {
  readonly ciphertext: Bytes;
  readonly sharedSecret: Bytes;
}

export interface HpkeSuite {
  readonly kem:
    | 'DHKEM-X25519-HKDF-SHA256'
    | 'DHKEM-P256-HKDF-SHA256'
    | 'DHKEM-X448-HKDF-SHA512'
    | 'DHKEM-ML-KEM-768';
  readonly kdf: 'HKDF-SHA256' | 'HKDF-SHA384' | 'HKDF-SHA512';
  readonly aead: 'AES-128-GCM' | 'AES-256-GCM' | 'CHACHA20-POLY1305';
}

export interface EnvelopeEncryptedKey {
  readonly wrappedDek: Bytes; // DEK encrypted with KEK (AES-256-GCM)
  readonly dekIv: Bytes;
  readonly dekTag: Bytes;
  readonly kemId: string; // KEK key identifier
  readonly algorithm: SymmetricAlgorithm;
}

// ── Streaming ──────────────────────────────────────────────────────────────

export interface StreamEncryptOptions {
  readonly algorithm: 'AES-256-GCM' | 'CHACHA20-POLY1305' | 'XCHACHA20-POLY1305';
  readonly key: Bytes;
  readonly aad?: Bytes;
  readonly chunkSize?: number; // Default: 64 * 1024 (64 KB)
}

export interface StreamDecryptOptions {
  readonly algorithm: 'AES-256-GCM' | 'CHACHA20-POLY1305' | 'XCHACHA20-POLY1305';
  readonly key: Bytes;
  readonly aad?: Bytes;
  readonly chunkSize?: number;
}

// ── Audit log ──────────────────────────────────────────────────────────────

export interface AuditLogEntry {
  readonly timestamp: number; // Unix ms
  readonly operation: string; // 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'keygen' | ...
  readonly algorithm: string;
  readonly keyId?: string;
  readonly inputLength?: number;
  readonly outputLength?: number;
  readonly success: boolean;
  readonly errorCode?: string;
  readonly platform?: string;
  readonly eccBlock?: Bytes; // RS(255,239) parity block from LombokECC
}

// ── Platform ───────────────────────────────────────────────────────────────

export type Platform = 'node' | 'browser' | 'deno' | 'bun' | 'wasm' | 'embedded';

export interface PlatformCapabilities {
  readonly platform: Platform;
  readonly hasAesNi: boolean;
  readonly hasShaExtensions: boolean;
  readonly hasAvx2: boolean;
  readonly hasNeon: boolean;
  readonly hasSubtleCrypto: boolean;
  readonly hasHardwareRng: boolean;
  readonly hasHsm: boolean;
  readonly hasTpm: boolean;
  readonly hasSecureEnclave: boolean;
}
