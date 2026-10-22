/**
 * LombokEncryptDecrypt — Constants
 * @module constants
 */

export const VERSION = '0.1.0' as const;
export const LIBRARY_NAME = 'LombokEncryptDecrypt' as const;

// ── Key sizes (bytes) ──────────────────────────────────────────────────────
export const KEY_SIZES = {
  AES_128: 16,
  AES_192: 24,
  AES_256: 32,
  CHACHA20: 32,
  XCHACHA20: 32,
  SM4: 16,
  CAMELLIA_128: 16,
  CAMELLIA_256: 32,
  ZUC: 16,
  SNOW3G: 16,
} as const;

// ── IV / Nonce sizes (bytes) ────────────────────────────────────────────────
export const IV_SIZES = {
  AES_GCM: 12, // 96-bit recommended
  AES_CCM: 13, // 104-bit default
  AES_CTR: 16,
  AES_CBC: 16,
  CHACHA20: 12,
  XCHACHA20: 24, // 192-bit
  SM4_GCM: 12,
} as const;

// ── Tag sizes (bytes) ──────────────────────────────────────────────────────
export const TAG_SIZES = {
  GCM: 16,
  CCM: 16,
  EAX: 16,
  OCB3: 16,
  POLY1305: 16,
  CHACHA20_POLY1305: 16,
} as const;

// ── Hash output sizes (bytes) ─────────────────────────────────────────────
export const HASH_SIZES = {
  SHA224: 28,
  SHA256: 32,
  SHA384: 48,
  SHA512: 64,
  SHA512_224: 28,
  SHA512_256: 32,
  SHA3_224: 28,
  SHA3_256: 32,
  SHA3_384: 48,
  SHA3_512: 64,
  BLAKE2b: 64,
  BLAKE2s: 32,
  BLAKE3: 32,
  SM3: 32,
  WHIRLPOOL: 64,
} as const;

// ── PQC key / ciphertext sizes (bytes) ────────────────────────────────────
export const PQC_SIZES = {
  KYBER512_PK: 800,
  KYBER512_SK: 1632,
  KYBER512_CT: 768,
  KYBER512_SS: 32,

  KYBER768_PK: 1184,
  KYBER768_SK: 2400,
  KYBER768_CT: 1088,
  KYBER768_SS: 32,

  KYBER1024_PK: 1568,
  KYBER1024_SK: 3168,
  KYBER1024_CT: 1568,
  KYBER1024_SS: 32,

  DILITHIUM2_PK: 1312,
  DILITHIUM2_SK: 2528,
  DILITHIUM2_SIG: 2420,

  DILITHIUM3_PK: 1952,
  DILITHIUM3_SK: 4000,
  DILITHIUM3_SIG: 3293,

  DILITHIUM5_PK: 2592,
  DILITHIUM5_SK: 4864,
  DILITHIUM5_SIG: 4595,

  FALCON512_PK: 897,
  FALCON512_SK: 1281,
  FALCON512_SIG_MAX: 666,

  FALCON1024_PK: 1793,
  FALCON1024_SK: 2305,
  FALCON1024_SIG_MAX: 1280,
} as const;

// ── Default KDF parameters (OWASP 2024 recommendations) ───────────────────
export const KDF_DEFAULTS = {
  ARGON2ID: { m: 65536, t: 3, p: 4 }, // 64MB, 3 iterations, 4 parallel
  SCRYPT: { N: 65536, r: 8, p: 1 },
  PBKDF2: { iterations: 600_000, hash: 'SHA-256' as const },
  BCRYPT: { cost: 12 },
} as const;

// ── Streaming chunk size ───────────────────────────────────────────────────
export const STREAM_CHUNK_SIZE = 64 * 1024; // 64 KB default

// ── Audit log ─────────────────────────────────────────────────────────────
export const AUDIT_LOG_MAGIC = new Uint8Array([0x4c, 0x45, 0x44, 0x4c]); // 'LEDL'
export const AUDIT_LOG_VERSION = 1;
