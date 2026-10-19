/**
 * LombokEncryptDecrypt
 * Encrypt/decrypt toolkit for TypeScript (AEAD, hashes, MACs, KDFs, Ed25519, ECDH, KeyStore, streaming)
 *
 * @version 0.1.0
 * @license Apache-2.0
 * @author codinglombok
 * @see https://github.com/codinglombok/LombokEncryptDecrypt
 */

// ── Error classes ─────────────────────────────────────────────────────────
export { LombokCryptoError, ErrorCode } from './errors.js';

// ── Types ─────────────────────────────────────────────────────────────────
export type {
  Bytes, HexString, Base64String, PemString,
  SymmetricAlgorithm, HashAlgorithm, MacAlgorithm, KdfAlgorithm,
  AsymmetricAlgorithm, PQCAlgorithm,
  GlobalCryptoOptions,
  AeadEncryptOptions, AeadDecryptOptions, AeadResult,
  Argon2Options, ScryptOptions, Pbkdf2Options, HkdfOptions,
  KeyPair, KEMKeyPair, KEMResult,
  HpkeSuite, EnvelopeEncryptedKey,
  StreamEncryptOptions, StreamDecryptOptions,
  AuditLogEntry, Platform, PlatformCapabilities,
} from './types.js';

// ── Constants ─────────────────────────────────────────────────────────────
export {
  VERSION, LIBRARY_NAME,
  KEY_SIZES, IV_SIZES, TAG_SIZES, HASH_SIZES, PQC_SIZES, KDF_DEFAULTS,
  STREAM_CHUNK_SIZE,
} from './constants.js';

// ── Utilities ─────────────────────────────────────────────────────────────
export { timingSafeEqual, zeroize, ctSelect } from './utils/timing.js';
export { randomBytes, randomKey256, randomKey128, randomSalt } from './utils/random.js';
export {
  bytesToHex, hexToBytes,
  bytesToBase64, bytesToBase64Url, base64ToBytes,
  stringToBytes, bytesToString,
  concatBytes, xorBytes,
} from './utils/encoding.js';

// ── Platform ──────────────────────────────────────────────────────────────
export { getPlatformCapabilities, PLATFORM } from './platform/detect.js';

// ── Implemented in v0.1.0 (see docs/IMPLEMENTATION_STATUS.md) ──────────────
export * from './symmetric.js';
export * from './asymmetric.js';
export * from './hash.js';
export * from './mac.js';
export * from './kdf.js';
export * from './keystore.js';
export * from './stream.js';
export * from './audit.js';
export * as legacy from './legacy.js';
export { envelopeEncrypt } from './hybrid/envelope.js';

// ── NOT exported yet ──────────────────────────────────────────────────────
// Argon2 (RFC 9106) and ML-KEM-768 have source files but no working backend in
// v0.1.0 (they throw UNSUPPORTED_ALGORITHM), so they are deliberately not exported.
// Planned: ECDSA, RSA, SM2, ML-DSA, SLH-DSA, FALCON, BLAKE2/BLAKE3, FF1/FF3-1, HPKE,
// JWK/PEM/X.509, PKCS#11. Track progress in docs/IMPLEMENTATION_STATUS.md.
