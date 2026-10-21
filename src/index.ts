/**
 * LombokEncryptDecrypt — public API root.
 *
 * v0.1.0 (pre-release). Argon2 and ML-KEM are intentionally NOT exported:
 * they fail closed (see docs/IMPLEMENTATION_STATUS.md).
 */

// Errors
export { ErrorCode, LombokCryptoError } from './errors.js';

// Platform
export {
  PLATFORM,
  getPlatformCapabilities,
  getPlatformLabel,
  type PlatformCapabilities,
  type PlatformName,
} from './platform/index.js';

// Symmetric
export {
  aesGcm,
  aesGcmEncrypt,
  aesGcmDecrypt,
  type AesGcmOptions,
  type AeadEncryptResult,
} from './modes/gcm.js';
export {
  chaCha20Poly1305,
  xchaChaPoly1305,
  type ChaChaPolyOptions,
  type ChaChaEncryptResult,
} from './modes/chacha.js';
export { aesCbcEncrypt, aesCbcDecrypt, type AesCbcOptions } from './modes/cbc.js';
export { aesXtsEncrypt, aesXtsDecrypt } from './modes/xts.js';
export { sm4, sm4ExpandKey, sm4EncryptBlock, sm4DecryptBlock } from './core/sm/sm4.js';

// Hash
export { sha256, sha224, sha384, sha512 } from './core/sha/sha256.js';
export { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from './core/sha/sha3.js';
export { sm3, sm3Raw } from './core/sm/sm3.js';
export { blake3 } from './core/blake3/blake3.js';

// MAC
export { hmacSha256, hmacSha384, hmacSha512, hmac } from './mac/hmac.js';
export { cmac } from './mac/cmac.js';

// KDF
export { hkdf, hkdfDerive, type HkdfOptions } from './kdf/hkdf.js';
export { pbkdf2, pbkdf2Derive, type Pbkdf2Options } from './kdf/pbkdf2.js';
export { scryptDerive, type ScryptOptions } from './kdf/scrypt.js';

// Asymmetric
export { ed25519, type Ed25519KeyPair } from './core/ecc/ed25519.js';
export { ecdsaP256, ecdsaP384, ecdsaP521, type EcdsaKeyPair } from './core/ecc/ecdh.js';
export {
  ecdh,
  ecdhP256,
  ecdhP384,
  ecdhP521,
  ecdhX25519,
  ecdhX448,
  type OkpKeyPair,
} from './core/ecc/ecdh.js';

// Protocols
export { KeyStore, type KeyStoreCreateOptions } from './keystore/keystore.js';
export {
  envelopeEncrypt,
  type EncryptedKey,
  type EnvelopeEncryptResult,
} from './envelope/envelope.js';
export {
  createEncryptStream,
  createDecryptStream,
  encryptStreamGen,
  decryptStreamGen,
  type EncryptStream,
  type DecryptStream,
  type StreamOptions,
  type StreamAlgorithm,
} from './stream/encrypt_stream.js';
export { AuditLogger, type AuditEntry, type AuditInput } from './audit/audit.js';
export { legacy } from './legacy/legacy.js';

// Utilities
export {
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  bytesToBase64Url,
  base64UrlToBytes,
  stringToBytes,
  bytesToString,
  concatBytes,
  xorBytes,
  timingSafeEqual,
  zeroize,
} from './utils/encoding.js';
export {
  randomBytes,
  randomKey128,
  randomKey256,
  randomSalt,
  randomIv,
  getRandomInto,
} from './utils/random.js';
