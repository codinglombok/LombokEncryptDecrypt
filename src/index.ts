/**
 * LombokEncryptDecrypt
 * Universal Encrypt/Decrypt Library — 50+ Algorithms, 12 Languages
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

// ── Implemented and tested (known-answer + differential tests in tests/unit/pdf_primitives.test.ts) ──
export { createAes, expandKey, aesEncryptBlock, aesDecryptBlock } from './core/aes/aes.js';
export type { AesCore } from './core/aes/aes.js';
export { aesCbc, aesEcb } from './modes/cbc.js';
export type { BlockPadding, CbcOptions } from './modes/cbc.js';
export { sha256, sha224 } from './core/sha/sha256.js';
export { sha384, sha512 } from './core/sha/sha512.js';
/** Legacy algorithms (MD5, RC4) for reading old formats only. */
export * as legacy from './legacy/index.js';

// ── Symmetric ciphers ─────────────────────────────────────────────────────
// (modules implemented progressively — re-exported when ready)
// export { aesGcm } from './modes/gcm.js';
// export { chaCha20Poly1305 } from './core/chacha/chacha20.js';
// export { xchaChaPoly1305 } from './core/chacha/xchacha20.js';
// export { sm4Gcm } from './core/sm/sm4.js';

// ── Hash functions ────────────────────────────────────────────────────────
// export { sha3_256, sha3_512 } from './core/sha/sha3.js';  (sha256/384/512 exported above)
// export { blake2b, blake2s, blake3 } from './core/sha/blake3.js';
// export { sm3 } from './core/sm/sm3.js';

// ── MAC ───────────────────────────────────────────────────────────────────
// export { hmacSha256, hmacSha512 } from './mac/hmac.js';
// export { cmacAes } from './mac/cmac.js';
// export { poly1305 } from './mac/poly1305.js';

// ── KDF ───────────────────────────────────────────────────────────────────
// export { pbkdf2 } from './kdf/pbkdf2.js';
// export { scrypt } from './kdf/scrypt.js';
// export { argon2id, argon2i, argon2d } from './kdf/argon2.js';
// export { hkdf } from './kdf/hkdf.js';

// ── Asymmetric ────────────────────────────────────────────────────────────
// export { ecdh } from './asym/ecdh.js';
// export { ecdsa } from './asym/ecdsa.js';
// export { ed25519 } from './core/ecc/ed25519.js';
// export { ed448 } from './core/ecc/ed448.js';
// export { rsaOaep, rsaPss } from './core/rsa/rsa_core.js';
// export { sm2 } from './core/sm/sm2.js';

// ── Post-Quantum ──────────────────────────────────────────────────────────
// export { kyber512, kyber768, kyber1024 } from './pq/kyber/index.js';
// export { dilithium2, dilithium3, dilithium5 } from './pq/dilithium/index.js';
// export { sphincsPlus } from './pq/sphincs/sphincsplus.js';
// export { falcon512, falcon1024 } from './pq/falcon/index.js';

// ── Hybrid / Protocol ─────────────────────────────────────────────────────
// export { hpke } from './hybrid/hpke.js';
// export { ecies } from './hybrid/ecies_full.js';
// export { envelopeEncrypt, envelopeDecrypt } from './hybrid/envelope.js';

// ── Key Management ────────────────────────────────────────────────────────
// export { KeyStore } from './keystore/keystore.js';
// export { KeyRing } from './keystore/keyring.js';
// export { importJwk, exportJwk } from './keystore/jwk.js';
// export { parsePem, serializePem } from './keystore/pem.js';
// export { parseX509, verifyX509Chain } from './keystore/x509.js';

// ── Streaming ─────────────────────────────────────────────────────────────
// export { encryptStream, decryptStream } from './stream/index.js';

// ── Audit Log ─────────────────────────────────────────────────────────────
// export { AuditLogger } from './audit/logger.js';
// export { readAuditLog, verifyAuditLog } from './audit/reader.js';

// ── Special-purpose ───────────────────────────────────────────────────────
// export { ff1Encrypt, ff1Decrypt } from './modes/fpe_ff1.js';
// export { ff3Encrypt, ff3Decrypt } from './modes/fpe_ff3.js';
// export { xtsEncrypt, xtsDecrypt } from './modes/xts.js';
// export { aesKeyWrap, aesKeyUnwrap } from './core/rsa/keywrap.js';
