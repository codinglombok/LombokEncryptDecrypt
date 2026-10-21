/**
 * LombokEncryptDecrypt — streaming AEAD subpath.
 */

export {
  createEncryptStream,
  createDecryptStream,
  encryptStreamGen,
  decryptStreamGen,
  type EncryptStream,
  type DecryptStream,
  type StreamOptions,
  type StreamAlgorithm,
} from './encrypt_stream.js';
