/**
 * LombokEncryptDecrypt — streaming AEAD subpath.
 */

export {
  createEncryptStream,
  encryptStreamGen,
  STREAM_FLAG_MORE,
  STREAM_FLAG_LAST,
  type EncryptStream,
  type StreamOptions,
  type StreamAlgorithm,
} from './encrypt_stream.js';
export { createDecryptStream, decryptStreamGen, type DecryptStream } from './decrypt_stream.js';
