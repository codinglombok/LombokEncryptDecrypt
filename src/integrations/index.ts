/**
 * Optional ecosystem integrations (Lombok Ecosystem — LombokRAGFrameworks).
 *
 * - `vector.ts`: encrypted vector embeddings ranked via `lombokvector`
 * - `simhash.ts`: plaintext SimHash fingerprints via `lomboksimhash`
 *
 * Both peer packages are OPTIONAL dependencies — each module dynamic-imports
 * its package and fails closed (UNSUPPORTED_ALGORITHM) when it is absent.
 *
 * @module integrations
 */

export {
  decryptVector,
  encryptVector,
  rankEncryptedVectors,
  type DecryptVectorOptions,
  type EncryptedVectorRecord,
  type EncryptVectorOptions,
  type LombokVectorLoader,
  type RankOptions,
  type VectorInput,
  type VectorRanking,
} from './vector.js';

export {
  fingerprintPlaintext,
  hammingDistance,
  type SimHashLoader,
  type SimHashOptions,
} from './simhash.js';
