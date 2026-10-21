/**
 * LombokEncryptDecrypt — SHA-2 public hash objects (async API).
 */

import { sha224Raw, sha256Raw, sha384Raw, sha512Raw } from './sha2.js';

async function digest(fn: (data: Uint8Array) => Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  return fn(data);
}

/** SHA-256 — 32-byte digest. */
export const sha256 = {
  async hash(data: Uint8Array): Promise<Uint8Array> {
    return digest(sha256Raw, data);
  },
};

/** SHA-224 — 28-byte digest. */
export const sha224 = {
  async hash(data: Uint8Array): Promise<Uint8Array> {
    return digest(sha224Raw, data);
  },
};

/** SHA-384 — 48-byte digest. */
export const sha384 = {
  async hash(data: Uint8Array): Promise<Uint8Array> {
    return digest(sha384Raw, data);
  },
};

/** SHA-512 — 64-byte digest. */
export const sha512 = {
  async hash(data: Uint8Array): Promise<Uint8Array> {
    return digest(sha512Raw, data);
  },
};
