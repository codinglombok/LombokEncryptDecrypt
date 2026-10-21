/**
 * LombokEncryptDecrypt — Argon2id (RFC 9106) — FAILS CLOSED.
 *
 * v0.1.0 does not ship an Argon2 implementation: every operation throws
 * UNSUPPORTED_ALGORITHM. The module exists so code that imports the deep
 * path (benchmarks, ports) compiles and fails predictably instead of
 * silently falling back to a weaker KDF.
 */

import { ErrorCode, LombokCryptoError } from '../errors.js';

export interface Argon2Options {
  m?: number;
  t?: number;
  p?: number;
  hashLength?: number;
}

function fail(method: string): never {
  throw new LombokCryptoError(
    ErrorCode.UNSUPPORTED_ALGORITHM,
    `Argon2id ${method} is not implemented in v0.1.0 and fails closed`,
    'Argon2id',
  );
}

/** Fail-closed Argon2id stub — see IMPLEMENTATION_STATUS.md. */
export const argon2id = {
  async hash(password: string | Uint8Array, options?: Argon2Options): Promise<string> {
    void password;
    void options;
    fail('hash');
  },
  async verify(phcHash: string, password: string | Uint8Array): Promise<boolean> {
    void phcHash;
    void password;
    fail('verify');
  },
  async raw(
    password: string | Uint8Array,
    salt: Uint8Array,
    options?: Argon2Options,
  ): Promise<Uint8Array> {
    void password;
    void salt;
    void options;
    fail('raw');
  },
};
