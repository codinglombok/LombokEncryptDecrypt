/**
 * LombokEncryptDecrypt — ECDSA (NIST P-256 / P-384 / P-521) via platform WebCrypto.
 *
 * No pure-TypeScript fallback: if `crypto.subtle` is missing, operations throw
 * UNSUPPORTED_ALGORITHM (fail closed). Signatures are IEEE P1363 (r || s).
 *
 * @module core/ecc/ecdsa
 */

import { LombokCryptoError, ErrorCode } from '../../errors.js';

export type EcdsaCurve = 'P-256' | 'P-384' | 'P-521';
export type EcdsaHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

export interface EcdsaKeyPair {
  curve: EcdsaCurve;
  /** PKCS#8 DER */
  privateKey: Uint8Array;
  /** Uncompressed SEC1 point (0x04 || X || Y) */
  publicKey: Uint8Array;
}

const DEFAULT_HASH: Record<EcdsaCurve, EcdsaHash> = { 'P-256': 'SHA-256', 'P-384': 'SHA-384', 'P-521': 'SHA-512' };
const COORD: Record<EcdsaCurve, number> = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new LombokCryptoError(ErrorCode.UNSUPPORTED_ALGORITHM, 'ECDSA requires WebCrypto (crypto.subtle)');
  return s;
}

function checkCurve(curve: string): asserts curve is EcdsaCurve {
  if (!(curve in COORD)) throw new LombokCryptoError(ErrorCode.INVALID_PARAMETER, `ECDSA: unsupported curve ${curve}`);
}

const buf = (u: Uint8Array): ArrayBuffer => u.slice().buffer as ArrayBuffer;

export const ecdsa = {
  async generateKeyPair(curve: EcdsaCurve = 'P-256'): Promise<EcdsaKeyPair> {
    checkCurve(curve);
    const kp = await subtle().generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify']);
    const [priv, pub] = await Promise.all([
      subtle().exportKey('pkcs8', kp.privateKey),
      subtle().exportKey('raw', kp.publicKey),
    ]);
    return { curve, privateKey: new Uint8Array(priv), publicKey: new Uint8Array(pub) };
  },

  /** Sign `message` (hashed internally). Returns r||s (2 * coordinate size bytes). */
  async sign(curve: EcdsaCurve, privateKey: Uint8Array, message: Uint8Array, hash?: EcdsaHash): Promise<Uint8Array> {
    checkCurve(curve);
    let key: CryptoKey;
    try {
      key = await subtle().importKey('pkcs8', buf(privateKey), { name: 'ECDSA', namedCurve: curve }, false, ['sign']);
    } catch (e) {
      throw new LombokCryptoError(ErrorCode.INVALID_INPUT, 'ECDSA: invalid private key', { cause: e });
    }
    const sig = await subtle().sign({ name: 'ECDSA', hash: hash ?? DEFAULT_HASH[curve] }, key, buf(message));
    return new Uint8Array(sig);
  },

  /** Verify an r||s signature. Never throws on bad input: returns false. */
  async verify(curve: EcdsaCurve, publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array, hash?: EcdsaHash): Promise<boolean> {
    checkCurve(curve);
    if (signature.length !== 2 * COORD[curve]) return false;
    try {
      const key = await subtle().importKey('raw', buf(publicKey), { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
      return await subtle().verify({ name: 'ECDSA', hash: hash ?? DEFAULT_HASH[curve] }, key, buf(signature), buf(message));
    } catch {
      return false;
    }
  },
};
