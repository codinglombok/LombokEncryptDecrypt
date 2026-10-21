/**
 * LombokEncryptDecrypt — Ed25519 (RFC 8032 / FIPS 186-5) via platform crypto.
 *
 * Keys are exposed as raw 32-byte seeds / 32-byte compressed points and
 * translated to/from PKCS#8 / SPKI DER on the fly. Signatures are 64 bytes,
 * deterministic. Verify NEVER throws on invalid input — it returns false.
 */

import {
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
  generateKeyPairSync,
  randomBytes,
  KeyObject,
} from 'node:crypto';
import { ErrorCode, LombokCryptoError } from '../../errors.js';

const SEED_SIZE = 32;
const PUB_SIZE = 32;
const SIG_SIZE = 64;

const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function assertSeed(seed: Uint8Array): void {
  if (seed.length !== SEED_SIZE) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `Ed25519 private key (seed) must be ${SEED_SIZE} bytes, got ${seed.length}`,
      'Ed25519',
    );
  }
}

function privateKeyObjectFromSeed(seed: Uint8Array): KeyObject {
  const der = new Uint8Array(PKCS8_PREFIX.length + SEED_SIZE);
  der.set(PKCS8_PREFIX);
  der.set(seed, PKCS8_PREFIX.length);
  return createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' });
}

function publicKeyObjectFromRaw(publicKey: Uint8Array): KeyObject {
  const der = new Uint8Array(SPKI_PREFIX.length + PUB_SIZE);
  der.set(SPKI_PREFIX);
  der.set(publicKey, SPKI_PREFIX.length);
  return createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' });
}

export interface Ed25519KeyPair {
  /** 32-byte seed. */
  privateKey: Uint8Array;
  /** 32-byte compressed Edwards point. */
  publicKey: Uint8Array;
}

export const ed25519 = {
  /** Generate a fresh key pair (32-byte seed + 32-byte public key). */
  async generateKeyPair(): Promise<Ed25519KeyPair> {
    const { privateKey } = generateKeyPairSync('ed25519');
    const jwk = privateKey.export({ format: 'jwk' }) as { d?: string };
    if (jwk.d === undefined) {
      throw new LombokCryptoError(
        ErrorCode.UNSUPPORTED_ALGORITHM,
        'platform did not expose the Ed25519 seed',
        'Ed25519',
      );
    }
    const seed = new Uint8Array(Buffer.from(jwk.d, 'base64url'));
    const kp = await ed25519.fromSeed(seed);
    return { privateKey: kp.privateKey, publicKey: kp.publicKey };
  },

  /** Expand a 32-byte seed into its key pair (deterministic). */
  async fromSeed(seed: Uint8Array): Promise<Ed25519KeyPair> {
    assertSeed(seed);
    const privateKeyObject = privateKeyObjectFromSeed(seed);
    const jwk = privateKeyObject.export({ format: 'jwk' }) as { x?: string };
    if (jwk.x === undefined) {
      throw new LombokCryptoError(
        ErrorCode.UNSUPPORTED_ALGORITHM,
        'platform did not expose the Ed25519 public key',
        'Ed25519',
      );
    }
    const publicKey = new Uint8Array(Buffer.from(jwk.x, 'base64url'));
    return { privateKey: new Uint8Array(seed), publicKey };
  },

  /** Deterministic 64-byte signature over the message. */
  async sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    assertSeed(privateKey);
    const keyObject = privateKeyObjectFromSeed(privateKey);
    return new Uint8Array(nodeSign(null, new Uint8Array(message), keyObject));
  },

  /** Constant verification contract: returns false on any invalid input. */
  async verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ): Promise<boolean> {
    if (signature.length !== SIG_SIZE) return false;
    if (publicKey.length !== PUB_SIZE) return false;
    try {
      const keyObject = publicKeyObjectFromRaw(publicKey);
      return nodeVerify(null, new Uint8Array(message), keyObject, new Uint8Array(signature));
    } catch {
      /* istanbul ignore next -- defensive: node rejects only structurally broken DER, which the 32-byte length rule above already prevents */
      return false;
    }
  },

  /** Seed for testing/keystores (kept for symmetry with the async API). */
  randomSeed(): Uint8Array {
    return randomBytes(SEED_SIZE);
  },
};
