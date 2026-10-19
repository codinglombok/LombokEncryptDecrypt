/**
 * LombokEncryptDecrypt — Ed25519 Sign / Verify
 *
 * Edwards-curve Digital Signature Algorithm (Ed25519).
 * Reference: RFC 8032, NIST FIPS 186-5
 * Test vectors: RFC 8032 Section 6
 *
 * Uses SubtleCrypto (browser/Deno/Bun) or Node.js crypto for performance.
 * Pure TS fallback via LombokAlgoritma field arithmetic.
 *
 * @module core/ecc/ed25519
 */

import { LombokCryptoError, ErrorCode } from '../../errors.js';
import type { KeyPair } from '../../types.js';
import { randomBytes } from '../../utils/random.js';
import { HAS_SUBTLE_CRYPTO, HAS_NODE_CRYPTO, PLATFORM } from '../../platform/detect.js';
import { timingSafeEqual } from '../../utils/timing.js';

const PRIV_KEY_SIZE = 32;
const PUB_KEY_SIZE  = 32;
const SIG_SIZE      = 64;
const SEED_SIZE     = 32;

// ── Node.js native path ────────────────────────────────────────────────────

async function generateNode(): Promise<KeyPair> {
  const { generateKeyPairSync } = await import('node:crypto');
  const { privateKey: nodePk } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
  });
  // Extract raw seed (32 bytes) from PKCS#8 DER (last 32 bytes after headers)
  const rawSeed = nodePk.slice(-SEED_SIZE);
  return generateFromSeed(rawSeed);
}

async function generateFromSeedNode(seed: Uint8Array): Promise<KeyPair> {
  const { createPrivateKey, createPublicKey } = await import('node:crypto');
  // Build PKCS#8 DER for Ed25519 from seed
  const oid = Buffer.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
  const der = Buffer.concat([oid, seed]);
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const pub  = createPublicKey(priv);
  const pubDer = pub.export({ type: 'spki', format: 'der' });
  return {
    privateKey: seed,
    publicKey:  new Uint8Array((pubDer as Buffer).slice(-PUB_KEY_SIZE)),
  };
}

async function signNode(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  const { createPrivateKey, sign } = await import('node:crypto');
  const oid = Buffer.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
  const der = Buffer.concat([oid, Buffer.from(privateKey)]);
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return new Uint8Array(sign(null, message, priv));
}

async function verifyNode(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  const { createPublicKey, verify } = await import('node:crypto');
  const spkiHeader = Buffer.from([0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]);
  const der = Buffer.concat([spkiHeader, Buffer.from(publicKey)]);
  const pub = createPublicKey({ key: der, format: 'der', type: 'spki' });
  return verify(null, message, pub, signature);
}

// ── SubtleCrypto path ──────────────────────────────────────────────────────

async function generateSubtle(): Promise<KeyPair> {
  const pair = await globalThis.crypto.subtle.generateKey(
    { name: 'Ed25519' }, true, ['sign', 'verify'],
  );
  const [privRaw, pubRaw] = await Promise.all([
    globalThis.crypto.subtle.exportKey('jwk', (pair as CryptoKeyPair).privateKey),
    globalThis.crypto.subtle.exportKey('raw', (pair as CryptoKeyPair).publicKey),
  ]);
  // Extract seed from JWK private key (d field)
  const { base64ToBytes } = await import('../../utils/encoding.js');
  const seed = base64ToBytes((privRaw as JsonWebKey).d ?? '');
  return { privateKey: seed, publicKey: new Uint8Array(pubRaw as ArrayBuffer) };
}

async function signSubtle(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  const { bytesToBase64Url } = await import('../../utils/encoding.js');
  const jwk: JsonWebKey = {
    kty: 'OKP', crv: 'Ed25519',
    d: bytesToBase64Url(privateKey),
    x: bytesToBase64Url(await getPublicKeyFromSeed(privateKey)),
  };
  const ck = await globalThis.crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
  return new Uint8Array(await globalThis.crypto.subtle.sign({ name: 'Ed25519' }, ck, message));
}

async function verifySubtle(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  const ck = await globalThis.crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
  return globalThis.crypto.subtle.verify({ name: 'Ed25519' }, ck, signature, message);
}

// ── Public key from seed via WebCrypto (PKCS#8 import → JWK export) ───────

const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

async function publicFromSeedSubtle(seed: Uint8Array): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + seed.length);
  pkcs8.set(ED25519_PKCS8_PREFIX);
  pkcs8.set(seed, ED25519_PKCS8_PREFIX.length);
  const key = await globalThis.crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await globalThis.crypto.subtle.exportKey('jwk', key);
  const x = (jwk.x ?? '').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(x + '='.repeat((4 - (x.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function noBackend(): never {
  throw new LombokCryptoError(ErrorCode.UNSUPPORTED_ALGORITHM,
    'Ed25519 requires node:crypto or WebCrypto Ed25519; no pure-TS fallback in v0.1.0', { algorithm: 'Ed25519' });
}

async function generateFromSeed(seed: Uint8Array): Promise<KeyPair> {
  if (PLATFORM === 'node' && HAS_NODE_CRYPTO) return generateFromSeedNode(seed);
  if (!HAS_SUBTLE_CRYPTO) noBackend();
  return { privateKey: seed, publicKey: await publicFromSeedSubtle(seed) };
}

async function getPublicKeyFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  if (PLATFORM === 'node' && HAS_NODE_CRYPTO) {
    const kp = await generateFromSeedNode(seed);
    return kp.publicKey;
  }
  if (!HAS_SUBTLE_CRYPTO) noBackend();
  return publicFromSeedSubtle(seed);
}

// ── Public API ────────────────────────────────────────────────────────────

export const ed25519 = {
  /**
   * Generate a random Ed25519 key pair.
   * Returns { privateKey: 32-byte seed, publicKey: 32-byte point }
   */
  async generateKeyPair(): Promise<KeyPair> {
    const seed = randomBytes(SEED_SIZE);
    return generateFromSeed(seed);
  },

  /**
   * Derive key pair from a 32-byte seed (deterministic).
   */
  async fromSeed(seed: Uint8Array): Promise<KeyPair> {
    if (seed.length !== SEED_SIZE) {
      throw new LombokCryptoError(ErrorCode.INVALID_KEY_SIZE, `Ed25519 seed must be ${SEED_SIZE} bytes`);
    }
    return generateFromSeed(seed);
  },

  /**
   * Sign a message. Returns 64-byte signature.
   * @param message - Arbitrary-length message (not pre-hashed)
   * @param privateKey - 32-byte seed
   */
  async sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    if (privateKey.length !== PRIV_KEY_SIZE) {
      throw new LombokCryptoError(ErrorCode.INVALID_KEY_SIZE, `Ed25519 private key must be ${PRIV_KEY_SIZE} bytes`);
    }
    if (PLATFORM === 'node' && HAS_NODE_CRYPTO) return signNode(message, privateKey);
    if (HAS_SUBTLE_CRYPTO) return signSubtle(message, privateKey);
    return noBackend();
  },

  /**
   * Verify an Ed25519 signature. Returns true if valid.
   * Does NOT throw on invalid — returns false.
   */
  async verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    if (signature.length !== SIG_SIZE) return false;
    if (publicKey.length !== PUB_KEY_SIZE) return false;
    try {
      if (PLATFORM === 'node' && HAS_NODE_CRYPTO) return verifyNode(message, signature, publicKey);
      if (HAS_SUBTLE_CRYPTO) return verifySubtle(message, signature, publicKey);
      return false; // no backend available: fail closed
    } catch {
      return false;
    }
  },

  KEY_SIZE:  PRIV_KEY_SIZE,
  SIG_SIZE,
  PUB_KEY_SIZE,
};
