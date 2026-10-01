/**
 * LombokEncryptDecrypt — ECDH Key Agreement
 * Supported curves: P-256, P-384, P-521, X25519, X448
 * Reference: RFC 8422, RFC 7748, NIST SP 800-56A
 * @module asym/ecdh
 */

import { LombokCryptoError, ErrorCode } from '../../errors.js';
import type { KeyPair } from '../../types.js';
import { HAS_SUBTLE_CRYPTO, HAS_NODE_CRYPTO, PLATFORM } from '../../platform/detect.js';

export type EcdhCurve = 'P-256' | 'P-384' | 'P-521' | 'X25519' | 'X448';

const CURVE_KEY_SIZES: Record<EcdhCurve, number> = {
  'P-256':  32, 'P-384': 48, 'P-521': 66,
  'X25519': 32, 'X448':  56,
};

const SHARED_SECRET_SIZES: Record<EcdhCurve, number> = {
  'P-256':  32, 'P-384': 48, 'P-521': 66,
  'X25519': 32, 'X448':  56,
};

// ── SubtleCrypto ECDH ────────────────────────────────────────────────────

async function generateSubtle(curve: EcdhCurve): Promise<KeyPair> {
  const algName = curve.startsWith('X') ? curve : 'ECDH';
  const params  = curve.startsWith('X') ? { name: curve } : { name: 'ECDH', namedCurve: curve };
  const pair = await globalThis.crypto.subtle.generateKey(params as EcKeyGenParams, true, ['deriveKey','deriveBits']);
  const [privJwk, pubRaw] = await Promise.all([
    globalThis.crypto.subtle.exportKey('jwk', (pair as CryptoKeyPair).privateKey),
    globalThis.crypto.subtle.exportKey('raw', (pair as CryptoKeyPair).publicKey),
  ]);
  const { base64ToBytes, bytesToBase64Url } = await import('../../utils/encoding.js');
  const priv = base64ToBytes((privJwk as JsonWebKey).d ?? '');
  return { privateKey: priv, publicKey: new Uint8Array(pubRaw as ArrayBuffer) };
}

async function deriveSubtle(curve: EcdhCurve, privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
  const { bytesToBase64Url } = await import('../../utils/encoding.js');
  const algName = curve.startsWith('X') ? curve : 'ECDH';

  let privCk: CryptoKey;
  if (curve.startsWith('X')) {
    privCk = await globalThis.crypto.subtle.importKey('raw', privateKey, { name: curve } as AlgorithmIdentifier, false, ['deriveBits']);
  } else {
    const jwk: JsonWebKey = { kty: 'EC', crv: curve, d: bytesToBase64Url(privateKey), key_ops: ['deriveBits'] };
    privCk = await globalThis.crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: curve }, false, ['deriveBits']);
  }

  let pubCk: CryptoKey;
  if (curve.startsWith('X')) {
    pubCk = await globalThis.crypto.subtle.importKey('raw', publicKey, { name: curve } as AlgorithmIdentifier, false, []);
  } else {
    pubCk = await globalThis.crypto.subtle.importKey('raw', publicKey, { name: 'ECDH', namedCurve: curve }, false, []);
  }

  const shared = await globalThis.crypto.subtle.deriveBits(
    { name: algName, public: pubCk } as EcdhKeyDeriveParams,
    privCk,
    SHARED_SECRET_SIZES[curve] * 8,
  );
  return new Uint8Array(shared);
}

// ── Node.js ECDH ──────────────────────────────────────────────────────────

async function generateNode(curve: EcdhCurve): Promise<KeyPair> {
  const { generateKeyPairSync } = await import('node:crypto');
  const nodeCurve = curve === 'X25519' ? 'x25519' : curve === 'X448' ? 'x448' : curve.toLowerCase();
  const { privateKey, publicKey } = generateKeyPairSync(nodeCurve as 'x25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding: { type: 'spki', format: 'der' },
  });
  const rawPriv = (privateKey as Buffer).slice(-CURVE_KEY_SIZES[curve]);
  const rawPub  = (publicKey as Buffer).slice(-CURVE_KEY_SIZES[curve] * (curve.startsWith('P') ? 2 + 1 : 1));
  return { privateKey: new Uint8Array(rawPriv), publicKey: new Uint8Array(rawPub) };
}

async function deriveNode(curve: EcdhCurve, privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
  const { createECDH } = await import('node:crypto');
  const nodeCurve = curve === 'P-256' ? 'prime256v1' : curve === 'P-384' ? 'secp384r1' : 'secp521r1';
  if (curve.startsWith('X')) {
    // Use Node.js crypto.diffieHellman for X25519/X448
    const { diffieHellman, createPrivateKey, createPublicKey } = await import('node:crypto');
    const privK = createPrivateKey({ key: privateKey, format: 'der', type: 'pkcs8' });
    const pubK  = createPublicKey({ key: publicKey, format: 'der', type: 'spki' });
    return new Uint8Array(diffieHellman({ privateKey: privK, publicKey: pubK }));
  }
  const dh = createECDH(nodeCurve);
  dh.setPrivateKey(Buffer.from(privateKey));
  return new Uint8Array(dh.computeSecret(Buffer.from(publicKey)));
}

// ── Public API ────────────────────────────────────────────────────────────

function makeCurve(curve: EcdhCurve) {
  return {
    /** Generate an ECDH key pair */
    async generateKeyPair(): Promise<KeyPair> {
      if (PLATFORM === 'node' && HAS_NODE_CRYPTO) return generateNode(curve);
      if (HAS_SUBTLE_CRYPTO) return generateSubtle(curve);
      // LombokAlgoritma fallback for P-256 / X25519
      const { ecdh } = await import('lombokalgoritma/math');
      return ecdh.generateKeyPair(curve);
    },

    /**
     * Compute shared secret.
     * Always run through HKDF before use as a key.
     */
    async computeSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
      if (PLATFORM === 'node' && HAS_NODE_CRYPTO) return deriveNode(curve, privateKey, publicKey);
      if (HAS_SUBTLE_CRYPTO) return deriveSubtle(curve, privateKey, publicKey);
      const { ecdh } = await import('lombokalgoritma/math');
      return ecdh.computeSharedSecret(curve, privateKey, publicKey);
    },

    CURVE: curve,
    KEY_SIZE: CURVE_KEY_SIZES[curve],
    SHARED_SECRET_SIZE: SHARED_SECRET_SIZES[curve],
  };
}

export const ecdhP256  = makeCurve('P-256');
export const ecdhP384  = makeCurve('P-384');
export const ecdhP521  = makeCurve('P-521');
export const ecdhX25519 = makeCurve('X25519');
export const ecdhX448   = makeCurve('X448');

/** Generic ECDH — choose curve at call time */
export const ecdh = {
  P256: ecdhP256, P384: ecdhP384, P521: ecdhP521, X25519: ecdhX25519, X448: ecdhX448,
  async generateKeyPair(curve: EcdhCurve): Promise<KeyPair> {
    return makeCurve(curve).generateKeyPair();
  },
  async computeSharedSecret(curve: EcdhCurve, priv: Uint8Array, pub: Uint8Array): Promise<Uint8Array> {
    return makeCurve(curve).computeSharedSecret(priv, pub);
  },
};
