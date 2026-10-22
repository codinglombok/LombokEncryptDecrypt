/**
 * LombokEncryptDecrypt — ECDH Key Agreement
 * Supported curves: P-256, P-384, P-521, X25519, X448
 * Reference: RFC 8422, RFC 7748, NIST SP 800-56A
 * @module asym/ecdh
 */

import { LombokCryptoError, ErrorCode } from '../errors.js';
import type { KeyPair } from '../types.js';
import { HAS_SUBTLE_CRYPTO, HAS_NODE_CRYPTO, PLATFORM } from '../platform/detect.js';

export type EcdhCurve = 'P-256' | 'P-384' | 'P-521' | 'X25519' | 'X448';

const CURVE_KEY_SIZES: Record<EcdhCurve, number> = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  X25519: 32,
  X448: 56,
};

const SHARED_SECRET_SIZES: Record<EcdhCurve, number> = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  X25519: 32,
  X448: 56,
};

// ── SubtleCrypto ECDH ────────────────────────────────────────────────────

async function generateSubtle(curve: EcdhCurve): Promise<KeyPair> {
  const params = curve.startsWith('X') ? { name: curve } : { name: 'ECDH', namedCurve: curve };
  const pair = await globalThis.crypto.subtle.generateKey(params as EcKeyGenParams, true, [
    'deriveKey',
    'deriveBits',
  ]);
  const [privJwk, pubRaw] = await Promise.all([
    globalThis.crypto.subtle.exportKey('jwk', (pair as CryptoKeyPair).privateKey),
    globalThis.crypto.subtle.exportKey('raw', (pair as CryptoKeyPair).publicKey),
  ]);
  const { base64ToBytes } = await import('../utils/encoding.js');
  const priv = base64ToBytes((privJwk as JsonWebKey).d ?? '');
  return { privateKey: priv, publicKey: new Uint8Array(pubRaw as ArrayBuffer) };
}

async function deriveSubtle(
  curve: EcdhCurve,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Promise<Uint8Array> {
  const { bytesToBase64Url } = await import('../utils/encoding.js');
  const algName = curve.startsWith('X') ? curve : 'ECDH';

  let privCk: CryptoKey;
  if (curve.startsWith('X')) {
    privCk = await globalThis.crypto.subtle.importKey(
      'raw',
      privateKey,
      { name: curve } as AlgorithmIdentifier,
      false,
      ['deriveBits'],
    );
  } else {
    const jwk: JsonWebKey = {
      kty: 'EC',
      crv: curve,
      d: bytesToBase64Url(privateKey),
      key_ops: ['deriveBits'],
    };
    privCk = await globalThis.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDH', namedCurve: curve },
      false,
      ['deriveBits'],
    );
  }

  let pubCk: CryptoKey;
  if (curve.startsWith('X')) {
    pubCk = await globalThis.crypto.subtle.importKey(
      'raw',
      publicKey,
      { name: curve } as AlgorithmIdentifier,
      false,
      [],
    );
  } else {
    pubCk = await globalThis.crypto.subtle.importKey(
      'raw',
      publicKey,
      { name: 'ECDH', namedCurve: curve },
      false,
      [],
    );
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
  const { base64UrlToBytes } = await import('../utils/encoding.js');
  // Generate KeyObjects and export through JWK — never slice DER: the PKCS#8
  // ECPrivateKey (RFC 5915) carries the public point as its LAST field, so
  // tail-slicing the DER yields point bytes, not the scalar.
  const kp =
    curve === 'X25519'
      ? generateKeyPairSync('x25519')
      : curve === 'X448'
        ? generateKeyPairSync('x448')
        : generateKeyPairSync('ec', {
            namedCurve:
              curve === 'P-256' ? 'prime256v1' : curve === 'P-384' ? 'secp384r1' : 'secp521r1',
          });
  const jwkPriv = kp.privateKey.export({ format: 'jwk' });
  const jwkPub = kp.publicKey.export({ format: 'jwk' });
  const priv = base64UrlToBytes(String(jwkPriv.d ?? ''));
  let pub: Uint8Array;
  if (curve.startsWith('P')) {
    const x = base64UrlToBytes(String(jwkPub.x ?? ''));
    const y = base64UrlToBytes(String(jwkPub.y ?? ''));
    pub = new Uint8Array(1 + x.length + y.length);
    pub[0] = 0x04;
    pub.set(x, 1);
    pub.set(y, 1 + x.length);
  } else {
    pub = base64UrlToBytes(String(jwkPub.x ?? ''));
  }
  return { privateKey: priv, publicKey: pub };
}

async function deriveNode(
  curve: EcdhCurve,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Promise<Uint8Array> {
  const { diffieHellman, createPrivateKey, createPublicKey } = await import('node:crypto');
  const { bytesToBase64Url } = await import('../utils/encoding.js');
  if (curve.startsWith('X')) {
    // Raw OKP keys: import through JWK (RFC 8410). node:crypto accepts JWK
    // for X25519/X448, which keeps generateKeyPair()/computeSharedSecret()
    // consistent on raw byte keys (no DER wrapper mismatch).
    // RFC 8037 OKP JWKs carry the public part (x) alongside d.
    const privK = createPrivateKey({
      key: {
        kty: 'OKP',
        crv: curve,
        x: bytesToBase64Url(publicKey),
        d: bytesToBase64Url(privateKey),
      },
      format: 'jwk',
    });
    const pubK = createPublicKey({
      key: { kty: 'OKP', crv: curve, x: bytesToBase64Url(publicKey) },
      format: 'jwk',
    });
    return new Uint8Array(diffieHellman({ privateKey: privK, publicKey: pubK }));
  }
  // P-curves: public key = uncompressed point (0x04 || X || Y). Import both
  // sides through JWK — createECDH().setPrivateKey(rawScalar) does not round
  // -trip the scalar reliably, while JWK import validates the key on-curve.
  const point = publicKey.subarray(1);
  const x = bytesToBase64Url(point.subarray(0, CURVE_KEY_SIZES[curve]));
  const y = bytesToBase64Url(point.subarray(CURVE_KEY_SIZES[curve]));
  const privK = createPrivateKey({
    key: { kty: 'EC', crv: curve, x, y, d: bytesToBase64Url(privateKey) },
    format: 'jwk',
  });
  const pubK = createPublicKey({
    key: { kty: 'EC', crv: curve, x, y },
    format: 'jwk',
  });
  return new Uint8Array(diffieHellman({ privateKey: privK, publicKey: pubK }));
}

// ── Public API ────────────────────────────────────────────────────────────

export interface EcdhCurveHandle {
  readonly CURVE: EcdhCurve;
  readonly KEY_SIZE: number;
  readonly SHARED_SECRET_SIZE: number;
  generateKeyPair(): Promise<KeyPair>;
  computeSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array>;
}

function makeCurve(curve: EcdhCurve): EcdhCurveHandle {
  return {
    /** Generate an ECDH key pair */
    async generateKeyPair(): Promise<KeyPair> {
      if (PLATFORM === 'node' && HAS_NODE_CRYPTO) return generateNode(curve);
      if (HAS_SUBTLE_CRYPTO) return generateSubtle(curve);
      throw new LombokCryptoError(
        ErrorCode.UNSUPPORTED_ALGORITHM,
        'ECDH requires WebCrypto or node:crypto in v0.1.0',
        { algorithm: `ECDH-${curve}` },
      );
    },

    /**
     * Compute shared secret.
     * Always run through HKDF before use as a key.
     */
    async computeSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
      if (PLATFORM === 'node' && HAS_NODE_CRYPTO) return deriveNode(curve, privateKey, publicKey);
      if (HAS_SUBTLE_CRYPTO) return deriveSubtle(curve, privateKey, publicKey);
      throw new LombokCryptoError(
        ErrorCode.UNSUPPORTED_ALGORITHM,
        'ECDH requires WebCrypto or node:crypto in v0.1.0',
        { algorithm: `ECDH-${curve}` },
      );
    },

    CURVE: curve,
    KEY_SIZE: CURVE_KEY_SIZES[curve],
    SHARED_SECRET_SIZE: SHARED_SECRET_SIZES[curve],
  };
}

export const ecdhP256 = makeCurve('P-256');
export const ecdhP384 = makeCurve('P-384');
export const ecdhP521 = makeCurve('P-521');
export const ecdhX25519 = makeCurve('X25519');
export const ecdhX448 = makeCurve('X448');

/** Generic ECDH — choose curve at call time */
export const ecdh = {
  P256: ecdhP256,
  P384: ecdhP384,
  P521: ecdhP521,
  X25519: ecdhX25519,
  X448: ecdhX448,
  async generateKeyPair(curve: EcdhCurve): Promise<KeyPair> {
    return makeCurve(curve).generateKeyPair();
  },
  async computeSharedSecret(
    curve: EcdhCurve,
    priv: Uint8Array,
    pub: Uint8Array,
  ): Promise<Uint8Array> {
    return makeCurve(curve).computeSharedSecret(priv, pub);
  },
};
