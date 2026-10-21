/**
 * LombokEncryptDecrypt — ECDSA (P-256/384/521) & ECDH (P-256/384/521,
 * X25519, X448) via platform crypto (node:crypto). Keys are raw byte
 * strings; the platform translation is contained here.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  diffieHellman,
  KeyObject,
} from 'node:crypto';
import { ErrorCode, LombokCryptoError } from '../../errors.js';

export type EcCurve = 'P-256' | 'P-384' | 'P-521';
export type OkpCurve = 'X25519' | 'X448';

interface CurveSpec {
  namedCurve: string;
  privateKeySize: number;
  publicKeySize: number;
  coordinateSize: number;
}

const EC_PUBLIC_KEY_OID = Uint8Array.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);

const EC_SPECS: Record<EcCurve, CurveSpec> = {
  'P-256': { namedCurve: 'prime256v1', privateKeySize: 32, publicKeySize: 65, coordinateSize: 32 },
  'P-384': { namedCurve: 'secp384r1', privateKeySize: 48, publicKeySize: 97, coordinateSize: 48 },
  'P-521': { namedCurve: 'secp521r1', privateKeySize: 66, publicKeySize: 133, coordinateSize: 66 },
};

const OKP_SPECS: Record<
  OkpCurve,
  { privateKeySize: number; publicKeySize: number; jwkAlg: string; jwkCrv: string }
> = {
  X25519: { privateKeySize: 32, publicKeySize: 32, jwkAlg: 'X25519', jwkCrv: 'X25519' },
  X448: { privateKeySize: 56, publicKeySize: 56, jwkAlg: 'X448', jwkCrv: 'X448' },
};

function concatBytesList(...lists: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const l of lists) total += l.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const l of lists) {
    out.set(l, offset);
    offset += l.length;
  }
  return out;
}

/** DER length octets — short form below 128, long form above. */
function derLength(length: number): Uint8Array {
  if (length < 0x80) return new Uint8Array([length]);
  if (length < 0x100) return new Uint8Array([0x81, length]);
  /* istanbul ignore next -- defensive: EC key structures never exceed 2 bytes of length */
  return new Uint8Array([0x82, (length >>> 8) & 0xff, length & 0xff]);
}

function derTagged(tag: number, content: Uint8Array): Uint8Array {
  return concatBytesList(new Uint8Array([tag]), derLength(content.length), content);
}

function derSequence(...parts: Uint8Array[]): Uint8Array {
  return derTagged(0x30, concatBytesList(...parts));
}

function derOctetString(data: Uint8Array): Uint8Array {
  return derTagged(0x04, data);
}

function ecCurveOid(curve: EcCurve): Uint8Array {
  if (curve === 'P-256')
    return new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
  if (curve === 'P-384') return new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);
  return new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]);
}

function ecPkcs8FromRaw(curve: EcCurve, privateKey: Uint8Array): Uint8Array {
  // AlgorithmIdentifier ::= SEQUENCE { ecPublicKey OID, namedCurve OID }
  const curveOid = ecCurveOid(curve);
  const algId = derSequence(EC_PUBLIC_KEY_OID, curveOid);
  // SEC1: ECPrivateKey ::= SEQUENCE { version(1), privateKey }
  const sec1 = derSequence(new Uint8Array([0x02, 0x01, 0x01]), derOctetString(privateKey));
  return derSequence(new Uint8Array([0x02, 0x01, 0x00]), algId, derOctetString(sec1));
}

function ecSpkiFromRaw(curve: EcCurve, publicKey: Uint8Array): Uint8Array {
  const algId = derSequence(EC_PUBLIC_KEY_OID, ecCurveOid(curve));
  const bitString = derTagged(0x03, concatBytesList(new Uint8Array([0x00]), publicKey));
  return derSequence(algId, bitString);
}

function assertEcPrivateKey(curve: EcCurve, key: Uint8Array): void {
  if (key.length !== EC_SPECS[curve].privateKeySize) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `${curve} private key must be ${EC_SPECS[curve].privateKeySize} bytes, got ${key.length}`,
      'ECDSA',
    );
  }
}

function assertEcPublicKey(curve: EcCurve, key: Uint8Array): void {
  if (key.length !== EC_SPECS[curve].publicKeySize) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `${curve} public key must be ${EC_SPECS[curve].publicKeySize} bytes (0x04 uncompressed), got ${key.length}`,
      'ECDSA',
    );
  }
  if (key[0] !== 0x04) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `${curve} public key must start with 0x04 (uncompressed)`,
      'ECDSA',
    );
  }
}

function ecKeyObjects(
  curve: EcCurve,
  privateKey: Uint8Array,
  publicKey?: Uint8Array,
): { priv: KeyObject; pub: KeyObject } {
  assertEcPrivateKey(curve, privateKey);
  const priv = createPrivateKey({
    key: Buffer.from(ecPkcs8FromRaw(curve, privateKey)),
    format: 'der',
    type: 'pkcs8',
  });
  let pub: KeyObject;
  if (publicKey !== undefined) {
    assertEcPublicKey(curve, publicKey);
    pub = createPublicKey({
      key: Buffer.from(ecSpkiFromRaw(curve, publicKey)),
      format: 'der',
      type: 'spki',
    });
  } else {
    pub = createPublicKey(priv);
  }
  return { priv, pub };
}

function rawEcPublic(curve: EcCurve, keyObject: KeyObject): Uint8Array {
  const buf = Buffer.from(keyObject.export({ format: 'der', type: 'spki' }));
  // uncompressed point: find 0x04 0x<len+1> 0x04 tail (last 2*coord+1 bytes)
  const size = EC_SPECS[curve].publicKeySize;
  return new Uint8Array(buf.subarray(buf.length - size));
}

function rawEcPrivate(curve: EcCurve, keyObject: KeyObject): Uint8Array {
  const jwk = keyObject.export({ format: 'jwk' }) as { d?: string };
  if (jwk.d === undefined)
    throw new LombokCryptoError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      'platform did not expose the private scalar',
      'ECDH',
    );
  const raw = new Uint8Array(Buffer.from(jwk.d, 'base64url'));
  const size = EC_SPECS[curve].privateKeySize;
  if (raw.length === size) return raw;
  const out = new Uint8Array(size);
  out.set(raw, size - raw.length);
  return out;
}

export interface EcdsaKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

function makeEcdsa(
  curve: EcCurve,
  algorithmName: 'sha256' | 'sha384' | 'sha512',
): {
  generateKeyPair(): Promise<EcdsaKeyPair>;
  sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
} {
  return {
    async generateKeyPair(): Promise<EcdsaKeyPair> {
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: EC_SPECS[curve].namedCurve,
      });
      return {
        privateKey: rawEcPrivate(curve, privateKey),
        publicKey: rawEcPublic(curve, publicKey),
      };
    },
    /** DER-encoded ECDSA signature (WebCrypto-compatible output). */
    async sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
      const { priv } = ecKeyObjects(curve, privateKey);
      return new Uint8Array(nodeSign(algorithmName, new Uint8Array(message), priv));
    },
    /** Never throws on invalid signature — returns false. */
    async verify(
      message: Uint8Array,
      signature: Uint8Array,
      publicKey: Uint8Array,
    ): Promise<boolean> {
      try {
        assertEcPublicKey(curve, publicKey);
        const pubOnly = createPublicKey({
          key: Buffer.from(ecSpkiFromRaw(curve, publicKey)),
          format: 'der',
          type: 'spki',
        });
        return nodeVerify(
          algorithmName,
          new Uint8Array(message),
          pubOnly,
          new Uint8Array(signature),
        );
      } catch {
        return false;
      }
    },
  };
}

/** ECDSA P-256 with SHA-256. */
export const ecdsaP256 = makeEcdsa('P-256', 'sha256');
/** ECDSA P-384 with SHA-384. */
export const ecdsaP384 = makeEcdsa('P-384', 'sha384');
/** ECDSA P-521 with SHA-512. */
export const ecdsaP521 = makeEcdsa('P-521', 'sha512');

const OKP_PKCS8_PREFIX: Record<OkpCurve, Uint8Array> = {
  X25519: Uint8Array.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
  ]),
  X448: Uint8Array.from([
    0x30, 0x46, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x04, 0x3a, 0x04, 0x38,
  ]),
};
const OKP_SPKI_PREFIX: Record<OkpCurve, Uint8Array> = {
  X25519: Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]),
  X448: Uint8Array.from([0x30, 0x42, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x03, 0x39, 0x00]),
};

function okpKeyObjects(
  curve: OkpCurve,
  privateKey?: Uint8Array,
  publicKey?: Uint8Array,
): { priv?: KeyObject; pub?: KeyObject } {
  const spec = OKP_SPECS[curve];
  const result: { priv?: KeyObject; pub?: KeyObject } = {};
  if (privateKey !== undefined) {
    if (privateKey.length !== spec.privateKeySize) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_KEY_SIZE,
        `${curve} private key must be ${spec.privateKeySize} bytes, got ${privateKey.length}`,
        curve,
      );
    }
    const der = concatBytesList(OKP_PKCS8_PREFIX[curve], privateKey);
    result.priv = createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' });
  }
  if (publicKey !== undefined) {
    if (publicKey.length !== spec.publicKeySize) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_KEY_SIZE,
        `${curve} public key must be ${spec.publicKeySize} bytes, got ${publicKey.length}`,
        curve,
      );
    }
    const der = concatBytesList(OKP_SPKI_PREFIX[curve], publicKey);
    result.pub = createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' });
  }
  return result;
}

export interface OkpKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

function makeOkp(curve: OkpCurve): {
  generateKeyPair(): Promise<OkpKeyPair>;
  computeSharedSecret(privateKey: Uint8Array, theirPublicKey: Uint8Array): Promise<Uint8Array>;
} {
  return {
    async generateKeyPair(): Promise<OkpKeyPair> {
      const generated =
        curve === 'X25519' ? generateKeyPairSync('x25519') : generateKeyPairSync('x448');
      const { privateKey } = generated;
      const jwk = privateKey.export({ format: 'jwk' }) as { d?: string; x?: string };
      if (jwk.d === undefined || jwk.x === undefined) {
        throw new LombokCryptoError(
          ErrorCode.UNSUPPORTED_ALGORITHM,
          `platform did not expose ${curve} key material`,
          curve,
        );
      }
      return {
        privateKey: new Uint8Array(Buffer.from(jwk.d, 'base64url')),
        publicKey: new Uint8Array(Buffer.from(jwk.x, 'base64url')),
      };
    },
    /** X25519/X448 shared secret (RFC 7748). Run through HKDF before use as a key. */
    async computeSharedSecret(
      privateKey: Uint8Array,
      theirPublicKey: Uint8Array,
    ): Promise<Uint8Array> {
      const { priv, pub } = okpKeyObjects(curve, privateKey, theirPublicKey);
      if (priv === undefined || pub === undefined) {
        throw new LombokCryptoError(
          ErrorCode.INVALID_KEY_SIZE,
          'both private and public keys are required',
          curve,
        );
      }
      try {
        return new Uint8Array(diffieHellman({ privateKey: priv, publicKey: pub }));
      } catch (e) {
        throw new LombokCryptoError(
          ErrorCode.INVALID_KEY_SIZE,
          `ECDH failed: ${(e as Error).message}`,
          curve,
        );
      }
    },
  };
}

/** X25519 key agreement (RFC 7748). */
export const ecdhX25519 = makeOkp('X25519');
/** X448 key agreement (RFC 7748). */
export const ecdhX448 = makeOkp('X448');

function makeEcdh(curve: EcCurve): {
  generateKeyPair(): Promise<EcdsaKeyPair>;
  computeSharedSecret(privateKey: Uint8Array, theirPublicKey: Uint8Array): Promise<Uint8Array>;
} {
  return {
    async generateKeyPair(): Promise<EcdsaKeyPair> {
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: EC_SPECS[curve].namedCurve,
      });
      return {
        privateKey: rawEcPrivate(curve, privateKey),
        publicKey: rawEcPublic(curve, publicKey),
      };
    },
    /** ECDH shared secret. Run through HKDF before use as a symmetric key. */
    async computeSharedSecret(
      privateKey: Uint8Array,
      theirPublicKey: Uint8Array,
    ): Promise<Uint8Array> {
      const { priv } = ecKeyObjects(curve, privateKey);
      assertEcPublicKey(curve, theirPublicKey);
      let pub: KeyObject;
      try {
        pub = createPublicKey({
          key: Buffer.from(ecSpkiFromRaw(curve, theirPublicKey)),
          format: 'der',
          type: 'spki',
        });
        return new Uint8Array(diffieHellman({ privateKey: priv, publicKey: pub }));
      } catch (e) {
        throw new LombokCryptoError(
          ErrorCode.INVALID_KEY_SIZE,
          `ECDH failed: ${(e as Error).message}`,
          curve,
        );
      }
    },
  };
}

/** ECDH P-256. */
export const ecdhP256 = makeEcdh('P-256');
/** ECDH P-384. */
export const ecdhP384 = makeEcdh('P-384');
/** ECDH P-521. */
export const ecdhP521 = makeEcdh('P-521');

/** Generic ECDH by curve name ('X25519' | 'X448' | 'P-256' | 'P-384' | 'P-521'). */
export const ecdh = {
  async computeSharedSecret(
    curve: EcCurve | OkpCurve,
    privateKey: Uint8Array,
    theirPublicKey: Uint8Array,
  ): Promise<Uint8Array> {
    if (curve === 'X25519') return ecdhX25519.computeSharedSecret(privateKey, theirPublicKey);
    if (curve === 'X448') return ecdhX448.computeSharedSecret(privateKey, theirPublicKey);
    return makeEcdh(curve).computeSharedSecret(privateKey, theirPublicKey);
  },
};
