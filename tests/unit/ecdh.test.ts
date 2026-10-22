/**
 * LombokEncryptDecrypt — ECDH key agreement tests (src/asym/ecdh.ts).
 *
 * P-curves: roundtrip + symmetry + node:crypto cross-check.
 * OKP curves (X25519/X448): raw-key roundtrip, symmetry, RFC 7748 §6.1 vector.
 */
import { diffieHellman, generateKeyPairSync } from 'node:crypto';
import { ecdh, ecdhP256 } from '../../src/asym/ecdh.js';
import { bytesToHex, hexToBytes } from '../../src/utils/encoding.js';

const SIZES = { 'P-256': 32, 'P-384': 48, 'P-521': 66, X25519: 32, X448: 56 } as const;

// Bun's node:crypto does not implement X448 key generation — probe, don't assume.
const HAS_X448 = (() => {
  try {
    generateKeyPairSync('x448');
    return true;
  } catch {
    return false;
  }
})();
const OKP_CURVES = HAS_X448 ? (['X25519', 'X448'] as const) : (['X25519'] as const);

describe('ECDH (asym/ecdh)', () => {
  it.each(['P-256', 'P-384', 'P-521'] as const)('%s: roundtrip and symmetry', async (curve) => {
    const a = await ecdh.generateKeyPair(curve);
    const b = await ecdh.generateKeyPair(curve);
    expect(a.privateKey.length).toBe(SIZES[curve]);
    expect(a.publicKey.length).toBe(1 + 2 * SIZES[curve]); // 0x04 || X || Y
    const s1 = await ecdh.computeSharedSecret(curve, a.privateKey, b.publicKey);
    const s2 = await ecdh.computeSharedSecret(curve, b.privateKey, a.publicKey);
    expect(s1.length).toBe(SIZES[curve]);
    expect(bytesToHex(s1)).toBe(bytesToHex(s2));
  });

  it.each(OKP_CURVES)('%s: raw-key roundtrip and symmetry', async (curve) => {
    const a = await ecdh.generateKeyPair(curve);
    const b = await ecdh.generateKeyPair(curve);
    expect(a.privateKey.length).toBe(SIZES[curve]);
    expect(a.publicKey.length).toBe(SIZES[curve]);
    const s1 = await ecdh.computeSharedSecret(curve, a.privateKey, b.publicKey);
    const s2 = await ecdh.computeSharedSecret(curve, b.privateKey, a.publicKey);
    expect(bytesToHex(s1)).toBe(bytesToHex(s2));
  });

  it('X25519 agrees with node:crypto on independently generated keys', async () => {
    const a = generateKeyPairSync('x25519');
    const b = generateKeyPairSync('x25519');
    const expected = diffieHellman({ privateKey: a.privateKey, publicKey: b.publicKey });
    // Raw private = last 32 bytes of the PKCS#8 DER; raw public = last 32 of SPKI.
    const rawPriv = new Uint8Array(a.privateKey.export({ format: 'der', type: 'pkcs8' })).slice(
      -32,
    );
    const rawPub = new Uint8Array(b.publicKey.export({ format: 'der', type: 'spki' })).slice(-32);
    const shared = await ecdh.computeSharedSecret('X25519', rawPriv, rawPub);
    expect(bytesToHex(shared)).toBe(bytesToHex(new Uint8Array(expected)));
  });

  it('X25519 matches the RFC 7748 §6.1 shared secret', async () => {
    const alicePriv = hexToBytes(
      '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
    );
    const bobPub = hexToBytes('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    const shared = await ecdh.computeSharedSecret('X25519', alicePriv, bobPub);
    expect(bytesToHex(shared)).toBe(
      '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
    );
  });

  it('curve handles expose metadata and per-curve helpers', async () => {
    expect(ecdhP256.CURVE).toBe('P-256');
    expect(ecdhP256.KEY_SIZE).toBe(32);
    expect(ecdhP256.SHARED_SECRET_SIZE).toBe(32);
    const a = await ecdhP256.generateKeyPair();
    const b = await ecdhP256.generateKeyPair();
    const s = await ecdhP256.computeSharedSecret(a.privateKey, b.publicKey);
    expect(s.length).toBe(32);
  });
});
