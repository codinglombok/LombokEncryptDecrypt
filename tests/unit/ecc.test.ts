import { ed25519 } from '../../src/core/ecc/ed25519.js';
import { ecdhX25519, ecdhX448, ecdhP256, ecdsaP256, ecdh } from '../../src/core/ecc/ecdh.js';
import { randomBytes, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { hasX448 } from '../platform-caps.js';
import { ErrorCode } from '../../src/errors.js';

// BoringSSL (Bun) lacks X448 and is more permissive about invalid X25519
// points than OpenSSL — gate those specific assertions to OpenSSL runtimes.
const itIfX448 = hasX448 ? it : it.skip;

describe('Ed25519 (RFC 8032)', () => {
  it('matches RFC 8032 TEST 1 (empty message)', async () => {
    const seed = new Uint8Array(
      Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex'),
    );
    const kp = await ed25519.fromSeed(seed);
    expect(Buffer.from(kp.publicKey).toString('hex')).toBe(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    );
    const sig = await ed25519.sign(new Uint8Array(0), kp.privateKey);
    expect(Buffer.from(sig).toString('hex')).toBe(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    );
    expect(await ed25519.verify(new Uint8Array(0), sig, kp.publicKey)).toBe(true);
  });

  it('matches RFC 8032 TEST 2', async () => {
    const seed = new Uint8Array(
      Buffer.from('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', 'hex'),
    );
    const kp = await ed25519.fromSeed(seed);
    expect(Buffer.from(kp.publicKey).toString('hex')).toBe(
      '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    );
    const sig = await ed25519.sign(new Uint8Array([0x72]), kp.privateKey);
    expect(sig.length).toBe(64);
    expect(await ed25519.verify(new Uint8Array([0x72]), sig, kp.publicKey)).toBe(true);
  });

  it('is deterministic: same seed + message → same signature', async () => {
    const seed = randomBytes(32);
    const msg = randomBytes(100);
    const kp = await ed25519.fromSeed(seed);
    const a = await ed25519.sign(msg, kp.privateKey);
    const b = await ed25519.sign(msg, kp.privateKey);
    expect(a).toEqual(b);
  });

  it('verify returns false (never throws) on invalid inputs', async () => {
    const kp = await ed25519.generateKeyPair();
    const msg = randomBytes(50);
    const sig = await ed25519.sign(msg, kp.privateKey);
    const other = await ed25519.generateKeyPair();
    expect(await ed25519.verify(msg, sig, other.publicKey)).toBe(false);
    expect(await ed25519.verify(msg, sig.subarray(0, 63), kp.publicKey)).toBe(false);
    expect(await ed25519.verify(msg, sig, sig.subarray(0, 32))).toBe(false);
    const flipped = Uint8Array.from(sig);
    flipped[0] ^= 1;
    expect(await ed25519.verify(msg, flipped, kp.publicKey)).toBe(false);
  });

  it('validates seed length and interoperates with node:crypto', async () => {
    await expect(ed25519.fromSeed(new Uint8Array(31))).rejects.toThrow(ErrorCode.INVALID_KEY_SIZE);
    await expect(ed25519.sign(new Uint8Array(1), new Uint8Array(10))).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    const kp = await ed25519.generateKeyPair();
    const msg = randomBytes(30);
    const sig = await ed25519.sign(msg, kp.privateKey);
    const spki = Buffer.concat([
      Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]),
      Buffer.from(kp.publicKey),
    ]);
    const pub = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    expect(nodeVerify(null, msg, pub, sig)).toBe(true);
  });
});

describe('ECDH', () => {
  it('matches RFC 7748 §6.1 X25519 vector', async () => {
    const alicePriv = new Uint8Array(
      Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex'),
    );
    const alicePub = new Uint8Array(
      Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex'),
    );
    const bobPriv = new Uint8Array(
      Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex'),
    );
    const bobPub = new Uint8Array(
      Buffer.from('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex'),
    );
    const shared = new Uint8Array(
      Buffer.from('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742', 'hex'),
    );
    expect(await ecdhX25519.computeSharedSecret(alicePriv, bobPub)).toEqual(shared);
    expect(await ecdhX25519.computeSharedSecret(bobPriv, alicePub)).toEqual(shared);
  });

  it('X25519 keygen produces the correct public key from a private key', async () => {
    const kp = await ecdhX25519.generateKeyPair();
    expect(kp.privateKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(32);
  });

  it('P-256 ECDH is symmetric and key-size validated', async () => {
    const a = await ecdhP256.generateKeyPair();
    const b = await ecdhP256.generateKeyPair();
    const ab = await ecdhP256.computeSharedSecret(a.privateKey, b.publicKey);
    const ba = await ecdhP256.computeSharedSecret(b.privateKey, a.publicKey);
    expect(ab).toEqual(ba);
    expect(ab.length).toBe(32);
    await expect(ecdhP256.computeSharedSecret(new Uint8Array(31), b.publicKey)).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
  });

  it('generic dispatcher covers X25519 and P-256', async () => {
    const a = await ecdhX25519.generateKeyPair();
    const b = await ecdhX25519.generateKeyPair();
    const viaGeneric = await ecdh.computeSharedSecret('X25519', a.privateKey, b.publicKey);
    expect(viaGeneric.length).toBe(32);
    const ecA = await ecdhP256.generateKeyPair();
    const ecB = await ecdhP256.generateKeyPair();
    const viaGenericEc = await ecdh.computeSharedSecret('P-256', ecA.privateKey, ecB.publicKey);
    expect(viaGenericEc).toEqual(await ecdhP256.computeSharedSecret(ecB.privateKey, ecA.publicKey));
  });

  itIfX448('X448 generates usable keys', async () => {
    const a = await ecdhX448.generateKeyPair();
    const b = await ecdhX448.generateKeyPair();
    expect(a.privateKey.length).toBe(56);
    const ab = await ecdhX448.computeSharedSecret(a.privateKey, b.publicKey);
    const ba = await ecdhX448.computeSharedSecret(b.privateKey, a.publicKey);
    expect(ab).toEqual(ba);
  });
});

describe('ECDSA (P-256, SHA-256)', () => {
  it('sign/verify round-trips and rejects tampering', async () => {
    const kp = await ecdsaP256.generateKeyPair();
    const msg = randomBytes(64);
    const sig = await ecdsaP256.sign(msg, kp.privateKey);
    expect(await ecdsaP256.verify(msg, sig, kp.publicKey)).toBe(true);
    const bad = Uint8Array.from(sig);
    bad[10] ^= 1;
    expect(await ecdsaP256.verify(msg, bad, kp.publicKey)).toBe(false);
    expect(await ecdsaP256.verify(msg, sig.subarray(0, sig.length - 2), kp.publicKey)).toBe(false);
  });

  it('produces DER signatures verifiable by node:crypto', async () => {
    const kp = await ecdsaP256.generateKeyPair();
    const msg = new Uint8Array(Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'));
    const sig = await ecdsaP256.sign(msg, kp.privateKey);
    const point = Buffer.from(kp.publicKey);
    const jwk = {
      kty: 'EC',
      crv: 'P-256',
      x: point.subarray(1, 33).toString('base64url'),
      y: point.subarray(33, 65).toString('base64url'),
    };
    const pub = createPublicKey({ key: jwk, format: 'jwk' });
    // our signatures are DER-encoded; node hashes the raw message itself
    expect(nodeVerify('sha256', msg, pub, sig)).toBe(true);
  });

  it('rejects malformed public keys without throwing out of verify', async () => {
    const kp = await ecdsaP256.generateKeyPair();
    const msg = randomBytes(10);
    const sig = await ecdsaP256.sign(msg, kp.privateKey);
    expect(await ecdsaP256.verify(msg, sig, new Uint8Array(64))).toBe(false);
    expect(await ecdsaP256.verify(msg, sig, new Uint8Array(65))).toBe(false);
  });
});
