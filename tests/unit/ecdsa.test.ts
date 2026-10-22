import {
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import { ecdsa, type EcdsaCurve } from '../../src/core/ecc/ecdsa.js';

const msg = new TextEncoder().encode('lombok ecdsa test message');
const SPKI: Record<EcdsaCurve, string> = {
  'P-256': '3059301306072a8648ce3d020106082a8648ce3d030107034200',
  'P-384': '3076301006072a8648ce3d020106052b81040022036200',
  'P-521': '30819b301006072a8648ce3d020106052b8104002303818600',
};
const HASH = { 'P-256': 'sha256', 'P-384': 'sha384', 'P-521': 'sha512' } as const;

describe('ECDSA (WebCrypto)', () => {
  for (const curve of ['P-256', 'P-384', 'P-521'] as const) {
    it(`${curve}: sign/verify round trip and tamper detection`, async () => {
      const kp = await ecdsa.generateKeyPair(curve);
      const sig = await ecdsa.sign(curve, kp.privateKey, msg);
      expect(await ecdsa.verify(curve, kp.publicKey, msg, sig)).toBe(true);
      expect(await ecdsa.verify(curve, kp.publicKey, new TextEncoder().encode('other'), sig)).toBe(
        false,
      );
      const bad = sig.slice();
      bad[0]! ^= 1;
      expect(await ecdsa.verify(curve, kp.publicKey, msg, bad)).toBe(false);
      expect(await ecdsa.verify(curve, kp.publicKey, msg, sig.slice(1))).toBe(false);
    });

    it(`${curve}: interoperates with OpenSSL (node:crypto) both ways`, async () => {
      const kp = await ecdsa.generateKeyPair(curve);
      const priv = createPrivateKey({
        key: Buffer.from(kp.privateKey),
        format: 'der',
        type: 'pkcs8',
      });
      const pub = createPublicKey({
        key: Buffer.concat([Buffer.from(SPKI[curve], 'hex'), Buffer.from(kp.publicKey)]),
        format: 'der',
        type: 'spki',
      });
      // ours -> OpenSSL
      const sig = await ecdsa.sign(curve, kp.privateKey, msg);
      expect(nodeVerify(HASH[curve], msg, { key: pub, dsaEncoding: 'ieee-p1363' }, sig)).toBe(true);
      // OpenSSL -> ours
      const sig2 = nodeSign(HASH[curve], msg, { key: priv, dsaEncoding: 'ieee-p1363' });
      expect(await ecdsa.verify(curve, kp.publicKey, msg, new Uint8Array(sig2))).toBe(true);
    });
  }

  it('rejects an invalid private key and unsupported curve', async () => {
    await expect(ecdsa.sign('P-256', new Uint8Array(10), msg)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(ecdsa.generateKeyPair('P-192' as never)).rejects.toMatchObject({
      code: 'INVALID_PARAMETER',
    });
  });
});
