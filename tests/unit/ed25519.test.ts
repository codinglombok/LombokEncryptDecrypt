/**
 * LombokEncryptDecrypt — Ed25519 Tests
 * RFC 8032 test vectors
 */

import { ed25519 } from '../../src/core/ecc/ed25519.js';
import { hexToBytes, bytesToHex } from '../../src/utils/encoding.js';

// RFC 8032 Section 6 — official test vectors
const RFC8032_VECTORS = [
  {
    id: 'rfc8032-1',
    privateKey: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55',
    publicKey:  'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    message:    '',
    signature:  'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  },
  {
    id: 'rfc8032-2',
    privateKey: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4d0bd6d4',
    publicKey:  '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    message:    '72',
    signature:  '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  },
  {
    id: 'rfc8032-3',
    privateKey: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    publicKey:  'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    message:    'af82',
    signature:  '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
  },
];

describe('Ed25519', () => {
  describe('RFC 8032 test vectors — sign', () => {
    for (const v of RFC8032_VECTORS) {
      it(`${v.id} produces correct signature`, async () => {
        const privateKey = hexToBytes(v.privateKey);
        const message    = v.message ? hexToBytes(v.message) : new Uint8Array(0);

        const sig = await ed25519.sign(message, privateKey);
        expect(bytesToHex(sig)).toBe(v.signature);
      });
    }
  });

  describe('RFC 8032 test vectors — verify', () => {
    for (const v of RFC8032_VECTORS) {
      it(`${v.id} verifies correctly`, async () => {
        const publicKey = hexToBytes(v.publicKey);
        const message   = v.message ? hexToBytes(v.message) : new Uint8Array(0);
        const signature = hexToBytes(v.signature);

        const valid = await ed25519.verify(message, signature, publicKey);
        expect(valid).toBe(true);
      });
    }
  });

  describe('Key pair generation', () => {
    it('generates valid key pair', async () => {
      const kp = await ed25519.generateKeyPair();
      expect(kp.privateKey.length).toBe(32);
      expect(kp.publicKey.length).toBe(32);
    });

    it('roundtrip sign + verify', async () => {
      const kp      = await ed25519.generateKeyPair();
      const message = new TextEncoder().encode('LombokEncryptDecrypt Ed25519 test');
      const sig     = await ed25519.sign(message, kp.privateKey);
      expect(sig.length).toBe(64);
      const valid = await ed25519.verify(message, sig, kp.publicKey);
      expect(valid).toBe(true);
    });

    it('rejects tampered signature', async () => {
      const kp  = await ed25519.generateKeyPair();
      const msg = new TextEncoder().encode('test');
      const sig = await ed25519.sign(msg, kp.privateKey);
      const bad = new Uint8Array(sig); bad[0] ^= 0x01;
      const ok  = await ed25519.verify(msg, bad, kp.publicKey);
      expect(ok).toBe(false);
    });

    it('rejects wrong public key', async () => {
      const kp1 = await ed25519.generateKeyPair();
      const kp2 = await ed25519.generateKeyPair();
      const msg = new TextEncoder().encode('test');
      const sig = await ed25519.sign(msg, kp1.privateKey);
      const ok  = await ed25519.verify(msg, sig, kp2.publicKey);
      expect(ok).toBe(false);
    });

    it('derives deterministic key pair from seed', async () => {
      const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55');
      const kp   = await ed25519.fromSeed(seed);
      expect(bytesToHex(kp.publicKey)).toBe('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    });

    it('rejects invalid seed length', async () => {
      await expect(ed25519.fromSeed(new Uint8Array(16))).rejects.toMatchObject({
        code: 'INVALID_KEY_SIZE',
      });
    });
  });
});
