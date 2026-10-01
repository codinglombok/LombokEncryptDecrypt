/**
 * LombokEncryptDecrypt — AES-GCM Unit Tests
 * NIST FIPS 197 + NIST SP 800-38D test vectors
 */

import { aesGcm } from '../../src/modes/gcm.js';
import { hexToBytes, bytesToHex } from '../../src/utils/encoding.js';
import { randomKey256, randomIv } from '../../src/utils/random.js';

// NIST GCM test vectors from NIST GCMVS
const GCM_VECTORS = [
  {
    id: 'aes-gcm-128-empty',
    alg: 'AES-128-GCM' as const,
    key: '00000000000000000000000000000000',
    iv:  '000000000000000000000000',
    aad: '',
    plaintext: '',
    ciphertext: '',
    tag: '58e2fccefa7e3061367f1d57a4e7455a',
  },
  {
    id: 'aes-gcm-256-1',
    alg: 'AES-256-GCM' as const,
    key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
    iv:  'cafebabefacedbaddecaf888',
    aad: '',
    plaintext: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
    ciphertext: '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad',
    tag: 'b094dac5d93471bdec1a502270e3cc6c',
  },
];

describe('AES-GCM', () => {
  describe('NIST test vectors', () => {
    for (const v of GCM_VECTORS) {
      it(`${v.id} — encrypt`, async () => {
        const key = hexToBytes(v.key);
        const iv = hexToBytes(v.iv);
        const aad = v.aad ? hexToBytes(v.aad) : undefined;
        const plaintext = v.plaintext ? hexToBytes(v.plaintext) : new Uint8Array(0);

        const result = await aesGcm.encrypt(plaintext, key, { iv, aad });

        expect(bytesToHex(result.ciphertext)).toBe(v.ciphertext);
        expect(bytesToHex(result.tag)).toBe(v.tag);
      });

      it(`${v.id} — decrypt + verify`, async () => {
        const key = hexToBytes(v.key);
        const iv = hexToBytes(v.iv);
        const aad = v.aad ? hexToBytes(v.aad) : undefined;
        const ciphertext = v.ciphertext ? hexToBytes(v.ciphertext) : new Uint8Array(0);
        const tag = hexToBytes(v.tag);
        const expectedPt = v.plaintext ? hexToBytes(v.plaintext) : new Uint8Array(0);

        const decrypted = await aesGcm.decrypt(ciphertext, key, iv, tag, { aad });
        expect(bytesToHex(decrypted)).toBe(bytesToHex(expectedPt));
      });
    }
  });

  describe('Roundtrip', () => {
    it('encrypts and decrypts 1KB message', async () => {
      const key = randomKey256();
      const plaintext = new Uint8Array(1024);
      globalThis.crypto.getRandomValues(plaintext);

      const { ciphertext, tag, iv } = await aesGcm.encrypt(plaintext, key);
      const decrypted = await aesGcm.decrypt(ciphertext, key, iv, tag);

      expect(bytesToHex(decrypted)).toBe(bytesToHex(plaintext));
    });

    it('roundtrip with AAD', async () => {
      const key = randomKey256();
      const plaintext = new TextEncoder().encode('hello, LombokEncryptDecrypt!');
      const aad = new TextEncoder().encode('additional-auth-data');

      const { ciphertext, tag, iv } = await aesGcm.encrypt(plaintext, key, { aad });
      const decrypted = await aesGcm.decrypt(ciphertext, key, iv, tag, { aad });

      expect(new TextDecoder().decode(decrypted)).toBe('hello, LombokEncryptDecrypt!');
    });

    it('rejects tampered ciphertext', async () => {
      const key = randomKey256();
      const plaintext = new TextEncoder().encode('sensitive data');

      const { ciphertext, tag, iv } = await aesGcm.encrypt(plaintext, key);

      // Tamper the first byte
      const tampered = new Uint8Array(ciphertext);
      tampered[0] ^= 0x01;

      await expect(aesGcm.decrypt(tampered, key, iv, tag)).rejects.toMatchObject({
        code: 'AUTHENTICATION_FAILED',
      });
    });

    it('rejects tampered tag', async () => {
      const key = randomKey256();
      const plaintext = new TextEncoder().encode('sensitive data');

      const { ciphertext, tag, iv } = await aesGcm.encrypt(plaintext, key);

      const tamperedTag = new Uint8Array(tag);
      tamperedTag[0] ^= 0xFF;

      await expect(aesGcm.decrypt(ciphertext, key, iv, tamperedTag)).rejects.toMatchObject({
        code: 'AUTHENTICATION_FAILED',
      });
    });

    it('rejects wrong key size', async () => {
      const key = new Uint8Array(17);  // invalid
      const plaintext = new Uint8Array(16);
      await expect(aesGcm.encrypt(plaintext, key)).rejects.toMatchObject({
        code: 'INVALID_KEY_SIZE',
      });
    });
  });

  describe('Key generation', () => {
    it('generates 256-bit key', () => {
      const key = aesGcm.generateKey(256);
      expect(key.length).toBe(32);
    });

    it('generates 128-bit key', () => {
      const key = aesGcm.generateKey(128);
      expect(key.length).toBe(16);
    });

    it('generates unique IVs', () => {
      const iv1 = aesGcm.generateIv();
      const iv2 = aesGcm.generateIv();
      expect(bytesToHex(iv1)).not.toBe(bytesToHex(iv2));
    });
  });
});
