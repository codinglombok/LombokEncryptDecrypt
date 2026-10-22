/**
 * LombokEncryptDecrypt — KeyStore Tests
 */

import { KeyStore } from '../../src/keystore/keystore.js';
import { randomKey256 } from '../../src/utils/random.js';
import { bytesToHex } from '../../src/utils/encoding.js';

const PASSWORD = 'test-vault-password-2026';

describe('KeyStore', () => {
  describe('create + set + get', () => {
    it('creates a new KeyStore and stores a key', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      const key = randomKey256();
      await ks.set('test-key', key);
      const retrieved = await ks.get('test-key');
      expect(bytesToHex(retrieved)).toBe(bytesToHex(key));
    });

    it('generates and stores a random key', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      const key = await ks.generateKey('auto-key', 'AES-256-GCM');
      expect(key.length).toBe(32);
      const retrieved = await ks.get('auto-key');
      expect(bytesToHex(retrieved)).toBe(bytesToHex(key));
    });

    it('lists all key IDs', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      await ks.set('key-a', randomKey256());
      await ks.set('key-b', randomKey256());
      await ks.set('key-c', randomKey256());
      expect(ks.list().sort()).toEqual(['key-a', 'key-b', 'key-c']);
    });

    it('deletes a key', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      await ks.set('temp-key', randomKey256());
      expect(ks.list()).toContain('temp-key');
      const deleted = ks.delete('temp-key');
      expect(deleted).toBe(true);
      expect(ks.list()).not.toContain('temp-key');
    });

    it('throws KEY_NOT_FOUND for missing key', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      await expect(ks.get('nonexistent')).rejects.toMatchObject({
        code: 'KEY_NOT_FOUND',
      });
    });

    it('stores multiple keys independently', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      const k1 = randomKey256();
      const k2 = randomKey256();
      await ks.set('k1', k1);
      await ks.set('k2', k2);
      expect(bytesToHex(await ks.get('k1'))).toBe(bytesToHex(k1));
      expect(bytesToHex(await ks.get('k2'))).toBe(bytesToHex(k2));
    });
  });

  describe('serialize + open', () => {
    it('roundtrip serialize + open with correct password', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024, r: 8, p: 1 });
      const key = randomKey256();
      await ks.set('persist-key', key);
      const blob = await ks.serialize();
      expect(blob.length).toBeGreaterThan(32);

      const ks2 = await KeyStore.open(blob, { password: PASSWORD, N: 1024 });
      const key2 = await ks2.get('persist-key');
      expect(bytesToHex(key2)).toBe(bytesToHex(key));
    });

    it('rejects wrong password on open', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024, r: 8, p: 1 });
      await ks.set('k', randomKey256());
      const blob = await ks.serialize();
      await expect(KeyStore.open(blob, { password: 'wrong-password' })).rejects.toMatchObject({
        code: 'KEYSTORE_CORRUPT',
      });
    });

    it('multiple keys survive serialize/open roundtrip', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024, r: 8, p: 1 });
      const keys = ['k1', 'k2', 'k3'].map(() => randomKey256());
      await Promise.all(keys.map((k, i) => ks.set(`key-${i}`, k)));
      const blob = await ks.serialize();

      const ks2 = await KeyStore.open(blob, { password: PASSWORD, N: 1024 });
      for (let i = 0; i < keys.length; i++) {
        const retrieved = await ks2.get(`key-${i}`);
        expect(bytesToHex(retrieved)).toBe(bytesToHex(keys[i]!));
      }
    });
  });

  describe('lock + security', () => {
    it('lock() prevents further access', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      await ks.set('k', randomKey256());
      ks.lock();
      await expect(ks.get('k')).rejects.toMatchObject({ code: 'KEYSTORE_LOCKED' });
    });

    it('lock() clears all key IDs', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      await ks.set('k1', randomKey256());
      await ks.set('k2', randomKey256());
      ks.lock();
      expect(ks.list()).toHaveLength(0);
    });
  });

  describe('format robustness', () => {
    it('stores more than 255 keys and reads them back', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      for (let i = 0; i < 300; i++) await ks.set(`k${i}`, new Uint8Array(32).fill(i & 0xff));
      const reopened = await KeyStore.open(await ks.serialize(), { password: PASSWORD });
      expect(reopened.list()).toHaveLength(300);
      expect((await reopened.get('k299'))[0]).toBe(299 & 0xff);
    });

    it('reads KDF parameters from the file, not from the options', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 2048, r: 4, p: 2 });
      await ks.set('a', randomKey256());
      const reopened = await KeyStore.open(await ks.serialize(), { password: PASSWORD, N: 1024 });
      expect(reopened.list()).toEqual(['a']);
    });

    it('rejects hostile KDF parameters before doing any work', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      const blob = (await ks.serialize()).slice();
      blob[6] = 40; // log2N = 40
      await expect(KeyStore.open(blob, { password: PASSWORD })).rejects.toMatchObject({
        code: 'KEYSTORE_CORRUPT',
      });
    });

    it('detects any single-byte modification', async () => {
      const ks = await KeyStore.create({ password: PASSWORD, N: 1024 });
      await ks.set('a', randomKey256());
      const blob = await ks.serialize();
      for (const pos of [20, 40, Math.floor(blob.length / 2), blob.length - 1]) {
        const bad = blob.slice();
        bad[pos] ^= 0x01;
        await expect(KeyStore.open(bad, { password: PASSWORD })).rejects.toBeDefined();
      }
    });

    it('rejects too-large or non-power-of-two N', async () => {
      await expect(KeyStore.create({ password: PASSWORD, N: 1000 })).rejects.toMatchObject({
        code: 'INVALID_PARAMETER',
      });
      await expect(KeyStore.create({ password: PASSWORD, N: 2 ** 30 })).rejects.toMatchObject({
        code: 'INVALID_PARAMETER',
      });
    });
  });
});
