/**
 * LombokEncryptDecrypt — KeyStore Tests
 */

import { KeyStore } from '../../src/keystore/keystore.js';
import { randomKey256 } from '../../src/utils/random.js';
import { bytesToHex } from '../../src/utils/encoding.js';
import { LombokCryptoError } from '../../src/errors.js';

const PASSWORD = 'test-vault-password-2026';

describe('KeyStore', () => {
  describe('create + set + get', () => {
    it('creates a new KeyStore and stores a key', async () => {
      const ks = await KeyStore.create({ password: PASSWORD });
      const key = randomKey256();
      await ks.set('test-key', key);
      const retrieved = await ks.get('test-key');
      expect(bytesToHex(retrieved)).toBe(bytesToHex(key));
    });

    it('generates and stores a random key', async () => {
      const ks  = await KeyStore.create({ password: PASSWORD });
      const key = await ks.generateKey('auto-key', 'AES-256-GCM');
      expect(key.length).toBe(32);
      const retrieved = await ks.get('auto-key');
      expect(bytesToHex(retrieved)).toBe(bytesToHex(key));
    });

    it('lists all key IDs', async () => {
      const ks = await KeyStore.create({ password: PASSWORD });
      await ks.set('key-a', randomKey256());
      await ks.set('key-b', randomKey256());
      await ks.set('key-c', randomKey256());
      expect(ks.list().sort()).toEqual(['key-a', 'key-b', 'key-c']);
    });

    it('deletes a key', async () => {
      const ks = await KeyStore.create({ password: PASSWORD });
      await ks.set('temp-key', randomKey256());
      expect(ks.list()).toContain('temp-key');
      const deleted = ks.delete('temp-key');
      expect(deleted).toBe(true);
      expect(ks.list()).not.toContain('temp-key');
    });

    it('throws KEY_NOT_FOUND for missing key', async () => {
      const ks = await KeyStore.create({ password: PASSWORD });
      await expect(ks.get('nonexistent')).rejects.toMatchObject({
        code: 'KEY_NOT_FOUND',
      });
    });

    it('stores multiple keys independently', async () => {
      const ks  = await KeyStore.create({ password: PASSWORD });
      const k1  = randomKey256();
      const k2  = randomKey256();
      await ks.set('k1', k1); await ks.set('k2', k2);
      expect(bytesToHex(await ks.get('k1'))).toBe(bytesToHex(k1));
      expect(bytesToHex(await ks.get('k2'))).toBe(bytesToHex(k2));
    });
  });

  describe('serialize + open', () => {
    it('roundtrip serialize + open with correct password', async () => {
      const ks  = await KeyStore.create({ password: PASSWORD, m: 19456, t: 2, p: 1 });
      const key = randomKey256();
      await ks.set('persist-key', key);
      const blob = await ks.serialize();
      expect(blob.length).toBeGreaterThan(32);

      const ks2  = await KeyStore.open(blob, { password: PASSWORD });
      const key2 = await ks2.get('persist-key');
      expect(bytesToHex(key2)).toBe(bytesToHex(key));
    });

    it('rejects wrong password on open', async () => {
      const ks   = await KeyStore.create({ password: PASSWORD, m: 19456, t: 2, p: 1 });
      await ks.set('k', randomKey256());
      const blob = await ks.serialize();
      await expect(KeyStore.open(blob, { password: 'wrong-password' }))
        .rejects.toMatchObject({ code: 'KEYSTORE_CORRUPT' });
    });

    it('multiple keys survive serialize/open roundtrip', async () => {
      const ks   = await KeyStore.create({ password: PASSWORD, m: 19456, t: 2, p: 1 });
      const keys = ['k1','k2','k3'].map(() => randomKey256());
      await Promise.all(keys.map((k,i) => ks.set(`key-${i}`, k)));
      const blob = await ks.serialize();

      const ks2  = await KeyStore.open(blob, { password: PASSWORD });
      for (let i = 0; i < keys.length; i++) {
        const retrieved = await ks2.get(`key-${i}`);
        expect(bytesToHex(retrieved)).toBe(bytesToHex(keys[i]!));
      }
    });
  });

  describe('lock + security', () => {
    it('lock() prevents further access', async () => {
      const ks = await KeyStore.create({ password: PASSWORD });
      await ks.set('k', randomKey256());
      ks.lock();
      await expect(ks.get('k')).rejects.toMatchObject({ code: 'KEYSTORE_LOCKED' });
    });

    it('lock() clears all key IDs', async () => {
      const ks = await KeyStore.create({ password: PASSWORD });
      await ks.set('k1', randomKey256());
      await ks.set('k2', randomKey256());
      ks.lock();
      expect(ks.list()).toHaveLength(0);
    });
  });
});
