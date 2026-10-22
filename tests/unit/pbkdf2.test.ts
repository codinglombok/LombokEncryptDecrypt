/**
 * LombokEncryptDecrypt — PBKDF2-SHA256 Tests
 * RFC 6070 + RFC 7914 test vectors
 */

import { pbkdf2 } from '../../src/kdf/pbkdf2.js';
import { bytesToHex, stringToBytes } from '../../src/utils/encoding.js';

// RFC 7914 §11 PBKDF2-SHA-256 vectors
const PBKDF2_VECTORS = [
  {
    id: 'rfc7914-1',
    password: 'passwd',
    salt: 'salt',
    iter: 1,
    dkLen: 64,
    dk: '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783',
  },
  {
    id: 'rfc7914-2',
    password: 'Password',
    salt: 'NaCl',
    iter: 80000,
    dkLen: 64,
    dk: '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d',
  },
];

describe('PBKDF2-SHA256', () => {
  describe('RFC 7914 vectors', () => {
    for (const v of PBKDF2_VECTORS) {
      it(
        v.id,
        async () => {
          const dk = await pbkdf2.sha256.derive(
            stringToBytes(v.password),
            stringToBytes(v.salt),
            v.iter,
            v.dkLen,
          );
          expect(bytesToHex(dk)).toBe(v.dk);
        },
        120_000,
      ); // Argon2/PBKDF2 timeout
    }
  });

  describe('hash() + verify()', () => {
    it('produces verifiable PHC string', async () => {
      const hash = await pbkdf2.hash('my-password', { hash: 'SHA-256', iterations: 1000 });
      expect(hash).toMatch(/^\$pbkdf2-sha256\$i=1000\$/);
      const ok = await pbkdf2.verify(hash, 'my-password');
      expect(ok).toBe(true);
    });

    it('verify rejects wrong password', async () => {
      const hash = await pbkdf2.hash('correct', { hash: 'SHA-256', iterations: 1000 });
      const ok = await pbkdf2.verify(hash, 'wrong');
      expect(ok).toBe(false);
    });

    it('SHA-512 variant', async () => {
      const dk = await pbkdf2.sha512.derive(
        stringToBytes('password'),
        stringToBytes('salt'),
        1,
        64,
      );
      expect(dk.length).toBe(64);
    });
  });

  describe('Output length', () => {
    it('produces correct output length', async () => {
      for (const len of [16, 32, 48, 64]) {
        const dk = await pbkdf2.sha256.derive(stringToBytes('pw'), stringToBytes('s'), 1, len);
        expect(dk.length).toBe(len);
      }
    });
  });

  describe('Determinism', () => {
    it('same input → same output', async () => {
      const pw = stringToBytes('password');
      const salt = stringToBytes('salt');
      const [d1, d2] = await Promise.all([
        pbkdf2.sha256.derive(pw, salt, 100, 32),
        pbkdf2.sha256.derive(pw, salt, 100, 32),
      ]);
      expect(bytesToHex(d1)).toBe(bytesToHex(d2));
    });

    it('different passwords → different outputs', async () => {
      const salt = stringToBytes('salt');
      const d1 = await pbkdf2.sha256.derive(stringToBytes('pw1'), salt, 1, 32);
      const d2 = await pbkdf2.sha256.derive(stringToBytes('pw2'), salt, 1, 32);
      expect(bytesToHex(d1)).not.toBe(bytesToHex(d2));
    });
  });
});
