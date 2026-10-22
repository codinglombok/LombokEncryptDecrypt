/**
 * scrypt — pure-TypeScript backend checked against OpenSSL (node:crypto.scryptSync),
 * plus the RFC 7914 §12 vectors and PHC string handling.
 */
import { scryptSync } from 'node:crypto';
import { scrypt, scryptPureInternal } from '../../src/kdf/scrypt.js';
import { bytesToHex } from '../../src/utils/encoding.js';

const enc = new TextEncoder();
const ossl = (pw: string, salt: string, N: number, r: number, p: number, len: number) =>
  scryptSync(pw, salt, len, { N, r, p, maxmem: 512 * N * r }).toString('hex');

describe('scrypt', () => {
  describe('RFC 7914 §12 vectors', () => {
    it('empty password/salt, N=16 r=1 p=1', async () => {
      const dk = await scrypt.derive('', { N: 16, r: 1, p: 1, dkLen: 64, salt: new Uint8Array(0) });
      expect(bytesToHex(dk)).toBe(
        '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906',
      );
    });
    it('"password"/"NaCl", N=1024 r=8 p=16', async () => {
      const dk = await scrypt.derive('password', {
        N: 1024,
        r: 8,
        p: 16,
        dkLen: 64,
        salt: enc.encode('NaCl'),
      });
      expect(bytesToHex(dk)).toBe(
        'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
      );
    });
  });

  describe('pure TypeScript backend matches OpenSSL', () => {
    it.each([
      ['', '', 16, 1, 1, 64],
      ['password', 'NaCl', 1024, 8, 16, 64],
      ['pleaseletmein', 'SodiumChloride', 16384, 8, 1, 64],
      ['abc', 'salty', 64, 2, 3, 50],
      ['x', 'y', 2, 1, 1, 1],
      ['long'.repeat(40), 'salt', 256, 4, 2, 100],
    ])(
      'pw=%j salt=%j N=%i r=%i p=%i len=%i',
      async (pw, salt, N, r, p, len) => {
        const pure = await scryptPureInternal(enc.encode(pw), enc.encode(salt), N, r, p, len);
        expect(bytesToHex(pure)).toBe(ossl(pw, salt, N, r, p, len));
      },
      120_000,
    );
  });

  describe('parameter validation', () => {
    it.each([{ N: 1000 }, { N: 1 }, { N: 2 ** 31 }, { r: 0 }, { p: 0 }, { dkLen: 0 }])(
      'rejects %j',
      async (bad) => {
        await expect(scrypt.derive('pw', { N: 16, ...bad })).rejects.toThrow(RangeError);
      },
    );
  });

  describe('PHC strings', () => {
    it('hash then verify', async () => {
      const phc = await scrypt.hash('hunter2', { N: 1024 });
      expect(phc).toMatch(/^\$scrypt\$ln=10,r=8,p=1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
      expect(await scrypt.verify(phc, 'hunter2')).toBe(true);
      expect(await scrypt.verify(phc, 'hunter3')).toBe(false);
    });
    it('verify returns false (never throws) on malformed input', async () => {
      for (const bad of [
        '',
        'x',
        '$scrypt$',
        '$scrypt$ln=99,r=8,p=1$AAAA$AAAA',
        '$argon2id$v=19$m=1,t=1,p=1$AA$AA',
        '$scrypt$ln=10,r=8,p=1$@@@$@@@',
      ]) {
        expect(await scrypt.verify(bad, 'pw')).toBe(false);
      }
    });
    it('same password hashes differently (random salt)', async () => {
      expect(await scrypt.hash('pw', { N: 16 })).not.toBe(await scrypt.hash('pw', { N: 16 }));
    });
  });
});
