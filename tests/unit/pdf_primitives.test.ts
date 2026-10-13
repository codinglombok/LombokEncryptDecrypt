/**
 * LombokEncryptDecrypt — AES block decrypt, AES-CBC/ECB, SHA-384/512, MD5, RC4.
 *
 * Known-answer tests: NIST FIPS 197 (Appendix C), NIST SP 800-38A (F.1, F.2),
 * NIST FIPS 180-4 examples, RFC 1321 (Appendix A.5), RC4 published examples.
 * Differential tests compare with node:crypto (OpenSSL) on random inputs.
 */
import { createCipheriv, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createAes } from '../../src/core/aes/aes.js';
import { aesCbc, aesEcb } from '../../src/modes/cbc.js';
import { sha256 } from '../../src/core/sha/sha256.js';
import { sha384, sha512 } from '../../src/core/sha/sha512.js';
import { md5 } from '../../src/legacy/md5.js';
import { rc4 } from '../../src/legacy/rc4.js';
import { LombokCryptoError, ErrorCode } from '../../src/errors.js';
import { bytesToHex, hexToBytes, stringToBytes } from '../../src/utils/encoding.js';

const hex = (s: string) => hexToBytes(s.replace(/\s+/g, ''));
const ascii = (s: string) => stringToBytes(s);

function rng(seed: number): (n: number) => Uint8Array {
  let s = seed >>> 0;
  return n => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; out[i] = s >>> 24; }
    return out;
  };
}

function code(fn: () => unknown): string {
  try { fn(); } catch (e) { if (e instanceof LombokCryptoError) return e.code; throw e; }
  return 'NO_ERROR';
}

describe('AES block cipher (FIPS 197 Appendix C)', () => {
  const pt = '00112233445566778899aabbccddeeff';
  const cases = [
    ['000102030405060708090a0b0c0d0e0f', '69c4e0d86a7b0430d8cdb78070b4c55a'],
    ['000102030405060708090a0b0c0d0e0f1011121314151617', 'dda97ca4864cdfe06eaf70a0ec0d7191'],
    ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '8ea2b7ca516745bfeafc49904b496089'],
  ];
  for (const [key, ct] of cases) {
    it(`AES-${key!.length * 4} encrypt and decrypt`, () => {
      const aes = createAes(hex(key!));
      expect(bytesToHex(aes.encryptBlock(hex(pt)))).toBe(ct);
      expect(bytesToHex(aes.decryptBlock(hex(ct!)))).toBe(pt);
    });
  }
  it('rejects blocks that are not 16 bytes', () => {
    expect(code(() => createAes(new Uint8Array(16)).decryptBlock(new Uint8Array(15)))).toBe(ErrorCode.INVALID_INPUT);
  });
});

describe('AES-CBC and AES-ECB (NIST SP 800-38A)', () => {
  const iv = '000102030405060708090a0b0c0d0e0f';
  const pt = `6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
              30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710`;
  const k128 = '2b7e151628aed2a6abf7158809cf4f3c';
  const k256 = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';

  it('F.2.1/F.2.2 CBC-AES128', () => {
    const ct = `7649abac8119b246cee98e9b12e9197d 5086cb9b507219ee95db113a917678b2
                73bed6b8e3c1743b7116e69e22229516 3ff1caa1681fac09120eca307586e1a7`;
    expect(bytesToHex(aesCbc.encrypt(hex(k128), hex(iv), hex(pt), { padding: 'none' }))).toBe(ct.replace(/\s+/g, ''));
    expect(bytesToHex(aesCbc.decrypt(hex(k128), hex(iv), hex(ct), { padding: 'none' }))).toBe(pt.replace(/\s+/g, ''));
  });

  it('F.2.5/F.2.6 CBC-AES256', () => {
    const ct = `f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d
                39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b`;
    expect(bytesToHex(aesCbc.encrypt(hex(k256), hex(iv), hex(pt), { padding: 'none' }))).toBe(ct.replace(/\s+/g, ''));
    expect(bytesToHex(aesCbc.decrypt(hex(k256), hex(iv), hex(ct), { padding: 'none' }))).toBe(pt.replace(/\s+/g, ''));
  });

  it('F.1.1/F.1.2 ECB-AES128', () => {
    const ct = `3ad77bb40d7a3660a89ecaf32466ef97 f5d3d58503b9699de785895a96fdbaaf
                43b1cd7f598ece23881b00e3ed030688 7b0c785e27e8ad3f8223207104725dd4`;
    expect(bytesToHex(aesEcb.encrypt(hex(k128), hex(pt)))).toBe(ct.replace(/\s+/g, ''));
    expect(bytesToHex(aesEcb.decrypt(hex(k128), hex(ct)))).toBe(pt.replace(/\s+/g, ''));
  });

  it('PKCS#7 padding adds 1-16 bytes and round-trips', () => {
    const key = hex(k128);
    for (const n of [0, 1, 15, 16, 17, 31, 32]) {
      const data = rng(n)(n);
      const ct = aesCbc.encrypt(key, hex(iv), data);
      expect(ct.length).toBe((Math.floor(n / 16) + 1) * 16);
      expect(bytesToHex(aesCbc.decrypt(key, hex(iv), ct))).toBe(bytesToHex(data));
    }
  });

  it('rejects malformed padding, bad lengths and bad IVs', () => {
    const key = hex(k128);
    const ct = aesCbc.encrypt(key, hex(iv), ascii('hello'));
    const bad = Uint8Array.from(ct); bad[bad.length - 1]! ^= 0x01;
    expect(code(() => aesCbc.decrypt(key, hex(iv), bad))).toBe(ErrorCode.INTEGRITY_CHECK_FAILED);
    expect(code(() => aesCbc.decrypt(key, hex(iv), new Uint8Array(0)))).toBe(ErrorCode.INTEGRITY_CHECK_FAILED);
    expect(code(() => aesCbc.decrypt(key, hex(iv), ct.subarray(1)))).toBe(ErrorCode.INVALID_INPUT);
    expect(code(() => aesCbc.encrypt(key, new Uint8Array(8), ct))).toBe(ErrorCode.INVALID_IV_SIZE);
    expect(code(() => aesCbc.encrypt(key, hex(iv), new Uint8Array(5), { padding: 'none' }))).toBe(ErrorCode.INVALID_INPUT);
    expect(code(() => aesCbc.encrypt(new Uint8Array(10), hex(iv), new Uint8Array(16)))).toBe(ErrorCode.INVALID_KEY_SIZE);
    expect(bytesToHex(aesEcb.decrypt(key, aesEcb.encrypt(key, ascii('x'), { padding: 'pkcs7' }), { padding: 'pkcs7' }))).toBe('78');
  });

  it('matches OpenSSL on random inputs (differential)', () => {
    const r = rng(1);
    for (let n = 0; n < 200; n++) {
      const keyLen = [16, 24, 32][n % 3]!;
      const key = r(keyLen), ivb = r(16), data = r(n * 3);
      const ref = createCipheriv(`aes-${keyLen * 8}-cbc`, key, ivb);
      const expected = Buffer.concat([ref.update(data), ref.final()]);
      const got = aesCbc.encrypt(key, ivb, data);
      expect(bytesToHex(got)).toBe(expected.toString('hex'));
      expect(bytesToHex(aesCbc.decrypt(key, ivb, got))).toBe(bytesToHex(data));
    }
  });
});

describe('SHA-2 (FIPS 180-4 examples)', () => {
  const abc = ascii('abc');
  const two = ascii('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu');

  it('SHA-256', () => {
    expect(bytesToHex(sha256.hashSync(new Uint8Array(0)))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(bytesToHex(sha256.hashSync(abc))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(bytesToHex(sha256.hashSync(ascii('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))))
      .toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });

  it('SHA-512', async () => {
    expect(bytesToHex(sha512.hashSync(new Uint8Array(0))))
      .toBe('cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
    expect(bytesToHex(sha512.hashSync(abc)))
      .toBe('ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
    expect(bytesToHex(await sha512.hash(two)))
      .toBe('8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909');
    expect(bytesToHex(sha512.hashSync(new Uint8Array(1_000_000).fill(0x61))))
      .toBe('e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b');
  });

  it('SHA-384', async () => {
    expect(bytesToHex(sha384.hashSync(new Uint8Array(0))))
      .toBe('38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b');
    expect(bytesToHex(sha384.hashSync(abc)))
      .toBe('cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7');
    expect(bytesToHex(await sha384.hash(two)))
      .toBe('09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039');
  });

  it('matches OpenSSL for every length 0-300 (padding boundaries)', () => {
    const r = rng(2);
    for (let n = 0; n <= 300; n++) {
      const data = r(n);
      expect(bytesToHex(sha512.hashSync(data))).toBe(createHash('sha512').update(data).digest('hex'));
      expect(bytesToHex(sha384.hashSync(data))).toBe(createHash('sha384').update(data).digest('hex'));
      expect(bytesToHex(sha256.hashSync(data))).toBe(createHash('sha256').update(data).digest('hex'));
    }
  });
});

describe('legacy: MD5 (RFC 1321 A.5) and RC4', () => {
  it('MD5 test suite', async () => {
    const suite: [string, string][] = [
      ['', 'd41d8cd98f00b204e9800998ecf8427e'],
      ['a', '0cc175b9c0f1b6a831c399e269772661'],
      ['abc', '900150983cd24fb0d6963f7d28e17f72'],
      ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
      ['abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'],
      ['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 'd174ab98d277d9f5a5611c2c9f419d9f'],
      ['1234567890'.repeat(8), '57edf4a22be3c955ac49da2e2107b67a'],
    ];
    for (const [m, d] of suite) expect(bytesToHex(md5.hashSync(ascii(m)))).toBe(d);
    expect(bytesToHex(await md5.hash(ascii('abc')))).toBe('900150983cd24fb0d6963f7d28e17f72');
  });

  it('MD5 matches OpenSSL for every length 0-200', () => {
    const r = rng(3);
    for (let n = 0; n <= 200; n++) {
      const data = r(n);
      expect(bytesToHex(md5.hashSync(data))).toBe(createHash('md5').update(data).digest('hex'));
    }
  });

  it('RC4 published examples', () => {
    const cases: [string, string, string][] = [
      ['Key', 'Plaintext', 'bbf316e8d940af0ad3'],
      ['Wiki', 'pedia', '1021bf0420'],
      ['Secret', 'Attack at dawn', '45a01f645fc35b383552544b9bf5'],
    ];
    for (const [k, p, c] of cases) {
      expect(bytesToHex(rc4(ascii(k), ascii(p)))).toBe(c);
      expect(bytesToHex(rc4(ascii(k), hex(c)))).toBe(bytesToHex(ascii(p)));
    }
  });

  it('RC4 rejects empty and oversized keys', () => {
    expect(code(() => rc4(new Uint8Array(0), ascii('x')))).toBe(ErrorCode.INVALID_KEY_SIZE);
    expect(code(() => rc4(new Uint8Array(257), ascii('x')))).toBe(ErrorCode.INVALID_KEY_SIZE);
  });
});

describe('cross-language vectors (tests/vectors/lombokencryptdecrypt-vectors-v1.json)', () => {
  const doc = JSON.parse(readFileSync(new URL('../vectors/lombokencryptdecrypt-vectors-v1.json', import.meta.url), 'utf8'));
  it('aes_cbc and aes_ecb', () => {
    for (const v of doc.aes_cbc) {
      expect(bytesToHex(aesCbc.encrypt(hex(v.key), hex(v.iv), hex(v.plaintext), { padding: v.padding }))).toBe(v.ciphertext);
      expect(bytesToHex(aesCbc.decrypt(hex(v.key), hex(v.iv), hex(v.ciphertext), { padding: v.padding }))).toBe(v.plaintext);
    }
    for (const v of doc.aes_ecb) expect(bytesToHex(aesEcb.encrypt(hex(v.key), hex(v.plaintext), { padding: v.padding }))).toBe(v.ciphertext);
  });
  it('sha256, sha384, sha512, md5, rc4', () => {
    for (const v of doc.sha256) expect(bytesToHex(sha256.hashSync(hex(v.input)))).toBe(v.output);
    for (const v of doc.sha384) expect(bytesToHex(sha384.hashSync(hex(v.input)))).toBe(v.output);
    for (const v of doc.sha512) expect(bytesToHex(sha512.hashSync(hex(v.input)))).toBe(v.output);
    for (const v of doc.md5) expect(bytesToHex(md5.hashSync(hex(v.input)))).toBe(v.output);
    for (const v of doc.rc4) expect(bytesToHex(rc4(hex(v.key), hex(v.plaintext)))).toBe(v.ciphertext);
  });
});
