import { aesEncryptBlock, aesDecryptBlock, aesExpandKey } from '../../src/core/aes/aes.js';
import { LombokCryptoError, ErrorCode } from '../../src/errors.js';

describe('AES block cipher (FIPS 197)', () => {
  const cases: Array<[string, string, string, string]> = [
    [
      '128',
      '000102030405060708090a0b0c0d0e0f',
      '00112233445566778899aabbccddeeff',
      '69c4e0d86a7b0430d8cdb78070b4c55a',
    ],
    [
      '192',
      '000102030405060708090a0b0c0d0e0f1011121314151617',
      '00112233445566778899aabbccddeeff',
      'dda97ca4864cdfe06eaf70a0ec0d7191',
    ],
    [
      '256',
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      '00112233445566778899aabbccddeeff',
      '8ea2b7ca516745bfeafc49904b496089',
    ],
  ];

  for (const [bits, keyHex, ptHex, ctHex] of cases) {
    it(`round-trips the FIPS-197 appendix C vector for AES-${bits}`, () => {
      const expanded = aesExpandKey(new Uint8Array(Buffer.from(keyHex, 'hex')));
      const pt = new Uint8Array(Buffer.from(ptHex, 'hex'));
      const ct = aesEncryptBlock(expanded, pt);
      expect(Buffer.from(ct).toString('hex')).toBe(ctHex);
      const back = aesDecryptBlock(expanded, ct);
      expect(Buffer.from(back).toString('hex')).toBe(ptHex);
    });
  }

  it('rejects invalid key sizes with INVALID_KEY_SIZE', () => {
    try {
      aesExpandKey(new Uint8Array(15));
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(LombokCryptoError);
      expect((e as LombokCryptoError).code).toBe(ErrorCode.INVALID_KEY_SIZE);
    }
    expect(() => aesExpandKey(new Uint8Array(0))).toThrow();
    expect(() => aesExpandKey(new Uint8Array(33))).toThrow();
  });

  it('rejects non-16-byte blocks', () => {
    const expanded = aesExpandKey(new Uint8Array(16));
    expect(() => aesEncryptBlock(expanded, new Uint8Array(15))).toThrow();
    expect(() => aesDecryptBlock(expanded, new Uint8Array(17))).toThrow();
  });

  it('decrypt is the exact inverse of encrypt for random blocks', () => {
    for (const size of [16, 24, 32]) {
      const key = new Uint8Array(size);
      for (let i = 0; i < size; i++) key[i] = (i * 89 + 1) & 0xff;
      const expanded = aesExpandKey(key);
      const block = new Uint8Array(16);
      for (let i = 0; i < 16; i++) block[i] = (i * 7 + size) & 0xff;
      const ct = aesEncryptBlock(expanded, block);
      expect(aesDecryptBlock(expanded, ct)).toEqual(block);
    }
  });
});
