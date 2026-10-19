/**
 * CMAC-AES — RFC 4493 / NIST SP 800-38B.
 * Reference values produced independently with the Python `cryptography` library.
 */
import { cmac, cmacAes128, cmacAes256 } from '../../src/mac/cmac.js';
import { hexToBytes, bytesToHex } from '../../src/utils/encoding.js';

const MSG = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710';
const K128 = '2b7e151628aed2a6abf7158809cf4f3c';
const K256 = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';

const VECTORS: Array<[string, string, number, string]> = [
  ['AES-128', K128, 0,  'bb1d6929e95937287fa37d129b756746'],
  ['AES-128', K128, 16, '070a16b46b4d4144f79bdd9dd04a287c'],
  ['AES-128', K128, 40, 'dfa66747de9ae63030ca32611497c827'],
  ['AES-128', K128, 64, '51f0bebf7e3b9d92fc49741779363cfe'],
  ['AES-256', K256, 0,  '028962f61b7bf89efc6b551f4667d983'],
  ['AES-256', K256, 16, '28a7023f452e8f82bd4bf28d8c37c35c'],
  ['AES-256', K256, 40, 'aaf3d8f1de5640c232f5b169b9c911e6'],
  ['AES-256', K256, 64, 'e1992190549f6ed5696a2c056c315410'],
];

describe('CMAC-AES', () => {
  it.each(VECTORS)('%s, %s-byte-key vector with %i-byte message', (_alg, key, len, expected) => {
    const mac = cmac.compute(hexToBytes(key), hexToBytes(MSG.slice(0, len * 2)));
    expect(bytesToHex(mac)).toBe(expected);
  });

  it('cmacAes128 / cmacAes256 enforce their key sizes', () => {
    expect(() => cmacAes128.compute(hexToBytes(K256), new Uint8Array(1))).toThrow();
    expect(() => cmacAes256.compute(hexToBytes(K128), new Uint8Array(1))).toThrow();
  });

  it('rejects unsupported key sizes', () => {
    expect(() => cmac.compute(new Uint8Array(24), new Uint8Array(1))).toThrow();
  });

  it('verify accepts the right MAC and rejects a modified one', () => {
    const key = hexToBytes(K128), msg = hexToBytes(MSG.slice(0, 80));
    const mac = cmac.compute(key, msg);
    expect(cmac.verify(key, msg, mac)).toBe(true);
    const bad = mac.slice(); bad[0] ^= 1;
    expect(cmac.verify(key, msg, bad)).toBe(false);
    expect(cmac.verify(key, msg, mac.slice(0, 15))).toBe(false);
  });
});
