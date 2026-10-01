/**
 * LombokEncryptDecrypt — Encoding Utilities Tests
 */

import {
  bytesToHex, hexToBytes,
  bytesToBase64, base64ToBytes, bytesToBase64Url,
  stringToBytes, bytesToString,
  concatBytes, xorBytes,
} from '../../src/utils/encoding.js';

import { timingSafeEqual } from '../../src/utils/timing.js';

describe('bytesToHex / hexToBytes', () => {
  it('roundtrip empty', () => {
    expect(bytesToHex(new Uint8Array(0))).toBe('');
    expect(hexToBytes('')).toEqual(new Uint8Array(0));
  });

  it('roundtrip known value', () => {
    const bytes = new Uint8Array([0xca, 0xfe, 0xba, 0xbe]);
    expect(bytesToHex(bytes)).toBe('cafebabe');
    expect(hexToBytes('cafebabe')).toEqual(bytes);
  });

  it('handles uppercase hex input', () => {
    expect(hexToBytes('CAFEBABE')).toEqual(new Uint8Array([0xca, 0xfe, 0xba, 0xbe]));
  });

  it('throws on odd-length hex', () => {
    expect(() => hexToBytes('abc')).toThrow(RangeError);
  });
});

describe('base64 / base64url', () => {
  it('roundtrip base64', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it('base64url has no +/= characters', () => {
    const bytes = new Uint8Array(100).map((_, i) => i);
    const b64url = bytesToBase64Url(bytes);
    expect(b64url).not.toMatch(/[+/=]/);
  });

  it('roundtrip base64url', () => {
    const bytes = new Uint8Array(33).map((_, i) => i * 7);
    expect(base64ToBytes(bytesToBase64Url(bytes))).toEqual(bytes);
  });
});

describe('stringToBytes / bytesToString', () => {
  it('roundtrip ASCII', () => {
    const str = 'hello world';
    expect(bytesToString(stringToBytes(str))).toBe(str);
  });

  it('roundtrip Unicode', () => {
    const str = 'Lombok 🔐 Encrypt';
    expect(bytesToString(stringToBytes(str))).toBe(str);
  });
});

describe('concatBytes', () => {
  it('concatenates arrays', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4]);
    const c = new Uint8Array([5]);
    expect(concatBytes(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
  });

  it('handles empty arrays', () => {
    const a = new Uint8Array([1]);
    const empty = new Uint8Array(0);
    expect(concatBytes(empty, a, empty)).toEqual(a);
  });
});

describe('xorBytes', () => {
  it('XOR known values', () => {
    const a = new Uint8Array([0xFF, 0x00]);
    const b = new Uint8Array([0x0F, 0xF0]);
    expect(xorBytes(a, b)).toEqual(new Uint8Array([0xF0, 0xF0]));
  });

  it('XOR with self is zero', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    expect(xorBytes(a, a)).toEqual(new Uint8Array([0, 0, 0, 0]));
  });

  it('throws on length mismatch', () => {
    expect(() => xorBytes(new Uint8Array(2), new Uint8Array(3))).toThrow(RangeError);
  });
});

describe('timingSafeEqual', () => {
  it('returns true for equal arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    expect(timingSafeEqual(a, b)).toBe(true);
  });

  it('returns false for different arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 4]);
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it('returns false for different lengths', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([1, 2, 3]);
    expect(timingSafeEqual(a, b)).toBe(false);
  });

  it('returns true for empty arrays', () => {
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});
