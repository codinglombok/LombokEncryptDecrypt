import {
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  bytesToBase64Url,
  base64UrlToBytes,
  stringToBytes,
  bytesToString,
  concatBytes,
  xorBytes,
  timingSafeEqual,
  zeroize,
} from '../../src/utils/encoding.js';

describe('encoding utilities', () => {
  it('round-trips hex', () => {
    const bytes = new Uint8Array([0x00, 0x01, 0xfe, 0xff]);
    expect(bytesToHex(bytes)).toBe('0001feff');
    expect(bytesToHex(hexToBytes('DeadBeef'))).toBe('deadbeef');
  });

  it('rejects malformed hex', () => {
    expect(() => hexToBytes('abc')).toThrow();
    expect(() => hexToBytes('zz')).toThrow();
  });

  it('round-trips base64 with padding rules', () => {
    for (const len of [0, 1, 2, 3, 4, 5, 17, 64]) {
      const data = new Uint8Array(len);
      for (let i = 0; i < len; i++) data[i] = (i * 37 + 11) & 0xff;
      const b64 = bytesToBase64(data);
      expect(base64ToBytes(b64)).toEqual(data);
      const url = bytesToBase64Url(data);
      expect(url).not.toContain('+');
      expect(url).not.toContain('/');
      expect(url).not.toContain('=');
      expect(base64UrlToBytes(url)).toEqual(data);
    }
  });

  it('decodes padded base64url too', () => {
    expect(base64UrlToBytes(bytesToBase64(new Uint8Array([1, 2, 3])))).toEqual(
      new Uint8Array([1, 2, 3]),
    );
  });

  it('round-trips UTF-8', () => {
    const text = 'halo lombok — kripto 🔐';
    expect(bytesToString(stringToBytes(text))).toBe(text);
  });

  it('concatenates and xors', () => {
    expect(concatBytes(new Uint8Array([1]), new Uint8Array(), new Uint8Array([2, 3]))).toEqual(
      new Uint8Array([1, 2, 3]),
    );
    const a = new Uint8Array([0x0f, 0xf0]);
    const b = new Uint8Array([0xff, 0x00]);
    expect(xorBytes(a, b)).toEqual(new Uint8Array([0xf0, 0xf0]));
    expect(() => xorBytes(a, new Uint8Array([1]))).toThrow();
  });

  it('timingSafeEqual behaves like a constant-time comparator', () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  it('zeroize wipes buffers', () => {
    const buf = new Uint8Array([1, 2, 3]);
    zeroize(buf);
    expect(buf).toEqual(new Uint8Array(3));
  });
});
