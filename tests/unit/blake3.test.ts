import { blake3, Blake3Hasher } from '../../src/core/blake3/blake3.js';

const enc = new TextEncoder();

describe('BLAKE3', () => {
  it('matches the official hash-mode vectors', async () => {
    expect(Buffer.from(await blake3.hash(new Uint8Array(0))).toString('hex')).toBe(
      'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262',
    );
    expect(Buffer.from(await blake3.hash(enc.encode('abc'))).toString('hex')).toBe(
      '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85',
    );
  });

  it('is XOF: longer outputs extend, never change', async () => {
    const data = enc.encode('extendable output function');
    const short = await blake3.hash(data, 32);
    const long = await blake3.hash(data, 100);
    expect(long.subarray(0, 32)).toEqual(short);
  });

  it('handles multi-chunk inputs (tree merging)', async () => {
    // 1024 = one full chunk, 1025/3072/16385 exercise parent-node merging
    for (const len of [1023, 1024, 1025, 2048, 3072, 5000, 16385]) {
      const data = new Uint8Array(len);
      for (let i = 0; i < len; i++) data[i] = (i * 17 + 5) & 0xff;
      // self-consistency: incremental (odd-sized updates) === one-shot, XOF extended
      const oneShot32 = await blake3.hash(data, 32);
      const oneShot100 = await blake3.hash(data, 100);
      expect(oneShot100.subarray(0, 32)).toEqual(oneShot32);
      const hasher = Blake3Hasher.create();
      let offset = 0;
      while (offset < len) {
        const take = Math.min(97, len - offset);
        hasher.update(data.subarray(offset, offset + take));
        offset += take;
      }
      expect(hasher.finalize(32)).toEqual(oneShot32);
      // second incremental pass must be identical
      const hasher2 = Blake3Hasher.create();
      hasher2.update(data);
      expect(hasher2.finalize(32)).toEqual(oneShot32);
    }
  });

  it('keyed hash requires exactly 32 bytes and differs from plain hash', async () => {
    const key = new Uint8Array(32).fill(7);
    const data = enc.encode('keyed mode');
    expect(() => Blake3Hasher.createKeyed(new Uint8Array(31))).toThrow();
    const plain = await blake3.hash(data);
    const keyed = await blake3.keyed(key, data);
    expect(Buffer.from(keyed).toString('hex')).not.toBe(Buffer.from(plain).toString('hex'));
  });

  it('derive_key mode is stable and context-sensitive', async () => {
    const material = new Uint8Array(64);
    for (let i = 0; i < 64; i++) material[i] = i;
    const a = await blake3.deriveKey('lombok test context', material);
    const b = await blake3.deriveKey('lombok test context', material);
    const c = await blake3.deriveKey('other context', material);
    expect(a).toEqual(b);
    expect(a).not.toEqual(c);
  });
});
