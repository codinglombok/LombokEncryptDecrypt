import {
  randomBytes,
  randomKey128,
  randomKey256,
  randomSalt,
  randomIv,
} from '../../src/utils/random.js';

describe('CSPRNG', () => {
  it('produces the requested lengths', () => {
    expect(randomBytes(0).length).toBe(0);
    expect(randomBytes(1).length).toBe(1);
    expect(randomBytes(32).length).toBe(32);
    expect(randomKey128().length).toBe(16);
    expect(randomKey256().length).toBe(32);
    expect(randomSalt(16).length).toBe(16);
    expect(randomIv(12).length).toBe(12);
    expect(randomSalt().length).toBe(16);
    expect(randomIv().length).toBe(12);
  });

  it('rejects invalid lengths', () => {
    expect(() => randomBytes(-1)).toThrow();
    expect(() => randomBytes(1.5)).toThrow();
  });

  it('produces distinct outputs and handles >64 KiB requests', () => {
    const a = randomBytes(1024);
    const b = randomBytes(1024);
    expect(a).not.toEqual(b);
    // getRandomValues quota is 65536 bytes per call — chunking must work
    const big = randomBytes(200_000);
    expect(big.length).toBe(200_000);
    let zeros = 0;
    for (const byte of big) if (byte === 0) zeros++;
    expect(zeros).toBeLessThan(1000); // ~1/256 of 200k ≈ 780 expected
  });
});
