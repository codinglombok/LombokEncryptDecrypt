import { sha256, sha224, sha384, sha512 } from '../../src/core/sha/sha256.js';
import { createHash } from 'node:crypto';

const enc = new TextEncoder();

describe('SHA-2 (FIPS 180-4)', () => {
  it('matches the published FIPS vectors', async () => {
    expect(Buffer.from(await sha256.hash(enc.encode('abc'))).toString('hex')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(
      Buffer.from(
        await sha256.hash(enc.encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')),
      ).toString('hex'),
    ).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
    expect(Buffer.from(await sha224.hash(enc.encode('abc'))).toString('hex')).toBe(
      '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
    );
    expect(Buffer.from(await sha384.hash(enc.encode('abc'))).toString('hex')).toBe(
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    );
    expect(Buffer.from(await sha512.hash(enc.encode('abc'))).toString('hex')).toBe(
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    );
  });

  it('matches node:crypto across block-boundary lengths', async () => {
    for (const len of [
      0, 1, 55, 56, 63, 64, 65, 111, 112, 119, 120, 127, 128, 129, 255, 256, 300,
    ]) {
      const data = new Uint8Array(len);
      for (let i = 0; i < len; i++) data[i] = (i * 131 + 7) & 0xff;
      const cases: Array<[Promise<Uint8Array>, string]> = [
        [sha256.hash(data), 'sha256'],
        [sha224.hash(data), 'sha224'],
        [sha384.hash(data), 'sha384'],
        [sha512.hash(data), 'sha512'],
      ];
      for (const [promise, alg] of cases) {
        const mine = Buffer.from(await promise).toString('hex');
        const ref = createHash(alg).update(data).digest('hex');
        expect(mine).toBe(ref);
      }
    }
  });
});
