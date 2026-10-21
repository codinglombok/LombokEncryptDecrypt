import {
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  shake128,
  shake256,
} from '../../src/core/sha/sha3.js';
import { createHash } from 'node:crypto';

const enc = new TextEncoder();

describe('SHA-3 & SHAKE (FIPS 202)', () => {
  it('matches the published "abc" vectors', async () => {
    expect(Buffer.from(await sha3_224.hash(enc.encode('abc'))).toString('hex')).toBe(
      'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
    );
    expect(Buffer.from(await sha3_256.hash(enc.encode('abc'))).toString('hex')).toBe(
      '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    );
    expect(Buffer.from(await sha3_384.hash(enc.encode('abc'))).toString('hex')).toBe(
      'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25',
    );
    expect(Buffer.from(await sha3_512.hash(enc.encode('abc'))).toString('hex')).toBe(
      'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
    );
  });

  it('empty-input digests match', async () => {
    expect(Buffer.from(await sha3_256.hash(new Uint8Array(0))).toString('hex')).toBe(
      'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    );
    expect(Buffer.from(await shake128.hash(new Uint8Array(0), 32)).toString('hex')).toBe(
      '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
    );
    expect(Buffer.from(await shake256.hash(new Uint8Array(0), 32)).toString('hex')).toBe(
      '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f',
    );
  });

  it('cross-checks against node:crypto across rate boundaries and XOF lengths', async () => {
    for (const len of [0, 1, 135, 136, 137, 143, 144, 145, 167, 168, 169, 300]) {
      const data = new Uint8Array(len);
      for (let i = 0; i < len; i++) data[i] = (i * 29 + 3) & 0xff;
      const cases: Array<[Promise<Uint8Array>, string, number]> = [
        [sha3_224.hash(data), 'sha3-224', 0],
        [sha3_256.hash(data), 'sha3-256', 0],
        [sha3_384.hash(data), 'sha3-384', 0],
        [sha3_512.hash(data), 'sha3-512', 0],
        [shake128.hash(data, 32), 'shake128', 32],
        [shake128.hash(data, 250), 'shake128', 250],
        [shake256.hash(data, 64), 'shake256', 64],
        [shake256.hash(data, 300), 'shake256', 300],
      ];
      for (const [promise, alg, outLen] of cases) {
        const mine = Buffer.from(await promise).toString('hex');
        const ref =
          outLen > 0
            ? createHash(alg, { outputLength: outLen }).update(data).digest('hex')
            : createHash(alg).update(data).digest('hex');
        expect(mine).toBe(ref);
      }
    }
  });

  it('rejects invalid XOF lengths', async () => {
    await expect(shake128.hash(new Uint8Array(1), 0)).rejects.toThrow();
    await expect(shake256.hash(new Uint8Array(1), 1.5)).rejects.toThrow();
  });
});
