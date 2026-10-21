import { sm3 } from '../../src/core/sm/sm3.js';
import { createHash, randomBytes } from 'node:crypto';
import { hasNodeSm3 } from '../platform-caps.js';

const enc = new TextEncoder();

// Bun does not expose OpenSSL's SM3 — cross-check only where available.
const itIfSm3 = hasNodeSm3 ? it : it.skip;

describe('SM3 (GM/T 0004-2012)', () => {
  it('matches the published "abc" vector (synchronous API)', () => {
    expect(Buffer.from(sm3.hash(enc.encode('abc'))).toString('hex')).toBe(
      '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
    );
  });

  itIfSm3('cross-checks against OpenSSL SM3 across block boundaries', () => {
    for (const len of [0, 1, 55, 56, 63, 64, 65, 128, 300]) {
      const data = randomBytes(len);
      expect(Buffer.from(sm3.hash(data)).toString('hex')).toBe(
        createHash('sm3').update(data).digest('hex'),
      );
    }
  });
});
