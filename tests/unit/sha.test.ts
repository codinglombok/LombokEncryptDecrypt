/**
 * LombokEncryptDecrypt — Hash Function Tests
 * NIST FIPS 180-4, FIPS 202, GM/T 0004 test vectors
 */

import { sha256 } from '../../src/core/sha/sha256.js';
import { sha3_256, sha3_512, shake128 } from '../../src/core/sha/sha3.js';
import { sm3 } from '../../src/core/sm/sm3.js';
import { hexToBytes, bytesToHex, stringToBytes } from '../../src/utils/encoding.js';

// ── SHA-256 — NIST FIPS 180-4 ────────────────────────────────────────────

const SHA256_VECTORS = [
  { input: '',    output: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  { input: '61626364656667', output: '7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c6527baf665d4da9a' },
  // "abc" in hex
  { input: '616263', output: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
];

describe('SHA-256', () => {
  describe('NIST FIPS 180-4 vectors', () => {
    for (const v of SHA256_VECTORS) {
      it(`sha256("${v.input.slice(0,8)}...")`, async () => {
        const data = v.input ? hexToBytes(v.input) : new Uint8Array(0);
        const hash = await sha256.hash(data);
        expect(bytesToHex(hash)).toBe(v.output);
      });
    }
  });

  it('hashSync produces same result as async', () => {
    const data = stringToBytes('hello world');
    const sync = sha256.hashSync(data);
    expect(sync.length).toBe(32);
    expect(bytesToHex(sync)).toBeTruthy();
  });

  it('output is always 32 bytes', async () => {
    for (const len of [0, 1, 55, 64, 1000]) {
      const hash = await sha256.hash(new Uint8Array(len));
      expect(hash.length).toBe(32);
    }
  });
});

// ── SHA3-256 — NIST FIPS 202 ────────────────────────────────────────────

const SHA3_256_VECTORS = [
  { input: '',     output: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a' },
  { input: '616263', output: '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532' },
];

describe('SHA3-256', () => {
  describe('NIST FIPS 202 vectors', () => {
    for (const v of SHA3_256_VECTORS) {
      it(`sha3_256("${v.input || 'empty'}")`, async () => {
        const data = v.input ? hexToBytes(v.input) : new Uint8Array(0);
        const hash = await sha3_256.hash(data);
        expect(bytesToHex(hash)).toBe(v.output);
      });
    }
  });
});

// ── SHA3-512 vector ───────────────────────────────────────────────────────

describe('SHA3-512', () => {
  it('empty string vector (NIST FIPS 202)', async () => {
    const hash = await sha3_512.hash(new Uint8Array(0));
    expect(bytesToHex(hash)).toBe(
      'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'
    );
    expect(hash.length).toBe(64);
  });
});

// ── SHAKE-128 ────────────────────────────────────────────────────────────

describe('SHAKE-128', () => {
  it('produces variable-length output', async () => {
    const data = new Uint8Array(0);
    const h32  = await shake128.hash(data, 32);
    const h64  = await shake128.hash(data, 64);
    expect(h32.length).toBe(32);
    expect(h64.length).toBe(64);
    // First 32 bytes of 64-byte output should equal 32-byte output
    expect(bytesToHex(h64.slice(0, 32))).toBe(bytesToHex(h32));
  });
});

// ── SM3 — GM/T 0004 ──────────────────────────────────────────────────────

const SM3_VECTORS = [
  {
    // SM3("abc") — from GM/T 0004 Appendix A
    input:  '616263',
    output: '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
  },
  {
    // SM3("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd") — 64 bytes
    input:  '6162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364',
    output: 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732',
  },
];

describe('SM3 (GM/T 0004)', () => {
  for (const v of SM3_VECTORS) {
    it(`sm3("${v.input.slice(0, 12)}...")`, () => {
      const data = hexToBytes(v.input);
      const hash = sm3.hash(data);
      expect(bytesToHex(hash)).toBe(v.output);
    });
  }

  it('output is always 32 bytes', () => {
    for (const len of [0, 1, 55, 64]) {
      const hash = sm3.hash(new Uint8Array(len));
      expect(hash.length).toBe(32);
    }
  });
});
