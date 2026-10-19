/**
 * LombokEncryptDecrypt — HMAC + HKDF Tests
 * RFC 4231, RFC 5869 test vectors
 */

import { hmacSha256, hmacSha512, hmac } from '../../src/mac/hmac.js';
import { hkdf } from '../../src/kdf/hkdf.js';
import { hexToBytes, bytesToHex } from '../../src/utils/encoding.js';

// ── HMAC-SHA256 — RFC 4231 vectors ────────────────────────────────────────

const HMAC_SHA256_VECTORS = [
  {
    id: 'rfc4231-tc1',
    key:     '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    message: '4869205468657265',
    output:  'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
  },
  {
    id: 'rfc4231-tc2',
    key:     '4a656665',
    message: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
    output:  '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  },
  {
    id: 'rfc4231-tc3',
    key:     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    message: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    output:  '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
  },
];

describe('HMAC-SHA256', () => {
  describe('RFC 4231 test vectors', () => {
    for (const v of HMAC_SHA256_VECTORS) {
      it(v.id, async () => {
        const key     = hexToBytes(v.key);
        const message = hexToBytes(v.message);
        const mac     = await hmacSha256.compute(key, message);
        expect(bytesToHex(mac)).toBe(v.output);
      });
    }
  });

  it('verify returns true for correct MAC', async () => {
    const key = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const msg = hexToBytes('4869205468657265');
    const mac = await hmacSha256.compute(key, msg);
    expect(await hmacSha256.verify(key, msg, mac)).toBe(true);
  });

  it('verify returns false for tampered MAC', async () => {
    const key = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const msg = hexToBytes('4869205468657265');
    const mac = await hmacSha256.compute(key, msg);
    const bad = new Uint8Array(mac); bad[0] ^= 0xFF;
    expect(await hmacSha256.verify(key, msg, bad)).toBe(false);
  });

  it('generic hmac.compute with SHA-256 matches hmacSha256', async () => {
    const key = new Uint8Array(32).fill(0xAA);
    const msg = new TextEncoder().encode('test message');
    const [r1, r2] = await Promise.all([
      hmacSha256.compute(key, msg),
      hmac.compute('SHA-256', key, msg),
    ]);
    expect(bytesToHex(r1)).toBe(bytesToHex(r2));
  });
});

// ── HKDF-SHA256 — RFC 5869 vectors ───────────────────────────────────────

const HKDF_VECTORS = [
  {
    id:     'rfc5869-tc1',
    ikm:    '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt:   '000102030405060708090a0b0c',
    info:   'f0f1f2f3f4f5f6f7f8f9',
    length: 42,
    okm:    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  },
  {
    id:     'rfc5869-tc2',
    ikm:    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
    salt:   '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    info:   'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    length: 82,
    okm:    'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
  },
  {
    id:     'rfc5869-tc3',
    ikm:    '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt:   '',
    info:   '',
    length: 42,
    okm:    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
  },
];

describe('HKDF-SHA256', () => {
  describe('RFC 5869 test vectors', () => {
    for (const v of HKDF_VECTORS) {
      it(v.id, async () => {
        const ikm  = hexToBytes(v.ikm);
        const salt = v.salt ? hexToBytes(v.salt) : undefined;
        const info = v.info ? hexToBytes(v.info) : new Uint8Array(0);
        const okm  = await hkdf.derive(ikm, { hash: 'SHA-256', salt, info, outputLength: v.length });
        expect(bytesToHex(okm)).toBe(v.okm);
      });
    }
  });

  it('sha256 convenience method produces same output', async () => {
    const ikm  = new Uint8Array(32).fill(0x0B);
    const r1   = await hkdf.derive(ikm, { hash: 'SHA-256', outputLength: 32 });
    const r2   = await hkdf.sha256(ikm, undefined, undefined, 32);
    expect(bytesToHex(r1)).toBe(bytesToHex(r2));
  });

  it('rejects output length > 32*255', async () => {
    await expect(hkdf.derive(new Uint8Array(32), { hash: 'SHA-256', outputLength: 32 * 256 }))
      .rejects.toThrow(RangeError);
  });
});
