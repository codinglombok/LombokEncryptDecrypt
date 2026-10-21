/**
 * Extended NIST CAVP vectors — gated by LOMBOK_VERIFY_NIST_CAVP=true
 * (the vectors job sets this). Keeps the always-on suite fast while the
 * nightly/weekly job exercises the deeper published cases.
 */

import { aesGcmEncrypt } from '../../src/modes/gcm.js';
import { sha256, sha512 } from '../../src/core/sha/sha256.js';

const enc = new TextEncoder();
const CAVP_ENABLED = process.env.LOMBOK_VERIFY_NIST_CAVP === 'true';

const describeCavp = CAVP_ENABLED ? describe : describe.skip;

describeCavp('NIST CAVP deep vectors (LOMBOK_VERIFY_NIST_CAVP=true)', () => {
  it('GCM official spec vectors (TC3/TC4/TC6/TC7)', async () => {
    // NIST GCM spec (McGrew-Viega) Appendix B test cases. TC3/TC4 use the
    // 128-bit key, TC6/TC7 the 256-bit key; TC4/TC7 truncate the 64-byte
    // plaintext to 60 bytes and authenticate the 20-byte AAD.
    const pt64 = Buffer.from(
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
      'hex',
    );
    const pt60 = pt64.subarray(0, 60);
    const iv = Buffer.from('cafebabefacedbaddecaf888', 'hex');
    const aad = Buffer.from('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex');

    // TC3 — 128-bit key
    const key128 = Buffer.from('feffe9928665731c6d6a8f9467308308', 'hex');
    const res3 = await aesGcmEncrypt(new Uint8Array(pt64), new Uint8Array(key128), {
      iv: new Uint8Array(iv),
    });
    expect(Buffer.from(res3.ciphertext).toString('hex')).toBe(
      '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
    );
    expect(Buffer.from(res3.tag).toString('hex')).toBe('4d5c2af327cd64a62cf35abd2ba6fab4');

    // TC4 — 128-bit key + AAD
    const res4 = await aesGcmEncrypt(new Uint8Array(pt60), new Uint8Array(key128), {
      iv: new Uint8Array(iv),
      aad: new Uint8Array(aad),
    });
    expect(Buffer.from(res4.ciphertext).toString('hex')).toBe(
      '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091',
    );
    expect(Buffer.from(res4.tag).toString('hex')).toBe('5bc94fbc3221a5db94fae95ae7121a47');

    // TC6 — 256-bit key
    const key256 = Buffer.from(
      'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
      'hex',
    );
    const res6 = await aesGcmEncrypt(new Uint8Array(pt64), new Uint8Array(key256), {
      iv: new Uint8Array(iv),
    });
    expect(Buffer.from(res6.ciphertext).toString('hex')).toBe(
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad',
    );
    expect(Buffer.from(res6.tag).toString('hex')).toBe('b094dac5d93471bdec1a502270e3cc6c');

    // TC7 — 256-bit key + AAD
    const res7 = await aesGcmEncrypt(new Uint8Array(pt60), new Uint8Array(key256), {
      iv: new Uint8Array(iv),
      aad: new Uint8Array(aad),
    });
    expect(Buffer.from(res7.ciphertext).toString('hex')).toBe(
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
    );
    expect(Buffer.from(res7.tag).toString('hex')).toBe('76fc6ece0f4e1768cddf8853bb2d551b');
  });

  it('SHA-2 "two-block" messages (56-byte NIST example)', async () => {
    const msg = enc.encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
    expect(Buffer.from(await sha256.hash(msg)).toString('hex')).toBe(
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    );
    const millionA = new Uint8Array(1_000_000).fill(0x61);
    expect(Buffer.from(await sha256.hash(millionA)).toString('hex')).toBe(
      'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
    );
    expect(Buffer.from(await sha512.hash(millionA)).toString('hex')).toBe(
      'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b',
    );
  });
});
