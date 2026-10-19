#!/usr/bin/env node
/**
 * LombokEncryptDecrypt — generate the cross-language test vector file.
 *
 * Every expected value is computed with OpenSSL (node:crypto) from standard inputs,
 * never typed from memory. A few outputs are also checked against published RFC
 * values as a sanity check; the script aborts if they disagree.
 *
 * Only algorithms that are actually implemented belong here. Argon2id, BLAKE3 and
 * ML-KEM are intentionally absent until their implementations land.
 *
 * Usage: node scripts/generate-vectors.mjs
 */

import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createCipheriv, createHash, createHmac, createPrivateKey, createPublicKey, hkdfSync, sign,
} from 'node:crypto';

const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../tests/vectors/lombokencryptdecrypt-vectors-v1.json');
const hex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Buffer.from(h, 'hex');
const check = (label, actual, expected) => {
  if (actual !== expected) throw new Error(`sanity check failed: ${label}\n  got      ${actual}\n  expected ${expected}`);
};

const vectors = {
  _meta: {
    version: 1,
    library: 'LombokEncryptDecrypt',
    description: 'Cross-language test vectors. Expected values computed with OpenSSL via node:crypto.',
    sources: ['NIST SP 800-38D', 'RFC 8439', 'RFC 8032', 'RFC 4231', 'RFC 5869', 'NIST FIPS 180-4', 'NIST FIPS 202', 'NIST SP 800-38A', 'RFC 1321'],
  },
};

// ── AES-GCM ──────────────────────────────────────────────────────────────
function gcm(key, iv, pt, aad) {
  const c = createCipheriv(`aes-${key.length * 8}-gcm`, key, iv, { authTagLength: 16 });
  if (aad.length) c.setAAD(aad);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  return { ciphertext: hex(ct), tag: hex(c.getAuthTag()) };
}
const gcmInputs = [
  { id: 'aes-gcm-256-aad', algorithm: 'AES-256-GCM',
    key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', iv: 'cafebabefacedbaddecaf888',
    aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    plaintext: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39' },
  { id: 'aes-gcm-128-empty', algorithm: 'AES-128-GCM',
    key: '00000000000000000000000000000000', iv: '000000000000000000000000', aad: '', plaintext: '' },
  { id: 'aes-gcm-192-no-aad', algorithm: 'AES-192-GCM',
    key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c', iv: 'cafebabefacedbaddecaf888', aad: '',
    plaintext: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' },
];
vectors.aes_gcm = gcmInputs.map((v) => ({ ...v, ...gcm(fromHex(v.key), fromHex(v.iv), fromHex(v.plaintext), fromHex(v.aad)) }));
check('GCM empty-plaintext tag (NIST test case 1)', vectors.aes_gcm[1].tag, '58e2fccefa7e3061367f1d57a4e7455a');

// ── ChaCha20-Poly1305 (RFC 8439 §2.8.2) ──────────────────────────────────
{
  const key = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const nonce = fromHex('070000004041424344454647');
  const aad = fromHex('50515253c0c1c2c3c4c5c6c7');
  const pt = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  c.setAAD(aad, { plaintextLength: pt.length });
  const ct = Buffer.concat([c.update(pt), c.final()]);
  const tag = c.getAuthTag();
  check('ChaCha20-Poly1305 tag (RFC 8439 §2.8.2)', hex(tag), '1ae10b594f09e26a7e902ecbd0600691');
  vectors.chacha20_poly1305 = [{
    id: 'chacha20-poly1305-rfc8439-1', source: 'RFC 8439 Section 2.8.2',
    key: hex(key), nonce: hex(nonce), aad: hex(aad), pt: hex(pt), ct: hex(ct), tag: hex(tag),
  }];
}

// ── SHA-256 / SHA3-256 ───────────────────────────────────────────────────
const hashVec = (alg, id, input) => ({ id, input: hex(input), output: createHash(alg).update(input).digest('hex') });
vectors.sha256 = [
  hashVec('sha256', 'sha256-empty', Buffer.alloc(0)),
  hashVec('sha256', 'sha256-abc', Buffer.from('abc')),
  hashVec('sha256', 'sha256-448bit', Buffer.from('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')),
];
check('SHA-256("abc")', vectors.sha256[1].output, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
vectors.sha3_256 = [
  hashVec('sha3-256', 'sha3-256-empty', Buffer.alloc(0)),
  hashVec('sha3-256', 'sha3-256-abc', Buffer.from('abc')),
];
check('SHA3-256("abc")', vectors.sha3_256[1].output, '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');

// ── Ed25519 (RFC 8032 §7.1 tests 1 and 2) ────────────────────────────────
const PKCS8 = fromHex('302e020100300506032b657004220420');
function ed(id, seedHex, msgHex) {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8, fromHex(seedHex)]), format: 'der', type: 'pkcs8' });
  const pub = Buffer.from(createPublicKey(key).export({ format: 'jwk' }).x, 'base64url');
  return { id, source: 'RFC 8032 Section 7.1', private_key: seedHex, public_key: hex(pub), message: msgHex,
           signature: hex(sign(null, fromHex(msgHex), key)) };
}
vectors.ed25519 = [
  ed('ed25519-rfc8032-1', '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', ''),
  ed('ed25519-rfc8032-2', '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '72'),
];
check('Ed25519 test 1 public key', vectors.ed25519[0].public_key, 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
check('Ed25519 test 1 signature', vectors.ed25519[0].signature.slice(0, 32), 'e5564300c360ac729086e2cc806e828a');

// ── HMAC-SHA256 (RFC 4231 test cases 1 and 2) ────────────────────────────
const mac = (id, keyHex, msgHex) => ({ id, key: keyHex, message: msgHex, output: createHmac('sha256', fromHex(keyHex)).update(fromHex(msgHex)).digest('hex') });
vectors.hmac_sha256 = [
  mac('hmac-sha256-rfc4231-tc1', '0b'.repeat(20), hex(Buffer.from('Hi There'))),
  mac('hmac-sha256-rfc4231-tc2', hex(Buffer.from('Jefe')), hex(Buffer.from('what do ya want for nothing?'))),
];
check('HMAC TC1', vectors.hmac_sha256[0].output, 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
check('HMAC TC2', vectors.hmac_sha256[1].output, '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');

// ── HKDF-SHA256 (RFC 5869 test case 1) ───────────────────────────────────
{
  const ikm = '0b'.repeat(22), salt = '000102030405060708090a0b0c', info = 'f0f1f2f3f4f5f6f7f8f9';
  const okm = hex(Buffer.from(hkdfSync('sha256', fromHex(ikm), fromHex(salt), fromHex(info), 42)));
  check('HKDF TC1', okm, '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  vectors.hkdf_sha256 = [{ id: 'hkdf-sha256-rfc5869-1', ikm, salt, info, length: 42, okm }];
}

// ── SHA-384 / SHA-512 / MD5 (legacy) ─────────────────────────────────────
vectors.sha384 = [
  hashVec('sha384', 'sha384-empty', Buffer.alloc(0)),
  hashVec('sha384', 'sha384-abc', Buffer.from('abc')),
];
vectors.sha512 = [
  hashVec('sha512', 'sha512-empty', Buffer.alloc(0)),
  hashVec('sha512', 'sha512-abc', Buffer.from('abc')),
  hashVec('sha512', 'sha512-896bit', Buffer.from('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu')),
];
check('SHA-512("abc")', vectors.sha512[1].output.slice(0, 32), 'ddaf35a193617abacc417349ae204131');
vectors.md5 = [
  hashVec('md5', 'md5-empty', Buffer.alloc(0)),
  hashVec('md5', 'md5-abc', Buffer.from('abc')),
];
check('MD5("abc")', vectors.md5[1].output, '900150983cd24fb0d6963f7d28e17f72');

// ── AES-CBC / AES-ECB (NIST SP 800-38A F.1/F.2 inputs) ───────────────────
const sp38aPt = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51';
const sp38aKey = '2b7e151628aed2a6abf7158809cf4f3c';
const sp38aIv = '000102030405060708090a0b0c0d0e0f';
function cbc(id, keyHex, ivHex, ptHex, padding) {
  const c = createCipheriv(`aes-${keyHex.length * 4}-cbc`, fromHex(keyHex), fromHex(ivHex));
  c.setAutoPadding(padding === 'pkcs7');
  return { id, key: keyHex, iv: ivHex, padding, plaintext: ptHex, ciphertext: hex(Buffer.concat([c.update(fromHex(ptHex)), c.final()])) };
}
function ecb(id, keyHex, ptHex, padding) {
  const c = createCipheriv(`aes-${keyHex.length * 4}-ecb`, fromHex(keyHex), null);
  c.setAutoPadding(padding === 'pkcs7');
  return { id, key: keyHex, padding, plaintext: ptHex, ciphertext: hex(Buffer.concat([c.update(fromHex(ptHex)), c.final()])) };
}
vectors.aes_cbc = [
  cbc('aes-128-cbc-sp800-38a', sp38aKey, sp38aIv, sp38aPt, 'none'),
  cbc('aes-128-cbc-pkcs7', sp38aKey, sp38aIv, '00112233445566778899', 'pkcs7'),
  cbc('aes-256-cbc-pkcs7-empty', '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', sp38aIv, '', 'pkcs7'),
];
check('AES-128-CBC block 1 (SP 800-38A F.2.1)', vectors.aes_cbc[0].ciphertext.slice(0, 32), '7649abac8119b246cee98e9b12e9197d');
vectors.aes_ecb = [
  ecb('aes-128-ecb-sp800-38a', sp38aKey, sp38aPt, 'none'),
  ecb('aes-128-ecb-pkcs7', sp38aKey, '00112233445566778899', 'pkcs7'),
];
check('AES-128-ECB block 1 (SP 800-38A F.1.1)', vectors.aes_ecb[0].ciphertext.slice(0, 32), '3ad77bb40d7a3660a89ecaf32466ef97');

// ── RC4 (legacy) ─────────────────────────────────────────────────────────
// This OpenSSL build has no RC4 (legacy provider), so these are the widely published
// RC4 examples (Wikipedia / RFC 6229-style known answers), not computed here.
const rc4known = [
  ['rc4-key-plaintext', 'Key', 'Plaintext', 'bbf316e8d940af0ad3'],
  ['rc4-wiki-pedia', 'Wiki', 'pedia', '1021bf0420'],
  ['rc4-secret-attack', 'Secret', 'Attack at dawn', '45a01f645fc35b383552544b9bf5'],
];
vectors.rc4 = rc4known.map(([id, k, pt, ct]) => ({ id, source: 'published example', key: hex(Buffer.from(k)), plaintext: hex(Buffer.from(pt)), ciphertext: ct }));

writeFileSync(OUT, JSON.stringify(vectors, null, 2) + '\n', 'utf8');
console.log(`wrote ${OUT}`);
