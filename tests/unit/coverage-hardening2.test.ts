/**
 * Coverage hardening round 2 — remaining branch surfaces.
 */

import { blake3, Blake3Hasher } from '../../src/core/blake3/blake3.js';
import { sm4EncryptBlock, sm4ExpandKey, sm4DecryptBlock } from '../../src/core/sm/sm4.js';
import { sha384, sha224 } from '../../src/core/sha/sha256.js';
import { hkdf, hkdfDerive } from '../../src/kdf/hkdf.js';
import { scryptDerive } from '../../src/kdf/scrypt.js';
import { AuditLogger } from '../../src/audit/audit.js';
import { envelopeEncrypt } from '../../src/envelope/envelope.js';
import { chaCha20Poly1305, xchaChaPoly1305 } from '../../src/modes/chacha.js';
import { aesCbcEncrypt, aesCbcDecrypt } from '../../src/modes/cbc.js';
import { KeyStore } from '../../src/keystore/keystore.js';
import { createEncryptStream } from '../../src/stream/encrypt_stream.js';
import { randomKey256, randomBytes } from '../../src/utils/random.js';
import { ErrorCode } from '../../src/errors.js';

const enc = new TextEncoder();

describe('blake3 additional branches', () => {
  it('keyed + derive round-trips with XOF lengths', async () => {
    const key = randomKey256();
    const data = enc.encode('blake3 branches');
    expect(await blake3.keyed(key, data, 64)).toHaveLength(64);
    expect(await blake3.deriveKey('ctx', data, 17)).toHaveLength(17);
    // keyed + one-shot XOF consistency
    const hasher = Blake3Hasher.createKeyed(key);
    hasher.update(data);
    expect(hasher.finalize(40)).toEqual(await blake3.keyed(key, data, 40));
  });
});

describe('sm4 direct block validation', () => {
  it('rejects non-16-byte blocks', () => {
    const expanded = sm4ExpandKey(new Uint8Array(16));
    expect(() => sm4EncryptBlock(expanded, new Uint8Array(15))).toThrow(ErrorCode.INVALID_IV_SIZE);
    expect(() => sm4DecryptBlock(expanded, new Uint8Array(17))).toThrow(ErrorCode.INVALID_IV_SIZE);
  });
});

describe('sha224/384 public objects', () => {
  it('hash through the async wrappers', async () => {
    expect(await sha224.hash(enc.encode('abc'))).toHaveLength(28);
    expect(await sha384.hash(enc.encode('abc'))).toHaveLength(48);
  });
});

describe('hkdf sha384 convenience', () => {
  it('derives via all three hashes', async () => {
    const ikm = new Uint8Array(16).fill(9);
    expect(await hkdf.sha384(ikm, undefined, undefined, 32)).toHaveLength(32);
    expect(await hkdfDerive(ikm, { hash: 'SHA-384', outputLength: 48 })).toHaveLength(48);
  });
});

describe('scrypt extra parameter shapes', () => {
  it('handles dkLen 1 and multi-block outputs', async () => {
    expect(await scryptDerive('a', 'b', { N: 16, r: 1, p: 1, dkLen: 1 })).toHaveLength(1);
    expect(await scryptDerive('a', 'b', { N: 16, r: 2, p: 3, dkLen: 100 })).toHaveLength(100);
  });
});

describe('audit branches', () => {
  it('rejects oversized payloads and decodes entries without keyId', () => {
    const log = new AuditLogger();
    log.log({
      operation: 'op',
      algorithm: 'AES-256-GCM',
      inputLength: 1,
      outputLength: 1,
      success: true,
    });
    const decoded = AuditLogger.decode(log.toBytes());
    expect(decoded[0].keyId).toBeUndefined();
    const huge = 'x'.repeat(70000);
    expect(() =>
      log.log({ operation: huge, algorithm: 'a', inputLength: 1, outputLength: 1, success: true }),
    ).toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
  });
});

describe('envelope rewrap validation', () => {
  it('rejects invalid KEK sizes in rewrap', async () => {
    const kek = randomKey256();
    const res = await envelopeEncrypt.encrypt(new Uint8Array(4), kek, 'k');
    await expect(envelopeEncrypt.rewrap(res.encryptedKey, kek, new Uint8Array(31))).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
  });
});

describe('chacha facade helpers', () => {
  it('generateKey/generateNonce sizes', () => {
    expect(chaCha20Poly1305.generateKey()).toHaveLength(32);
    expect(chaCha20Poly1305.generateNonce()).toHaveLength(12);
    expect(xchaChaPoly1305.generateKey()).toHaveLength(32);
    expect(xchaChaPoly1305.generateNonce()).toHaveLength(24);
  });
});

describe('cbc includeIv edge', () => {
  it('rejects a blob that contains only an IV', async () => {
    const key = randomKey256();
    await expect(
      aesCbcDecrypt(randomBytes(16), key, undefined, { includeIv: true }),
    ).rejects.toThrow(ErrorCode.INVALID_IV_SIZE);
    const pt = randomBytes(16);
    const { ciphertext } = await aesCbcEncrypt(pt, key, randomBytes(16));
    await expect(aesCbcDecrypt(ciphertext.subarray(0, 15), key, randomBytes(16))).rejects.toThrow(
      ErrorCode.INVALID_INPUT,
    );
  });
});

describe('keystore expiry round-trip through serialization', () => {
  it('expired entries stay expired after open()', async () => {
    const ks = await KeyStore.create({ password: 'pw', m: 1024, r: 8, p: 1 });
    await ks.set('gone', randomKey256(), 'AES-256-GCM', { ttlMs: -1000 });
    const blob = await ks.serialize();
    const reopened = await KeyStore.open(blob, { password: 'pw' });
    await expect(reopened.get('gone')).rejects.toThrow(ErrorCode.KEY_EXPIRED);
  });
});

describe('stream chunkSize validation', () => {
  it('rejects non-integer chunk sizes', () => {
    expect(() =>
      createEncryptStream({ algorithm: 'AES-256-GCM', key: randomKey256(), chunkSize: 1.5 }),
    ).toThrow(ErrorCode.INVALID_IV_SIZE);
  });
});
