import { envelopeEncrypt } from '../../src/envelope/envelope.js';
import { KeyStore } from '../../src/keystore/keystore.js';
import { AuditLogger } from '../../src/audit/audit.js';
import { legacy } from '../../src/legacy/legacy.js';
import { createCipheriv, createHash } from 'node:crypto';
import { randomBytes, randomKey256 } from '../../src/utils/random.js';
import { bytesToString, stringToBytes, timingSafeEqual } from '../../src/utils/encoding.js';
import { ErrorCode } from '../../src/errors.js';

describe('envelope encryption (KEK/DEK)', () => {
  const kek = randomKey256();
  const kek2 = randomKey256();

  it('round-trips and encodes encryptedData as IV||CT||tag', async () => {
    const msg = randomBytes(100);
    const res = await envelopeEncrypt.encrypt(msg, kek, 'kek-2026', stringToBytes('ctx'));
    expect(res.encryptedData.length).toBe(12 + 100 + 16);
    expect(res.encryptedKey.algorithm).toBe('AES-256-GCM');
    expect(res.encryptedKey.kemId).toBe('kek-2026');
    const back = await envelopeEncrypt.decrypt(
      res.encryptedData,
      res.encryptedKey,
      kek,
      stringToBytes('ctx'),
    );
    expect(back).toEqual(msg);
  });

  it('fails with the wrong KEK or wrong AAD', async () => {
    const msg = randomBytes(50);
    const res = await envelopeEncrypt.encrypt(msg, kek, 'kek-1');
    await expect(
      envelopeEncrypt.decrypt(res.encryptedData, res.encryptedKey, kek2),
    ).rejects.toThrow(ErrorCode.AUTHENTICATION_FAILED);
    await expect(
      envelopeEncrypt.decrypt(res.encryptedData, res.encryptedKey, kek, stringToBytes('other')),
    ).rejects.toThrow(ErrorCode.AUTHENTICATION_FAILED);
  });

  it('rewrap rotates the KEK without touching encryptedData', async () => {
    const msg = randomBytes(33);
    const res = await envelopeEncrypt.encrypt(msg, kek, 'kek-1');
    const rotated = await envelopeEncrypt.rewrap(res.encryptedKey, kek, kek2, 'kek-2');
    expect(rotated.kemId).toBe('kek-2');
    expect(Buffer.from(rotated.wrappedDek).toString('hex')).not.toBe(
      Buffer.from(res.encryptedKey.wrappedDek).toString('hex'),
    );
    const back = await envelopeEncrypt.decrypt(res.encryptedData, rotated, kek2);
    expect(back).toEqual(msg);
    await expect(envelopeEncrypt.decrypt(res.encryptedData, rotated, kek)).rejects.toThrow(
      ErrorCode.AUTHENTICATION_FAILED,
    );
  });

  it('validates KEK size and algorithm string', async () => {
    await expect(
      envelopeEncrypt.encrypt(new Uint8Array(4), new Uint8Array(31), 'k'),
    ).rejects.toThrow(ErrorCode.INVALID_KEY_SIZE);
    const res = await envelopeEncrypt.encrypt(new Uint8Array(4), kek, 'k');
    await expect(
      envelopeEncrypt.decrypt(
        res.encryptedData,
        { ...res.encryptedKey, algorithm: 'AES-128-GCM' },
        kek,
      ),
    ).rejects.toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
    await expect(envelopeEncrypt.decrypt(new Uint8Array(3), res.encryptedKey, kek)).rejects.toThrow(
      ErrorCode.INTEGRITY_CHECK_FAILED,
    );
  });
});

describe('KeyStore v2 (scrypt → HKDF → AES-GCM + HMAC trailer)', () => {
  const PASSWORD = 'vault-password';
  const SLOW = { m: 1024, r: 8, p: 1 };

  it('stores, lists, generates, deletes and round-trips via serialize/open', async () => {
    const ks = await KeyStore.create({ password: PASSWORD, ...SLOW });
    const key = randomKey256();
    await ks.set('my-key', key, 'AES-256-GCM');
    await ks.generateKey('enc-2026', 'AES-256-GCM');
    await ks.set('chacha', randomKey256(), 'ChaCha20-Poly1305');
    expect(ks.list().sort()).toEqual(['chacha', 'enc-2026', 'my-key']);
    expect(await ks.get('my-key')).toEqual(key);
    ks.delete('chacha');
    expect(ks.list().sort()).toEqual(['enc-2026', 'my-key']);

    const blob = await ks.serialize();
    const reopened = await KeyStore.open(blob, { password: PASSWORD });
    expect(await reopened.get('my-key')).toEqual(key);
    expect(await reopened.get('enc-2026').then((k) => k.length)).toBe(32);
  });

  it('throws KEYSTORE_CORRUPT on wrong password or tampering', async () => {
    const ks = await KeyStore.create({ password: PASSWORD, ...SLOW });
    await ks.generateKey('k', 'AES-256-GCM');
    const blob = await ks.serialize();
    await expect(KeyStore.open(blob, { password: 'wrong' })).rejects.toThrow(
      ErrorCode.KEYSTORE_CORRUPT,
    );
    const tampered = new Uint8Array(blob);
    tampered[tampered.length - 40] ^= 1;
    await expect(KeyStore.open(tampered, { password: PASSWORD })).rejects.toThrow(
      ErrorCode.KEYSTORE_CORRUPT,
    );
    await expect(KeyStore.open(new Uint8Array(10), { password: PASSWORD })).rejects.toThrow(
      ErrorCode.KEYSTORE_CORRUPT,
    );
    const badMagic = new Uint8Array(blob);
    badMagic[0] = 0x00;
    await expect(KeyStore.open(badMagic, { password: PASSWORD })).rejects.toThrow(
      ErrorCode.KEYSTORE_CORRUPT,
    );
    const badVersion = new Uint8Array(blob);
    badVersion[4] = 9;
    await expect(KeyStore.open(badVersion, { password: PASSWORD })).rejects.toThrow(
      ErrorCode.KEYSTORE_CORRUPT,
    );
  });

  it('enforces lock/unlock lifecycle', async () => {
    const ks = await KeyStore.create({ password: PASSWORD, ...SLOW });
    await ks.generateKey('k', 'AES-256-GCM');
    ks.lock();
    await expect(ks.get('k')).rejects.toThrow(ErrorCode.KEYSTORE_LOCKED);
    await expect(ks.set('k2', randomKey256(), 'AES-256-GCM')).rejects.toThrow(
      ErrorCode.KEYSTORE_LOCKED,
    );
    await expect(ks.serialize()).rejects.toThrow(ErrorCode.KEYSTORE_LOCKED);
    await ks.unlock(PASSWORD);
    expect((await ks.get('k')).length).toBe(32);
  });

  it('reports KEY_NOT_FOUND and KEY_EXPIRED', async () => {
    const ks = await KeyStore.create({ password: PASSWORD, ...SLOW });
    await expect(ks.get('missing')).rejects.toThrow(ErrorCode.KEY_NOT_FOUND);
    await ks.set('temp', randomKey256(), 'AES-256-GCM', { ttlMs: -1000 });
    await expect(ks.get('temp')).rejects.toThrow(ErrorCode.KEY_EXPIRED);
  });

  it('validates algorithm names and key sizes', async () => {
    const ks = await KeyStore.create({ password: PASSWORD, ...SLOW });
    await expect(ks.set('x', new Uint8Array(16), 'NOT-ALG')).rejects.toThrow(
      ErrorCode.UNSUPPORTED_ALGORITHM,
    );
    await expect(ks.set('x', new Uint8Array(15), 'AES-128-GCM')).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    await expect(ks.generateKey('x', 'SM4-ECB')).rejects.toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
  });
});

describe('AuditLogger', () => {
  it('appends, encodes and decodes entries with the LEDL block format', () => {
    const log = new AuditLogger();
    log.log({
      operation: 'encrypt',
      algorithm: 'AES-256-GCM',
      inputLength: 10,
      outputLength: 10,
      success: true,
      timestamp: 1726643200000,
    });
    log.log({
      operation: 'decrypt',
      algorithm: 'AES-256-GCM',
      keyId: 'k-1',
      inputLength: 20,
      outputLength: 20,
      success: false,
      timestamp: 1726643201000,
    });
    const bytes = log.toBytes();
    const decoded = AuditLogger.decode(bytes);
    expect(decoded.length).toBe(2);
    expect(decoded[0].operation).toBe('encrypt');
    expect(decoded[0].timestamp).toBe(1726643200000);
    expect(decoded[0].platform).toContain('/');
    expect(decoded[1].keyId).toBe('k-1');
    expect(decoded[1].success).toBe(false);
    // magic bytes
    expect(String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3])).toBe('LEDL');
  });

  it('detects structural corruption', () => {
    const log = new AuditLogger();
    log.log({
      operation: 'op',
      algorithm: 'AES-256-GCM',
      inputLength: 1,
      outputLength: 1,
      success: true,
    });
    const bytes = new Uint8Array(log.toBytes());
    bytes[0] = 0x00; // bad magic
    expect(() => AuditLogger.decode(bytes)).toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
    const truncated = new Uint8Array(log.toBytes().subarray(0, 10));
    expect(() => AuditLogger.decode(truncated)).toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
    const version = new Uint8Array(log.toBytes());
    version[4] = 99;
    expect(() => AuditLogger.decode(version)).toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
    const badJson = new Uint8Array(log.toBytes());
    badJson[15] = 0x7b ^ 0xff; // corrupt first payload byte (starts '{')
    expect(() => AuditLogger.decode(badJson)).toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
  });
});

describe('legacy namespace', () => {
  it('refuses to run without { legacy: true }', async () => {
    await expect(legacy.md5(new Uint8Array(4))).rejects.toThrow(ErrorCode.LEGACY_DISABLED);
    expect(() => legacy.rc4(new Uint8Array(16), new Uint8Array(4))).toThrow(
      ErrorCode.LEGACY_DISABLED,
    );
    await expect(legacy.aesEcbEncrypt(new Uint8Array(16), new Uint8Array(16))).rejects.toThrow(
      ErrorCode.LEGACY_DISABLED,
    );
    await expect(legacy.aesEcbDecrypt(new Uint8Array(16), new Uint8Array(16))).rejects.toThrow(
      ErrorCode.LEGACY_DISABLED,
    );
  });

  it('MD5 matches node and the RFC 1321 vectors', async () => {
    const gate = { legacy: true as const };
    const abc = await legacy.md5(new TextEncoder().encode('abc'), gate);
    expect(Buffer.from(abc).toString('hex')).toBe('900150983cd24fb0d6963f7d28e17f72');
    expect(Buffer.from(abc).toString('hex')).toBe(createHash('md5').update('abc').digest('hex'));
  });

  it('RC4 matches the published "Attack at dawn" vector and is symmetric', () => {
    const gate = { legacy: true as const };
    // Widely-published RC4 test vector (Wikipedia / standard test sets)
    const wiki = legacy.rc4(
      new Uint8Array(Buffer.from('Secret', 'ascii')),
      new Uint8Array(Buffer.from('Attack at dawn', 'ascii')),
      gate,
    );
    expect(Buffer.from(wiki).toString('hex')).toBe('45a01f645fc35b383552544b9bf5');
    const key = new Uint8Array(Buffer.from('0102030405', 'hex'));
    const pt = new Uint8Array(38);
    const ct = legacy.rc4(key, pt, gate);
    expect(Buffer.from(ct).toString('hex')).toBe(
      'b2396305f03dc027ccc3524a0a1118a86982944f18fc82d589c403a47a0d0919b68f78c28d15',
    );
    const back = legacy.rc4(key, ct, gate);
    expect(back).toEqual(pt);
    expect(() => legacy.rc4(new Uint8Array(0), pt, gate)).toThrow(ErrorCode.INVALID_KEY_SIZE);
    expect(() => legacy.rc4(new Uint8Array(257), pt, gate)).toThrow(ErrorCode.INVALID_KEY_SIZE);
  });

  it('AES-ECB round-trips and matches OpenSSL', async () => {
    const gate = { legacy: true as const };
    const key = randomBytes(32);
    const data = randomBytes(48);
    const ct = await legacy.aesEcbEncrypt(key, data, gate);
    const ref = createCipheriv('aes-256-ecb', key, null);
    ref.setAutoPadding(false);
    const refCt = Buffer.concat([ref.update(data), ref.final()]);
    expect(Buffer.from(ct).equals(refCt)).toBe(true);
    expect(await legacy.aesEcbDecrypt(key, ct, gate)).toEqual(data);
    await expect(legacy.aesEcbEncrypt(key, new Uint8Array(15), gate)).rejects.toThrow(
      ErrorCode.INTEGRITY_CHECK_FAILED,
    );
    await expect(
      legacy.aesEcbEncrypt(new Uint8Array(15), new Uint8Array(16), gate),
    ).rejects.toThrow(ErrorCode.INVALID_KEY_SIZE);
  });

  it('exposes timingSafeEqual semantics through the root barrel as well', () => {
    expect(timingSafeEqual(new Uint8Array([1]), new Uint8Array([1]))).toBe(true);
    expect(bytesToString(stringToBytes('ok'))).toBe('ok');
  });
});
