import { aesGcm, aesGcmEncrypt, aesGcmDecrypt } from '../../src/modes/gcm.js';
import { createCipheriv, createDecipheriv, randomBytes, type CipherGCM } from 'node:crypto';
import { hasNodeAesGcm } from '../platform-caps.js';
import { ErrorCode, LombokCryptoError } from '../../src/errors.js';

const itIfAesGcm = hasNodeAesGcm ? it : it.skip;

describe('AES-GCM (SP 800-38D)', () => {
  it('matches the published NIST test cases 1 & 2', async () => {
    const key = new Uint8Array(16);
    const iv = new Uint8Array(12);
    const empty = await aesGcmEncrypt(new Uint8Array(0), key, { iv });
    expect(Buffer.from(empty.tag).toString('hex')).toBe('58e2fccefa7e3061367f1d57a4e7455a');
    const single = await aesGcmEncrypt(new Uint8Array(16), key, { iv });
    expect(Buffer.from(single.ciphertext).toString('hex')).toBe('0388dace60b6a392f328c2b971b2fe78');
    expect(Buffer.from(single.tag).toString('hex')).toBe('ab6e47d42cec13bdf53a67b21257bddf');
  });

  itIfAesGcm(
    'cross-checks ciphertext+tag against OpenSSL for all key sizes, lengths and AADs',
    async () => {
      for (const size of [16, 24, 32]) {
        for (const len of [0, 15, 16, 17, 33, 64]) {
          for (const aadLen of [0, 12, 21]) {
            const key = randomBytes(size);
            const pt = randomBytes(len);
            const aad = randomBytes(aadLen);
            const iv = randomBytes(12);
            const mine = await aesGcmEncrypt(pt, key, { iv, aad });
            const ref = createCipheriv('aes-' + size * 8 + '-gcm', key, iv) as CipherGCM;
            ref.setAAD(aad);
            const refCt = Buffer.concat([ref.update(pt), ref.final()]);
            expect(Buffer.from(mine.ciphertext).equals(refCt)).toBe(true);
            expect(Buffer.from(mine.tag).equals(ref.getAuthTag())).toBe(true);
            const back = await aesGcmDecrypt(mine.ciphertext, key, iv, mine.tag, { aad });
            expect(Buffer.from(back).equals(pt)).toBe(true);
          }
        }
      }
    },
  );

  itIfAesGcm('supports truncated tags and infers tag length on decrypt', async () => {
    const key = randomBytes(32);
    const pt = randomBytes(40);
    const iv = randomBytes(12);
    for (const tagLen of [4, 6, 8, 10, 12, 14, 16] as const) {
      const res = await aesGcmEncrypt(pt, key, { iv, tagLength: tagLen });
      expect(res.tag.length).toBe(tagLen);
      const back = await aesGcmDecrypt(res.ciphertext, key, iv, res.tag);
      expect(Buffer.from(back).equals(pt)).toBe(true);
    }
  });

  it('throws AUTHENTICATION_FAILED on tampering (constant path, no partial plaintext)', async () => {
    const key = randomBytes(32);
    const pt = randomBytes(50);
    const res = await aesGcm.encrypt(pt, key);
    res.tag[0] ^= 1;
    let caught: LombokCryptoError | undefined;
    try {
      await aesGcm.decrypt(res.ciphertext, key, res.iv, res.tag);
    } catch (e) {
      caught = e as LombokCryptoError;
    }
    expect(caught).toBeInstanceOf(LombokCryptoError);
    expect(caught?.code).toBe(ErrorCode.AUTHENTICATION_FAILED);
    // tampered ciphertext
    const res2 = await aesGcm.encrypt(pt, key);
    res2.ciphertext[3] ^= 0x80;
    await expect(aesGcm.decrypt(res2.ciphertext, key, res2.iv, res2.tag)).rejects.toThrow(
      ErrorCode.AUTHENTICATION_FAILED,
    );
    // wrong AAD
    const res3 = await aesGcm.encrypt(pt, key, { aad: new Uint8Array([1, 2, 3]) });
    await expect(
      aesGcm.decrypt(res3.ciphertext, key, res3.iv, res3.tag, { aad: new Uint8Array([1, 2, 4]) }),
    ).rejects.toThrow(ErrorCode.AUTHENTICATION_FAILED);
  });

  it('validates key and IV sizes with the documented error codes', async () => {
    await expect(aesGcmEncrypt(new Uint8Array(4), new Uint8Array(17))).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    await expect(
      aesGcmEncrypt(new Uint8Array(4), new Uint8Array(32), { iv: new Uint8Array(11) }),
    ).rejects.toThrow(ErrorCode.INVALID_IV_SIZE);
    await expect(
      aesGcmDecrypt(new Uint8Array(16), new Uint8Array(32), new Uint8Array(12), new Uint8Array(16)),
    ).rejects.toThrow(ErrorCode.AUTHENTICATION_FAILED);
    await expect(
      aesGcm.encrypt(new Uint8Array(4), new Uint8Array(16), { tagLength: 5 as 4 }),
    ).rejects.toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
  });

  it('generates a random IV when omitted and returns it', async () => {
    const key = randomBytes(32);
    const a = await aesGcm.encrypt(new Uint8Array(8), key);
    const b = await aesGcm.encrypt(new Uint8Array(8), key);
    expect(a.iv.length).toBe(12);
    expect(Buffer.from(a.iv).toString('hex')).not.toBe(Buffer.from(b.iv).toString('hex'));
  });

  it('facade helpers produce correct sizes', () => {
    expect(aesGcm.generateKey(128).length).toBe(16);
    expect(aesGcm.generateKey(192).length).toBe(24);
    expect(aesGcm.generateKey(256).length).toBe(32);
    expect(aesGcm.generateKey().length).toBe(32);
    expect(aesGcm.generateIv().length).toBe(12);
    expect(() => aesGcm.generateKey(100 as 128)).toThrow();
  });

  itIfAesGcm('is compatible with OpenSSL decryption of its own output', async () => {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const aad = randomBytes(9);
    const pt = randomBytes(77);
    const mine = await aesGcmEncrypt(pt, key, { iv, aad });
    const d = createDecipheriv('aes-256-gcm', key, iv);
    d.setAAD(aad);
    d.setAuthTag(mine.tag);
    const back = Buffer.concat([d.update(mine.ciphertext), d.final()]);
    expect(back.equals(pt)).toBe(true);
  });
});
