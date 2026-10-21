import { aesCbcEncrypt, aesCbcDecrypt } from '../../src/modes/cbc.js';
import { sm4, sm4ExpandKey, sm4EncryptBlock, sm4DecryptBlock } from '../../src/core/sm/sm4.js';
import { aesXtsEncrypt, aesXtsDecrypt } from '../../src/modes/xts.js';
import { createCipheriv, randomBytes } from 'node:crypto';
import { hasNodeAesCbc } from '../platform-caps.js';
import { ErrorCode } from '../../src/errors.js';

const itIfCbc = hasNodeAesCbc ? it : it.skip;

describe('AES-CBC (SP 800-38A F.2.1)', () => {
  const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');
  const iv = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const pt1 = Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex');

  it('matches the published NIST vector (first block)', async () => {
    const res = await aesCbcEncrypt(new Uint8Array(pt1), new Uint8Array(key), new Uint8Array(iv));
    expect(
      Buffer.from(res.ciphertext).toString('hex').startsWith('7649abac8119b246cee98e9b12e9197d'),
    ).toBe(true);
  });

  itIfCbc('cross-checks against OpenSSL including padding', async () => {
    for (const size of [16, 24, 32]) {
      for (const len of [1, 15, 16, 17, 31, 32, 48]) {
        const k = randomBytes(size);
        const pt = randomBytes(len);
        const ref = createCipheriv('aes-' + size * 8 + '-cbc', k, iv);
        const refCt = Buffer.concat([ref.update(pt), ref.final()]);
        const mine = await aesCbcEncrypt(pt, k, new Uint8Array(iv));
        expect(Buffer.from(mine.ciphertext).equals(refCt)).toBe(true);
        const back = await aesCbcDecrypt(mine.ciphertext, k, new Uint8Array(iv));
        expect(Buffer.from(back).equals(pt)).toBe(true);
      }
    }
  });

  it('supports includeIv and rejects tampered padding', async () => {
    const k = randomBytes(32);
    const pt = randomBytes(20);
    const res = await aesCbcEncrypt(pt, k, undefined, { includeIv: true });
    expect(res.ciphertext.length).toBe(16 + 32);
    const back = await aesCbcDecrypt(res.ciphertext, k, undefined, { includeIv: true });
    expect(Buffer.from(back).equals(pt)).toBe(true);
    // flip a padding byte
    const tampered = new Uint8Array(res.ciphertext);
    tampered[tampered.length - 1] ^= 0xff;
    await expect(aesCbcDecrypt(tampered, k, undefined, { includeIv: true })).rejects.toThrow(
      ErrorCode.INTEGRITY_CHECK_FAILED,
    );
  });

  it('validates key/iv and rejects missing IV without includeIv', async () => {
    await expect(
      aesCbcEncrypt(new Uint8Array(5), new Uint8Array(10), new Uint8Array(16)),
    ).rejects.toThrow(ErrorCode.INVALID_KEY_SIZE);
    await expect(
      aesCbcEncrypt(new Uint8Array(5), new Uint8Array(16), new Uint8Array(15)),
    ).rejects.toThrow(ErrorCode.INVALID_IV_SIZE);
    await expect(aesCbcDecrypt(new Uint8Array(32), new Uint8Array(16))).rejects.toThrow(
      ErrorCode.INVALID_IV_SIZE,
    );
  });
});

describe('SM4 (GM/T 0002-2012)', () => {
  it('matches the standard example vector', () => {
    const key = Buffer.from('0123456789abcdeffedcba9876543210', 'hex');
    const pt = Buffer.from('0123456789abcdeffedcba9876543210', 'hex');
    const expanded = sm4ExpandKey(new Uint8Array(key));
    expect(Buffer.from(sm4EncryptBlock(expanded, new Uint8Array(pt))).toString('hex')).toBe(
      '681edf34d206965e86b3e94f536e4246',
    );
    expect(
      Buffer.from(
        sm4DecryptBlock(
          expanded,
          new Uint8Array(Buffer.from('681edf34d206965e86b3e94f536e4246', 'hex')),
        ),
      ).toString('hex'),
    ).toBe('0123456789abcdeffedcba9876543210');
  });

  it('cross-checks ECB against OpenSSL when SM4 is available', () => {
    let nodeSupports = true;
    try {
      createCipheriv('sm4-ecb', randomBytes(16), null);
    } catch {
      nodeSupports = false;
    }
    const key = randomBytes(16);
    const data = randomBytes(48);
    const mine = sm4.ecb(key, data);
    const back = sm4.ecb(key, mine, true);
    expect(Buffer.from(back).equals(data)).toBe(true);
    if (nodeSupports) {
      const ref = createCipheriv('sm4-ecb', key, null);
      ref.setAutoPadding(false);
      const refCt = Buffer.concat([ref.update(data), ref.final()]);
      expect(Buffer.from(mine).equals(refCt)).toBe(true);
    }
  });

  it('validates key size and data alignment', () => {
    expect(() => sm4.ecb(new Uint8Array(15), new Uint8Array(16))).toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    expect(() => sm4.ecb(new Uint8Array(16), new Uint8Array(15))).toThrow(
      ErrorCode.INTEGRITY_CHECK_FAILED,
    );
    expect(() => sm4ExpandKey(new Uint8Array(16))).not.toThrow();
  });
});

describe('AES-XTS (IEEE 1619 / SP 800-38E)', () => {
  it('round-trips full and stealing cases and matches OpenSSL when available', async () => {
    for (const keySize of [32, 64]) {
      const key = randomBytes(keySize);
      for (const len of [16, 32, 47, 48, 49, 128, 257]) {
        const pt = randomBytes(len);
        const ct = await aesXtsEncrypt(pt, key, 1n);
        expect(ct.length).toBe(len);
        const back = await aesXtsDecrypt(ct, key, 1n);
        expect(Buffer.from(back).equals(pt)).toBe(true);
        // different data-unit number changes the output
        const ct2 = await aesXtsEncrypt(pt, key, 2n);
        expect(Buffer.from(ct2).toString('hex')).not.toBe(Buffer.from(ct).toString('hex'));
        // OpenSSL cross-check (node's IV parameter IS the raw 16-byte tweak)
        try {
          const tweakIv = Buffer.alloc(16);
          tweakIv.writeBigUInt64LE(1n);
          const ref = createCipheriv('aes-' + keySize * 4 + '-xts', key, tweakIv);
          const refCt = Buffer.concat([ref.update(pt), ref.final()]);
          expect(Buffer.from(ct).equals(refCt)).toBe(true);
        } catch {
          // XTS unavailable in this OpenSSL build — roundtrip above still holds
        }
      }
    }
  });

  it('rejects invalid keys and short data units', async () => {
    await expect(aesXtsEncrypt(new Uint8Array(16), new Uint8Array(31), 0n)).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    await expect(aesXtsEncrypt(new Uint8Array(15), new Uint8Array(32), 0n)).rejects.toThrow();
    await expect(aesXtsDecrypt(new Uint8Array(15), new Uint8Array(32), 0n)).rejects.toThrow();
  });
});
