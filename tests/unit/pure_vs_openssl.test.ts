/**
 * The library prefers node:crypto / WebCrypto, so tests that only call the public API
 * never touch the pure-TypeScript fallbacks. This suite runs those fallbacks directly
 * and compares them with OpenSSL, so a bug in a fallback cannot hide behind the native path.
 */
import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { aesGcmEncryptPure, aesGcmDecryptPure } from '../../src/modes/gcm.js';
import { chachaEncryptPure, chachaDecryptPure } from '../../src/core/chacha/chacha20.js';
import {
  hChaCha20,
  xchachaEncryptPure,
  xchachaDecryptPure,
} from '../../src/core/chacha/xchacha20.js';
import { keccakSponge } from '../../src/core/sha/sha3.js';
import { sha256 } from '../../src/core/sha/sha256.js';
import { sm3 } from '../../src/core/sm/sm3.js';
import { sm4EncryptBlock, sm4KeySchedule } from '../../src/core/sm/sm4.js';
import { createAes } from '../../src/core/aes/aes.js';

const hasCipher = (name: string): boolean => {
  try {
    const c = createCipheriv(name as 'aes-128-gcm', Buffer.alloc(16), Buffer.alloc(16), {
      authTagLength: 16,
    });
    c.final();
    return true;
  } catch {
    return false;
  }
};
const hasDigest = (name: string): boolean => {
  try {
    createHash(name as 'sha256')
      .update(new Uint8Array(0))
      .digest('hex');
    return true;
  } catch {
    return false;
  }
};
const HAS_CHACHA = hasCipher('chacha20-poly1305');
const HAS_SM4 = hasCipher('sm4-ecb');
const HAS_SM3 = hasDigest('sm3');
const hx = (b: Uint8Array | Buffer) => Buffer.from(b).toString('hex');
const u8 = (b: Buffer) => new Uint8Array(b);
const LENGTHS = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 135, 136, 137, 200, 1000];

describe('pure-TypeScript fallbacks match OpenSSL', () => {
  describe.each([16, 24, 32])('AES-%i', (keyLen) => {
    it('block cipher', () => {
      for (let i = 0; i < 20; i++) {
        const key = randomBytes(keyLen),
          block = randomBytes(16);
        const e = createCipheriv(`aes-${keyLen * 8}-ecb`, key, null);
        e.setAutoPadding(false);
        expect(hx(createAes(u8(key)).encryptBlock(u8(block)))).toBe(
          hx(Buffer.concat([e.update(block), e.final()])),
        );
      }
    });
    it('GCM encrypt and decrypt', async () => {
      for (const len of LENGTHS) {
        const key = randomBytes(keyLen),
          iv = randomBytes(12),
          data = randomBytes(len),
          aad = randomBytes(len % 29);
        const c = createCipheriv(`aes-${keyLen * 8}-gcm` as 'aes-128-gcm', key, iv);
        if (aad.length) c.setAAD(aad);
        const ct = Buffer.concat([c.update(data), c.final()]),
          tag = c.getAuthTag();
        const a = aad.length ? u8(aad) : undefined;
        const r = await aesGcmEncryptPure(u8(data), u8(key), u8(iv), a);
        expect(hx(r.ciphertext)).toBe(ct.toString('hex'));
        expect(hx(r.tag)).toBe(tag.toString('hex'));
        expect(hx(await aesGcmDecryptPure(u8(ct), u8(key), u8(iv), u8(tag), a))).toBe(
          data.toString('hex'),
        );
      }
    });
  });

  (HAS_CHACHA ? it : it.skip)('ChaCha20-Poly1305', () => {
    for (const len of LENGTHS) {
      const key = randomBytes(32),
        nonce = randomBytes(12),
        data = randomBytes(len),
        aad = randomBytes(len % 37);
      const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
      c.setAAD(aad, { plaintextLength: len });
      const ct = Buffer.concat([c.update(data), c.final()]),
        tag = c.getAuthTag();
      const r = chachaEncryptPure(u8(data), u8(key), u8(nonce), u8(aad));
      expect(hx(r.ciphertext)).toBe(ct.toString('hex'));
      expect(hx(r.tag)).toBe(tag.toString('hex'));
      expect(hx(chachaDecryptPure(u8(ct), u8(key), u8(nonce), u8(tag), u8(aad)))).toBe(
        data.toString('hex'),
      );
    }
  });

  describe('XChaCha20-Poly1305', () => {
    it('HChaCha20 matches the draft-irtf-cfrg-xchacha §2.2.1 vector', () => {
      const key = Uint8Array.from({ length: 32 }, (_, i) => i);
      const nonce = Buffer.from('000000090000004a0000000031415927', 'hex');
      expect(hx(hChaCha20(key, u8(nonce)))).toBe(
        '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc',
      );
    });
    (HAS_CHACHA ? it : it.skip)(
      'equals ChaCha20-Poly1305 under the HChaCha20 subkey (OpenSSL)',
      () => {
        for (const len of LENGTHS) {
          const key = randomBytes(32),
            n24 = randomBytes(24),
            data = randomBytes(len),
            aad = randomBytes(len % 19);
          const sub = hChaCha20(u8(key), u8(n24.subarray(0, 16)));
          const n12 = Buffer.concat([Buffer.alloc(4), n24.subarray(16)]);
          const c = createCipheriv('chacha20-poly1305', sub, n12, { authTagLength: 16 });
          c.setAAD(aad, { plaintextLength: len });
          const ct = Buffer.concat([c.update(data), c.final()]),
            tag = c.getAuthTag();
          const r = xchachaEncryptPure(u8(data), u8(key), u8(n24), u8(aad));
          expect(hx(r.ciphertext)).toBe(ct.toString('hex'));
          expect(hx(r.tag)).toBe(tag.toString('hex'));
          expect(hx(xchachaDecryptPure(u8(ct), u8(key), u8(n24), u8(tag), u8(aad)))).toBe(
            data.toString('hex'),
          );
        }
      },
    );
  });

  it('Keccak: SHA-3 and SHAKE across rate boundaries', () => {
    for (const len of LENGTHS) {
      const data = randomBytes(len);
      for (const [alg, rate, out] of [
        ['sha3-224', 1152, 28],
        ['sha3-256', 1088, 32],
        ['sha3-384', 832, 48],
        ['sha3-512', 576, 64],
      ] as const) {
        expect(hx(keccakSponge(u8(data), rate, out, 0x06))).toBe(
          createHash(alg).update(data).digest('hex'),
        );
      }
      for (const [alg, rate] of [
        ['shake128', 1344],
        ['shake256', 1088],
      ] as const) {
        expect(hx(keccakSponge(u8(data), rate, 100, 0x1f))).toBe(
          createHash(alg, { outputLength: 100 }).update(data).digest('hex'),
        );
      }
    }
  });

  it('SHA-256', () => {
    for (const len of LENGTHS) {
      const data = randomBytes(len);
      expect(hx(sha256.hashSync(u8(data)))).toBe(createHash('sha256').update(data).digest('hex'));
    }
  });

  (HAS_SM3 ? it : it.skip)('SM3', () => {
    for (const len of LENGTHS) {
      const data = randomBytes(len);
      expect(hx(sm3.hash(u8(data)))).toBe(createHash('sm3').update(data).digest('hex'));
    }
  });

  (HAS_SM4 ? it : it.skip)('SM4 block cipher', () => {
    for (let i = 0; i < 20; i++) {
      const key = randomBytes(16),
        block = randomBytes(16);
      const e = createCipheriv('sm4-ecb', key, null);
      e.setAutoPadding(false);
      expect(hx(sm4EncryptBlock(u8(block), sm4KeySchedule(u8(key))))).toBe(
        hx(Buffer.concat([e.update(block), e.final()])),
      );
    }
  });
});
