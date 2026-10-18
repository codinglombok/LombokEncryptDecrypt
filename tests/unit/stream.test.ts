/**
 * LombokEncryptDecrypt — Streaming API Tests
 */

import { createEncryptStream, encryptStreamGen } from '../../src/stream/encrypt_stream.js';
import { createDecryptStream, decryptStreamGen } from '../../src/stream/decrypt_stream.js';
import { randomKey256 } from '../../src/utils/random.js';
import { bytesToHex, concatBytes } from '../../src/utils/encoding.js';

async function collectAsyncGen(gen: AsyncGenerator<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of gen) chunks.push(chunk);
  return concatBytes(...chunks);
}

describe('Streaming Encrypt / Decrypt', () => {
  const key = randomKey256();

  describe('AES-256-GCM streaming', () => {
    it('roundtrip small message (< 1 chunk)', async () => {
      const plaintext = new TextEncoder().encode('Hello, LombokEncryptDecrypt streaming!');

      const enc  = createEncryptStream({ algorithm: 'AES-256-GCM', key, chunkSize: 65536 });
      const encs = await enc.update(plaintext);
      const final = await enc.final();
      const encBytes = concatBytes(...encs, final);

      const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key, chunkSize: 65536 });
      const decs = await dec.update(encBytes);
      const decFinal = await dec.final();
      const decBytes = concatBytes(...decs, decFinal);

      expect(new TextDecoder().decode(decBytes)).toBe('Hello, LombokEncryptDecrypt streaming!');
    });

    it('roundtrip 1MB message (multiple chunks)', async () => {
      const plaintext = new Uint8Array(1024 * 1024);
      for (let i = 0; i < plaintext.length; i++) plaintext[i] = i & 0xFF;

      const enc   = createEncryptStream({ algorithm: 'AES-256-GCM', key, chunkSize: 16384 });
      const parts: Uint8Array[] = [];
      parts.push(...await enc.update(plaintext));
      parts.push(await enc.final());
      const encBytes = concatBytes(...parts);

      const dec   = createDecryptStream({ algorithm: 'AES-256-GCM', key, chunkSize: 16384 });
      const plain: Uint8Array[] = [];
      plain.push(...await dec.update(encBytes));
      plain.push(await dec.final());
      const decBytes = concatBytes(...plain);

      expect(bytesToHex(decBytes)).toBe(bytesToHex(plaintext));
    });

    it('async generator roundtrip', async () => {
      const plaintext = new Uint8Array(200 * 1024).fill(0x42);

      async function* makeSource(): AsyncGenerator<Uint8Array> {
        let offset = 0;
        while (offset < plaintext.length) {
          yield plaintext.slice(offset, offset + 8192);
          offset += 8192;
        }
      }

      const encrypted = await collectAsyncGen(
        encryptStreamGen(makeSource(), { algorithm: 'AES-256-GCM', key })
      );

      async function* encSource(): AsyncGenerator<Uint8Array> {
        yield encrypted;
      }

      const decrypted = await collectAsyncGen(
        decryptStreamGen(encSource(), { algorithm: 'AES-256-GCM', key })
      );

      expect(bytesToHex(decrypted)).toBe(bytesToHex(plaintext));
    });

    it('throws if update called after final', async () => {
      const enc = createEncryptStream({ algorithm: 'AES-256-GCM', key });
      await enc.final();
      await expect(enc.update(new Uint8Array(1))).rejects.toMatchObject({
        code: 'STREAM_FINALISED',
      });
    });

    it('detects chunk reordering', async () => {
      const plaintext = new Uint8Array(32 * 1024).fill(0xAA);
      const enc   = createEncryptStream({ algorithm: 'AES-256-GCM', key, chunkSize: 16384 });
      const chunks: Uint8Array[] = [];
      chunks.push(...await enc.update(plaintext));
      chunks.push(await enc.final());
      const encBytes = concatBytes(...chunks);

      // Swap first two records (each is index4 + flags1 + iv12 + ctLen4 + ct + tag16)
      const chunkLen = 4 + 1 + 12 + 4 + 16384 + 16;
      const chunk0 = encBytes.slice(0, chunkLen);
      const chunk1 = encBytes.slice(chunkLen, chunkLen * 2);
      const rest   = encBytes.slice(chunkLen * 2);
      const swapped = concatBytes(chunk1, chunk0, rest);

      const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key, chunkSize: 16384 });
      await expect(dec.update(swapped)).rejects.toMatchObject({
        code: 'INTEGRITY_CHECK_FAILED',
      });
    });
  });

  describe('framing, truncation and algorithms', () => {
    const concat = (parts: Uint8Array[]) => concatBytes(...parts);

    async function encryptAll(data: Uint8Array, algorithm: 'AES-256-GCM' | 'CHACHA20-POLY1305' | 'XCHACHA20-POLY1305', chunkSize: number, aad?: Uint8Array) {
      const enc = createEncryptStream({ algorithm, key, chunkSize, ...(aad ? { aad } : {}) });
      const parts = await enc.update(data);
      parts.push(await enc.final());
      return concat(parts);
    }
    async function decryptAll(data: Uint8Array, algorithm: 'AES-256-GCM' | 'CHACHA20-POLY1305' | 'XCHACHA20-POLY1305', aad?: Uint8Array) {
      const dec = createDecryptStream({ algorithm, key, ...(aad ? { aad } : {}) });
      const parts = await dec.update(data);
      parts.push(await dec.final());
      return concat(parts);
    }

    it.each(['AES-256-GCM', 'CHACHA20-POLY1305', 'XCHACHA20-POLY1305'] as const)('%s roundtrip across sizes', async (alg) => {
      for (const size of [0, 1, 4095, 4096, 4097, 8192, 10000]) {
        const data = new Uint8Array(size).map((_, i) => (i * 7) & 0xff);
        const out = await decryptAll(await encryptAll(data, alg, 4096), alg);
        expect(bytesToHex(out)).toBe(bytesToHex(data));
      }
    });

    it('empty stream still produces an authenticated final record', async () => {
      const encrypted = await encryptAll(new Uint8Array(0), 'AES-256-GCM', 1024);
      expect(encrypted.length).toBeGreaterThan(0);
      expect((await decryptAll(encrypted, 'AES-256-GCM')).length).toBe(0);
    });

    it('rejects a stream truncated at a record boundary', async () => {
      const data = new Uint8Array(3 * 4096).fill(1);
      const encrypted = await encryptAll(data, 'AES-256-GCM', 4096);
      const record = 4 + 1 + 12 + 4 + 4096 + 16;
      const truncated = encrypted.slice(0, record * 2); // drop the LAST record
      const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key });
      await dec.update(truncated);
      await expect(dec.final()).rejects.toMatchObject({ code: 'INTEGRITY_CHECK_FAILED' });
    });

    it('rejects a forged LAST flag on an earlier record', async () => {
      const encrypted = await encryptAll(new Uint8Array(3 * 4096).fill(2), 'AES-256-GCM', 4096);
      const forged = encrypted.slice();
      forged[4] = 0x01; // flip first record's flag to LAST
      const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key });
      await expect(dec.update(forged)).rejects.toMatchObject({ code: 'AUTHENTICATION_FAILED' });
    });

    it('rejects tampered ciphertext', async () => {
      const encrypted = await encryptAll(new Uint8Array(100).fill(3), 'AES-256-GCM', 4096);
      const bad = encrypted.slice();
      bad[4 + 1 + 12 + 4 + 5] ^= 0x01;
      const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key });
      await expect(dec.update(bad)).rejects.toMatchObject({ code: 'AUTHENTICATION_FAILED' });
    });

    it('rejects data after the final record', async () => {
      const encrypted = await encryptAll(new Uint8Array(10).fill(4), 'AES-256-GCM', 4096);
      const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key });
      await expect(dec.update(concatBytes(encrypted, new Uint8Array([1])))).rejects.toMatchObject({ code: 'INTEGRITY_CHECK_FAILED' });
    });

    it('binds caller AAD', async () => {
      const aad = new TextEncoder().encode('ctx-1');
      const encrypted = await encryptAll(new Uint8Array(50).fill(5), 'AES-256-GCM', 4096, aad);
      expect((await decryptAll(encrypted, 'AES-256-GCM', aad)).length).toBe(50);
      await expect(decryptAll(encrypted, 'AES-256-GCM', new TextEncoder().encode('ctx-2'))).rejects.toMatchObject({ code: 'AUTHENTICATION_FAILED' });
    });

    it('accepts input fed in small pieces', async () => {
      const data = new Uint8Array(20000).map((_, i) => i & 0xff);
      const encrypted = await encryptAll(data, 'AES-256-GCM', 4096);
      const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key });
      const parts: Uint8Array[] = [];
      for (let i = 0; i < encrypted.length; i += 333) parts.push(...await dec.update(encrypted.slice(i, i + 333)));
      parts.push(await dec.final());
      expect(bytesToHex(concat(parts))).toBe(bytesToHex(data));
    });
  });
});
