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

      // Swap first two chunks (each is 4+12+chunkSize+16 bytes)
      const chunkLen = 4 + 12 + 16384 + 16;
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
});
