/**
 * LombokEncryptDecrypt — Fuzz Corpus: AES-GCM
 *
 * Used by LombokFuzzer to test boundary conditions, malformed inputs,
 * and edge cases in the AES-GCM implementation.
 *
 * Run with: node scripts/run-fuzz.mjs --target fuzz_aes_gcm
 */

import { aesGcm } from '../../src/modes/gcm.js';
import { randomBytes } from '../../src/utils/random.js';
import { LombokCryptoError } from '../../src/errors.js';

export interface FuzzCase {
  name: string;
  run: () => Promise<void>;
}

// ── Structured fuzz cases ─────────────────────────────────────────────────

export const cases: FuzzCase[] = [
  {
    name: 'empty-plaintext-all-key-sizes',
    async run() {
      for (const keyBits of [128, 192, 256] as const) {
        const key = randomBytes(keyBits / 8);
        const { ciphertext, tag, iv } = await aesGcm.encrypt(new Uint8Array(0), key);
        await aesGcm.decrypt(ciphertext, key, iv, tag);
      }
    },
  },
  {
    name: 'max-plaintext-1MB',
    async run() {
      const key = randomBytes(32);
      const plaintext = randomBytes(1024 * 1024);
      const { ciphertext, tag, iv } = await aesGcm.encrypt(plaintext, key);
      await aesGcm.decrypt(ciphertext, key, iv, tag);
    },
  },
  {
    name: 'all-zero-key',
    async run() {
      const key = new Uint8Array(32); // all zeros
      const pt = randomBytes(64);
      const { ciphertext, tag, iv } = await aesGcm.encrypt(pt, key);
      await aesGcm.decrypt(ciphertext, key, iv, tag);
    },
  },
  {
    name: 'all-zero-iv',
    async run() {
      const key = randomBytes(32);
      const iv = new Uint8Array(12); // all zeros — NEVER reuse IV with same key in production!
      const pt = randomBytes(16);
      const { ciphertext, tag } = await aesGcm.encrypt(pt, key, { iv });
      await aesGcm.decrypt(ciphertext, key, iv, tag);
    },
  },
  {
    name: 'max-aad-64kb',
    async run() {
      const key = randomBytes(32);
      const aad = randomBytes(64 * 1024);
      const pt = randomBytes(256);
      const { ciphertext, tag, iv } = await aesGcm.encrypt(pt, key, { aad });
      await aesGcm.decrypt(ciphertext, key, iv, tag, { aad });
    },
  },
  {
    name: 'invalid-key-sizes-throw',
    async run() {
      for (const size of [0, 1, 8, 15, 17, 23, 25, 31, 33, 64]) {
        const key = randomBytes(size);
        try {
          await aesGcm.encrypt(new Uint8Array(1), key);
          throw new Error(`Expected error for key size ${size}`);
        } catch (e) {
          if (e instanceof LombokCryptoError) {
            if (e.code !== 'INVALID_KEY_SIZE') throw e;
          } else {
            throw e;
          }
        }
      }
    },
  },
  {
    name: 'bit-flip-rejection',
    async run() {
      const key = randomBytes(32);
      const pt = randomBytes(128);
      const { ciphertext, tag, iv } = await aesGcm.encrypt(pt, key);

      // Flip every bit position in ciphertext and verify rejection
      for (let byte = 0; byte < Math.min(ciphertext.length, 32); byte++) {
        for (let bit = 0; bit < 8; bit++) {
          const tampered = new Uint8Array(ciphertext);
          tampered[byte] ^= 1 << bit;
          try {
            await aesGcm.decrypt(tampered, key, iv, tag);
            throw new Error(`Bit flip at byte ${byte} bit ${bit} was not detected`);
          } catch (e) {
            if (!(e instanceof LombokCryptoError) || e.code !== 'AUTHENTICATION_FAILED') throw e;
          }
        }
      }
    },
  },
  {
    name: 'all-plaintextlengths-0-to-255',
    async run() {
      const key = randomBytes(32);
      for (let len = 0; len <= 255; len++) {
        const pt = randomBytes(len);
        const { ciphertext, tag, iv } = await aesGcm.encrypt(pt, key);
        const dec = await aesGcm.decrypt(ciphertext, key, iv, tag);
        if (dec.length !== len) throw new Error(`Length mismatch at ${len}`);
      }
    },
  },
];

// ── Corpus runner (for LombokFuzzer integration) ─────────────────────────

export async function runAll(): Promise<{ passed: number; failed: number; errors: string[] }> {
  let passed = 0;
  let failed = 0;
  const errors: string[] = [];

  for (const c of cases) {
    try {
      await c.run();
      passed++;
    } catch (e) {
      failed++;
      errors.push(`[${c.name}] ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { passed, failed, errors };
}
