/**
 * LombokEncryptDecrypt — AES-GCM Throughput Benchmark
 *
 * Measures:
 *   - Pure TS fallback throughput
 *   - Node.js crypto (AES-NI) throughput
 *   - NAPI Rust core throughput (if available)
 */

import { aesGcm } from '../src/modes/gcm.js';
import { randomBytes } from '../src/utils/random.js';

const WARMUP_ROUNDS = 3;
const BENCH_ROUNDS = 10;

async function bench(
  name: string,
  fn: () => Promise<unknown>,
  dataSizeBytes: number,
): Promise<void> {
  // Warmup
  for (let i = 0; i < WARMUP_ROUNDS; i++) await fn();

  const times: number[] = [];
  for (let i = 0; i < BENCH_ROUNDS; i++) {
    const start = performance.now();
    await fn();
    times.push(performance.now() - start);
  }

  times.sort((a, b) => a - b);
  const median = times[Math.floor(times.length / 2)] ?? 0;
  const min = times[0] ?? 0;
  const max = times[times.length - 1] ?? 0;
  const mbps = dataSizeBytes / 1024 / 1024 / (median / 1000);

  console.log(
    `  ${name.padEnd(40)} median=${median.toFixed(2)}ms  min=${min.toFixed(2)}ms  max=${max.toFixed(2)}ms  ${mbps.toFixed(1)} MB/s`,
  );
}

async function main(): Promise<void> {
  console.log('\n=== AES-GCM Benchmark ===\n');

  const key = randomBytes(32);

  // 1 KB
  const data1k = randomBytes(1024);
  const aad = new TextEncoder().encode('benchmark-aad');

  await bench(
    'AES-256-GCM encrypt 1 KB',
    async () => {
      const { ciphertext, tag, iv } = await aesGcm.encrypt(data1k, key, { aad });
      await aesGcm.decrypt(ciphertext, key, iv, tag, { aad });
    },
    1024,
  );

  // 64 KB
  const data64k = randomBytes(64 * 1024);
  await bench(
    'AES-256-GCM encrypt 64 KB',
    async () => {
      const { ciphertext, tag, iv } = await aesGcm.encrypt(data64k, key);
      await aesGcm.decrypt(ciphertext, key, iv, tag);
    },
    64 * 1024,
  );

  // 1 MB
  const data1m = randomBytes(1024 * 1024);
  await bench(
    'AES-256-GCM encrypt 1 MB',
    async () => {
      const { ciphertext, tag, iv } = await aesGcm.encrypt(data1m, key);
      await aesGcm.decrypt(ciphertext, key, iv, tag);
    },
    1024 * 1024,
  );

  // 16 MB
  const data16m = randomBytes(16 * 1024 * 1024);
  await bench(
    'AES-256-GCM encrypt 16 MB',
    async () => {
      const { ciphertext, tag, iv } = await aesGcm.encrypt(data16m, key);
      await aesGcm.decrypt(ciphertext, key, iv, tag);
    },
    16 * 1024 * 1024,
  );

  // Encrypt-only throughput
  await bench(
    'AES-256-GCM encrypt-only 64 MB (no decrypt)',
    async () => {
      for (let i = 0; i < 4; i++) await aesGcm.encrypt(data16m, key);
    },
    64 * 1024 * 1024,
  );

  console.log('\n=== Key Generation ===\n');

  await bench(
    'generateKey (256-bit)',
    async () => {
      for (let i = 0; i < 10_000; i++) aesGcm.generateKey(256);
    },
    0,
  );

  await bench(
    'generateIV (96-bit)',
    async () => {
      for (let i = 0; i < 10_000; i++) aesGcm.generateIv();
    },
    0,
  );

  console.log('\nDone.\n');
}

main().catch(console.error);
