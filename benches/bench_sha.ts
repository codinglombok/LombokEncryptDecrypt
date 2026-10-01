/**
 * LombokEncryptDecrypt — Hash Function Benchmarks
 */

import { sha256 } from '../src/core/sha/sha256.js';
import { sha3_256 } from '../src/core/sha/sha3.js';
import { sm3 } from '../src/core/sm/sm3.js';
import { randomBytes } from '../src/utils/random.js';

async function bench(name: string, fn: () => Promise<unknown>, dataLen: number, rounds = 20): Promise<void> {
  for (let i = 0; i < 3; i++) await fn();
  const t0 = performance.now();
  for (let i = 0; i < rounds; i++) await fn();
  const elapsed = performance.now() - t0;
  const mbps    = (dataLen * rounds / 1024 / 1024) / (elapsed / 1000);
  console.log(`  ${name.padEnd(42)} ${(elapsed/rounds).toFixed(2)}ms/op   ${mbps.toFixed(0)} MB/s`);
}

async function main(): Promise<void> {
  console.log('\n=== Hash Benchmarks ===\n');

  const data1k  = randomBytes(1024);
  const data64k = randomBytes(64 * 1024);
  const data1m  = randomBytes(1024 * 1024);

  await bench('SHA-256 (1 KB)',     () => sha256.hash(data1k),  1024);
  await bench('SHA-256 (64 KB)',    () => sha256.hash(data64k), 64 * 1024);
  await bench('SHA-256 (1 MB)',     () => sha256.hash(data1m),  1024 * 1024);
  await bench('SHA3-256 (1 KB)',    () => sha3_256.hash(data1k),  1024);
  await bench('SHA3-256 (64 KB)',   () => sha3_256.hash(data64k), 64 * 1024);
  await bench('SM3 (1 KB sync)',    async () => sm3.hash(data1k),  1024);
  await bench('SM3 (64 KB sync)',   async () => sm3.hash(data64k), 64 * 1024);

  console.log('\nDone.\n');
}

main().catch(console.error);
