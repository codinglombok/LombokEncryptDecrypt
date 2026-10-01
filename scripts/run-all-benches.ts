/**
 * LombokEncryptDecrypt — Run All Benchmarks
 * Usage: tsx scripts/run-all-benches.ts
 */

import { spawnSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readdirSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const benchDir  = resolve(__dirname, '../benches');

const benches = readdirSync(benchDir).filter(f => f.endsWith('.ts'));

console.log(`\n⚡ LombokEncryptDecrypt Benchmark Suite`);
console.log(`   ${benches.length} benchmark files\n`);
console.log('='.repeat(70));

let failed = 0;
for (const bench of benches) {
  const path = resolve(benchDir, bench);
  console.log(`\n► ${bench}`);
  const result = spawnSync('tsx', [path], {
    stdio: 'inherit',
    env: { ...process.env, NODE_ENV: 'production' },
  });
  if (result.status !== 0) {
    console.error(`  ❌ ${bench} failed with exit ${result.status}`);
    failed++;
  }
}

console.log(`\n${'='.repeat(70)}`);
if (failed > 0) {
  console.error(`\n❌ ${failed} benchmark(s) failed`);
  process.exit(1);
} else {
  console.log(`\n✅ All benchmarks completed`);
}
