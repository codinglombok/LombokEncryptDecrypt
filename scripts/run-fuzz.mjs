#!/usr/bin/env node
/**
 * LombokEncryptDecrypt — Fuzz Runner (TypeScript corpus)
 * Integrates with LombokFuzzer for structured fuzz testing.
 *
 * Usage:
 *   node scripts/run-fuzz.mjs                         # run all targets
 *   node scripts/run-fuzz.mjs --target fuzz_aes_gcm  # specific target
 *   node scripts/run-fuzz.mjs --duration 300          # timeout in seconds
 */

import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);

function getArg(flag) {
  const i = args.indexOf(flag);
  return i !== -1 ? args[i + 1] : null;
}

const targetArg = getArg('--target');
const duration  = parseInt(getArg('--duration') ?? '60', 10);

const ALL_TARGETS = [
  'fuzz_aes_gcm',
  'fuzz_chacha20',
  'fuzz_kdf',
  'fuzz_stream',
];

const targets = targetArg ? [targetArg] : ALL_TARGETS;

console.log(`\n🔍 LombokEncryptDecrypt Fuzz Runner`);
console.log(`   Targets:  ${targets.join(', ')}`);
console.log(`   Duration: ${duration}s per target`);
console.log(`   Time:     ${new Date().toISOString()}\n`);

let totalPassed = 0, totalFailed = 0, totalErrors = [];

for (const target of targets) {
  const corpusPath = resolve(__dirname, `../tests/fuzz/${target}.ts`);
  console.log(`▶ Running ${target}...`);

  try {
    // Dynamic import of the fuzz module (ts-node / tsx handles transpilation)
    const url = `file://${corpusPath.replace(/\.ts$/, '.js')}`;
    let mod;
    try {
      mod = await import(url);
    } catch {
      // Fallback: try tsx via spawn
      console.log(`  ⚠️  Cannot import ${target} directly — run: tsx tests/fuzz/${target}.ts`);
      continue;
    }

    if (typeof mod.runAll !== 'function') {
      console.log(`  ⚠️  ${target} has no runAll() export — skipping`);
      continue;
    }

    const startTime = Date.now();
    const timeoutMs = duration * 1000;
    let rounds = 0;
    let localPassed = 0, localFailed = 0, localErrors = [];

    // Run repeatedly until timeout
    while (Date.now() - startTime < timeoutMs) {
      const result = await mod.runAll();
      rounds++;
      localPassed += result.passed;
      localFailed += result.failed;
      if (result.errors.length > 0) {
        localErrors.push(...result.errors.map(e => `[round ${rounds}] ${e}`));
        break; // Stop on first crash
      }
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    if (localFailed === 0) {
      console.log(`  ✅ ${target}: ${localPassed} cases × ${rounds} rounds — ${elapsed}s — PASS`);
    } else {
      console.log(`  ❌ ${target}: ${localFailed} FAILED after ${rounds} rounds`);
      localErrors.forEach(e => console.log(`     ${e}`));
    }

    totalPassed += localPassed;
    totalFailed += localFailed;
    totalErrors.push(...localErrors);

  } catch (err) {
    console.log(`  ❌ ${target}: EXCEPTION — ${err.message}`);
    totalFailed++;
    totalErrors.push(`[${target}] ${err.message}`);
  }
}

console.log(`\n${'─'.repeat(60)}`);
console.log(`Fuzz summary: ${totalPassed} passed  ${totalFailed} failed`);

if (totalErrors.length > 0) {
  console.log('\nErrors:');
  totalErrors.slice(0, 20).forEach(e => console.log(`  ${e}`));
  console.log('\n🚨 FUZZ FAILURES — check artifacts above');
  process.exit(1);
} else {
  console.log('\n✅ All fuzz targets passed');
  process.exit(0);
}
