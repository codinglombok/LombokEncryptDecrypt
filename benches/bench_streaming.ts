/**
 * LombokEncryptDecrypt — Streaming AEAD Benchmark
 * Measures throughput for large-file encryption (1 GB target).
 */

import { createEncryptStream, createDecryptStream } from '../src/stream/encrypt_stream.js';
import { randomKey256, randomBytes } from '../src/utils/random.js';
import { concatBytes } from '../src/utils/encoding.js';

async function benchStream(
  name: string,
  totalBytes: number,
  chunkSize: number,
  rounds = 3
): Promise<void> {
  const key     = randomKey256();
  const payload = randomBytes(Math.min(totalBytes, chunkSize));

  const times: number[] = [];
  for (let r = 0; r < rounds; r++) {
    const t0      = performance.now();
    const enc     = createEncryptStream({ algorithm: 'AES-256-GCM', key, chunkSize });
    const parts: Uint8Array[] = [];
    let   written  = 0;

    while (written < totalBytes) {
      const chunk = written + chunkSize <= totalBytes ? payload : payload.slice(0, totalBytes - written);
      parts.push(...await enc.update(chunk));
      written += chunk.length;
    }
    parts.push(await enc.final());
    const encBytes = concatBytes(...parts);

    // Decrypt pass
    const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key, chunkSize });
    const decParts: Uint8Array[] = [];
    decParts.push(...await dec.update(encBytes));
    decParts.push(await dec.final());

    times.push(performance.now() - t0);
  }

  const median = times.sort((a,b) => a-b)[Math.floor(times.length/2)]!;
  const mbps   = (totalBytes * 2 / 1024 / 1024) / (median / 1000); // enc + dec
  const mb     = (totalBytes / 1024 / 1024).toFixed(0);
  console.log(`  ${name.padEnd(45)} ${median.toFixed(0)}ms   ${mbps.toFixed(0)} MB/s (enc+dec, ${mb}MB)`);
}

async function main(): Promise<void> {
  console.log('\n=== Streaming AEAD Benchmark ===\n');
  console.log('  chunk=16KB');
  await benchStream('AES-256-GCM stream 1 MB  (16KB chunks)',   1 * 1024 * 1024,  16384);
  await benchStream('AES-256-GCM stream 16 MB (16KB chunks)',  16 * 1024 * 1024,  16384);
  await benchStream('AES-256-GCM stream 64 MB (16KB chunks)',  64 * 1024 * 1024,  16384);
  console.log('\n  chunk=64KB');
  await benchStream('AES-256-GCM stream 16 MB (64KB chunks)',  16 * 1024 * 1024,  65536);
  await benchStream('AES-256-GCM stream 64 MB (64KB chunks)',  64 * 1024 * 1024,  65536);
  await benchStream('AES-256-GCM stream 128 MB (64KB chunks)', 128 * 1024 * 1024, 65536, 2);
  console.log('\nDone.\n');
}

main().catch(console.error);
