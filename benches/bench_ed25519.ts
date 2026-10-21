/**
 * LombokEncryptDecrypt — Ed25519 + Kyber768 + Argon2id Benchmarks
 */

import { ed25519 } from '../src/core/ecc/ed25519.js';
import { kyber768 } from '../src/pq/kyber/kyber768.js';
import { argon2id } from '../src/kdf/argon2.js';
import { randomBytes } from '../src/utils/random.js';

const ROUNDS = 100;

async function bench(name: string, fn: () => Promise<unknown>, rounds = ROUNDS): Promise<void> {
  // Warmup
  for (let i = 0; i < 3; i++) await fn();

  const start = performance.now();
  for (let i = 0; i < rounds; i++) await fn();
  const elapsed = performance.now() - start;

  const opsPerSec = ((rounds / elapsed) * 1000).toFixed(0);
  const msEach = (elapsed / rounds).toFixed(3);
  console.log(`  ${name.padEnd(50)} ${msEach}ms/op   ${opsPerSec} ops/s`);
}

async function main(): Promise<void> {
  // ── Ed25519 ──────────────────────────────────────────────────────────

  console.log('\n=== Ed25519 ===\n');

  let kp = await ed25519.generateKeyPair();
  const msg = randomBytes(256);
  let sig = await ed25519.sign(msg, kp.privateKey);

  await bench('Ed25519 generateKeyPair()', () => ed25519.generateKeyPair());
  await bench('Ed25519 sign (256-byte message)', () => ed25519.sign(msg, kp.privateKey));
  await bench('Ed25519 verify (valid)', () => ed25519.verify(msg, sig, kp.publicKey));
  await bench('Ed25519 verify (invalid — wrong key)', async () => {
    const kp2 = await ed25519.generateKeyPair();
    return ed25519.verify(msg, sig, kp2.publicKey);
  });

  // ── ML-KEM-768 (Kyber) — fails closed in v0.1.0 ──────────────────────

  console.log('\n=== ML-KEM-768 (Kyber768) ===\n');
  try {
    const kemKp = await kyber768.generateKeyPair();
    const encap = await kyber768.encapsulate(kemKp.publicKey);

    await bench('Kyber768 generateKeyPair()', () => kyber768.generateKeyPair(), 20);
    await bench('Kyber768 encapsulate()', () => kyber768.encapsulate(kemKp.publicKey), 50);
    await bench(
      'Kyber768 decapsulate()',
      () => kyber768.decapsulate(encap.ciphertext, kemKp.secretKey),
      50,
    );
  } catch (err) {
    console.log(`  SKIPPED (fail-closed): ${(err as Error).message}`);
  }

  // ── Argon2id — fails closed in v0.1.0 ─────────────────────────────────

  console.log('\n=== Argon2id ===\n');
  try {
    const salt = randomBytes(16);

    await bench(
      'Argon2id m=65536,t=3,p=4 (64MB)',
      () => argon2id.raw('bench-password', salt, { m: 65536, t: 3, p: 4 }),
      5,
    );

    await bench(
      'Argon2id m=19456,t=2,p=1 (19MB, OWASP min)',
      () => argon2id.raw('bench-password', salt, { m: 19456, t: 2, p: 1 }),
      10,
    );

    await bench(
      'Argon2id hash() → PHC string',
      () => argon2id.hash('bench-password', { m: 19456, t: 2, p: 1 }),
      5,
    );
  } catch (err) {
    console.log(`  SKIPPED (fail-closed): ${(err as Error).message}`);
  }

  console.log('\nDone.\n');
}

main().catch(console.error);
