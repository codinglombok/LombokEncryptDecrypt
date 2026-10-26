/**
 * Ecosystem integration — REAL published packages under a REAL ESM loader.
 *
 * jest's CommonJS runtime cannot load the ESM-only `lombokvector` package
 * ("type": "module", no CJS export condition) — it transpiles import() to
 * require() and refuses the module. This suite runs OUTSIDE jest via
 * `npx tsx --test tests/ecosystem/*.test.ts` (real node ESM), plus under
 * `bun test` natively, so the published artifacts are exercised as shipped.
 *
 * Covered here end-to-end:
 *  - LED encryptVector/decryptVector/rankEncryptedVectors + lombokvector@0.1.0
 *  - LED fingerprintPlaintext/hammingDistance + lomboksimhash@0.1.0
 *  - the canonical cross-repo vector simhash64("the fox") = 54b080184441c10c
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  decryptVector,
  encryptVector,
  rankEncryptedVectors,
} from '../../src/integrations/vector.js';
import { fingerprintPlaintext, hammingDistance } from '../../src/integrations/simhash.js';
import { randomKey256 } from '../../src/utils/random.js';

test('encrypted embedding round trip is bit-exact', async () => {
  const key = randomKey256();
  const vector = [0.1, -2.5, 12345.6789, Number.EPSILON];
  const record = await encryptVector(vector, key);
  assert.equal(record.dimension, 4);
  assert.equal(record.ciphertext.length, 32);
  const opened = await decryptVector(record, key);
  assert.deepEqual(Array.from(opened), vector);
});

test('ranking via the real lombokvector matches manual cosine', async () => {
  const key = randomKey256();
  const docs = [
    [1, 0, 0],
    [0.7071067811865476, 0.7071067811865476, 0],
    [0, 1, 0],
    [0, 0, 0],
  ];
  const records = [];
  for (const v of docs) records.push(await encryptVector(v, key));
  const ranked = await rankEncryptedVectors([0.8, 0.6, 0], records, key);
  assert.deepEqual(
    ranked.map((r) => r.index),
    [1, 0, 2, 3],
  );
  assert.ok(Math.abs(ranked[0].score - 1.4 * 0.7071067811865476) < 1e-12);
  assert.equal(ranked[3].score, 0);
});

test('canonical LombokSimHash vector: simhash64("the fox") = 54b080184441c10c', async () => {
  const fp = await fingerprintPlaintext('the fox');
  assert.equal(fp, '54b080184441c10c');
  const near = await fingerprintPlaintext('the quick brown fox jumps over the lazy dog');
  const near2 = await fingerprintPlaintext('the quick brown cat jumps over the lazy dog');
  const d = await hammingDistance(near, near2);
  assert.ok(d <= 12, `near-duplicate hamming distance ${d} should be small`);
});
