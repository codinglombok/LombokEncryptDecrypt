/**
 * Ecosystem integration tests — encrypted vector embeddings (lombokvector)
 * and plaintext SimHash fingerprints (lomboksimhash).
 *
 * Both peer packages are optionalDependencies: the happy paths exercise the
 * REAL published packages (v0.1.0), while every failure path is driven
 * through the injectable `loader` so no module mocking is needed (keeps the
 * suite Deno-safe: under Deno the peer packages are not resolvable and the
 * whole suite is skipped).
 */
import { ErrorCode } from '../../src/errors.js';
import {
  decryptVector,
  encryptVector,
  rankEncryptedVectors,
  type EncryptedVectorRecord,
  type LombokVectorLoader,
} from '../../src/integrations/vector.js';
import {
  fingerprintPlaintext,
  hammingDistance,
  type SimHashLoader,
} from '../../src/integrations/simhash.js';
import { randomKey256 } from '../../src/utils/random.js';

const isDeno = typeof (globalThis as { Deno?: unknown }).Deno !== 'undefined';
const describeRuntime = isDeno ? describe.skip : describe;
// lombokvector is ESM-only ("type": "module"). jest's CommonJS runtime
// transpiles import() to require() and refuses ESM (even createRequire is
// patched), so the tests that load the REAL package run only under real ESM
// runtimes (Bun leg + the dedicated ecosystem job). Everything else — DI
// failure paths, record validation, crypto round trips — is runtime-safe.
const isJestCjs = typeof jest !== 'undefined';
const describeVectorReal = isDeno || isJestCjs ? describe.skip : describe;

/** Loader that always fails — stands in for "optional package not installed". */
const brokenLoader = async () => {
  throw new Error('Cannot find package (simulated)');
};

describeRuntime('LombokVector integration — encrypted embeddings', () => {
  const key = randomKey256();

  it('seals and opens a vector with bit-exact binary64 round trip', async () => {
    const vector = [0.1, -2.5, 12345.6789, Number.EPSILON];
    const record = await encryptVector(vector, key);
    expect(record.format).toBe('lombok-encrypted-vector');
    expect(record.version).toBe(1);
    expect(record.algorithm).toBe('AES-256-GCM');
    expect(record.dimension).toBe(4);
    expect(record.iv.length).toBe(12);
    expect(record.ciphertext.length).toBe(4 * 8);
    const opened = await decryptVector(record, key);
    expect(Array.from(opened)).toEqual(vector);
  });

  it('honors explicit IV + AAD; wrong AAD is rejected', async () => {
    const iv = new Uint8Array(12).fill(7);
    const aad = new TextEncoder().encode('doc-42');
    const record = await encryptVector([1, 2, 3], key, { iv, aad });
    expect(Array.from(record.iv)).toEqual(Array.from(iv));
    const ok = await decryptVector(record, key, { aad });
    expect(Array.from(ok)).toEqual([1, 2, 3]);
    await expect(decryptVector(record, key)).rejects.toThrow(ErrorCode.AUTHENTICATION_FAILED);
  });

  it('detects ciphertext tampering', async () => {
    const record = await encryptVector([9, 8, 7, 6], key);
    const tampered: EncryptedVectorRecord = {
      ...record,
      ciphertext: record.ciphertext.map((b, i) => (i === 0 ? b ^ 1 : b)),
    };
    await expect(decryptVector(tampered, key)).rejects.toThrow(ErrorCode.AUTHENTICATION_FAILED);
  });

  it('rejects malformed records before touching the cipher', async () => {
    const base = await encryptVector([1], key);
    await expect(
      decryptVector({ ...base, format: 'other' } as unknown as EncryptedVectorRecord, key),
    ).rejects.toThrow(ErrorCode.INVALID_INPUT);
    await expect(
      decryptVector({ ...base, version: 2 } as unknown as EncryptedVectorRecord, key),
    ).rejects.toThrow(ErrorCode.INVALID_INPUT);
    await expect(
      decryptVector({ ...base, algorithm: 'ChaCha20' } as unknown as EncryptedVectorRecord, key),
    ).rejects.toThrow(ErrorCode.INVALID_INPUT);
    await expect(decryptVector({ ...base, dimension: 0 }, key)).rejects.toThrow(
      ErrorCode.INVALID_INPUT,
    );
    await expect(
      decryptVector({ ...base, dimension: 2 } as EncryptedVectorRecord, key),
    ).rejects.toThrow(ErrorCode.INVALID_INPUT);
    await expect(
      decryptVector({ ...base, iv: 0, tag: 0 } as unknown as EncryptedVectorRecord, key),
    ).rejects.toThrow(ErrorCode.INVALID_INPUT);
    await expect(decryptVector(null as unknown as EncryptedVectorRecord, key)).rejects.toThrow(
      ErrorCode.INVALID_INPUT,
    );
  });

  it('rejects non-finite and non-numeric components', async () => {
    await expect(encryptVector([], key)).rejects.toThrow(ErrorCode.INVALID_INPUT);
    await expect(encryptVector([1, Number.NaN], key)).rejects.toThrow(ErrorCode.INVALID_INPUT);
    await expect(encryptVector([1, Number.POSITIVE_INFINITY], key)).rejects.toThrow(
      ErrorCode.INVALID_INPUT,
    );
    await expect(encryptVector(['x'] as unknown as number[], key)).rejects.toThrow(
      ErrorCode.INVALID_INPUT,
    );
  });

  it('fails closed when lombokvector is not installed (injectable loader)', async () => {
    const loader: LombokVectorLoader = brokenLoader;
    const records = [await encryptVector([1, 2], key)];
    await expect(rankEncryptedVectors([1, 2], records, key, { loader })).rejects.toThrow(
      ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });

  it('fails closed when the loaded module lacks batchCosine', async () => {
    const loader: LombokVectorLoader = async () => ({});
    const records = [await encryptVector([1, 2], key)];
    await expect(rankEncryptedVectors([1, 2], records, key, { loader })).rejects.toThrow(
      ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });
});

describeVectorReal('LombokVector integration — ranking with the real ESM package', () => {
  const key = randomKey256();

  it('ranks decrypted vectors by cosine similarity, descending', async () => {
    const docs = [
      [1, 0, 0],
      [0.7071067811865476, 0.7071067811865476, 0],
      [0, 1, 0],
      [0, 0, 0], // zero-magnitude candidate must score 0, not throw
    ];
    const records: EncryptedVectorRecord[] = [];
    for (const v of docs) records.push(await encryptVector(v, key));
    const query = [0.8, 0.6, 0]; // closest direction to docs[1]
    const ranked = await rankEncryptedVectors(query, records, key);
    expect(ranked.map((r) => r.index)).toEqual([1, 0, 2, 3]);
    // cosine = (0.8 + 0.6) * √2/2 — both vectors are unit-length
    expect(ranked[0].score).toBeCloseTo(1.4 * 0.7071067811865476, 12);
    expect(ranked[3].score).toBe(0);
    // Reference cosine computed WITHOUT lombokvector (pure manual math):
    const manual = (query[0] * 0.7071067811865476 + query[1] * 0.7071067811865476) / 1;
    expect(ranked[0].score).toBeCloseTo(manual, 12);
  });

  it('wraps dimension mismatches into INVALID_INPUT', async () => {
    const records = [await encryptVector([1, 2, 3], key)];
    await expect(rankEncryptedVectors([1, 2], records, key)).rejects.toThrow(
      ErrorCode.INVALID_INPUT,
    );
  });

  it('propagates authentication failures from inside ranking', async () => {
    const record = await encryptVector([1, 2, 3], key);
    const tampered: EncryptedVectorRecord = {
      ...record,
      tag: record.tag.map((b) => b ^ 0xff),
    };
    await expect(rankEncryptedVectors([1, 2, 3], [tampered], key)).rejects.toThrow(
      ErrorCode.AUTHENTICATION_FAILED,
    );
  });
});

describeRuntime('LombokSimHash integration — plaintext fingerprints', () => {
  it('reproduces the canonical cross-repo vector (the fox)', async () => {
    // Canonical LombokSimHash v0.1.0 vector, pinned bit-identically across
    // every language port: simhash64("the fox") = 54b080184441c10c
    const fp = await fingerprintPlaintext('the fox');
    expect(fp).toBe('54b080184441c10c');
    expect(fp.length).toBe(16);
  });

  it('is deterministic and separates near-duplicates from unrelated text', async () => {
    const a = await fingerprintPlaintext('the quick brown fox jumps over the lazy dog');
    const a2 = await fingerprintPlaintext('the quick brown fox jumps over the lazy dog');
    expect(a).toBe(a2);
    const near = await fingerprintPlaintext('the quick brown cat jumps over the lazy dog');
    const far = await fingerprintPlaintext('completely unrelated text about quantum key rotation');
    const dNear = await hammingDistance(a, near);
    const dFar = await hammingDistance(a, far);
    expect(dNear).toBeLessThanOrEqual(12);
    expect(dFar).toBeGreaterThanOrEqual(dNear);
  });

  it('fails closed when lomboksimhash is not installed', async () => {
    const loader: SimHashLoader = brokenLoader;
    await expect(fingerprintPlaintext('the fox', { loader })).rejects.toThrow(
      ErrorCode.UNSUPPORTED_ALGORITHM,
    );
    await expect(hammingDistance('00', 'ff', { loader })).rejects.toThrow(
      ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });

  it('rejects non-hexadecimal fingerprints', async () => {
    await expect(hammingDistance('zzzz', '00ff', {})).rejects.toThrow(ErrorCode.INVALID_INPUT);
  });
});
