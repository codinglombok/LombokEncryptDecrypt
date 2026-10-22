/**
 * Coverage hardening — exercises defensive branches, error paths and
 * less-travelled API surfaces so the 95/90 thresholds are met honestly.
 */

import { internal } from '../../src/modes/chacha.js';
import { aesGcmDecrypt, aesGcmEncrypt } from '../../src/modes/gcm.js';
import { aesCbcEncrypt, aesCbcDecrypt } from '../../src/modes/cbc.js';
import { createEncryptStream } from '../../src/stream/encrypt_stream.js';
import { createDecryptStream, decryptStreamGen } from '../../src/stream/decrypt_stream.js';
import { hmac } from '../../src/mac/hmac.js';
import { hmacSha256 } from '../../src/mac/hmac.js';
import { cmac } from '../../src/mac/cmac.js';
import { pbkdf2 } from '../../src/kdf/pbkdf2.js';
import { hkdfDerive } from '../../src/kdf/hkdf.js';
import { scryptDerive } from '../../src/kdf/scrypt.js';
import {
  ecdhX25519,
  ecdhX448,
  ecdhP256,
  ecdhP384,
  ecdhP521,
  ecdsaP256,
  ecdsaP384,
  ecdsaP521,
  ecdh,
} from '../../src/core/ecc/ecdh.js';
import { ed25519 } from '../../src/core/ecc/ed25519.js';
import { hasX448 } from '../platform-caps.js';

const itIfX448 = hasX448 ? it : it.skip;
import { KeyStore } from '../../src/keystore/keystore.js';
import { base64ToBytes, concatBytes } from '../../src/utils/encoding.js';
import { ErrorCode } from '../../src/errors.js';
import { randomBytes, randomKey256 } from '../../src/utils/random.js';

const enc = new TextEncoder();

describe('stream error paths', () => {
  const KEY = randomKey256();

  it('decrypt generator yields decrypted chunks from a ReadableStream', async () => {
    const data = new Uint8Array(5000);
    for (let i = 0; i < 5000; i++) data[i] = (i * 13) & 0xff;
    const enc = createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 1024 });
    const parts: Uint8Array[] = [];
    for (let off = 0; off < data.length; off += 3000) {
      parts.push(...(await enc.update(data.subarray(off, Math.min(off + 3000, data.length)))));
    }
    parts.push(await enc.final());
    const encBytes = concatBytes(...parts);

    // feed in awkward split points to exercise partial-frame buffering
    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encBytes.subarray(0, 7));
        controller.enqueue(encBytes.subarray(7, 8));
        controller.enqueue(encBytes.subarray(8));
        controller.close();
      },
    });
    const out: Uint8Array[] = [];
    for await (const chunk of decryptStreamGen(source, {
      algorithm: 'AES-256-GCM',
      key: KEY,
      chunkSize: 1024,
    })) {
      out.push(chunk);
    }
    expect(concatBytes(...out)).toEqual(data);
  });

  it('buffers partial frames and rejects truncated declared lengths at final()', async () => {
    // < frame header: buffered, no error yet
    const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 1024 });
    await expect(dec.update(new Uint8Array(5))).resolves.toEqual([]);
    await expect(dec.final()).rejects.toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
    // header declares ctLen 100 but frame is cut short → truncation at final()
    const fake = new Uint8Array(25);
    fake[4] = 0;
    fake[5] = 0;
    fake[6] = 0;
    fake[7] = 100;
    const dec2 = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 1024 });
    await expect(dec2.update(fake)).resolves.toEqual([]);
    await expect(dec2.final()).rejects.toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
  });

  it('rejects data after the sentinel inside update()', async () => {
    const data = new Uint8Array(10);
    const enc = createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 1024 });
    const frame = concatBytes(...(await enc.update(data)), await enc.final());
    const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 1024 });
    await dec.update(frame);
    await expect(dec.update(new Uint8Array([1]))).rejects.toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
  });

  it('accepts the full valid chunk-size range', () => {
    expect(() =>
      createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 1 }),
    ).not.toThrow();
    expect(() =>
      createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 1048576 }),
    ).not.toThrow();
    // streaming is AES-GCM only (12-byte IV frame format, SPEC §9)
    expect(() =>
      createEncryptStream({ algorithm: 'ChaCha20-Poly1305' as never, key: KEY }),
    ).toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
    expect(() =>
      createEncryptStream({ algorithm: 'XChaCha20-Poly1305' as never, key: KEY }),
    ).toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
  });

  it('small chunks exercise per-byte framing', async () => {
    const data = new Uint8Array(37);
    for (let i = 0; i < 37; i++) data[i] = i;
    const enc = createEncryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 8 });
    const parts: Uint8Array[] = [];
    for (const byte of data) {
      parts.push(...(await enc.update(new Uint8Array([byte]))));
    }
    parts.push(await enc.final());
    const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY, chunkSize: 8 });
    const back: Uint8Array[] = [];
    const encBytes = concatBytes(...parts);
    for (let off = 0; off < encBytes.length; off += 11) {
      back.push(...(await dec.update(encBytes.subarray(off, Math.min(off + 11, encBytes.length)))));
    }
    back.push(await dec.final());
    expect(concatBytes(...back)).toEqual(data);
  });
});

describe('GCM decrypt edge branches', () => {
  it('explicit tagLength option mismatches the provided tag', async () => {
    const key = randomKey256();
    const pt = randomBytes(20);
    const res = await aesGcmEncrypt(pt, key);
    await expect(
      aesGcmDecrypt(res.ciphertext, key, res.iv, res.tag, { tagLength: 12 }),
    ).rejects.toThrow(ErrorCode.AUTHENTICATION_FAILED);
    const flippedPrefix = Uint8Array.from(res.tag.subarray(0, 12));
    flippedPrefix[0] ^= 1;
    await expect(aesGcmDecrypt(res.ciphertext, key, res.iv, flippedPrefix)).rejects.toThrow(
      ErrorCode.AUTHENTICATION_FAILED,
    );
    await expect(
      aesGcmDecrypt(res.ciphertext, key, res.iv, res.tag, { tagLength: 5 as 4 }),
    ).rejects.toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
  });
});

describe('ChaCha decrypt edge branches', () => {
  it('poly1305 rejects invalid key sizes', () => {
    expect(() => internal.poly1305Mac(new Uint8Array(31), new Uint8Array(4))).toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    expect(() => cmac.compute(new Uint8Array(33), new Uint8Array(4))).toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
  });

  it('xchacha decrypt validates tag length and nonce size', async () => {
    const key = randomKey256();
    const xchacha = (await import('../../src/modes/chacha.js')).xchaChaPoly1305;
    const enc = await xchacha.encrypt(new Uint8Array(10), key);
    await expect(
      xchacha.decrypt(enc.ciphertext, key, enc.iv, enc.tag.subarray(0, 15)),
    ).rejects.toThrow(ErrorCode.AUTHENTICATION_FAILED);
    await expect(xchacha.decrypt(enc.ciphertext, key, new Uint8Array(12), enc.tag)).rejects.toThrow(
      ErrorCode.INVALID_IV_SIZE,
    );
    const chacha = (await import('../../src/modes/chacha.js')).chaCha20Poly1305;
    const enc2 = await chacha.encrypt(new Uint8Array(10), key);
    await expect(
      chacha.decrypt(enc2.ciphertext, key, enc2.iv, enc2.tag.subarray(0, 8)),
    ).rejects.toThrow(ErrorCode.AUTHENTICATION_FAILED);
  });
});

describe('CBC padding edge branches', () => {
  it('rejects invalid PKCS#7 padding bytes and lengths', async () => {
    const key = randomKey256();
    const iv = randomBytes(16);
    const pt = randomBytes(20);
    const { ciphertext } = await aesCbcEncrypt(pt, key, iv);
    // last byte = 0x00 (invalid pad length)
    const bad1 = new Uint8Array(ciphertext);
    bad1[bad1.length - 1] = 0x00;
    await expect(aesCbcDecrypt(bad1, key, iv)).rejects.toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
    // last byte = 0x11 (17 > 16)
    const bad2 = new Uint8Array(ciphertext);
    bad2[bad2.length - 1] = 0x11;
    await expect(aesCbcDecrypt(bad2, key, iv)).rejects.toThrow(ErrorCode.INTEGRITY_CHECK_FAILED);
  });

  it('includeIv decrypt rejects blobs too short to contain IV + block', async () => {
    const key = randomKey256();
    await expect(
      aesCbcDecrypt(new Uint8Array(20), key, undefined, { includeIv: true }),
    ).rejects.toThrow(ErrorCode.INVALID_IV_SIZE);
  });
});

describe('base64 decode error branches', () => {
  it('rejects invalid characters and impossible lengths', () => {
    expect(() => base64ToBytes('!!!!')).toThrow();
    expect(() => base64ToBytes('A')).toThrow();
    expect(() => base64ToBytes('abcde')).toThrow();
  });
});

describe('HMAC/CMAC verify branches', () => {
  it('generic hmac.verify returns false for wrong-length tags', () => {
    const key = enc.encode('k');
    const msg = enc.encode('m');
    expect(hmac.verify('SHA-256', key, msg, new Uint8Array(31))).toBe(false);
    expect(hmac.verify('SHA-384', key, msg, new Uint8Array(47))).toBe(false);
    expect(hmac.verify('SHA-512', key, msg, new Uint8Array(63))).toBe(false);
    const mac = hmac.compute('SHA-256', key, msg);
    expect(hmac.verify('SHA-256', key, msg, mac)).toBe(true);
  });

  it('hmacSha256.verify handles wrong-length tags', async () => {
    const key = enc.encode('k2');
    const msg = enc.encode('m2');
    expect(await hmacSha256.verify(key, msg, new Uint8Array(10))).toBe(false);
  });
});

describe('PBKDF2 PHC parser branches', () => {
  it('verify returns false on every malformed PHC shape', async () => {
    expect(await pbkdf2.verify('', 'x')).toBe(false);
    expect(await pbkdf2.verify('$pbkdf2-sha256', 'x')).toBe(false);
    expect(await pbkdf2.verify('$argon2id$v=19$aa$bb', 'x')).toBe(false);
    expect(await pbkdf2.verify('$pbkdf2-md5$i=10$aa$bb', 'x')).toBe(false);
    expect(await pbkdf2.verify('$pbkdf2-sha256$junk$aa$bb', 'x')).toBe(false);
    expect(await pbkdf2.verify('$pbkdf2-sha256$i=0$aa$bb', 'x')).toBe(false);
    expect(await pbkdf2.verify('$pbkdf2-sha256$i=abc$aa$bb', 'x')).toBe(false);
  });

  it('supports all three PHC hash names and rejects unknown ones', async () => {
    for (const name of ['SHA-256', 'SHA-384', 'SHA-512'] as const) {
      const h = await pbkdf2.hash('pw', { hash: name, iterations: 10 });
      expect(h.startsWith(`$pbkdf2-${name.toLowerCase().replace('-', '')}$i=10$`)).toBe(true);
      expect(await pbkdf2.verify(h, 'pw')).toBe(true);
    }
    // 'SHA384' (missing dash) must fail loudly instead of falling back to SHA-256
    await expect(
      pbkdf2.hash('pw', { hash: 'SHA384' as 'SHA-256', iterations: 10 }),
    ).rejects.toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
    await expect(hkdfDerive(new Uint8Array(8), { hash: 'SHA384' as 'SHA-256' })).rejects.toThrow(
      ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });
});

describe('scrypt parameter validation', () => {
  it('rejects N=0-style nonsense and memory-exceeding parameters', async () => {
    await expect(scryptDerive('x', 'y', { N: 0, r: 1, p: 1 })).rejects.toThrow();
    await expect(scryptDerive('x', 'y', { N: 8, r: 0, p: 1 })).rejects.toThrow();
    await expect(scryptDerive('x', 'y', { N: 8, r: 1, p: 0 })).rejects.toThrow();
    // N*p must stay under the JS-safe memory budget
    await expect(scryptDerive('x', 'y', { N: 2 ** 28, r: 8, p: 64, dkLen: 32 })).rejects.toThrow();
  });
});

describe('asymmetric coverage', () => {
  it('P-384 and P-521 ECDH + ECDSA round-trip', async () => {
    for (const ecdhCurve of [ecdhP384, ecdhP521]) {
      const a = await ecdhCurve.generateKeyPair();
      const b = await ecdhCurve.generateKeyPair();
      const ab = await ecdhCurve.computeSharedSecret(a.privateKey, b.publicKey);
      const ba = await ecdhCurve.computeSharedSecret(b.privateKey, a.publicKey);
      expect(ab).toEqual(ba);
    }
    for (const ecdsaCurve of [ecdsaP384, ecdsaP521]) {
      const kp = await ecdsaCurve.generateKeyPair();
      const msg = randomBytes(40);
      const sig = await ecdsaCurve.sign(msg, kp.privateKey);
      expect(await ecdsaCurve.verify(msg, sig, kp.publicKey)).toBe(true);
      expect(await ecdsaCurve.verify(msg, sig, randomBytes(66))).toBe(false);
    }
  });

  it('validates EC key sizes on ECDH and ECDSA helpers', async () => {
    const kp = await ecdhP256.generateKeyPair();
    await expect(ecdhP256.computeSharedSecret(new Uint8Array(15), kp.publicKey)).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    await expect(ecdhP256.computeSharedSecret(kp.privateKey, new Uint8Array(64))).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    await expect(
      ecdhP256.computeSharedSecret(kp.privateKey, new Uint8Array(65).fill(4)),
    ).rejects.toThrow(ErrorCode.INVALID_KEY_SIZE);
    await expect(
      ecdh.computeSharedSecret('X448', new Uint8Array(10), new Uint8Array(10)),
    ).rejects.toThrow(ErrorCode.INVALID_KEY_SIZE);
    // corrupted public key point → verify false without throwing
    const sig = await ecdsaP256.sign(new Uint8Array(4), kp.privateKey);
    expect(await ecdsaP256.verify(new Uint8Array(4), sig, new Uint8Array(65).fill(4))).toBe(false);
  });

  it('X25519 rejects wrong-size key material with INVALID_KEY_SIZE', async () => {
    const kp = await ecdhX25519.generateKeyPair();
    await expect(ecdhX25519.computeSharedSecret(new Uint8Array(31), kp.publicKey)).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    await expect(ecdhX25519.computeSharedSecret(kp.privateKey, new Uint8Array(31))).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
  });
  itIfX448('X448 rejects wrong-size key material with INVALID_KEY_SIZE', async () => {
    const kp448 = await ecdhX448.generateKeyPair();
    await expect(ecdhX448.computeSharedSecret(new Uint8Array(55), kp448.publicKey)).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    await expect(
      ecdhX448.computeSharedSecret(kp448.privateKey, new Uint8Array(55)),
    ).rejects.toThrow(ErrorCode.INVALID_KEY_SIZE);
  });

  it('ed25519 sign/verify reject bad seeds and bad public keys', async () => {
    const kp = await ed25519.generateKeyPair();
    await expect(ed25519.sign(new Uint8Array(4), new Uint8Array(5))).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    await expect(ed25519.fromSeed(new Uint8Array(0))).rejects.toThrow(ErrorCode.INVALID_KEY_SIZE);
    const sig = await ed25519.sign(new Uint8Array(4), kp.privateKey);
    expect(await ed25519.verify(new Uint8Array(4), sig, new Uint8Array(5))).toBe(false);
  });
});

describe('KeyStore remaining branches', () => {
  const SLOW = { m: 1024, r: 8, p: 1 };
  it('unlock on an unlocked store is a no-op and unsupported TTL-less expiry works', async () => {
    const ks = await KeyStore.create({ password: 'pw', ...SLOW });
    await ks.unlock('pw'); // no-op
    await ks.generateKey('k1', 'AES-128-GCM');
    expect((await ks.get('k1')).length).toBe(16);
    await ks.set('k2', randomKey256(), 'AES-256-GCM', { ttlMs: 1 });
    await new Promise((r) => setTimeout(r, 5));
    await expect(ks.get('k2')).rejects.toThrow(ErrorCode.KEY_EXPIRED);
  });
});
