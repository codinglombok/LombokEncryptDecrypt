/**
 * Coverage hardening 3 — error/edge branches of the merged API surface:
 * XChaCha20-Poly1305 object errors, CMAC key-size gates, sync CBC/ECB edges,
 * stream record framing errors and envelope truncation detection.
 */
import { xchaChaPoly1305 } from '../../src/core/chacha/xchacha20.js';
import { cmac, cmacAes128, cmacAes256 } from '../../src/mac/cmac.js';
import { aesCbc, aesEcb } from '../../src/modes/cbc.js';
import { createDecryptStream } from '../../src/stream/decrypt_stream.js';
import { envelopeEncrypt } from '../../src/hybrid/envelope.js';
import { randomKey256 } from '../../src/utils/random.js';
import { hexToBytes } from '../../src/utils/encoding.js';
import { ErrorCode, LombokCryptoError } from '../../src/errors.js';

const KEY32 = randomKey256();
const KEY16 = hexToBytes('000102030405060708090a0b0c0d0e0f');
const IV24 = hexToBytes('404142434445464748494a4b4c4d4e4f5051525354555657');
const MSG = new TextEncoder().encode('coverage hardening 3');

function code(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof LombokCryptoError) return e.code;
    throw e;
  }
  return 'NO_ERROR';
}

describe('xchaChaPoly1305 object API', () => {
  it('roundtrips and rejects tampering', async () => {
    const { ciphertext, tag } = await xchaChaPoly1305.encrypt(MSG, KEY32, { iv: IV24 });
    const pt = await xchaChaPoly1305.decrypt(ciphertext, KEY32, IV24, tag);
    expect(new TextDecoder().decode(pt)).toBe('coverage hardening 3');
    const bad = tag.slice();
    bad[0] ^= 1;
    await expect(xchaChaPoly1305.decrypt(ciphertext, KEY32, IV24, bad)).rejects.toMatchObject({
      code: ErrorCode.AUTHENTICATION_FAILED,
    });
  });

  it('enforces key and nonce sizes', async () => {
    await expect(xchaChaPoly1305.encrypt(MSG, KEY16)).rejects.toMatchObject({
      code: ErrorCode.INVALID_KEY_SIZE,
    });
    await expect(
      xchaChaPoly1305.encrypt(MSG, KEY32, { iv: KEY16.subarray(0, 12) }),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_IV_SIZE });
    await expect(
      xchaChaPoly1305.decrypt(new Uint8Array(16), KEY16, IV24, new Uint8Array(16)),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_KEY_SIZE });
    await expect(
      xchaChaPoly1305.decrypt(new Uint8Array(16), KEY32, KEY16.subarray(0, 12), new Uint8Array(16)),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_IV_SIZE });
  });
});

describe('CMAC sized handles', () => {
  it('verify() returns false on wrong key size or tag length', () => {
    const tag = cmac.compute(KEY16, MSG);
    expect(cmacAes128.verify(KEY16, MSG, tag)).toBe(true);
    expect(cmacAes128.verify(KEY32, MSG, tag)).toBe(false);
    expect(cmacAes256.verify(KEY16, MSG, tag)).toBe(false);
    expect(cmacAes128.verify(KEY16, MSG, tag.subarray(0, 15))).toBe(false);
  });
});

describe('sync AES-ECB edges', () => {
  it('pkcs7 roundtrips and length errors are reported', () => {
    const ct = aesEcb.encrypt(KEY16, MSG, { padding: 'pkcs7' });
    expect(aesEcb.decrypt(KEY16, ct, { padding: 'pkcs7' })).toEqual(MSG);
    expect(code(() => aesEcb.encrypt(KEY16, new Uint8Array(0)))).toBe(
      ErrorCode.INTEGRITY_CHECK_FAILED,
    );
    expect(code(() => aesEcb.encrypt(KEY16, new Uint8Array(15)))).toBe(ErrorCode.INVALID_INPUT);
    expect(code(() => aesEcb.decrypt(KEY16, new Uint8Array(0)))).toBe(
      ErrorCode.INTEGRITY_CHECK_FAILED,
    );
    expect(code(() => aesEcb.decrypt(KEY16, new Uint8Array(15)))).toBe(ErrorCode.INVALID_INPUT);
    const badPad = ct.slice();
    badPad[badPad.length - 1] = 0x7f;
    expect(code(() => aesEcb.decrypt(KEY16, badPad, { padding: 'pkcs7' }))).toBe(
      ErrorCode.INTEGRITY_CHECK_FAILED,
    );
    expect(code(() => aesEcb.encrypt(new Uint8Array(15), MSG))).toBe(ErrorCode.INVALID_KEY_SIZE);
  });
});

describe('sync AES-CBC edges', () => {
  it('rejects invalid keys and empty ciphertexts', () => {
    const iv = KEY16;
    expect(code(() => aesCbc.encrypt(new Uint8Array(15), iv, MSG))).toBe(
      ErrorCode.INVALID_KEY_SIZE,
    );
    expect(code(() => aesCbc.decrypt(KEY16, iv, new Uint8Array(0)))).toBe(
      ErrorCode.INTEGRITY_CHECK_FAILED,
    );
    const ct = aesCbc.encrypt(KEY16, iv, MSG);
    expect(aesCbc.decrypt(KEY16, iv, ct)).toEqual(MSG);
    const badPad = ct.slice();
    badPad[badPad.length - 1] = 0x00;
    expect(code(() => aesCbc.decrypt(KEY16, iv, badPad))).toBe(ErrorCode.INTEGRITY_CHECK_FAILED);
  });
});

describe('stream record framing errors', () => {
  it('rejects unsupported algorithms before parsing', () => {
    expect(() =>
      createDecryptStream({
        algorithm: 'AES-128-CTR' as 'AES-256-GCM',
        key: KEY32,
      }),
    ).toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
  });

  it('rejects invalid record flags and oversized declared lengths', async () => {
    // record: index(4) flags(1) iv(12) ctLen(4) — forge an unknown flags byte
    const forged = new Uint8Array(21 + 16);
    forged[4] = 0x7f;
    const dec = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY32 });
    await expect(dec.update(forged)).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });

    // ctLen far above the 16 MiB record limit
    const huge = new Uint8Array(21);
    huge[17] = 0xff;
    huge[18] = 0xff;
    huge[19] = 0xff;
    const dec2 = createDecryptStream({ algorithm: 'AES-256-GCM', key: KEY32 });
    await expect(dec2.update(huge)).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
  });
});

describe('envelope truncation', () => {
  it('rejects packed payloads shorter than IV + tag', async () => {
    const kek = randomKey256();
    const env = await envelopeEncrypt.encrypt(MSG, kek, 'kek-h3');
    await expect(
      envelopeEncrypt.decrypt(new Uint8Array(10), env.encryptedKey, kek),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_INPUT });
  });
});
