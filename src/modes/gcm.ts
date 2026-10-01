/**
 * LombokEncryptDecrypt — AES-GCM (Galois/Counter Mode)
 *
 * AEAD: Authenticated Encryption with Associated Data.
 * Provides confidentiality + integrity + authenticity.
 *
 * Reference: NIST SP 800-38D
 * Test vectors: NIST CAVP, Wycheproof
 *
 * @module modes/gcm
 */

import { LombokCryptoError, ErrorCode } from '../../errors.js';
import type { AeadEncryptOptions, AeadDecryptOptions, AeadResult } from '../../types.js';
import { randomIv } from '../../utils/random.js';
import { timingSafeEqual } from '../../utils/timing.js';
import { concatBytes } from '../../utils/encoding.js';
import { HAS_NODE_CRYPTO, HAS_SUBTLE_CRYPTO, PLATFORM } from '../../platform/detect.js';
import { createAes } from '../aes/aes.js';

const GCM_IV_SIZE = 12;
const GCM_TAG_SIZE = 16;
const VALID_KEY_SIZES = [16, 24, 32] as const;

// ── GHASH ─────────────────────────────────────────────────────────────────

/** GHASH over GF(2^128) — used by GCM for authentication */
function ghash(hashKey: Uint8Array, data: Uint8Array): Uint8Array {
  const y = new Uint8Array(16);
  const blocks = Math.ceil(data.length / 16);

  for (let i = 0; i < blocks; i++) {
    const block = new Uint8Array(16);
    const chunk = data.slice(i * 16, (i + 1) * 16);
    block.set(chunk);
    // y = (y XOR block) * H in GF(2^128)
    for (let j = 0; j < 16; j++) y[j] ^= block[j] ?? 0;
    gfMul(y, hashKey);
  }
  return y;
}

/** Multiply two 128-bit blocks in GF(2^128) — constant-time implementation */
function gfMul(x: Uint8Array, y: Uint8Array): void {
  const z = new Uint8Array(16);
  const v = new Uint8Array(y);

  for (let i = 0; i < 128; i++) {
    const xi = (x[Math.floor(i / 8)] ?? 0) & (0x80 >>> (i % 8));
    if (xi !== 0) {
      for (let j = 0; j < 16; j++) z[j] ^= v[j] ?? 0;
    }
    const lsb = (v[15] ?? 0) & 1;
    // Right shift v by 1
    for (let j = 15; j > 0; j--) {
      v[j] = (((v[j] ?? 0) >>> 1) | (((v[j - 1] ?? 0) & 1) << 7)) & 0xff;
    }
    v[0] = ((v[0] ?? 0) >>> 1) & 0xff;
    // XOR with R = 0xe1000...0 if LSB was 1
    if (lsb) v[0] ^= 0xe1;
  }
  for (let i = 0; i < 16; i++) x[i] = z[i] ?? 0;
}

// ── CTR mode ──────────────────────────────────────────────────────────────

function gcmCtr(aesCore: ReturnType<typeof createAes>, iv: Uint8Array, data: Uint8Array, startCounter: number): Uint8Array {
  const output = new Uint8Array(data.length);
  const counter = new Uint8Array(16);
  counter.set(iv);

  let dataOffset = 0;
  let ctr = startCounter;

  while (dataOffset < data.length) {
    // Write counter (big-endian, last 4 bytes)
    counter[12] = (ctr >>> 24) & 0xff;
    counter[13] = (ctr >>> 16) & 0xff;
    counter[14] = (ctr >>> 8) & 0xff;
    counter[15] = ctr & 0xff;

    const keystream = aesCore.encryptBlock(counter);
    const remaining = data.length - dataOffset;
    const blockLen = Math.min(16, remaining);

    for (let i = 0; i < blockLen; i++) {
      output[dataOffset + i] = (data[dataOffset + i] ?? 0) ^ (keystream[i] ?? 0);
    }

    dataOffset += blockLen;
    ctr = (ctr + 1) >>> 0;
  }
  return output;
}

// ── AES-GCM via Node.js crypto (accelerated) ──────────────────────────────

async function encryptNode(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array,
  tagLength: number = GCM_TAG_SIZE,
): Promise<AeadResult> {
  const { createCipheriv } = await import('node:crypto');
  const alg = `aes-${key.length * 8}-gcm`;
  const cipher = createCipheriv(alg, key, iv, { authTagLength: tagLength } as object);
  if (aad) cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: new Uint8Array(encrypted),
    tag: new Uint8Array(tag),
    iv,
  };
}

async function decryptNode(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const { createDecipheriv } = await import('node:crypto');
  const alg = `aes-${key.length * 8}-gcm`;
  const decipher = createDecipheriv(alg, key, iv);
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad);
  try {
    return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
  } catch {
    throw LombokCryptoError.authenticationFailed('AES-GCM');
  }
}

// ── AES-GCM via SubtleCrypto (browser / Deno / Bun) ──────────────────────

async function encryptSubtle(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array,
  tagLength: number = GCM_TAG_SIZE,
): Promise<AeadResult> {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw', key, { name: 'AES-GCM' }, false, ['encrypt'],
  );
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv,
    additionalData: aad,
    tagLength: tagLength * 8,
  };
  const encrypted = await globalThis.crypto.subtle.encrypt(params, cryptoKey, plaintext);
  const buf = new Uint8Array(encrypted);
  const ciphertext = buf.slice(0, -tagLength);
  const tag = buf.slice(-tagLength);
  return { ciphertext, tag, iv };
}

async function decryptSubtle(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw', key, { name: 'AES-GCM' }, false, ['decrypt'],
  );
  const combined = concatBytes(ciphertext, tag);
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv,
    additionalData: aad,
    tagLength: tag.length * 8,
  };
  try {
    return new Uint8Array(await globalThis.crypto.subtle.decrypt(params, cryptoKey, combined));
  } catch {
    throw LombokCryptoError.authenticationFailed('AES-GCM');
  }
}

// ── AES-GCM pure TS fallback ───────────────────────────────────────────────

async function encryptPure(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array,
  tagLength: number = GCM_TAG_SIZE,
): Promise<AeadResult> {
  const aesCore = createAes(key);

  // H = AES_K(0^128)
  const h = aesCore.encryptBlock(new Uint8Array(16));

  // Encrypt-then-auth: CTR starting at counter=1
  const ciphertext = gcmCtr(aesCore, iv, plaintext, 2);

  // J0 = IV || 0^31 || 1
  const j0 = new Uint8Array(16);
  j0.set(iv);
  j0[15] = 1;
  const e_j0 = aesCore.encryptBlock(j0);

  // GHASH over AAD || ciphertext
  const aadLen = aad?.length ?? 0;
  const aadPadded = new Uint8Array(Math.ceil(aadLen / 16) * 16);
  if (aad) aadPadded.set(aad);
  const ctPadded = new Uint8Array(Math.ceil(ciphertext.length / 16) * 16);
  ctPadded.set(ciphertext);

  // Length block: len(aad) || len(ciphertext) in bits (big-endian 64-bit each)
  const lenBlock = new Uint8Array(16);
  const aadBits = aadLen * 8;
  const ctBits = ciphertext.length * 8;
  lenBlock[7] = aadBits & 0xff;
  lenBlock[6] = (aadBits >>> 8) & 0xff;
  lenBlock[15] = ctBits & 0xff;
  lenBlock[14] = (ctBits >>> 8) & 0xff;

  const authData = concatBytes(aadPadded, ctPadded, lenBlock);
  const s = ghash(h, authData);
  const fullTag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) fullTag[i] = s[i]! ^ e_j0[i]!;
  const tag = fullTag.slice(0, tagLength);

  return { ciphertext, tag, iv };
}

async function decryptPure(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const aesCore = createAes(key);
  const h = aesCore.encryptBlock(new Uint8Array(16));
  const j0 = new Uint8Array(16);
  j0.set(iv);
  j0[15] = 1;
  const e_j0 = aesCore.encryptBlock(j0);

  const aadLen = aad?.length ?? 0;
  const aadPadded = new Uint8Array(Math.ceil(aadLen / 16) * 16);
  if (aad) aadPadded.set(aad);
  const ctPadded = new Uint8Array(Math.ceil(ciphertext.length / 16) * 16);
  ctPadded.set(ciphertext);
  const lenBlock = new Uint8Array(16);
  const aadBits = aadLen * 8;
  const ctBits = ciphertext.length * 8;
  lenBlock[7] = aadBits & 0xff;
  lenBlock[6] = (aadBits >>> 8) & 0xff;
  lenBlock[15] = ctBits & 0xff;
  lenBlock[14] = (ctBits >>> 8) & 0xff;
  const authData = concatBytes(aadPadded, ctPadded, lenBlock);
  const s = ghash(h, authData);
  const computedTag = new Uint8Array(tag.length);
  for (let i = 0; i < tag.length; i++) computedTag[i] = s[i]! ^ e_j0[i]!;

  if (!timingSafeEqual(computedTag, tag)) {
    throw LombokCryptoError.authenticationFailed('AES-GCM');
  }

  return gcmCtr(aesCore, iv, ciphertext, 2);
}

// ── Public AES-GCM API ────────────────────────────────────────────────────

function validateKey(key: Uint8Array): void {
  if (!VALID_KEY_SIZES.includes(key.length as typeof VALID_KEY_SIZES[number])) {
    throw LombokCryptoError.invalidKeySize([16, 24, 32], key.length, 'AES-GCM');
  }
}

export const aesGcm = {
  /**
   * Encrypt plaintext with AES-GCM.
   * Returns { ciphertext, tag, iv } — all needed for decryption.
   *
   * @example
   * const key = randomKey256();
   * const { ciphertext, tag, iv } = await aesGcm.encrypt(plaintext, key);
   */
  async encrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    options: AeadEncryptOptions = {},
  ): Promise<AeadResult> {
    validateKey(key);
    const iv = options.iv ?? randomIv(GCM_IV_SIZE);
    const tagLength = options.tagLength ?? GCM_TAG_SIZE;

    if (PLATFORM === 'node' && HAS_NODE_CRYPTO) {
      return encryptNode(plaintext, key, iv, options.aad, tagLength);
    }
    if (HAS_SUBTLE_CRYPTO) {
      return encryptSubtle(plaintext, key, iv, options.aad, tagLength);
    }
    return encryptPure(plaintext, key, iv, options.aad, tagLength);
  },

  /**
   * Decrypt and verify ciphertext with AES-GCM.
   * Throws LombokCryptoError(AUTHENTICATION_FAILED) if tag verification fails.
   *
   * @example
   * const plaintext = await aesGcm.decrypt(ciphertext, key, iv, tag);
   */
  async decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    tag: Uint8Array,
    options: AeadDecryptOptions = {},
  ): Promise<Uint8Array> {
    validateKey(key);
    if (iv.length !== GCM_IV_SIZE) {
      throw new LombokCryptoError(ErrorCode.INVALID_IV_SIZE,
        `AES-GCM IV must be ${GCM_IV_SIZE} bytes; got ${iv.length}`);
    }

    if (PLATFORM === 'node' && HAS_NODE_CRYPTO) {
      return decryptNode(ciphertext, key, iv, tag, options.aad);
    }
    if (HAS_SUBTLE_CRYPTO) {
      return decryptSubtle(ciphertext, key, iv, tag, options.aad);
    }
    return decryptPure(ciphertext, key, iv, tag, options.aad);
  },

  /** Generate a random AES-256 key (32 bytes) */
  generateKey(bits: 128 | 192 | 256 = 256): Uint8Array {
    return randomIv(bits / 8);
  },

  /** Generate a random 96-bit IV (recommended for GCM) */
  generateIv(): Uint8Array {
    return randomIv(GCM_IV_SIZE);
  },
};
