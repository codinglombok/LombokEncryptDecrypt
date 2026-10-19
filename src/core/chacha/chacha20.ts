/**
 * LombokEncryptDecrypt — ChaCha20 + ChaCha20-Poly1305
 *
 * ChaCha20 stream cipher (RFC 7539) and AEAD construction with Poly1305 MAC.
 * XChaCha20-Poly1305 in xchacha20.ts.
 *
 * Reference: RFC 8439 (obsoletes RFC 7539)
 * Test vectors: RFC 8439, Wycheproof
 *
 * @module core/chacha/chacha20
 */

import { LombokCryptoError, ErrorCode } from '../../errors.js';
import type { AeadEncryptOptions, AeadDecryptOptions, AeadResult } from '../../types.js';
import { randomIv } from '../../utils/random.js';
import { timingSafeEqual } from '../../utils/timing.js';
import { concatBytes } from '../../utils/encoding.js';
import { HAS_NODE_CRYPTO, PLATFORM } from '../../platform/detect.js';

const KEY_SIZE   = 32;
const NONCE_SIZE = 12;
const TAG_SIZE   = 16;

// ── ChaCha20 quarter-round ─────────────────────────────────────────────────

function qround(state: Uint32Array, a: number, b: number, c: number, d: number): void {
  state[a] = (state[a]! + state[b]!) >>> 0;
  state[d] = rotl32(state[d]! ^ state[a]!, 16);
  state[c] = (state[c]! + state[d]!) >>> 0;
  state[b] = rotl32(state[b]! ^ state[c]!, 12);
  state[a] = (state[a]! + state[b]!) >>> 0;
  state[d] = rotl32(state[d]! ^ state[a]!, 8);
  state[c] = (state[c]! + state[d]!) >>> 0;
  state[b] = rotl32(state[b]! ^ state[c]!, 7);
}

function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

// ── ChaCha20 block function ────────────────────────────────────────────────

function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  // ChaCha20 constants: "expand 32-byte k"
  const state = new Uint32Array([
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    // Key words (little-endian)
    readLE32(key, 0),  readLE32(key, 4),  readLE32(key, 8),  readLE32(key, 12),
    readLE32(key, 16), readLE32(key, 20), readLE32(key, 24), readLE32(key, 28),
    // Counter
    counter >>> 0,
    // Nonce words
    readLE32(nonce, 0), readLE32(nonce, 4), readLE32(nonce, 8),
  ]);

  const working = new Uint32Array(state);

  // 20 rounds (10 column + 10 diagonal)
  for (let i = 0; i < 10; i++) {
    // Column rounds
    qround(working, 0, 4, 8, 12);
    qround(working, 1, 5, 9, 13);
    qround(working, 2, 6, 10, 14);
    qround(working, 3, 7, 11, 15);
    // Diagonal rounds
    qround(working, 0, 5, 10, 15);
    qround(working, 1, 6, 11, 12);
    qround(working, 2, 7, 8, 13);
    qround(working, 3, 4, 9, 14);
  }

  // Add initial state
  for (let i = 0; i < 16; i++) {
    working[i] = (working[i]! + state[i]!) >>> 0;
  }

  // Serialize to bytes (little-endian)
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    writeLE32(out, working[i]!, i * 4);
  }
  return out;
}

// ── ChaCha20 stream encrypt/decrypt ───────────────────────────────────────

function chacha20Crypt(
  key: Uint8Array,
  nonce: Uint8Array,
  initialCounter: number,
  data: Uint8Array,
): Uint8Array {
  const output = new Uint8Array(data.length);
  let offset = 0;
  let counter = initialCounter;

  while (offset < data.length) {
    const keystream = chacha20Block(key, counter, nonce);
    const len = Math.min(64, data.length - offset);
    for (let i = 0; i < len; i++) {
      output[offset + i] = (data[offset + i] ?? 0) ^ (keystream[i] ?? 0);
    }
    offset += len;
    counter = (counter + 1) >>> 0;
  }
  return output;
}

// ── Poly1305 MAC ──────────────────────────────────────────────────────────

function poly1305Mac(key: Uint8Array, message: Uint8Array): Uint8Array {
  // Poly1305 clamp and setup
  const r = new Uint8Array(key.slice(0, 16));
  const s = key.slice(16, 32);

  // Clamp r
  r[3]!  &= 0x0f; r[7]!  &= 0x0f; r[11]! &= 0x0f; r[15]! &= 0x0f;
  r[4]!  &= 0xfc; r[8]!  &= 0xfc; r[12]! &= 0xfc;

  // 130-bit integer arithmetic using BigInt for correctness
  const rBig = bytesToBigIntLE(r) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const sBig = bytesToBigIntLE(s);
  const p = (1n << 130n) - 5n;

  let acc = 0n;
  const blocks = Math.ceil(message.length / 16);

  for (let i = 0; i < blocks; i++) {
    const block = new Uint8Array(17);
    const chunk = message.slice(i * 16, (i + 1) * 16);
    block.set(chunk);
    block[chunk.length] = 1; // Padding bit
    const n = bytesToBigIntLE(block);
    acc = ((acc + n) * rBig) % p;
  }

  acc = (acc + sBig) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn;

  // Serialize (little-endian, 16 bytes)
  return bigIntToBytesLE(acc, 16);
}

function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i] ?? 0);
  }
  return result;
}

function bigIntToBytesLE(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(n & 0xFFn);
    n >>= 8n;
  }
  return out;
}

// ── Poly1305 key generation from ChaCha20 block 0 ─────────────────────────

function poly1305KeyGen(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  const block = chacha20Block(key, 0, nonce);
  return block.slice(0, 32);
}

// ── AEAD construction (RFC 8439 Section 2.8) ──────────────────────────────

function constructAeadMsg(aad: Uint8Array | undefined, ciphertext: Uint8Array): Uint8Array {
  const aadData = aad ?? new Uint8Array(0);
  const aadPad = new Uint8Array((16 - (aadData.length % 16)) % 16);
  const ctPad  = new Uint8Array((16 - (ciphertext.length % 16)) % 16);

  const lenBlock = new Uint8Array(16);
  const aadLen = BigInt(aadData.length);
  const ctLen  = BigInt(ciphertext.length);
  for (let i = 0; i < 8; i++) {
    lenBlock[i]     = Number((aadLen >> BigInt(i * 8)) & 0xFFn);
    lenBlock[8 + i] = Number((ctLen  >> BigInt(i * 8)) & 0xFFn);
  }

  return concatBytes(aadData, aadPad, ciphertext, ctPad, lenBlock);
}

// ── Node.js native path ────────────────────────────────────────────────────

async function encryptNode(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad?: Uint8Array,
): Promise<AeadResult> {
  const { createCipheriv } = await import('node:crypto');
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  if (aad) cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext: new Uint8Array(ct), tag: new Uint8Array(tag), iv: nonce };
}

async function decryptNode(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const { createDecipheriv } = await import('node:crypto');
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad, { plaintextLength: ciphertext.length });
  try {
    return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
  } catch {
    throw LombokCryptoError.authenticationFailed('ChaCha20-Poly1305');
  }
}

// ── Pure TS path ──────────────────────────────────────────────────────────

function encryptPure(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad?: Uint8Array,
): AeadResult {
  // Encrypt with ChaCha20 (counter starts at 1; block 0 is for Poly1305 key)
  const ciphertext = chacha20Crypt(key, nonce, 1, plaintext);
  // Generate Poly1305 key from block 0
  const macKey = poly1305KeyGen(key, nonce);
  // Compute MAC
  const macInput = constructAeadMsg(aad, ciphertext);
  const tag = poly1305Mac(macKey, macInput);
  return { ciphertext, tag, iv: nonce };
}

function decryptPure(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  // Verify tag first (authenticate-then-decrypt)
  const macKey = poly1305KeyGen(key, nonce);
  const macInput = constructAeadMsg(aad, ciphertext);
  const expectedTag = poly1305Mac(macKey, macInput);
  if (!timingSafeEqual(expectedTag, tag)) {
    throw LombokCryptoError.authenticationFailed('ChaCha20-Poly1305');
  }
  return chacha20Crypt(key, nonce, 1, ciphertext);
}

// ── Byte helpers ──────────────────────────────────────────────────────────

function readLE32(buf: Uint8Array, offset: number): number {
  return (
    (buf[offset] ?? 0) |
    ((buf[offset + 1] ?? 0) << 8) |
    ((buf[offset + 2] ?? 0) << 16) |
    ((buf[offset + 3] ?? 0) << 24)
  ) >>> 0;
}

function writeLE32(buf: Uint8Array, value: number, offset: number): void {
  buf[offset]     = value & 0xFF;
  buf[offset + 1] = (value >>> 8) & 0xFF;
  buf[offset + 2] = (value >>> 16) & 0xFF;
  buf[offset + 3] = (value >>> 24) & 0xFF;
}

// ── Public API ────────────────────────────────────────────────────────────

export const chaCha20Poly1305 = {
  /**
   * Encrypt with ChaCha20-Poly1305 (RFC 8439).
   * Returns { ciphertext, tag, iv } where iv = 96-bit nonce.
   *
   * @example
   * const key = randomKey256();
   * const { ciphertext, tag, iv } = await chaCha20Poly1305.encrypt(plaintext, key);
   */
  async encrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    options: AeadEncryptOptions = {},
  ): Promise<AeadResult> {
    if (key.length !== KEY_SIZE) throw LombokCryptoError.invalidKeySize(KEY_SIZE, key.length, 'ChaCha20-Poly1305');
    const nonce = options.iv ?? randomIv(NONCE_SIZE);
    if (nonce.length !== NONCE_SIZE) {
      throw new LombokCryptoError(ErrorCode.INVALID_IV_SIZE, `ChaCha20-Poly1305 nonce must be ${NONCE_SIZE} bytes`);
    }
    if (PLATFORM === 'node' && HAS_NODE_CRYPTO) {
      return encryptNode(plaintext, key, nonce, options.aad);
    }
    return encryptPure(plaintext, key, nonce, options.aad);
  },

  /**
   * Decrypt with ChaCha20-Poly1305.
   * Throws AUTHENTICATION_FAILED if tag does not match.
   */
  async decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    tag: Uint8Array,
    options: AeadDecryptOptions = {},
  ): Promise<Uint8Array> {
    if (key.length !== KEY_SIZE) throw LombokCryptoError.invalidKeySize(KEY_SIZE, key.length, 'ChaCha20-Poly1305');
    if (iv.length !== NONCE_SIZE) {
      throw new LombokCryptoError(ErrorCode.INVALID_IV_SIZE, `ChaCha20-Poly1305 nonce must be ${NONCE_SIZE} bytes`);
    }
    if (PLATFORM === 'node' && HAS_NODE_CRYPTO) {
      return decryptNode(ciphertext, key, iv, tag, options.aad);
    }
    return decryptPure(ciphertext, key, iv, tag, options.aad);
  },

  generateKey(): Uint8Array { return randomIv(KEY_SIZE); },
  generateNonce(): Uint8Array { return randomIv(NONCE_SIZE); },
};

// Export internal for XChaCha20
export { chacha20Block, chacha20Crypt, poly1305Mac, poly1305KeyGen, constructAeadMsg };

/** @internal exposed for conformance tests */
export { encryptPure as chachaEncryptPure, decryptPure as chachaDecryptPure };
