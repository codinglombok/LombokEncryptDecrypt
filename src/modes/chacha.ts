/**
 * LombokEncryptDecrypt — ChaCha20-Poly1305 & XChaCha20-Poly1305 AEAD
 * (RFC 8439 / draft-irtf-cfrg-xchacha), pure TypeScript.
 */

import { chacha20Block, chacha20Xor, hchacha20 } from '../core/chacha/chacha20.js';
import { poly1305Mac } from '../core/chacha/poly1305.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';
import { concatBytes, timingSafeEqual, xorBytes } from '../utils/encoding.js';
import { randomBytes } from '../utils/random.js';

export interface ChaChaPolyOptions {
  /** 12-byte nonce (ChaCha) — random when omitted. */
  nonce?: Uint8Array;
  /** 24-byte nonce (XChaCha) — random when omitted. */
  iv?: Uint8Array;
  /** Additional authenticated data. */
  aad?: Uint8Array;
}

export interface ChaChaEncryptResult {
  ciphertext: Uint8Array;
  tag: Uint8Array;
  /** The nonce used (12 bytes ChaCha, 24 bytes XChaCha). */
  iv: Uint8Array;
}

const KEY_SIZE = 32;
const NONCE_SIZE = 12;
const XNONCE_SIZE = 24;
const TAG_SIZE = 16;

function assertKey(key: Uint8Array): void {
  if (key.length !== KEY_SIZE) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `ChaCha20-Poly1305 key must be ${KEY_SIZE} bytes, got ${key.length}`,
      'ChaCha20-Poly1305',
    );
  }
}

function aeadEncrypt(
  key: Uint8Array,
  nonce12: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  const polyKeyBlock = chacha20Block(key, 0, nonce12);
  const polyKey = new Uint8Array(32);
  for (let w = 0; w < 8; w++) {
    const word = polyKeyBlock[w];
    polyKey[w * 4] = word & 0xff;
    polyKey[w * 4 + 1] = (word >>> 8) & 0xff;
    polyKey[w * 4 + 2] = (word >>> 16) & 0xff;
    polyKey[w * 4 + 3] = (word >>> 24) & 0xff;
  }
  const ciphertext = chacha20Xor(key, 1, nonce12, plaintext);
  const macData = buildMacData(aad, ciphertext);
  const tag = poly1305Mac(polyKey, macData);
  return { ciphertext, tag };
}

function aeadDecrypt(
  key: Uint8Array,
  nonce12: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (tag.length !== TAG_SIZE) {
    throw new LombokCryptoError(
      ErrorCode.AUTHENTICATION_FAILED,
      `Poly1305 tag must be ${TAG_SIZE} bytes, got ${tag.length}`,
      'ChaCha20-Poly1305',
    );
  }
  const polyKeyBlock = chacha20Block(key, 0, nonce12);
  const polyKey = new Uint8Array(32);
  for (let w = 0; w < 8; w++) {
    const word = polyKeyBlock[w];
    polyKey[w * 4] = word & 0xff;
    polyKey[w * 4 + 1] = (word >>> 8) & 0xff;
    polyKey[w * 4 + 2] = (word >>> 16) & 0xff;
    polyKey[w * 4 + 3] = (word >>> 24) & 0xff;
  }
  const macData = buildMacData(aad, ciphertext);
  const expected = poly1305Mac(polyKey, macData);
  if (!timingSafeEqual(expected, tag)) {
    throw new LombokCryptoError(
      ErrorCode.AUTHENTICATION_FAILED,
      'Poly1305 tag verification failed',
      'ChaCha20-Poly1305',
    );
  }
  return chacha20Xor(key, 1, nonce12, ciphertext);
}

function buildMacData(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const pad = (n: number): number => (n % 16 === 0 ? 0 : 16 - (n % 16));
  // RFC 8439 encodes the AAD and ciphertext lengths in BYTES (little-endian
  // u64) — unlike GCM's GHASH, which uses bit lengths. BigInt shifts are
  // required: JS `>>>`/`<<` wrap shift counts mod 32, which would corrupt
  // bytes 4..7 of the u64.
  const lenBlock = new Uint8Array(16);
  const aadLen = BigInt(aad.length);
  const ctLen = BigInt(ciphertext.length);
  for (let i = 0; i < 8; i++) lenBlock[i] = Number((aadLen >> BigInt(i * 8)) & 0xffn);
  for (let i = 0; i < 8; i++) lenBlock[8 + i] = Number((ctLen >> BigInt(i * 8)) & 0xffn);
  return concatBytes(
    aad,
    new Uint8Array(pad(aad.length)),
    ciphertext,
    new Uint8Array(pad(ciphertext.length)),
    lenBlock,
  );
}

function assertAad(aad?: Uint8Array): Uint8Array {
  return aad ?? new Uint8Array(0);
}

/** ChaCha20-Poly1305 AEAD (RFC 8439) — 12-byte nonce. */
export const chaCha20Poly1305 = {
  async encrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    options?: ChaChaPolyOptions,
  ): Promise<ChaChaEncryptResult> {
    assertKey(key);
    const nonce = options?.nonce ?? options?.iv ?? randomBytes(NONCE_SIZE);
    if (nonce.length !== NONCE_SIZE) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_IV_SIZE,
        `ChaCha20-Poly1305 nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`,
        'ChaCha20-Poly1305',
      );
    }
    const { ciphertext, tag } = aeadEncrypt(key, nonce, plaintext, assertAad(options?.aad));
    return { ciphertext, tag, iv: nonce };
  },

  async decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    tag: Uint8Array,
    options?: ChaChaPolyOptions,
  ): Promise<Uint8Array> {
    assertKey(key);
    if (nonce.length !== NONCE_SIZE) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_IV_SIZE,
        `ChaCha20-Poly1305 nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`,
        'ChaCha20-Poly1305',
      );
    }
    return aeadDecrypt(key, nonce, ciphertext, tag, assertAad(options?.aad));
  },

  /** 32 random bytes. */
  generateKey(): Uint8Array {
    return randomBytes(KEY_SIZE);
  },

  /** 12 random bytes. */
  generateNonce(): Uint8Array {
    return randomBytes(NONCE_SIZE);
  },
};

/** XChaCha20-Poly1305 AEAD — 24-byte nonce, HChaCha20 subkey derivation. */
export const xchaChaPoly1305 = {
  async encrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    options?: ChaChaPolyOptions,
  ): Promise<ChaChaEncryptResult> {
    assertKey(key);
    const nonce = options?.iv ?? randomBytes(XNONCE_SIZE);
    if (nonce.length !== XNONCE_SIZE) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_IV_SIZE,
        `XChaCha20-Poly1305 nonce must be ${XNONCE_SIZE} bytes, got ${nonce.length}`,
        'XChaCha20-Poly1305',
      );
    }
    const subkey = hchacha20(key, nonce.subarray(0, 16));
    const derivedNonce = concatBytes(new Uint8Array(4), nonce.subarray(16, 24));
    const { ciphertext, tag } = aeadEncrypt(
      subkey,
      derivedNonce,
      plaintext,
      assertAad(options?.aad),
    );
    return { ciphertext, tag, iv: nonce };
  },

  async decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    tag: Uint8Array,
    options?: ChaChaPolyOptions,
  ): Promise<Uint8Array> {
    assertKey(key);
    if (nonce.length !== XNONCE_SIZE) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_IV_SIZE,
        `XChaCha20-Poly1305 nonce must be ${XNONCE_SIZE} bytes, got ${nonce.length}`,
        'XChaCha20-Poly1305',
      );
    }
    const subkey = hchacha20(key, nonce.subarray(0, 16));
    const derivedNonce = concatBytes(new Uint8Array(4), nonce.subarray(16, 24));
    return aeadDecrypt(subkey, derivedNonce, ciphertext, tag, assertAad(options?.aad));
  },

  /** 32 random bytes. */
  generateKey(): Uint8Array {
    return randomBytes(KEY_SIZE);
  },

  /** 24 random bytes — safe to use randomly. */
  generateNonce(): Uint8Array {
    return randomBytes(XNONCE_SIZE);
  },
};

/** Exposed for cross-runtime tests of the raw primitives. */
export const internal = { chacha20Block, chacha20Xor, hchacha20, poly1305Mac, xorBytes };
