/**
 * LombokEncryptDecrypt — CMAC-AES
 * Cipher-based Message Authentication Code (NIST SP 800-38B, RFC 4493)
 * Supported key sizes: 128-bit (AES-128), 256-bit (AES-256)
 * Output: 16 bytes (128-bit tag)
 * @module mac/cmac
 */

import { LombokCryptoError, ErrorCode } from '../errors.js';
import { createAes } from '../core/aes/aes.js';
import { timingSafeEqual } from '../utils/timing.js';
import { xorBytes } from '../utils/encoding.js';

const BLOCK = 16;
const R128  = new Uint8Array([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x87]);

function leftShift1(buf: Uint8Array): Uint8Array {
  const out = new Uint8Array(BLOCK);
  let carry = 0;
  for (let i = BLOCK - 1; i >= 0; i--) {
    const byte = buf[i]!;
    out[i] = ((byte << 1) | carry) & 0xFF;
    carry = byte >>> 7;
  }
  return out;
}

function generateSubkeys(key: Uint8Array): [Uint8Array, Uint8Array] {
  const aes = createAes(key);
  const L   = aes.encryptBlock(new Uint8Array(BLOCK));

  // K1 = L << 1 XOR (0x87 if MSB of L is 1)
  const k1 = leftShift1(L);
  if (L[0]! & 0x80) { k1[15]! ^= 0x87; }

  // K2 = K1 << 1 XOR (0x87 if MSB of K1 is 1)
  const k2 = leftShift1(k1);
  if (k1[0]! & 0x80) { k2[15]! ^= 0x87; }

  return [k1, k2];
}

function cmacCompute(key: Uint8Array, message: Uint8Array): Uint8Array {
  if (key.length !== 16 && key.length !== 32) {
    throw LombokCryptoError.invalidKeySize([16, 32], key.length, 'CMAC-AES');
  }

  const aes = createAes(key);
  const [k1, k2] = generateSubkeys(key);
  const len = message.length;

  // Number of blocks (at least 1)
  const n = Math.max(1, Math.ceil(len / BLOCK));
  const isLastBlockComplete = len > 0 && len % BLOCK === 0;

  // Pad last block if needed
  let lastBlock: Uint8Array;
  if (isLastBlockComplete) {
    lastBlock = xorBytes(message.slice((n-1)*BLOCK), k1);
  } else {
    const padded = new Uint8Array(BLOCK);
    const rem = message.slice((n-1)*BLOCK);
    padded.set(rem);
    padded[rem.length] = 0x80; // ISO/IEC 7816-4 padding
    lastBlock = xorBytes(padded, k2);
  }

  // CBC MAC
  let x = new Uint8Array(BLOCK);
  for (let i = 0; i < n - 1; i++) {
    x = aes.encryptBlock(xorBytes(x, message.slice(i*BLOCK, (i+1)*BLOCK)));
  }
  return aes.encryptBlock(xorBytes(x, lastBlock));
}

export const cmacAes128 = {
  compute(key: Uint8Array, message: Uint8Array): Uint8Array {
    if (key.length !== 16) throw LombokCryptoError.invalidKeySize(16, key.length, 'CMAC-AES-128');
    return cmacCompute(key, message);
  },
  verify(key: Uint8Array, message: Uint8Array, mac: Uint8Array): boolean {
    return timingSafeEqual(cmacCompute(key, message), mac);
  },
};

export const cmacAes256 = {
  compute(key: Uint8Array, message: Uint8Array): Uint8Array {
    if (key.length !== 32) throw LombokCryptoError.invalidKeySize(32, key.length, 'CMAC-AES-256');
    return cmacCompute(key, message);
  },
  verify(key: Uint8Array, message: Uint8Array, mac: Uint8Array): boolean {
    return timingSafeEqual(cmacCompute(key, message), mac);
  },
};

/** Generic CMAC — key size determines variant */
export const cmac = {
  compute: cmacCompute,
  verify(key: Uint8Array, message: Uint8Array, mac: Uint8Array): boolean {
    return timingSafeEqual(cmacCompute(key, message), mac);
  },
};
