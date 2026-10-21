/**
 * LombokEncryptDecrypt — AES-CMAC (NIST SP 800-38B), pure TypeScript.
 * Subkeys K1/K2 derived per §5.3 with the 0x87 reduction in the MSB-first
 * GF(2^128) field. Verified against the SP 800-38B examples.
 */

import { aesEncryptBlock, aesExpandKey } from '../core/aes/aes.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';
import { timingSafeEqual } from '../utils/encoding.js';

function shiftLeftOne(block: Uint8Array): Uint8Array {
  // MSB-first left shift by one bit across the 16-byte block
  const out = new Uint8Array(16);
  let carry = 0;
  for (let i = 15; i >= 0; i--) {
    out[i] = ((block[i] << 1) | carry) & 0xff;
    carry = (block[i] >>> 7) & 1;
  }
  if (carry === 1) out[15] ^= 0x87;
  return out;
}

function generateSubkeys(key: Uint8Array): { k1: Uint8Array; k2: Uint8Array } {
  const expanded = aesExpandKey(key);
  const l = aesEncryptBlock(expanded, new Uint8Array(16));
  // shiftLeftOne applies the 0x87 reduction on carry-out automatically
  const k1 = shiftLeftOne(l);
  const k2 = shiftLeftOne(k1);
  return { k1, k2 };
}

function cmacRaw(key: Uint8Array, message: Uint8Array): Uint8Array {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `CMAC key must be 16, 24 or 32 bytes, got ${key.length}`,
      'CMAC',
    );
  }
  const { k1, k2 } = generateSubkeys(key);
  const expanded = aesExpandKey(key);
  const n = Math.ceil(message.length / 16);
  const lastComplete = n !== 0 && message.length % 16 === 0;

  let lastBlock: Uint8Array;
  if (n === 0) {
    lastBlock = new Uint8Array(16);
    lastBlock[0] = 0x80;
    for (let i = 0; i < 16; i++) lastBlock[i] ^= k2[i];
  } else if (lastComplete) {
    lastBlock = new Uint8Array(16);
    lastBlock.set(message.subarray((n - 1) * 16));
    for (let i = 0; i < 16; i++) lastBlock[i] ^= k1[i];
  } else {
    lastBlock = new Uint8Array(16);
    const rest = message.subarray((n - 1) * 16);
    lastBlock.set(rest);
    lastBlock[rest.length] = 0x80;
    for (let i = 0; i < 16; i++) lastBlock[i] ^= k2[i];
  }

  let x = new Uint8Array(16);
  for (let i = 0; i < n - 1; i++) {
    const block = new Uint8Array(16);
    block.set(message.subarray(i * 16, i * 16 + 16));
    for (let j = 0; j < 16; j++) block[j] ^= x[j];
    x = aesEncryptBlock(expanded, block);
  }
  const finalInput = new Uint8Array(16);
  for (let i = 0; i < 16; i++) finalInput[i] = lastBlock[i] ^ x[i];
  return aesEncryptBlock(expanded, finalInput);
}

/** AES-CMAC of `message` under `key` (16/24/32-byte key, 16-byte MAC). */
export const cmac = {
  compute(key: Uint8Array, message: Uint8Array): Uint8Array {
    return cmacRaw(key, message);
  },
  /** Constant-time verify — returns false on mismatch, never throws. */
  verify(key: Uint8Array, message: Uint8Array, tag: Uint8Array): boolean {
    if (tag.length !== 16) return false;
    return timingSafeEqual(cmacRaw(key, message), tag);
  },
};
