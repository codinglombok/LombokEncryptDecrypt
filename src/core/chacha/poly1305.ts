/**
 * LombokEncryptDecrypt — Poly1305 one-time authenticator (RFC 8439 §2.5),
 * pure TypeScript using BigInt for the 130-bit accumulator.
 */

import { ErrorCode, LombokCryptoError } from '../../errors.js';

const POLY1305_KEY_SIZE = 32;
const POLY1305_TAG_SIZE = 16;
const P1305 = (1n << 130n) - 5n;

function leInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

function clampR(r: bigint): bigint {
  // BigInt literal — a Number literal here would silently lose precision.
  const mask = 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  return r & mask;
}

function intToLe16(value: bigint): Uint8Array {
  const out = new Uint8Array(16);
  let v = value;
  for (let i = 0; i < 16; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Poly1305 MAC of `message` under the 32-byte one-time `key`. */
export function poly1305Mac(key: Uint8Array, message: Uint8Array): Uint8Array {
  if (key.length !== POLY1305_KEY_SIZE) {
    throw new LombokCryptoError(
      ErrorCode.INVALID_KEY_SIZE,
      `Poly1305 key must be ${POLY1305_KEY_SIZE} bytes, got ${key.length}`,
      'Poly1305',
    );
  }
  const r = clampR(leInt(key.subarray(0, 16)));
  const s = leInt(key.subarray(16, 32));
  let acc = 0n;
  for (let off = 0; off < message.length; off += 16) {
    const take = Math.min(16, message.length - off);
    const block = new Uint8Array(take + 1);
    block.set(message.subarray(off, off + take));
    block[take] = 1;
    acc = ((acc + leInt(block)) * r) % P1305;
  }
  acc = (acc + s) % (1n << 128n);
  return intToLe16(acc);
}

export { POLY1305_TAG_SIZE };
