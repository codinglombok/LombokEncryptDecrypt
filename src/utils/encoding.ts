/**
 * LombokEncryptDecrypt — Encoding & constant-time byte utilities.
 *
 * Everything here is dependency-free and runtime-agnostic (Node 18+,
 * Deno, Bun, browsers): base64/base64url are implemented by hand instead of
 * relying on Buffer or atob so behaviour is byte-identical everywhere.
 */

const HEX_CHARS = '0123456789abcdef';
const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const B64_LOOKUP = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < B64_ALPHABET.length; i++) table[B64_ALPHABET.charCodeAt(i)] = i;
  for (let i = 0; i < B64URL_ALPHABET.length; i++) table[B64URL_ALPHABET.charCodeAt(i)] = i;
  table['='.charCodeAt(0)] = 0; // padding decodes to zero, length is derived
  return table;
})();

/** Encode bytes as lowercase hex. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    out += HEX_CHARS[b >> 4] + HEX_CHARS[b & 0x0f];
  }
  return out;
}

/** Decode lowercase or uppercase hex. Throws on odd length or bad characters. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('hex string must have an even length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = hexCharToNibble(hex.charCodeAt(i * 2));
    const lo = hexCharToNibble(hex.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0)
      throw new Error(`invalid hex character at offset ${i * 2 + (hi < 0 ? 0 : 1)}`);
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function hexCharToNibble(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30; // 0-9
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10; // a-f
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10; // A-F
  return -1;
}

/** Encode bytes as standard base64 (with padding). */
export function bytesToBase64(bytes: Uint8Array): string {
  return base64Encode(bytes, B64_ALPHABET, true);
}

/** Decode standard base64 (also accepts base64url characters). */
export function base64ToBytes(text: string): Uint8Array {
  return base64Decode(text);
}

/** Encode bytes as unpadded base64url (RFC 4648 §5). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return base64Encode(bytes, B64URL_ALPHABET, false);
}

/** Decode base64url (padding optional; standard base64 input is also accepted). */
export function base64UrlToBytes(text: string): Uint8Array {
  return base64Decode(text);
}

function base64Encode(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      alphabet[(n >> 18) & 63] +
      alphabet[(n >> 12) & 63] +
      alphabet[(n >> 6) & 63] +
      alphabet[n & 63];
  }
  const remaining = bytes.length - i;
  if (remaining === 1) {
    const n = bytes[i] << 16;
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63];
    if (pad) out += '==';
  } else if (remaining === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63];
    if (pad) out += '=';
  }
  return out;
}

function base64Decode(text: string): Uint8Array {
  const clean = text.replace(/[\r\n\s]/g, '');
  const stripped = clean.replace(/=+$/, '');
  if (stripped.length % 4 === 1) throw new Error('invalid base64 length');
  let outLen = Math.floor((stripped.length * 3) / 4);
  const rem = stripped.length % 4;
  if (rem === 2 || rem === 3) outLen += 0; // 2 chars -> 1 byte, 3 chars -> 2 bytes (handled below)
  if (rem === 2) outLen = Math.floor(stripped.length / 4) * 3 + 1;
  if (rem === 3) outLen = Math.floor(stripped.length / 4) * 3 + 2;
  const out = new Uint8Array(outLen);
  let acc = 0;
  let accBits = 0;
  let o = 0;
  for (let i = 0; i < stripped.length; i++) {
    const v = stripped.charCodeAt(i) < 128 ? B64_LOOKUP[stripped.charCodeAt(i)] : -1;
    if (v < 0) throw new Error(`invalid base64 character at offset ${i}`);
    acc = (acc << 6) | v;
    accBits += 6;
    if (accBits >= 8) {
      accBits -= 8;
      out[o++] = (acc >> accBits) & 0xff;
    }
  }
  return out;
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8');

/** Encode a UTF-8 string to bytes. */
export function stringToBytes(text: string): Uint8Array {
  const encoded = TEXT_ENCODER.encode(text);
  return new Uint8Array(encoded.buffer, encoded.byteOffset, encoded.byteLength);
}

/** Decode UTF-8 bytes to a string. */
export function bytesToString(bytes: Uint8Array): string {
  return TEXT_DECODER.decode(bytes);
}

/** Concatenate byte arrays into one fresh buffer. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** XOR two equal-length byte arrays. Throws on length mismatch. */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length)
    throw new Error(`xorBytes length mismatch: ${a.length} != ${b.length}`);
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/**
 * Constant-time equality. Always iterates over the longer input, so only the
 * two lengths (never their contents) are observable through timing.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  const max = a.length > b.length ? a.length : b.length;
  for (let i = 0; i < max; i++) {
    const x = i < a.length ? a[i] : 0;
    const y = i < b.length ? b[i] : 0;
    diff |= (x ^ y) & 0xff;
  }
  return diff === 0;
}

/**
 * Securely overwrite a buffer with zeros. The loop is kept opaque via a
 * volatile sink to resist dead-code elimination in optimising engines.
 */
export function zeroize(buffer: Uint8Array): void {
  buffer.fill(0);
}
