/**
 * LombokEncryptDecrypt — MD5 (RFC 1321). LEGACY.
 *
 * MD5 is broken for collision resistance. It is provided only to read and verify
 * legacy formats that require it (for example PDF standard security handler R2-R4,
 * ISO 32000-1 §7.6.3). Never use it for new signatures, passwords, or integrity checks.
 *
 * @module legacy/md5
 */

const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];

const T = new Uint32Array(64);
for (let i = 0; i < 64; i++) T[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;

function md5Bytes(data: Uint8Array): Uint8Array {
  const total = ((data.length + 8) >> 6) + 1;
  const buf = new Uint8Array(total * 64);
  buf.set(data);
  buf[data.length] = 0x80;
  const bits = data.length * 8;
  const lo = bits >>> 0;
  const hi = Math.floor(bits / 0x100000000) >>> 0;
  const end = buf.length - 8;
  for (let i = 0; i < 4; i++) { buf[end + i] = (lo >>> (8 * i)) & 0xff; buf[end + 4 + i] = (hi >>> (8 * i)) & 0xff; }

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);
  for (let off = 0; off < buf.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      M[i] = buf[off + i * 4]! | (buf[off + i * 4 + 1]! << 8) | (buf[off + i * 4 + 2]! << 16) | (buf[off + i * 4 + 3]! << 24);
    }
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f: number, g: number;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      const x = (a + f + T[i]! + M[g]!) >>> 0;
      a = d; d = c; c = b;
      b = (b + ((x << S[i]!) | (x >>> (32 - S[i]!)))) >>> 0;
    }
    a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0;
  }
  const out = new Uint8Array(16);
  [a0, b0, c0, d0].forEach((w, k) => { for (let i = 0; i < 4; i++) out[k * 4 + i] = (w >>> (8 * i)) & 0xff; });
  return out;
}

/** MD5 digest (16 bytes). Legacy formats only. */
export const md5 = {
  hashSync(data: Uint8Array): Uint8Array { return md5Bytes(data); },
  async hash(data: Uint8Array): Promise<Uint8Array> { return md5Bytes(data); },
};
