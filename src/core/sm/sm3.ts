/**
 * LombokEncryptDecrypt — SM3 Hash Function
 * Chinese national standard GM/T 0004-2012
 * Output: 256-bit
 * @module core/sm/sm3
 */

const T_j = (j: number): number =>
  j < 16 ? 0x79cc4519 : 0x7a879d8a;

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function FF(x: number, y: number, z: number, j: number): number {
  return j < 16 ? (x ^ y ^ z) >>> 0 : ((x & y) | (x & z) | (y & z)) >>> 0;
}

function GG(x: number, y: number, z: number, j: number): number {
  return j < 16 ? (x ^ y ^ z) >>> 0 : ((x & y) | (~x & z)) >>> 0;
}

function P0(x: number): number { return (x ^ rotl(x, 9) ^ rotl(x, 17)) >>> 0; }
function P1(x: number): number { return (x ^ rotl(x, 15) ^ rotl(x, 23)) >>> 0; }

const IV = new Uint32Array([
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
]);

function sm3Compress(H: Uint32Array, block: Uint8Array): void {
  const W = new Uint32Array(68);
  const W2 = new Uint32Array(64);

  for (let i = 0; i < 16; i++) {
    W[i] = ((block[i*4]!<<24)|(block[i*4+1]!<<16)|(block[i*4+2]!<<8)|block[i*4+3]!) >>> 0;
  }
  for (let i = 16; i < 68; i++) {
    W[i] = (P1(W[i-16]!^W[i-9]!^rotl(W[i-3]!,15)) ^ rotl(W[i-13]!,7) ^ W[i-6]!) >>> 0;
  }
  for (let i = 0; i < 64; i++) W2[i] = (W[i]! ^ W[i+4]!) >>> 0;

  let [A,B,C,D,E,F,G,HH] = [...H];
  for (let j = 0; j < 64; j++) {
    const SS1 = rotl((rotl(A!,12) + E! + rotl(T_j(j), j%32)) >>> 0, 7);
    const SS2 = (SS1 ^ rotl(A!,12)) >>> 0;
    const TT1 = (FF(A!,B!,C!,j) + D! + SS2 + W2[j]!) >>> 0;
    const TT2 = (GG(E!,F!,G!,j) + HH! + SS1 + W[j]!) >>> 0;
    D=C!; C=rotl(B!,9); B=A!; A=TT1;
    HH=G!; G=rotl(F!,19); F=E!; E=P0(TT2);
  }
  H[0]=(A!^H[0]!)>>>0; H[1]=(B!^H[1]!)>>>0; H[2]=(C!^H[2]!)>>>0; H[3]=(D!^H[3]!)>>>0;
  H[4]=(E!^H[4]!)>>>0; H[5]=(F!^H[5]!)>>>0; H[6]=(G!^H[6]!)>>>0; H[7]=(HH!^H[7]!)>>>0;
}

function sm3Raw(data: Uint8Array): Uint8Array {
  const H = new Uint32Array(IV);
  const bitLen = BigInt(data.length * 8);
  const padded = new Uint8Array(Math.ceil((data.length + 9) / 64) * 64);
  padded.set(data);
  padded[data.length] = 0x80;
  for (let i = 0; i < 8; i++) padded[padded.length-1-i] = Number((bitLen >> BigInt(i*8)) & 0xFFn);
  for (let i = 0; i < padded.length; i += 64) sm3Compress(H, padded.subarray(i, i+64));
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i*4]=H[i]!>>>24; out[i*4+1]=(H[i]!>>>16)&0xFF; out[i*4+2]=(H[i]!>>>8)&0xFF; out[i*4+3]=H[i]!&0xFF;
  }
  return out;
}

export const sm3 = {
  /** SM3 hash (GM/T 0004). Input: any bytes. Output: 32 bytes. */
  hash(data: Uint8Array): Uint8Array { return sm3Raw(data); },
  async hashAsync(data: Uint8Array): Promise<Uint8Array> { return sm3Raw(data); },
  OUTPUT_SIZE: 32,
};
