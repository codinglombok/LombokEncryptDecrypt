/**
 * LombokEncryptDecrypt — SHA-3 (FIPS 202) & SHAKE, pure TypeScript.
 *
 * Keccak-f[1600] implemented over BigInt lanes. The 24 round constants are
 * generated from the FIPS 202 LFSR (x^8+x^6+x^5+x^4+1) and the rho offsets
 * from the standard (t+1)(t+2)/2 walk, so no constant table is transcribed.
 * Verified against the FIPS 202 "abc" examples and cross-checked with
 * node:crypto on random inputs during development.
 */

const M64 = (1n << 64n) - 1n;

function lfsrRc(t: number): number {
  const tt = t % 255;
  if (tt === 0) return 1;
  let r = 1;
  for (let i = 1; i <= tt; i++) {
    r = ((r << 1) & 0xff) ^ ((r & 0x80) !== 0 ? 0x71 : 0);
  }
  return r & 1;
}

/** The 24 Keccak round constants, derived from the FIPS 202 LFSR. */
const ROUND_CONSTANTS: bigint[] = (() => {
  const constants: bigint[] = [];
  for (let round = 0; round < 24; round++) {
    let rc = 0n;
    for (let j = 0; j < 7; j++) {
      const bit = lfsrRc(j + 7 * round);
      if (bit === 1) rc |= 1n << BigInt((1 << j) - 1);
    }
    constants.push(rc & M64);
  }
  return constants;
})();

/** rho rotation offsets, derived from the FIPS 202 (t+1)(t+2)/2 walk. */
const RHO_OFFSETS: number[][] = (() => {
  const offsets: number[][] = [
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
  ];
  let x = 1;
  let y = 0;
  for (let t = 0; t < 24; t++) {
    offsets[x][y] = (((t + 1) * (t + 2)) / 2) % 64;
    const nx = y;
    const ny = (2 * x + 3 * y) % 5;
    x = nx;
    y = ny;
  }
  return offsets;
})();

function keccakF1600(state: bigint[]): void {
  for (let round = 0; round < 24; round++) {
    // θ
    const c = new Array<bigint>(5).fill(0n);
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    const d = new Array<bigint>(5).fill(0n);
    for (let x = 0; x < 5; x++) {
      const cx = c[(x + 1) % 5];
      const rotated = ((cx << 1n) | (cx >> 63n)) & M64;
      d[x] = c[(x + 4) % 5] ^ rotated;
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] = (state[x + 5 * y] ^ d[x]) & M64;
      }
    }
    // ρ and π
    const b = new Array<bigint>(25).fill(0n);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const r = BigInt(RHO_OFFSETS[x][y]);
        const v = state[x + 5 * y];
        const rotated = r === 0n ? v : ((v << r) | (v >> (64n - r))) & M64;
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotated;
      }
    }
    // χ
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] =
          b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & b[((x + 2) % 5) + 5 * y] & M64);
      }
    }
    // ι
    state[0] = (state[0] ^ ROUND_CONSTANTS[round]) & M64;
  }
}

function laneFromBytes(block: Uint8Array, offset: number): bigint {
  let lane = 0n;
  for (let j = 7; j >= 0; j--) {
    lane = (lane << 8n) | BigInt(block[offset + j]);
  }
  return lane;
}

function laneToBytes(lane: bigint, out: Uint8Array, offset: number): void {
  let v = lane;
  for (let j = 0; j < 8; j++) {
    out[offset + j] = Number(v & 0xffn);
    v >>= 8n;
  }
}

/**
 * Keccak sponge. `rate` is in bytes; `padByte` is the domain byte
 * (0x06 for SHA-3, 0x1F for SHAKE) — the trailing bit is applied to the last
 * block byte per the multi-rate pad10*1 rule.
 */
class KeccakSponge {
  private readonly state: bigint[] = new Array<bigint>(25).fill(0n);
  private readonly buf = new Uint8Array(200);
  private readonly scratch = new Uint8Array(200);
  private bufLen = 0;
  private readonly rate: number;
  private readonly padByte: number;

  public constructor(rate: number, padByte: number) {
    this.rate = rate;
    this.padByte = padByte;
  }

  public absorb(data: Uint8Array): void {
    let offset = 0;
    while (offset < data.length) {
      const take = Math.min(this.rate - this.bufLen, data.length - offset);
      this.buf.set(data.subarray(offset, offset + take), this.bufLen);
      this.bufLen += take;
      offset += take;
      if (this.bufLen === this.rate) this.absorbBlock(false);
    }
  }

  public squeeze(output: Uint8Array): void {
    let produced = 0;
    // first squeeze from the freshly padded state
    this.absorbBlock(true);
    while (produced < output.length) {
      const take = Math.min(this.rate, output.length - produced);
      for (let lane = 0; lane < this.rate / 8; lane++) {
        laneToBytes(this.state[lane], this.scratch, lane * 8);
      }
      output.set(this.scratch.subarray(0, take), produced);
      produced += take;
      if (produced < output.length) keccakF1600(this.state);
    }
  }

  private absorbBlock(final: boolean): void {
    if (final) {
      // zero stale tail bytes, then apply the multi-rate pad10*1 rule
      this.buf.fill(0, this.bufLen, this.rate);
      if (this.bufLen === this.rate - 1) {
        this.buf[this.bufLen] = this.padByte | 0x80;
      } else {
        this.buf[this.bufLen] = this.padByte;
        this.buf[this.rate - 1] |= 0x80;
      }
    }
    for (let lane = 0; lane < this.rate / 8; lane++) {
      this.state[lane] = (this.state[lane] ^ laneFromBytes(this.buf, lane * 8)) & M64;
    }
    keccakF1600(this.state);
    this.bufLen = 0;
  }
}

function sha3Sponge(rate: number, data: Uint8Array, outputLength: number): Uint8Array {
  const sponge = new KeccakSponge(rate, 0x06);
  sponge.absorb(data);
  const out = new Uint8Array(outputLength);
  sponge.squeeze(out);
  return out;
}

function shakeSponge(rate: number, data: Uint8Array, outputLength: number): Uint8Array {
  const sponge = new KeccakSponge(rate, 0x1f);
  sponge.absorb(data);
  const out = new Uint8Array(outputLength);
  sponge.squeeze(out);
  return out;
}

/** SHA3-224 — 28-byte digest. */
export function sha3_224Raw(data: Uint8Array): Uint8Array {
  return sha3Sponge(144, data, 28);
}

/** SHA3-256 — 32-byte digest. */
export function sha3_256Raw(data: Uint8Array): Uint8Array {
  return sha3Sponge(136, data, 32);
}

/** SHA3-384 — 48-byte digest. */
export function sha3_384Raw(data: Uint8Array): Uint8Array {
  return sha3Sponge(104, data, 48);
}

/** SHA3-512 — 64-byte digest. */
export function sha3_512Raw(data: Uint8Array): Uint8Array {
  return sha3Sponge(72, data, 64);
}

/** SHAKE128 — variable-length XOF output. */
export function shake128Raw(data: Uint8Array, outputLength: number): Uint8Array {
  return shakeSponge(168, data, outputLength);
}

/** SHAKE256 — variable-length XOF output. */
export function shake256Raw(data: Uint8Array, outputLength: number): Uint8Array {
  return shakeSponge(136, data, outputLength);
}

// ── Public async hash objects ────────────────────────────────────────────────

async function dig(fn: (data: Uint8Array) => Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  return fn(data);
}

/** SHA3-224. */
export const sha3_224 = {
  async hash(data: Uint8Array): Promise<Uint8Array> {
    return dig(sha3_224Raw, data);
  },
};

/** SHA3-256. */
export const sha3_256 = {
  async hash(data: Uint8Array): Promise<Uint8Array> {
    return dig(sha3_256Raw, data);
  },
};

/** SHA3-384. */
export const sha3_384 = {
  async hash(data: Uint8Array): Promise<Uint8Array> {
    return dig(sha3_384Raw, data);
  },
};

/** SHA3-512. */
export const sha3_512 = {
  async hash(data: Uint8Array): Promise<Uint8Array> {
    return dig(sha3_512Raw, data);
  },
};

/** SHAKE128 XOF — output length is caller-chosen. */
export const shake128 = {
  async hash(data: Uint8Array, outputLength: number): Promise<Uint8Array> {
    if (!Number.isInteger(outputLength) || outputLength < 1)
      throw new RangeError(`SHAKE128 outputLength must be a positive integer, got ${outputLength}`);
    return dig((d: Uint8Array) => shake128Raw(d, outputLength), data);
  },
};

/** SHAKE256 XOF — output length is caller-chosen. */
export const shake256 = {
  async hash(data: Uint8Array, outputLength: number): Promise<Uint8Array> {
    if (!Number.isInteger(outputLength) || outputLength < 1)
      throw new RangeError(`SHAKE256 outputLength must be a positive integer, got ${outputLength}`);
    return dig((d: Uint8Array) => shake256Raw(d, outputLength), data);
  },
};
