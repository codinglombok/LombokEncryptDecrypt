/**
 * LombokEncryptDecrypt — KeyStore
 *
 * Encrypted, serializable key store.
 *   password --scrypt--> master key --HKDF--> encKey (AES-256-GCM) + macKey (HMAC-SHA256)
 *
 * Binary format v2 (integers big-endian):
 *   "LKST"(4) | version=2 (1) | kdf=1 scrypt (1) | log2N (1) | r (4) | p (4) | salt (16)
 *   | entryCount (4) | { idLen (2) | id | encLen (4) | iv(12) tag(16) ciphertext }*
 *   | HMAC-SHA256 over everything above (32)
 *
 * The header (including KDF parameters) is covered by the HMAC and by each entry's
 * AAD, and KDF parameters read from a file are bounded before use so a hostile file
 * cannot request unbounded memory.
 *
 * @module keystore/keystore
 */

import { LombokCryptoError, ErrorCode } from '../errors.js';
import { aesGcm } from '../modes/gcm.js';
import { scrypt } from '../kdf/scrypt.js';
import { hkdf } from '../kdf/hkdf.js';
import { hmacSha256 } from '../mac/hmac.js';
import { randomSalt, randomKey256 } from '../utils/random.js';
import { stringToBytes, concatBytes } from '../utils/encoding.js';

const MAGIC = new Uint8Array([0x4C, 0x4B, 0x53, 0x54]); // 'LKST'
const VERSION = 2;
const KDF_SCRYPT = 1;
const HEADER_LEN = 4 + 1 + 1 + 1 + 4 + 4 + 16 + 4;
const MAC_LEN = 32;
const MAX_LOG2_N = 22;
const MAX_R = 32;
const MAX_P = 16;
const MAX_ENTRIES = 1_000_000;

interface KeyEntry {
  id: string;
  key: Uint8Array;
  algorithm: string;
  created: number;
  expires?: number | undefined;
}

export interface KeyStoreOptions {
  /** Password used to derive the master key */
  readonly password: string;
  /** scrypt cost N (power of two). Default 2^17 (OWASP 2024 minimum for scrypt). */
  readonly N?: number;
  /** scrypt block size. Default 8. */
  readonly r?: number;
  /** scrypt parallelism. Default 1. */
  readonly p?: number;
}

interface KdfParams { N: number; r: number; p: number }

const enc = new TextEncoder();
const dec = new TextDecoder();

function u32(value: number): Uint8Array {
  return new Uint8Array([(value >>> 24) & 0xFF, (value >>> 16) & 0xFF, (value >>> 8) & 0xFF, value & 0xFF]);
}
function rd32(buf: Uint8Array, off: number): number {
  return (((buf[off]!) << 24) | ((buf[off + 1]!) << 16) | ((buf[off + 2]!) << 8) | (buf[off + 3]!)) >>> 0;
}

function checkParams({ N, r, p }: KdfParams): void {
  const log2N = Math.log2(N);
  if (!Number.isInteger(log2N) || log2N < 1 || log2N > MAX_LOG2_N ||
      !Number.isInteger(r) || r < 1 || r > MAX_R ||
      !Number.isInteger(p) || p < 1 || p > MAX_P) {
    throw new LombokCryptoError(ErrorCode.INVALID_PARAMETER, 'Invalid or out-of-range scrypt parameters');
  }
}

function corrupt(message: string): LombokCryptoError {
  return new LombokCryptoError(ErrorCode.KEYSTORE_CORRUPT, message);
}

export class KeyStore {
  private keys: { enc: Uint8Array; mac: Uint8Array } | null = null;
  private entries = new Map<string, KeyEntry>();

  private constructor(private readonly salt: Uint8Array, private readonly params: KdfParams) {}

  private async unlock(password: string): Promise<void> {
    const master = await scrypt.derive(password, { ...this.params, salt: this.salt, dkLen: 32 });
    const info = (label: string) => enc.encode(`lombokencryptdecrypt/keystore/v2/${label}`);
    this.keys = {
      enc: await hkdf.sha256(master, this.salt, info('enc'), 32),
      mac: await hkdf.sha256(master, this.salt, info('mac'), 32),
    };
    master.fill(0);
  }

  /** Create a new empty KeyStore */
  static async create(options: KeyStoreOptions): Promise<KeyStore> {
    const params: KdfParams = { N: options.N ?? 2 ** 17, r: options.r ?? 8, p: options.p ?? 1 };
    checkParams(params);
    const store = new KeyStore(randomSalt(16), params);
    await store.unlock(options.password);
    return store;
  }

  /** Open a serialized KeyStore. KDF parameters come from the file (bounded). */
  static async open(serialized: Uint8Array, options: KeyStoreOptions): Promise<KeyStore> {
    if (serialized.length < HEADER_LEN + MAC_LEN) throw corrupt('KeyStore data too short');
    for (let i = 0; i < 4; i++) if (serialized[i] !== MAGIC[i]) throw corrupt('Not a KeyStore file');
    if (serialized[4] !== VERSION || serialized[5] !== KDF_SCRYPT) throw corrupt('Unsupported KeyStore version or KDF');
    const params: KdfParams = { N: 2 ** serialized[6]!, r: rd32(serialized, 7), p: rd32(serialized, 11) };
    try { checkParams(params); } catch { throw corrupt('KeyStore KDF parameters out of range'); }

    const store = new KeyStore(serialized.slice(15, 31), params);
    await store.unlock(options.password);
    await store.load(serialized);
    return store;
  }

  private ensureUnlocked(): { enc: Uint8Array; mac: Uint8Array } {
    if (!this.keys) throw new LombokCryptoError(ErrorCode.KEYSTORE_LOCKED, 'KeyStore is locked');
    return this.keys;
  }

  /** Store a key */
  async set(id: string, key: Uint8Array, algorithm = 'AES-256-GCM', expiresIn?: number): Promise<void> {
    this.ensureUnlocked();
    this.entries.set(id, {
      id,
      key: new Uint8Array(key),
      algorithm,
      created: Date.now(),
      expires: expiresIn ? Date.now() + expiresIn : undefined,
    });
  }

  /** Retrieve a key (returns a copy) */
  async get(id: string): Promise<Uint8Array> {
    this.ensureUnlocked();
    const entry = this.entries.get(id);
    if (!entry) throw new LombokCryptoError(ErrorCode.KEY_NOT_FOUND, `Key '${id}' not found in KeyStore`);
    if (entry.expires && Date.now() > entry.expires) {
      throw new LombokCryptoError(ErrorCode.KEY_EXPIRED, `Key '${id}' has expired`);
    }
    return new Uint8Array(entry.key);
  }

  /** Delete a key and zero its material */
  delete(id: string): boolean {
    const entry = this.entries.get(id);
    if (entry) entry.key.fill(0);
    return this.entries.delete(id);
  }

  list(): string[] {
    return Array.from(this.entries.keys());
  }

  /** Generate and store a new random 256-bit key */
  async generateKey(id: string, algorithm = 'AES-256-GCM'): Promise<Uint8Array> {
    const key = randomKey256();
    await this.set(id, key, algorithm);
    return key;
  }

  private header(): Uint8Array {
    const log2N = Math.log2(this.params.N);
    return concatBytes(
      MAGIC, new Uint8Array([VERSION, KDF_SCRYPT, log2N]),
      u32(this.params.r), u32(this.params.p), this.salt, u32(this.entries.size),
    );
  }

  /** Serialize to encrypted, integrity-protected bytes */
  async serialize(): Promise<Uint8Array> {
    const k = this.ensureUnlocked();
    const header = this.header();
    const parts: Uint8Array[] = [header];

    for (const [id, entry] of this.entries) {
      const idBytes = stringToBytes(id);
      if (idBytes.length > 0xFFFF) throw new LombokCryptoError(ErrorCode.INVALID_INPUT, 'Key id too long');
      const payload = enc.encode(JSON.stringify({
        algorithm: entry.algorithm,
        created: entry.created,
        expires: entry.expires ?? null,
        key: Array.from(entry.key),
      }));
      const { ciphertext, tag, iv } = await aesGcm.encrypt(payload, k.enc, { aad: concatBytes(header.slice(0, HEADER_LEN - 4), idBytes) });
      const blob = concatBytes(iv, tag, ciphertext);
      parts.push(new Uint8Array([idBytes.length >>> 8, idBytes.length & 0xFF]), idBytes, u32(blob.length), blob);
    }

    const body = concatBytes(...parts);
    return concatBytes(body, await hmacSha256.compute(k.mac, body));
  }

  private async load(data: Uint8Array): Promise<void> {
    const k = this.ensureUnlocked();
    const body = data.slice(0, data.length - MAC_LEN);
    const mac = data.slice(data.length - MAC_LEN);
    if (!(await hmacSha256.verify(k.mac, body, mac))) {
      throw corrupt('KeyStore integrity check failed: wrong password or tampered data');
    }

    const count = rd32(body, HEADER_LEN - 4);
    if (count > MAX_ENTRIES) throw corrupt('KeyStore entry count out of range');
    const aadHeader = body.slice(0, HEADER_LEN - 4);
    let off = HEADER_LEN;

    for (let i = 0; i < count; i++) {
      if (off + 2 > body.length) throw corrupt('KeyStore truncated');
      const idLen = (body[off]! << 8) | body[off + 1]!;
      off += 2;
      if (off + idLen + 4 > body.length) throw corrupt('KeyStore truncated');
      const idBytes = body.slice(off, off + idLen);
      off += idLen;
      const blobLen = rd32(body, off);
      off += 4;
      if (blobLen < 28 || off + blobLen > body.length) throw corrupt('KeyStore truncated');
      const blob = body.slice(off, off + blobLen);
      off += blobLen;

      const payload = await aesGcm.decrypt(
        blob.slice(28), k.enc, blob.slice(0, 12), blob.slice(12, 28),
        { aad: concatBytes(aadHeader, idBytes) },
      );
      const parsed = JSON.parse(dec.decode(payload)) as {
        algorithm: string; created: number; expires: number | null; key: number[];
      };
      const id = dec.decode(idBytes);
      this.entries.set(id, {
        id,
        key: new Uint8Array(parsed.key),
        algorithm: parsed.algorithm,
        created: parsed.created,
        expires: parsed.expires ?? undefined,
      });
    }
    if (off !== body.length) throw corrupt('KeyStore has trailing data');
  }

  /** Zero all key material and lock the store */
  lock(): void {
    for (const entry of this.entries.values()) entry.key.fill(0);
    this.keys?.enc.fill(0);
    this.keys?.mac.fill(0);
    this.keys = null;
    this.entries.clear();
  }
}
