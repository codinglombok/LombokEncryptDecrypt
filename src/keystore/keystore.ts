/**
 * LombokEncryptDecrypt — KeyStore
 *
 * Encrypted persistent key store.
 * Master password → Argon2id → master key → AES-256-GCM per entry.
 *
 * File format (binary):
 *   MAGIC(4) | VERSION(1) | SALT(16) | ARGON2_PARAMS(12) |
 *   ENTRY_COUNT(4) | [ ENTRY_ID_LEN(2) | ENTRY_ID | ENCRYPTED_KEY ]* |
 *   HMAC-SHA256 of all above (32 bytes)
 *
 * @module keystore/keystore
 */

import { LombokCryptoError, ErrorCode } from '../../errors.js';
import { aesGcm } from '../../modes/gcm.js';
import { argon2id } from '../../kdf/argon2.js';
import { hmacSha256 } from '../../mac/hmac.js';
import { randomSalt, randomKey256 } from '../../utils/random.js';
import { stringToBytes, concatBytes } from '../../utils/encoding.js';

const KEYSTORE_MAGIC   = new Uint8Array([0x4C, 0x4B, 0x53, 0x54]); // 'LKST'
const KEYSTORE_VERSION = 1;

interface KeyEntry {
  id: string;
  key: Uint8Array;
  algorithm: string;
  created: number;
  expires?: number;
}

export interface KeyStoreOptions {
  /** Password to derive master key */
  readonly password: string;
  /** Argon2id memory cost (KiB). Default: 65536 */
  readonly m?: number;
  /** Argon2id time cost. Default: 3 */
  readonly t?: number;
  /** Argon2id parallelism. Default: 4 */
  readonly p?: number;
}

export class KeyStore {
  private masterKey: Uint8Array | null = null;
  private entries: Map<string, KeyEntry> = new Map();
  private salt: Uint8Array;
  private readonly options: Required<KeyStoreOptions>;

  private constructor(salt: Uint8Array, options: Required<KeyStoreOptions>) {
    this.salt = salt;
    this.options = options;
  }

  /** Create a new empty KeyStore */
  static async create(options: KeyStoreOptions): Promise<KeyStore> {
    const salt = randomSalt(16);
    const store = new KeyStore(salt, {
      password: options.password,
      m: options.m ?? 65536,
      t: options.t ?? 3,
      p: options.p ?? 4,
    });
    await store.unlock(options.password);
    return store;
  }

  /** Open an existing KeyStore from serialized bytes */
  static async open(serialized: Uint8Array, options: KeyStoreOptions): Promise<KeyStore> {
    const salt = serialized.slice(5, 21); // After MAGIC(4) + VERSION(1)
    const store = new KeyStore(salt, {
      password: options.password,
      m: options.m ?? 65536,
      t: options.t ?? 3,
      p: options.p ?? 4,
    });
    await store.unlock(options.password);
    await store.deserialize(serialized);
    return store;
  }

  /** Unlock the keystore by deriving the master key from the password */
  private async unlock(password: string): Promise<void> {
    this.masterKey = await argon2id.raw(
      stringToBytes(password),
      this.salt,
      { m: this.options.m, t: this.options.t, p: this.options.p, hashLength: 32 },
    );
  }

  private ensureUnlocked(): Uint8Array {
    if (!this.masterKey) {
      throw new LombokCryptoError(ErrorCode.KEYSTORE_LOCKED, 'KeyStore is locked');
    }
    return this.masterKey;
  }

  /** Store a key in the KeyStore */
  async set(id: string, key: Uint8Array, algorithm = 'AES-256-GCM', expiresIn?: number): Promise<void> {
    const mk = this.ensureUnlocked();
    const entry: KeyEntry = {
      id,
      key: new Uint8Array(key), // copy
      algorithm,
      created: Date.now(),
      expires: expiresIn ? Date.now() + expiresIn : undefined,
    };
    this.entries.set(id, entry);
  }

  /** Retrieve a key from the KeyStore */
  async get(id: string): Promise<Uint8Array> {
    this.ensureUnlocked();
    const entry = this.entries.get(id);
    if (!entry) {
      throw new LombokCryptoError(ErrorCode.KEY_NOT_FOUND, `Key '${id}' not found in KeyStore`);
    }
    if (entry.expires && Date.now() > entry.expires) {
      throw new LombokCryptoError(ErrorCode.KEY_EXPIRED, `Key '${id}' has expired`);
    }
    return new Uint8Array(entry.key);
  }

  /** Delete a key from the KeyStore */
  delete(id: string): boolean {
    const entry = this.entries.get(id);
    if (entry) entry.key.fill(0); // zero out key material
    return this.entries.delete(id);
  }

  /** List all key IDs */
  list(): string[] {
    return Array.from(this.entries.keys());
  }

  /** Generate and store a new random key */
  async generateKey(id: string, algorithm = 'AES-256-GCM'): Promise<Uint8Array> {
    const key = randomKey256();
    await this.set(id, key, algorithm);
    return key;
  }

  /** Serialize the KeyStore to bytes (encrypted) */
  async serialize(): Promise<Uint8Array> {
    const mk = this.ensureUnlocked();
    const parts: Uint8Array[] = [];

    // Header
    parts.push(KEYSTORE_MAGIC);
    parts.push(new Uint8Array([KEYSTORE_VERSION]));
    parts.push(this.salt);

    // Argon2id params (12 bytes)
    const params = new Uint8Array(12);
    const m = this.options.m;
    const t = this.options.t;
    const p = this.options.p;
    params[0] = (m >>> 24) & 0xFF; params[1] = (m >>> 16) & 0xFF;
    params[2] = (m >>> 8) & 0xFF;  params[3] = m & 0xFF;
    params[4] = t; params[8] = p;
    parts.push(params);

    // Entry count (4 bytes)
    const count = new Uint8Array(4);
    count[3] = this.entries.size & 0xFF;
    parts.push(count);

    // Entries (encrypted individually)
    for (const [id, entry] of this.entries) {
      const idBytes = stringToBytes(id);
      const idLen   = new Uint8Array([idBytes.length >>> 8, idBytes.length & 0xFF]);

      // Encrypt key entry with master key
      const payload = new TextEncoder().encode(JSON.stringify({
        algorithm: entry.algorithm,
        created: entry.created,
        expires: entry.expires,
        key: Array.from(entry.key),
      }));
      const { ciphertext, tag, iv } = await aesGcm.encrypt(payload, mk, { aad: idBytes });
      const encEntry = concatBytes(iv, tag, ciphertext);
      const encLen   = new Uint8Array(4);
      encLen[3] = encEntry.length & 0xFF; encLen[2] = (encEntry.length >>> 8) & 0xFF;

      parts.push(idLen, idBytes, encLen, encEntry);
    }

    const body = concatBytes(...parts);

    // HMAC-SHA256 of entire body
    const mac = await hmacSha256.compute(mk, body);
    return concatBytes(body, mac);
  }

  private async deserialize(data: Uint8Array): Promise<void> {
    const mk = this.ensureUnlocked();

    // Verify HMAC first
    const mac      = data.slice(data.length - 32);
    const body     = data.slice(0, data.length - 32);
    const valid    = await hmacSha256.verify(mk, body, mac);
    if (!valid) {
      throw new LombokCryptoError(ErrorCode.KEYSTORE_CORRUPT, 'KeyStore integrity check failed — wrong password or tampered data');
    }

    // Parse entries (simplified — full parser in production)
    let offset = 4 + 1 + 16 + 12; // magic + version + salt + params
    const entryCount = (body[offset + 3] ?? 0);
    offset += 4;

    for (let i = 0; i < entryCount; i++) {
      const idLen = ((body[offset] ?? 0) << 8) | (body[offset + 1] ?? 0);
      offset += 2;
      const idBytes = body.slice(offset, offset + idLen);
      const id = new TextDecoder().decode(idBytes);
      offset += idLen;
      const encLen = ((body[offset + 2] ?? 0) << 8) | (body[offset + 3] ?? 0);
      offset += 4;
      const encEntry = body.slice(offset, offset + encLen);
      offset += encLen;

      const iv  = encEntry.slice(0, 12);
      const tag = encEntry.slice(12, 28);
      const ct  = encEntry.slice(28);
      const payload = await aesGcm.decrypt(ct, mk, iv, tag, { aad: idBytes });
      const parsed  = JSON.parse(new TextDecoder().decode(payload)) as {
        algorithm: string; created: number; expires?: number; key: number[];
      };

      this.entries.set(id, {
        id,
        key: new Uint8Array(parsed.key),
        algorithm: parsed.algorithm,
        created: parsed.created,
        expires: parsed.expires,
      });
    }
  }

  /** Securely zero all key material and lock the store */
  lock(): void {
    for (const entry of this.entries.values()) {
      entry.key.fill(0);
    }
    this.masterKey?.fill(0);
    this.masterKey = null;
    this.entries.clear();
  }
}
