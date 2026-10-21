/**
 * LombokEncryptDecrypt — KeyStore v2 (password-protected key vault).
 *
 * Format: "LKS2" || ver(1) || N(4 BE) || r(1) || p(1) || salt(16) ||
 *         entries… || HMAC-SHA256(masterMac, everything before) (32)
 *
 * Key chain per IMPLEMENTATION_STATUS.md: scrypt(password) → masterKey,
 * HKDF(masterKey) → KEK per entry (random entry salt) → AES-256-GCM per
 * entry with AAD = id || alg, and an HMAC trailer over the whole blob.
 */

import { aesGcmDecrypt, aesGcmEncrypt } from '../modes/gcm.js';
import { hkdfDerive } from '../kdf/hkdf.js';
import { scryptDerive } from '../kdf/scrypt.js';
import { hmac, hmacSha256 } from '../mac/hmac.js';
import { ErrorCode, LombokCryptoError } from '../errors.js';
import {
  bytesToString,
  concatBytes,
  stringToBytes,
  timingSafeEqual,
  zeroize,
} from '../utils/encoding.js';
import { randomBytes } from '../utils/random.js';

const MAGIC = stringToBytes('LKS2');
const VERSION = 2;
const SALT_SIZE = 16;

export interface KeyStoreCreateOptions {
  password: string;
  /** scrypt memory cost (default 16384; OWASP floor 19456 recommended in production). */
  m?: number;
  /** scrypt block size (default 8). */
  r?: number;
  /** scrypt parallelisation (default 1). */
  p?: number;
}

interface Entry {
  id: string;
  alg: string;
  salt: Uint8Array;
  iv: Uint8Array;
  data: Uint8Array;
  tag: Uint8Array;
  expiresAt?: number;
}

function masterKeys(
  password: string,
  salt: Uint8Array,
  N: number,
  r: number,
  p: number,
): Promise<{ kek: Uint8Array; macKey: Uint8Array }> {
  return scryptDerive(password, salt, { N, r, p, dkLen: 32 }).then((master) =>
    Promise.all([
      hkdfDerive(master, {
        hash: 'SHA-256',
        salt: stringToBytes('LKS2-kek-v2'),
        info: salt,
        outputLength: 32,
      }),
      hkdfDerive(master, {
        hash: 'SHA-256',
        salt: stringToBytes('LKS2-mac-v2'),
        info: salt,
        outputLength: 32,
      }),
    ]).then(([kek, macKey]) => ({ kek, macKey })),
  );
}

function u16(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function u32(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

async function encryptEntry(
  kek: Uint8Array,
  entry: { id: string; alg: string; keyBytes: Uint8Array },
): Promise<Entry> {
  const salt = randomBytes(SALT_SIZE);
  const entryKey = await hkdfDerive(kek, {
    hash: 'SHA-256',
    salt,
    info: stringToBytes('LKS2-entry'),
    outputLength: 32,
  });
  const aad = concatBytes(stringToBytes(entry.id), stringToBytes(entry.alg));
  try {
    const { ciphertext, tag, iv } = await aesGcmEncrypt(entry.keyBytes, entryKey, { aad });
    return { id: entry.id, alg: entry.alg, salt, iv, data: ciphertext, tag };
  } finally {
    zeroize(entryKey);
  }
}

async function decryptEntry(kek: Uint8Array, entry: Entry): Promise<Uint8Array> {
  const entryKey = await hkdfDerive(kek, {
    hash: 'SHA-256',
    salt: entry.salt,
    info: stringToBytes('LKS2-entry'),
    outputLength: 32,
  });
  const aad = concatBytes(stringToBytes(entry.id), stringToBytes(entry.alg));
  try {
    return await aesGcmDecrypt(entry.data, entryKey, entry.iv, entry.tag, { aad });
  } catch {
    throw new LombokCryptoError(
      ErrorCode.KEYSTORE_CORRUPT,
      `entry "${entry.id}" failed authentication (wrong password or tampered blob)`,
      'KeyStore',
    );
  } finally {
    zeroize(entryKey);
  }
}

function headerBytes(meta: { N: number; r: number; p: number; salt: Uint8Array }): Uint8Array {
  return concatBytes(
    MAGIC,
    new Uint8Array([VERSION]),
    u32(meta.N),
    new Uint8Array([meta.r, meta.p]),
    meta.salt,
  );
}

function keySizeForAlg(alg: string): number {
  if (alg === 'AES-128-GCM') return 16;
  if (alg === 'AES-192-GCM') return 24;
  if (alg === 'AES-256-GCM' || alg === 'ChaCha20-Poly1305' || alg === 'XChaCha20-Poly1305')
    return 32;
  throw new LombokCryptoError(
    ErrorCode.UNSUPPORTED_ALGORITHM,
    `unsupported KeyStore algorithm ${alg}`,
    'KeyStore',
  );
}

/** Password-protected in-memory key vault with authenticated serialization. */
export class KeyStore {
  private readonly entries = new Map<string, Entry>();
  private locked = false;
  private readonly meta: { N: number; r: number; p: number; salt: Uint8Array };
  private kek?: Uint8Array;
  private macKey?: Uint8Array;

  private constructor(meta: KeyStoreCreateOptions & { salt: Uint8Array }) {
    this.meta = { N: meta.m ?? 16384, r: meta.r ?? 8, p: meta.p ?? 1, salt: meta.salt };
  }

  /** Create an empty vault with a fresh random salt. */
  public static async create(options: KeyStoreCreateOptions): Promise<KeyStore> {
    const store = new KeyStore({ ...options, salt: randomBytes(SALT_SIZE) });
    const keys = await masterKeys(
      options.password,
      store.meta.salt,
      store.meta.N,
      store.meta.r,
      store.meta.p,
    );
    store.kek = keys.kek;
    store.macKey = keys.macKey;
    return store;
  }

  /** Open a serialized vault. Throws KEYSTORE_CORRUPT on wrong password/tamper. */
  public static async open(blob: Uint8Array, options: { password: string }): Promise<KeyStore> {
    if (blob.length < MAGIC.length + 1 + 4 + 2 + SALT_SIZE + 32) {
      throw new LombokCryptoError(
        ErrorCode.KEYSTORE_CORRUPT,
        'KeyStore blob too short',
        'KeyStore',
      );
    }
    let offset = 0;
    const magic = blob.subarray(0, MAGIC.length);
    offset += MAGIC.length;
    if (!timingSafeEqual(magic, MAGIC)) {
      throw new LombokCryptoError(ErrorCode.KEYSTORE_CORRUPT, 'bad KeyStore magic', 'KeyStore');
    }
    const version = blob[offset++];
    if (version !== VERSION) {
      throw new LombokCryptoError(
        ErrorCode.KEYSTORE_CORRUPT,
        `unsupported KeyStore version ${version}`,
        'KeyStore',
      );
    }
    const N =
      (blob[offset] << 24) | (blob[offset + 1] << 16) | (blob[offset + 2] << 8) | blob[offset + 3];
    offset += 4;
    const r = blob[offset++];
    const p = blob[offset++];
    const salt = blob.subarray(offset, offset + SALT_SIZE);
    offset += SALT_SIZE;

    const body = blob.subarray(0, blob.length - 32);
    const trailer = blob.subarray(blob.length - 32);
    const keys = await masterKeys(options.password, salt, N, r, p);
    const expected = hmac.compute('SHA-256', keys.macKey, body);
    if (!timingSafeEqual(expected, trailer)) {
      throw new LombokCryptoError(
        ErrorCode.KEYSTORE_CORRUPT,
        'KeyStore HMAC verification failed (wrong password or tampered blob)',
        'KeyStore',
      );
    }

    const store = new KeyStore({
      password: options.password,
      m: N,
      r,
      p,
      salt: new Uint8Array(salt),
    });
    store.kek = keys.kek;
    store.macKey = keys.macKey;

    while (offset < body.length) {
      const idLen = (blob[offset] << 8) | blob[offset + 1];
      offset += 2;
      const id = bytesToString(blob.subarray(offset, offset + idLen));
      offset += idLen;
      const algLen = (blob[offset] << 8) | blob[offset + 1];
      offset += 2;
      const alg = bytesToString(blob.subarray(offset, offset + algLen));
      offset += algLen;
      const entrySalt = new Uint8Array(blob.subarray(offset, offset + SALT_SIZE));
      offset += SALT_SIZE;
      const iv = new Uint8Array(blob.subarray(offset, offset + 12));
      offset += 12;
      const dataLen =
        ((blob[offset] << 24) |
          (blob[offset + 1] << 16) |
          (blob[offset + 2] << 8) |
          blob[offset + 3]) >>>
        0;
      offset += 4;
      const data = new Uint8Array(blob.subarray(offset, offset + dataLen));
      offset += dataLen;
      const tag = new Uint8Array(blob.subarray(offset, offset + 16));
      offset += 16;
      const hasExp = blob[offset++];
      let expiresAt: number | undefined;
      if (hasExp === 1) {
        const secs =
          ((blob[offset] << 24) |
            (blob[offset + 1] << 16) |
            (blob[offset + 2] << 8) |
            blob[offset + 3]) >>>
          0;
        offset += 4;
        expiresAt = secs * 1000;
      }
      store.entries.set(id, { id, alg, salt: entrySalt, iv, data, tag, expiresAt });
    }
    return store;
  }

  private requireKeys(): { kek: Uint8Array; macKey: Uint8Array } {
    if (this.locked || this.kek === undefined || this.macKey === undefined) {
      throw new LombokCryptoError(ErrorCode.KEYSTORE_LOCKED, 'KeyStore is locked', 'KeyStore');
    }
    return { kek: this.kek, macKey: this.macKey };
  }

  /** Store key bytes under an id (overwrites existing). Optional TTL in ms. */
  public async set(
    id: string,
    keyBytes: Uint8Array,
    alg: string,
    options?: { ttlMs?: number },
  ): Promise<void> {
    const { kek } = this.requireKeys();
    keySizeForAlg(alg); // validate algorithm
    if (keyBytes.length !== keySizeForAlg(alg)) {
      throw new LombokCryptoError(
        ErrorCode.INVALID_KEY_SIZE,
        `key must be ${keySizeForAlg(alg)} bytes for ${alg}, got ${keyBytes.length}`,
        'KeyStore',
      );
    }
    const entry = await encryptEntry(kek, { id, alg, keyBytes });
    if (options?.ttlMs !== undefined) {
      entry.expiresAt = Date.now() + options.ttlMs;
    }
    this.entries.set(id, entry);
  }

  /** Decrypt and return the stored key. Throws KEY_NOT_FOUND / KEY_EXPIRED. */
  public async get(id: string): Promise<Uint8Array> {
    const { kek } = this.requireKeys();
    const entry = this.entries.get(id);
    if (entry === undefined) {
      throw new LombokCryptoError(ErrorCode.KEY_NOT_FOUND, `no key with id "${id}"`, 'KeyStore');
    }
    if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      throw new LombokCryptoError(ErrorCode.KEY_EXPIRED, `key "${id}" expired`, 'KeyStore');
    }
    return decryptEntry(kek, entry);
  }

  /** Generate a random key for the algorithm and store it. */
  public async generateKey(
    id: string,
    alg: string,
    options?: { ttlMs?: number },
  ): Promise<Uint8Array> {
    const keyBytes = randomBytes(keySizeForAlg(alg));
    await this.set(id, keyBytes, alg, options);
    return keyBytes;
  }

  /** All stored key ids. */
  public list(): string[] {
    return Array.from(this.entries.keys());
  }

  /** Delete an entry (no-op when absent). */
  public delete(id: string): void {
    this.entries.delete(id);
  }

  /** Serialize with an HMAC trailer. */
  public async serialize(): Promise<Uint8Array> {
    const { macKey } = this.requireKeys();
    const parts: Uint8Array[] = [headerBytes(this.meta)];
    for (const entry of this.entries.values()) {
      const idBytes = stringToBytes(entry.id);
      const algBytes = stringToBytes(entry.alg);
      const hasExp = entry.expiresAt !== undefined;
      const expBytes = hasExp
        ? u32(Math.floor((entry.expiresAt as number) / 1000))
        : new Uint8Array(0);
      parts.push(
        concatBytes(
          u16(idBytes.length),
          idBytes,
          u16(algBytes.length),
          algBytes,
          entry.salt,
          entry.iv,
          u32(entry.data.length),
          entry.data,
          entry.tag,
          new Uint8Array([hasExp ? 1 : 0]),
          expBytes,
        ),
      );
    }
    const body = concatBytes(...parts);
    return concatBytes(body, hmac.compute('SHA-256', macKey, body));
  }

  /** Zeroize derived keys and block further access. */
  public lock(): void {
    if (this.kek !== undefined) zeroize(this.kek);
    if (this.macKey !== undefined) zeroize(this.macKey);
    this.kek = undefined;
    this.macKey = undefined;
    this.locked = true;
  }

  /** Unlock after lock() with the same password. */
  public async unlock(password: string): Promise<void> {
    if (!this.locked) return;
    const keys = await masterKeys(password, this.meta.salt, this.meta.N, this.meta.r, this.meta.p);
    this.kek = keys.kek;
    this.macKey = keys.macKey;
    this.locked = false;
  }

  /** HMAC-SHA256 handle (exposed for tests). */
  public static readonly hmacSha256 = hmacSha256;
}
