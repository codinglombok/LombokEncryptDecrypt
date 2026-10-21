/**
 * LombokEncryptDecrypt — AuditLogger (v0.1.0: no Reed-Solomon parity yet).
 *
 * Block format: MAGIC("LEDL") || VERSION(1) || BLOCK_LEN(2 BE) ||
 *               TIMESTAMP(8 BE, ms) || PAYLOAD(UTF-8 JSON)
 * The log is append-only; readers verify structure and reject corruption
 * with INTEGRITY_CHECK_FAILED.
 */

import { ErrorCode, LombokCryptoError } from '../errors.js';
import { bytesToString, stringToBytes } from '../utils/encoding.js';
import { getPlatformLabel } from '../platform/index.js';

const MAGIC = stringToBytes('LEDL');
const AUDIT_VERSION = 1;
const HEADER_SIZE = MAGIC.length + 1 + 2 + 8;

export interface AuditEntry {
  /** Epoch milliseconds. */
  timestamp: number;
  operation: string;
  algorithm: string;
  keyId?: string;
  inputLength: number;
  outputLength: number;
  success: boolean;
  platform: string;
}

export interface AuditInput {
  operation: string;
  algorithm: string;
  keyId?: string;
  inputLength: number;
  outputLength: number;
  success: boolean;
  /** Override the timestamp (ms) — defaults to now. */
  timestamp?: number;
}

/** Append-only binary audit log. */
export class AuditLogger {
  private readonly blocks: Uint8Array[] = [];

  /** Append one structured entry; returns the encoded block. */
  public log(entry: AuditInput): Uint8Array {
    const payload: AuditEntry = {
      timestamp: entry.timestamp ?? Date.now(),
      operation: entry.operation,
      algorithm: entry.algorithm,
      inputLength: entry.inputLength,
      outputLength: entry.outputLength,
      success: entry.success,
      platform: getPlatformLabel(),
    };
    if (entry.keyId !== undefined) {
      payload.keyId = entry.keyId;
    }
    const json = stringToBytes(JSON.stringify(payload));
    const blockLen = HEADER_SIZE + json.length;
    if (blockLen > 0xffff) {
      throw new LombokCryptoError(
        ErrorCode.INTEGRITY_CHECK_FAILED,
        `audit block too large (${blockLen} bytes)`,
        'audit',
      );
    }
    const block = new Uint8Array(blockLen);
    block.set(MAGIC, 0);
    block[MAGIC.length] = AUDIT_VERSION;
    block[MAGIC.length + 1] = (blockLen >>> 8) & 0xff;
    block[MAGIC.length + 2] = blockLen & 0xff;
    const ts = BigInt(payload.timestamp);
    for (let i = 0; i < 8; i++) {
      block[MAGIC.length + 3 + i] = Number((ts >> BigInt((7 - i) * 8)) & 0xffn);
    }
    block.set(json, HEADER_SIZE);
    this.blocks.push(block);
    return block;
  }

  /** All appended blocks concatenated. */
  public toBytes(): Uint8Array {
    const parts: Uint8Array[] = this.blocks.map((b) => new Uint8Array(b));
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  /** Decoded entries (self-verified). Throws INTEGRITY_CHECK_FAILED on damage. */
  public static decode(blob: Uint8Array): AuditEntry[] {
    const entries: AuditEntry[] = [];
    let offset = 0;
    while (offset < blob.length) {
      if (blob.length - offset < HEADER_SIZE) {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          `truncated audit header at offset ${offset}`,
          'audit',
        );
      }
      const magic = blob.subarray(offset, offset + MAGIC.length);
      if (
        magic[0] !== MAGIC[0] ||
        magic[1] !== MAGIC[1] ||
        magic[2] !== MAGIC[2] ||
        magic[3] !== MAGIC[3]
      ) {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          `bad audit magic at offset ${offset}`,
          'audit',
        );
      }
      const version = blob[offset + 4];
      if (version !== AUDIT_VERSION) {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          `unsupported audit version ${version}`,
          'audit',
        );
      }
      const blockLen = (blob[offset + 5] << 8) | blob[offset + 6];
      if (offset + blockLen > blob.length) {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          `audit block at offset ${offset} overruns the log`,
          'audit',
        );
      }
      let ts = 0n;
      for (let i = 0; i < 8; i++) {
        ts = (ts << 8n) | BigInt(blob[offset + 7 + i]);
      }
      const json = bytesToString(blob.subarray(offset + HEADER_SIZE, offset + blockLen));
      let parsed: Partial<AuditEntry>;
      try {
        parsed = JSON.parse(json) as Partial<AuditEntry>;
      } catch {
        throw new LombokCryptoError(
          ErrorCode.INTEGRITY_CHECK_FAILED,
          `audit payload at offset ${offset} is not valid JSON`,
          'audit',
        );
      }
      entries.push({
        timestamp: Number(ts),
        operation: parsed.operation ?? '',
        algorithm: parsed.algorithm ?? '',
        inputLength: parsed.inputLength ?? -1,
        outputLength: parsed.outputLength ?? -1,
        success: parsed.success === true,
        platform: parsed.platform ?? '',
        ...(parsed.keyId !== undefined ? { keyId: parsed.keyId } : {}),
      });
      offset += blockLen;
    }
    return entries;
  }
}
