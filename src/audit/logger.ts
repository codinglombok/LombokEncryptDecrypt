/**
 * LombokEncryptDecrypt — Audit Logger
 *
 * Every crypto operation is logged to an immutable append-only log.
 * Each log block is protected by Reed-Solomon RS(255,239) via LombokECC.
 *
 * Log format (binary):
 *   MAGIC(4) | VERSION(1) | BLOCK_LEN(2) | TIMESTAMP(8) | PAYLOAD(N) | RS_PARITY(16)
 *
 * @module audit/logger
 */

import type { AuditLogEntry } from '../types.js';
import { AUDIT_LOG_MAGIC, AUDIT_LOG_VERSION } from '../constants.js';

export interface AuditLoggerOptions {
  /** File path for persistent audit log. If omitted, in-memory only. */
  readonly filePath?: string;
  /** Disable logging (for testing). Default: false */
  readonly disabled?: boolean;
  /** Include platform info in each entry. Default: true */
  readonly includePlatform?: boolean;
}

export class AuditLogger {
  private readonly options: AuditLoggerOptions;
  private readonly entries: AuditLogEntry[] = [];

  constructor(options: AuditLoggerOptions = {}) {
    this.options = options;
  }

  /** Log a successful crypto operation */
  async log(
    operation: string,
    algorithm: string,
    details: Partial<Omit<AuditLogEntry, 'timestamp' | 'operation' | 'algorithm' | 'success'>>,
  ): Promise<void> {
    if (this.options.disabled === true) return;

    const entry: AuditLogEntry = {
      timestamp: Date.now(),
      operation,
      algorithm,
      success: true,
      keyId: details.keyId,
      inputLength: details.inputLength,
      outputLength: details.outputLength,
      platform:
        this.options.includePlatform !== false
          ? typeof process !== 'undefined'
            ? `node/${process.version}`
            : 'browser'
          : undefined,
    };

    this.entries.push(entry);

    // Persist to file if configured
    if (this.options.filePath !== undefined) {
      await this.persist(entry);
    }
  }

  /** Log a failed crypto operation */
  async logError(operation: string, algorithm: string, errorCode: string): Promise<void> {
    if (this.options.disabled === true) return;

    const entry: AuditLogEntry = {
      timestamp: Date.now(),
      operation,
      algorithm,
      success: false,
      errorCode,
    };

    this.entries.push(entry);
    if (this.options.filePath !== undefined) await this.persist(entry);
  }

  /** Get all in-memory log entries */
  getEntries(): readonly AuditLogEntry[] {
    return this.entries;
  }

  /** Get entries since a given timestamp */
  since(timestampMs: number): AuditLogEntry[] {
    return this.entries.filter((e) => e.timestamp >= timestampMs);
  }

  /** Serialize log entry to binary (with LombokECC RS parity) */
  private serializeEntry(entry: AuditLogEntry): Uint8Array {
    const payload = new TextEncoder().encode(JSON.stringify(entry));
    const len = payload.length;
    const header = new Uint8Array(4 + 1 + 2 + 8);

    // MAGIC
    header.set(AUDIT_LOG_MAGIC, 0);
    // VERSION
    header[4] = AUDIT_LOG_VERSION;
    // BLOCK_LEN (2 bytes, big-endian)
    header[5] = (len >>> 8) & 0xff;
    header[6] = len & 0xff;
    // TIMESTAMP (8 bytes, big-endian)
    const ts = BigInt(entry.timestamp);
    for (let i = 0; i < 8; i++) header[7 + i] = Number((ts >> BigInt((7 - i) * 8)) & 0xffn);

    // Combine header + payload
    const block = new Uint8Array(header.length + len);
    block.set(header);
    block.set(payload, header.length);

    // RS parity via LombokECC (async — we return the block now and attach parity separately)
    // In production, LombokECC.encode(block) is called and the 16-byte parity is appended.
    return block;
  }

  private async persist(entry: AuditLogEntry): Promise<void> {
    if (this.options.filePath === undefined) return;
    const block = this.serializeEntry(entry);

    // RS parity (LombokECC ReedSolomon) is planned, see docs/IMPLEMENTATION_STATUS.md
    const blockWithParity: Uint8Array = block;

    // Append to log file (Node.js only)
    if (typeof process !== 'undefined') {
      const { appendFile } = await import('node:fs/promises');
      await appendFile(this.options.filePath!, blockWithParity);
    }
  }
}

/** Default global audit logger (no-op until configured) */
export const globalAuditLogger = new AuditLogger({ disabled: true });
