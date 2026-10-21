/**
 * LombokEncryptDecrypt — Runtime detection & capability reporting.
 *
 * Detection relies on runtime globals so the module stays dependency-free.
 * Hardware acceleration flags (AES-NI, SHA extensions, AVX2, NEON) cannot be
 * observed from JavaScript and are therefore always reported honestly as
 * `false` instead of guessed.
 */

export type PlatformName = 'node' | 'browser' | 'deno' | 'bun' | 'wasm' | 'embedded';

export interface PlatformCapabilities {
  /** Detected runtime family. */
  platform: PlatformName;
  /** True when a WebCrypto-compatible CSPRNG is available. */
  hasHardwareRng: boolean;
  /** True when WebCrypto subtle (asymmetric primitives) is available. */
  hasSubtleCrypto: boolean;
  /** Hardware AES-NI — not detectable from JS, always false. */
  hasAesNi: false;
  /** Hardware SHA extensions — not detectable from JS, always false. */
  hasShaExtensions: false;
  /** AVX2 — not detectable from JS, always false. */
  hasAvx2: false;
  /** ARM NEON — not detectable from JS, always false. */
  hasNeon: false;
  /** HSM backing — never assumed, always false. */
  hasHsm: false;
  /** TPM backing — never assumed, always false. */
  hasTpm: false;
  /** Secure enclave — never assumed, always false. */
  hasSecureEnclave: false;
}

function globalValue(key: string): unknown {
  const g = globalThis as Record<string, unknown>;
  return g[key];
}

function detectPlatform(): PlatformName {
  if (globalValue('Deno') !== undefined) return 'deno';
  if (globalValue('Bun') !== undefined) return 'bun';
  if (globalValue('process') !== undefined) {
    const versions = (globalValue('process') as { versions?: { node?: string } }).versions;
    if (versions !== undefined && typeof versions.node === 'string') return 'node';
  }
  if (globalValue('window') !== undefined) return 'browser';
  return 'embedded';
}

/** Detected runtime, computed once at module load. */
export const PLATFORM: PlatformName = detectPlatform();

function hasRng(): boolean {
  const rng = globalValue('crypto') as { getRandomValues?: unknown } | undefined;
  return rng !== undefined && typeof rng.getRandomValues === 'function';
}

function hasSubtle(): boolean {
  const rng = globalValue('crypto') as { subtle?: unknown } | undefined;
  return rng !== undefined && typeof rng.subtle === 'object' && rng.subtle !== null;
}

/** Human-readable platform label used by the audit log (`node/v22.0.0`). */
export function getPlatformLabel(): string {
  if (PLATFORM === 'node') {
    const versions = (globalValue('process') as { versions?: { node?: string } }).versions;
    return `node/v${versions?.node ?? 'unknown'}`;
  }
  if (PLATFORM === 'deno') {
    const deno = globalValue('Deno') as { version?: { deno?: string } } | undefined;
    return `deno/v${deno?.version?.deno ?? 'unknown'}`;
  }
  if (PLATFORM === 'bun') {
    const bun = globalValue('Bun') as { version?: string } | undefined;
    return `bun/v${bun?.version ?? 'unknown'}`;
  }
  return PLATFORM;
}

/** Resolve runtime capabilities (async to mirror the documented API). */
export async function getPlatformCapabilities(): Promise<PlatformCapabilities> {
  return {
    platform: PLATFORM,
    hasHardwareRng: hasRng(),
    hasSubtleCrypto: hasSubtle(),
    hasAesNi: false,
    hasShaExtensions: false,
    hasAvx2: false,
    hasNeon: false,
    hasHsm: false,
    hasTpm: false,
    hasSecureEnclave: false,
  };
}
