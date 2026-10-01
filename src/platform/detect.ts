/**
 * LombokEncryptDecrypt — Platform Detection
 * Auto-selects the fastest available crypto backend.
 * @module platform/detect
 */

import type { Platform, PlatformCapabilities } from '../types.js';

function detectPlatform(): Platform {
  if (typeof process !== 'undefined' && process.versions?.node) return 'node';
  if (typeof Deno !== 'undefined') return 'deno';
  // @ts-expect-error Bun global
  if (typeof Bun !== 'undefined') return 'bun';
  if (typeof WebAssembly !== 'undefined' && typeof window === 'undefined') return 'wasm';
  return 'browser';
}

function hasSubtleCrypto(): boolean {
  return typeof globalThis.crypto !== 'undefined' &&
    typeof globalThis.crypto.subtle !== 'undefined';
}

function hasNodeCrypto(): boolean {
  try {
    // Dynamic require to avoid bundler issues
    if (typeof process !== 'undefined' && process.versions?.node) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

/** Detect SIMD capabilities via WASM feature detection */
async function hasWasmSimd(): Promise<boolean> {
  try {
    // WASM SIMD v128 feature probe
    const simdBytes = new Uint8Array([
      0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7B, 0x03,
      0x02, 0x01, 0x00, 0x0A, 0x0A, 0x01, 0x08, 0x00,
      0x41, 0x00, 0xFD, 0x0F, 0x00, 0x00, 0x0B,
    ]);
    await WebAssembly.instantiate(simdBytes);
    return true;
  } catch {
    return false;
  }
}

// ── Singleton capabilities ─────────────────────────────────────────────────

let _capabilities: PlatformCapabilities | null = null;

export async function getPlatformCapabilities(): Promise<PlatformCapabilities> {
  if (_capabilities) return _capabilities;

  const platform = detectPlatform();
  const [wasmSimd] = await Promise.all([hasWasmSimd()]);

  _capabilities = {
    platform,
    hasAesNi: platform === 'node' || platform === 'bun',   // AES-NI used via Node.js crypto
    hasShaExtensions: platform === 'node' || platform === 'bun',
    hasAvx2: false,    // Only available in Rust NAPI build
    hasNeon: false,    // Only available in Rust NAPI build on ARM
    hasSubtleCrypto: hasSubtleCrypto(),
    hasHardwareRng: platform !== 'embedded',
    hasHsm: false,     // Detected at runtime by hardware/pkcs11.ts
    hasTpm: false,     // Detected at runtime by hardware/tpm2.ts
    hasSecureEnclave: platform === 'node' && process.platform === 'darwin',
  };

  // Detect NAPI Rust build (provides AVX2/NEON)
  try {
    const napiModule = await import('../platform/wasm_bridge.js');
    if (napiModule?.isRustCore) {
      _capabilities = {
        ..._capabilities,
        hasAvx2: napiModule.hasAvx2?.() ?? false,
        hasNeon: napiModule.hasNeon?.() ?? false,
      };
    }
  } catch {
    // NAPI not available — use pure TS + SubtleCrypto
  }

  return _capabilities;
}

/** Synchronous platform check (for simple runtime branching) */
export const PLATFORM: Platform = detectPlatform();
export const HAS_SUBTLE_CRYPTO: boolean = hasSubtleCrypto();
export const HAS_NODE_CRYPTO: boolean = hasNodeCrypto();
