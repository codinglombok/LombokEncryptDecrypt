import { PLATFORM, getPlatformCapabilities, getPlatformLabel } from '../../src/platform/index.js';
import { ErrorCode, LombokCryptoError } from '../../src/errors.js';
import { VECTORS_V1 } from '../vectors/vectors-data.js';

describe('platform detection', () => {
  it('identifies a supported runtime family', () => {
    expect(['node', 'browser', 'deno', 'bun', 'wasm', 'embedded']).toContain(PLATFORM);
  });

  it('reports capability flags honestly', async () => {
    const caps = await getPlatformCapabilities();
    expect(caps.platform).toBe(PLATFORM);
    expect(caps.hasHardwareRng).toBe(true);
    expect(caps.hasSubtleCrypto).toBe(true);
    expect(caps.hasAesNi).toBe(false);
    expect(caps.hasShaExtensions).toBe(false);
    expect(caps.hasAvx2).toBe(false);
    expect(caps.hasNeon).toBe(false);
    expect(caps.hasHsm).toBe(false);
    expect(caps.hasTpm).toBe(false);
    expect(caps.hasSecureEnclave).toBe(false);
    expect(getPlatformLabel()).toMatch(/\//);
  });
});

describe('error taxonomy', () => {
  it('LombokCryptoError carries code, algorithm and instanceof safety', () => {
    const err = new LombokCryptoError(ErrorCode.AUTHENTICATION_FAILED, 'boom', 'AES-GCM');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(LombokCryptoError);
    expect(err.code).toBe('AUTHENTICATION_FAILED');
    expect(err.algorithm).toBe('AES-GCM');
    expect(err.name).toBe('LombokCryptoError');
    expect(String(err)).toContain('boom');
    const plain = new LombokCryptoError(ErrorCode.UNSUPPORTED_ALGORITHM, 'no algo');
    expect(plain.algorithm).toBeUndefined();
  });

  it('exposes every documented error code', () => {
    const documented = [
      'INVALID_KEY_SIZE',
      'INVALID_IV_SIZE',
      'AUTHENTICATION_FAILED',
      'KEY_NOT_FOUND',
      'KEY_EXPIRED',
      'KEYSTORE_LOCKED',
      'KEYSTORE_CORRUPT',
      'LEGACY_DISABLED',
      'FIPS_VIOLATION',
      'STREAM_FINALISED',
      'INTEGRITY_CHECK_FAILED',
      'UNSUPPORTED_ALGORITHM',
    ];
    for (const code of documented) {
      expect(Object.values(ErrorCode)).toContain(code);
    }
  });
});

describe('package-level API surface', () => {
  it('exposes the documented root exports', async () => {
    const lib = await import('../../src/index.js');
    const required = [
      'aesGcm',
      'chaCha20Poly1305',
      'xchaChaPoly1305',
      'ed25519',
      'ecdh',
      'ecdhX25519',
      'pbkdf2',
      'hkdf',
      'hmacSha256',
      'hmacSha512',
      'sha256',
      'sha3_256',
      'blake3',
      'sm3',
      'sm4',
      'KeyStore',
      'envelopeEncrypt',
      'encryptStreamGen',
      'decryptStreamGen',
      'randomKey256',
      'randomBytes',
      'LombokCryptoError',
      'ErrorCode',
    ];
    for (const name of required) {
      expect(lib).toHaveProperty(name);
    }
    // fail-closed primitives are NOT exported from the root (documented rule)
    expect(lib).not.toHaveProperty('argon2id');
    expect(lib).not.toHaveProperty('kyber768');
    expect(lib).not.toHaveProperty('mlKem768');
  });

  it('vectors-data.ts module is structurally complete', () => {
    expect(VECTORS_V1.meta.version).toBe(1);
    expect(Object.keys(VECTORS_V1).length).toBeGreaterThan(20);
  });
});
