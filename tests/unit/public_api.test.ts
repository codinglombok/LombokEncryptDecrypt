import * as api from '../../src/index.js';

describe('public API (src/index.ts)', () => {
  it('exports the implemented primitives', () => {
    for (const name of ['aesGcm', 'chaCha20Poly1305', 'xchaChaPoly1305', 'sha256', 'sha3_256', 'hmacSha256',
      'hkdf', 'pbkdf2', 'scrypt', 'cmacAes128', 'ed25519', 'KeyStore', 'createEncryptStream', 'AuditLogger']) {
      expect((api as Record<string, unknown>)[name]).toBeDefined();
    }
  });

  it('does not export unimplemented algorithms', () => {
    for (const name of ['argon2', 'kyber768', 'mlKem768', 'blake3', 'dilithium3']) {
      expect((api as Record<string, unknown>)[name]).toBeUndefined();
    }
  });

  it('AES-GCM round-trips through the barrel export', async () => {
    const key = api.randomKey256();
    const aad = api.stringToBytes('ctx');
    const { ciphertext, tag, iv } = await api.aesGcm.encrypt(api.stringToBytes('halo lombok'), key, { aad });
    const pt = await api.aesGcm.decrypt(ciphertext, key, iv, tag, { aad });
    expect(api.bytesToString(pt)).toBe('halo lombok');
  });
});
