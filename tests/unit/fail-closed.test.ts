import { argon2id } from '../../src/kdf/argon2.js';
import { kyber768 } from '../../src/pq/kyber/kyber768.js';
import { ErrorCode, LombokCryptoError } from '../../src/errors.js';

describe('fail-closed: Argon2id (RFC 9106)', () => {
  it('every operation throws UNSUPPORTED_ALGORITHM', async () => {
    await expect(argon2id.hash('pw')).rejects.toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
    await expect(argon2id.verify('$argon2id$v=19$m=1,t=1,p=1$aa$bb', 'pw')).rejects.toThrow(
      ErrorCode.UNSUPPORTED_ALGORITHM,
    );
    await expect(argon2id.raw('pw', new Uint8Array(16))).rejects.toThrow(
      ErrorCode.UNSUPPORTED_ALGORITHM,
    );
    let caught: unknown;
    try {
      await argon2id.hash('pw', { m: 65536, t: 3, p: 4 });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(LombokCryptoError);
    expect((caught as LombokCryptoError).algorithm).toBe('Argon2id');
  });
});

describe('fail-closed: ML-KEM-768 / Kyber768 (FIPS 203)', () => {
  it('every operation throws UNSUPPORTED_ALGORITHM', async () => {
    await expect(kyber768.generateKeyPair()).rejects.toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
    await expect(kyber768.encapsulate(new Uint8Array(1184))).rejects.toThrow(
      ErrorCode.UNSUPPORTED_ALGORITHM,
    );
    await expect(kyber768.decapsulate(new Uint8Array(1088), new Uint8Array(2400))).rejects.toThrow(
      ErrorCode.UNSUPPORTED_ALGORITHM,
    );
    let caught: unknown;
    try {
      await kyber768.generateKeyPair();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(LombokCryptoError);
    expect((caught as LombokCryptoError).algorithm).toBe('ML-KEM-768');
  });

  it('mlKem768 alias fails closed identically', async () => {
    const { mlKem768 } = await import('../../src/pq/kyber/kyber768.js');
    await expect(mlKem768.generateKeyPair()).rejects.toThrow(ErrorCode.UNSUPPORTED_ALGORITHM);
  });
});
