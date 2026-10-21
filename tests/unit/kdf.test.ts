import { hkdf, hkdfDerive } from '../../src/kdf/hkdf.js';
import { pbkdf2, pbkdf2Derive } from '../../src/kdf/pbkdf2.js';
import { scryptDerive } from '../../src/kdf/scrypt.js';

describe('HKDF (RFC 5869)', () => {
  it('matches test case 1', async () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = new Uint8Array(Buffer.from('000102030405060708090a0b0c', 'hex'));
    const info = new Uint8Array(Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'));
    const okm = await hkdf.sha256(ikm, salt, info, 42);
    expect(Buffer.from(okm).toString('hex')).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  it('derives deterministic multi-block outputs (SHA-512, 200 bytes)', async () => {
    const ikm = new Uint8Array(32).fill(7);
    const a = await hkdf.sha512(ikm, undefined, undefined, 200);
    const b = await hkdf.sha512(ikm, undefined, undefined, 200);
    expect(a).toEqual(b);
    expect(a.length).toBe(200);
  });

  it('defaults: salt = zeros, info = empty, output 32 bytes', async () => {
    const ikm = new Uint8Array(16).fill(0x42);
    const withDefaults = await hkdfDerive(ikm);
    const explicit = await hkdfDerive(ikm, {
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new Uint8Array(0),
      outputLength: 32,
    });
    expect(withDefaults).toEqual(explicit);
  });

  it('rejects output lengths above the 255-block limit', async () => {
    await expect(hkdfDerive(new Uint8Array(16), { outputLength: 8160 })).resolves.toHaveLength(
      8160,
    );
    await expect(hkdfDerive(new Uint8Array(16), { outputLength: 8160 + 1 })).rejects.toThrow();
  });
});

describe('PBKDF2 (RFC 8018)', () => {
  it('matches known SHA-256 vectors', async () => {
    const salt = new Uint8Array(new TextEncoder().encode('salt'));
    expect(Buffer.from(await pbkdf2.sha256('password', salt, 1, 32)).toString('hex')).toBe(
      '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
    );
    expect(Buffer.from(await pbkdf2.sha256('password', salt, 2, 32)).toString('hex')).toBe(
      'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43',
    );
  });

  it('produces multi-block outputs correctly (dkLen > hash size)', async () => {
    const salt = new Uint8Array(new TextEncoder().encode('salt'));
    const dk = await pbkdf2.sha512('password', salt, 10, 100);
    expect(dk.length).toBe(100);
    const again = await pbkdf2.sha512('password', salt, 10, 100);
    expect(dk).toEqual(again);
  });

  it('accepts byte-array passwords and validates parameters', async () => {
    const dk = await pbkdf2Derive(new Uint8Array([1, 2, 3]), {
      iterations: 10,
      salt: new Uint8Array(8),
    });
    expect(dk.length).toBe(32);
    await expect(pbkdf2Derive('x', { iterations: 0 })).rejects.toThrow();
    await expect(pbkdf2Derive('x', { iterations: 10, dkLen: 0 })).rejects.toThrow();
  });

  it('PHC hash/verify round-trips and rejects wrong passwords', async () => {
    const hash = await pbkdf2.hash('correct horse', { iterations: 2000 });
    expect(hash.startsWith('$pbkdf2-sha256$i=2000$')).toBe(true);
    expect(await pbkdf2.verify(hash, 'correct horse')).toBe(true);
    expect(await pbkdf2.verify(hash, 'wrong')).toBe(false);
    expect(await pbkdf2.verify('garbage', 'wrong')).toBe(false);
  });
});

describe('scrypt (RFC 7914)', () => {
  it('matches both published test vectors', async () => {
    const v1 = await scryptDerive('password', 'NaCl', { N: 1024, r: 8, p: 16, dkLen: 64 });
    expect(Buffer.from(v1).toString('hex')).toBe(
      'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
    );
    const v2 = await scryptDerive('pleaseletmein', 'SodiumChloride', {
      N: 16384,
      r: 8,
      p: 1,
      dkLen: 64,
    });
    expect(Buffer.from(v2).toString('hex')).toBe(
      '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887',
    );
  });

  it('is deterministic and accepts byte inputs', async () => {
    const a = await scryptDerive(new Uint8Array([1, 2]), new Uint8Array([3, 4]), {
      N: 16,
      r: 1,
      p: 1,
      dkLen: 32,
    });
    const b = await scryptDerive(new Uint8Array([1, 2]), new Uint8Array([3, 4]), {
      N: 16,
      r: 1,
      p: 1,
      dkLen: 32,
    });
    expect(a).toEqual(b);
  });

  it('validates N as a power of two and memory bounds', async () => {
    await expect(scryptDerive('x', 'y', { N: 1000, r: 1, p: 1 })).rejects.toThrow();
    await expect(scryptDerive('x', 'y', { N: 1, r: 1, p: 1 })).rejects.toThrow();
    await expect(scryptDerive('x', 'y', { N: 16, r: 0, p: 1 })).rejects.toThrow();
  });
});
