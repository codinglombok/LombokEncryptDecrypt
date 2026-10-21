import { chaCha20Poly1305, xchaChaPoly1305, internal } from '../../src/modes/chacha.js';
import { createCipheriv, randomBytes } from 'node:crypto';
import { hasNodeChacha } from '../platform-caps.js';
import { ErrorCode } from '../../src/errors.js';

const enc = new TextEncoder();

// Bun does not expose chacha20-poly1305 via node:crypto — cross-checks
// against OpenSSL are skipped there; the RFC vectors still always run.
const itIfChacha = hasNodeChacha ? it : it.skip;

describe('ChaCha20-Poly1305 (RFC 8439)', () => {
  it('reproduces the §2.4.2 block function vector', () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i;
    const nonce = new Uint8Array([
      0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ]);
    const block = internal.chacha20Block(key, 1, nonce);
    const bytes = new Uint8Array(64);
    for (let w = 0; w < 16; w++) {
      bytes[w * 4] = block[w] & 0xff;
      bytes[w * 4 + 1] = (block[w] >>> 8) & 0xff;
      bytes[w * 4 + 2] = (block[w] >>> 16) & 0xff;
      bytes[w * 4 + 3] = (block[w] >>> 24) & 0xff;
    }
    expect(Buffer.from(bytes).toString('hex')).toBe(
      '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e',
    );
  });

  it('reproduces the §2.5.2 Poly1305 vector', () => {
    const key = Buffer.from(
      '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
      'hex',
    );
    const msg = enc.encode('Cryptographic Forum Research Group');
    expect(
      Buffer.from(internal.poly1305Mac(new Uint8Array(key), new Uint8Array(msg))).toString('hex'),
    ).toBe('a8061dc1305136c6c22b8baf0c0127a9');
  });

  itIfChacha('reproduces the §2.8.2 AEAD tag and ciphertext', async () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = 0x80 + i;
    const nonce = Buffer.from('070000004041424344454647', 'hex');
    const aad = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
    const pt = enc.encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    );
    const res = await chaCha20Poly1305.encrypt(new Uint8Array(pt), key, {
      nonce: new Uint8Array(nonce),
      aad: new Uint8Array(aad),
    });
    expect(Buffer.from(res.tag).toString('hex')).toBe('1ae10b594f09e26a7e902ecbd0600691');
    const ref = createCipheriv('chacha20-poly1305', key, new Uint8Array(nonce), {
      authTagLength: 16,
    });
    ref.setAAD(new Uint8Array(aad), { plaintextLength: aad.length });
    const refCt = Buffer.concat([ref.update(new Uint8Array(pt)), ref.final()]);
    expect(Buffer.from(res.ciphertext).equals(refCt)).toBe(true);
  });

  itIfChacha('cross-checks against OpenSSL on random inputs', async () => {
    for (const len of [0, 1, 31, 64, 100, 250]) {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      const aad = randomBytes(7);
      const pt = randomBytes(len);
      const mine = await chaCha20Poly1305.encrypt(pt, key, { nonce, aad });
      const ref = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
      ref.setAAD(aad, { plaintextLength: aad.length });
      const refCt = Buffer.concat([ref.update(pt), ref.final()]);
      expect(Buffer.from(mine.ciphertext).equals(refCt)).toBe(true);
      expect(Buffer.from(mine.tag).equals(ref.getAuthTag())).toBe(true);
      const back = await chaCha20Poly1305.decrypt(mine.ciphertext, key, nonce, mine.tag, { aad });
      expect(Buffer.from(back).equals(pt)).toBe(true);
    }
  });

  it('validates key/nonce sizes and rejects tampering', async () => {
    await expect(chaCha20Poly1305.encrypt(new Uint8Array(4), new Uint8Array(16))).rejects.toThrow(
      ErrorCode.INVALID_KEY_SIZE,
    );
    const key = randomBytes(32);
    await expect(
      chaCha20Poly1305.encrypt(new Uint8Array(4), key, { nonce: new Uint8Array(11) }),
    ).rejects.toThrow(ErrorCode.INVALID_IV_SIZE);
    const res = await chaCha20Poly1305.encrypt(new Uint8Array(10), key);
    res.tag[15] ^= 1;
    await expect(chaCha20Poly1305.decrypt(res.ciphertext, key, res.iv, res.tag)).rejects.toThrow(
      ErrorCode.AUTHENTICATION_FAILED,
    );
    await expect(
      chaCha20Poly1305.decrypt(res.ciphertext, key, res.iv, res.tag.subarray(0, 15)),
    ).rejects.toThrow(ErrorCode.AUTHENTICATION_FAILED);
  });
});

describe('XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha)', () => {
  it('reproduces the §2.2.1 HChaCha20 subkey', () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i;
    const nonce16 = Buffer.from('000000090000004a0000000031415927', 'hex');
    expect(Buffer.from(internal.hchacha20(key, new Uint8Array(nonce16))).toString('hex')).toBe(
      '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc',
    );
  });

  it('reproduces the §A.3.2 AEAD vector', async () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = 0x80 + i;
    const nonce = new Uint8Array(24);
    for (let i = 0; i < 24; i++) nonce[i] = 0x40 + i;
    const aad = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
    const pt = enc.encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    );
    const res = await xchaChaPoly1305.encrypt(new Uint8Array(pt), key, {
      iv: nonce,
      aad: new Uint8Array(aad),
    });
    expect(
      Buffer.from(res.ciphertext)
        .toString('hex')
        .startsWith('bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb'),
    ).toBe(true);
    expect(Buffer.from(res.tag).toString('hex')).toBe('c0875924c1c7987947deafd8780acf49');
  });

  itIfChacha('composes as HChaCha20 + ChaCha20-Poly1305 with a zero-prefixed nonce', async () => {
    const key = randomBytes(32);
    const nonce24 = randomBytes(24);
    const pt = randomBytes(123);
    const aad = randomBytes(10);
    const res = await xchaChaPoly1305.encrypt(pt, key, { iv: nonce24, aad });
    const subkey = internal.hchacha20(key, nonce24.subarray(0, 16));
    const derived = new Uint8Array(12);
    derived.set(nonce24.subarray(16, 24), 4);
    const ref = createCipheriv('chacha20-poly1305', subkey, derived, { authTagLength: 16 });
    ref.setAAD(aad, { plaintextLength: aad.length });
    const refCt = Buffer.concat([ref.update(pt), ref.final()]);
    expect(Buffer.from(res.ciphertext).equals(refCt)).toBe(true);
    expect(Buffer.from(res.tag).equals(ref.getAuthTag())).toBe(true);
    const back = await xchaChaPoly1305.decrypt(res.ciphertext, key, nonce24, res.tag, { aad });
    expect(Buffer.from(back).equals(pt)).toBe(true);
  });

  it('validates nonce size (24 bytes) and rejects tampering', async () => {
    const key = randomBytes(32);
    await expect(
      xchaChaPoly1305.encrypt(new Uint8Array(4), key, { iv: new Uint8Array(12) }),
    ).rejects.toThrow(ErrorCode.INVALID_IV_SIZE);
    const res = await xchaChaPoly1305.encrypt(new Uint8Array(10), key);
    res.ciphertext[0] ^= 1;
    await expect(xchaChaPoly1305.decrypt(res.ciphertext, key, res.iv, res.tag)).rejects.toThrow(
      ErrorCode.AUTHENTICATION_FAILED,
    );
  });
});
