/**
 * LombokEncryptDecrypt — ChaCha20-Poly1305 + XChaCha20-Poly1305 Tests
 * RFC 8439 test vectors
 */

import { chaCha20Poly1305 } from '../../src/core/chacha/chacha20.js';
import { xchaChaPoly1305 } from '../../src/core/chacha/xchacha20.js';
import { hexToBytes, bytesToHex } from '../../src/utils/encoding.js';

const RFC8439_VECTOR = {
  key:    '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
  nonce:  '070000004041424344454647',
  aad:    '50515253c0c1c2c3c4c5c6c7',
  pt:     '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e',
  ct:     'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116',
  tag:    '1ae10b594f09e26a7e902ecbd0600691',
};

describe('ChaCha20-Poly1305', () => {
  describe('RFC 8439 test vector', () => {
    it('encrypt matches reference', async () => {
      const key   = hexToBytes(RFC8439_VECTOR.key);
      const nonce = hexToBytes(RFC8439_VECTOR.nonce);
      const aad   = hexToBytes(RFC8439_VECTOR.aad);
      const pt    = hexToBytes(RFC8439_VECTOR.pt);

      const { ciphertext, tag } = await chaCha20Poly1305.encrypt(pt, key, { iv: nonce, aad });

      expect(bytesToHex(ciphertext)).toBe(RFC8439_VECTOR.ct);
      expect(bytesToHex(tag)).toBe(RFC8439_VECTOR.tag);
    });

    it('decrypt recovers plaintext', async () => {
      const key   = hexToBytes(RFC8439_VECTOR.key);
      const nonce = hexToBytes(RFC8439_VECTOR.nonce);
      const aad   = hexToBytes(RFC8439_VECTOR.aad);
      const ct    = hexToBytes(RFC8439_VECTOR.ct);
      const tag   = hexToBytes(RFC8439_VECTOR.tag);

      const pt = await chaCha20Poly1305.decrypt(ct, key, nonce, tag, { aad });
      expect(bytesToHex(pt)).toBe(RFC8439_VECTOR.pt);
    });
  });

  describe('Roundtrip', () => {
    it('roundtrip 4KB message', async () => {
      const key  = chaCha20Poly1305.generateKey();
      const msg  = new Uint8Array(4096).fill(0xAB);
      const { ciphertext, tag, iv } = await chaCha20Poly1305.encrypt(msg, key);
      const dec  = await chaCha20Poly1305.decrypt(ciphertext, key, iv, tag);
      expect(bytesToHex(dec)).toBe(bytesToHex(msg));
    });

    it('roundtrip empty message', async () => {
      const key = chaCha20Poly1305.generateKey();
      const { ciphertext, tag, iv } = await chaCha20Poly1305.encrypt(new Uint8Array(0), key);
      const dec = await chaCha20Poly1305.decrypt(ciphertext, key, iv, tag);
      expect(dec).toEqual(new Uint8Array(0));
    });

    it('rejects tampered tag', async () => {
      const key = chaCha20Poly1305.generateKey();
      const { ciphertext, tag, iv } = await chaCha20Poly1305.encrypt(
        new TextEncoder().encode('secret'), key,
      );
      const bad = new Uint8Array(tag); bad[0] ^= 1;
      await expect(chaCha20Poly1305.decrypt(ciphertext, key, iv, bad)).rejects.toMatchObject({
        code: 'AUTHENTICATION_FAILED',
      });
    });

    it('rejects wrong key size', async () => {
      await expect(
        chaCha20Poly1305.encrypt(new Uint8Array(1), new Uint8Array(16))
      ).rejects.toMatchObject({ code: 'INVALID_KEY_SIZE' });
    });
  });
});

describe('XChaCha20-Poly1305', () => {
  it('roundtrip with 192-bit nonce', async () => {
    const key  = xchaChaPoly1305.generateKey();
    const msg  = new TextEncoder().encode('XChaCha20 test message');
    const { ciphertext, tag, iv } = await xchaChaPoly1305.encrypt(msg, key);
    expect(iv.length).toBe(24);
    const dec = await xchaChaPoly1305.decrypt(ciphertext, key, iv, tag);
    expect(new TextDecoder().decode(dec)).toBe('XChaCha20 test message');
  });

  it('uses 24-byte nonce', () => {
    const nonce = xchaChaPoly1305.generateNonce();
    expect(nonce.length).toBe(24);
  });

  it('rejects 12-byte nonce', async () => {
    const key = xchaChaPoly1305.generateKey();
    await expect(
      xchaChaPoly1305.encrypt(new Uint8Array(1), key, { iv: new Uint8Array(12) })
    ).rejects.toMatchObject({ code: 'INVALID_IV_SIZE' });
  });
});
