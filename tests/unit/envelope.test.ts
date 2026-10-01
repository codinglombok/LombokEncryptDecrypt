/**
 * LombokEncryptDecrypt — Envelope Encryption Tests
 */

import { envelopeEncrypt } from '../../src/hybrid/envelope.js';
import { randomKey256 } from '../../src/utils/random.js';
import { bytesToHex } from '../../src/utils/encoding.js';

describe('Envelope Encryption (KEK/DEK)', () => {
  it('roundtrip basic', async () => {
    const kek = randomKey256();
    const plaintext = new TextEncoder().encode('Secret enterprise data');

    const { encryptedData, encryptedKey } = await envelopeEncrypt.encrypt(
      plaintext, kek, 'my-kek-v1',
    );

    expect(encryptedKey.kemId).toBe('my-kek-v1');
    expect(encryptedKey.algorithm).toBe('AES-256-GCM');
    expect(encryptedData.length).toBeGreaterThan(28); // IV + some ct + tag

    const decrypted = await envelopeEncrypt.decrypt(encryptedData, encryptedKey, kek);
    expect(new TextDecoder().decode(decrypted)).toBe('Secret enterprise data');
  });

  it('roundtrip with AAD', async () => {
    const kek = randomKey256();
    const plaintext = new TextEncoder().encode('confidential');
    const aad = new TextEncoder().encode('user-id:12345');

    const { encryptedData, encryptedKey } = await envelopeEncrypt.encrypt(
      plaintext, kek, 'kek-1', aad,
    );
    const decrypted = await envelopeEncrypt.decrypt(encryptedData, encryptedKey, kek, aad);
    expect(new TextDecoder().decode(decrypted)).toBe('confidential');
  });

  it('rejects wrong AAD on decrypt', async () => {
    const kek = randomKey256();
    const pt  = new TextEncoder().encode('data');
    const aad = new TextEncoder().encode('correct-aad');
    const { encryptedData, encryptedKey } = await envelopeEncrypt.encrypt(pt, kek, 'k', aad);
    const wrongAad = new TextEncoder().encode('wrong-aad');
    await expect(
      envelopeEncrypt.decrypt(encryptedData, encryptedKey, kek, wrongAad)
    ).rejects.toBeDefined();
  });

  it('key rotation (rewrap) does not change encrypted data', async () => {
    const oldKek = randomKey256();
    const newKek = randomKey256();
    const pt = new TextEncoder().encode('very sensitive');

    const { encryptedData, encryptedKey } = await envelopeEncrypt.encrypt(pt, oldKek, 'kek-v1');
    const rotatedKey = await envelopeEncrypt.rewrap(encryptedKey, oldKek, newKek, 'kek-v2');

    // encryptedData is unchanged — only the wrapped DEK changed
    expect(bytesToHex(encryptedData)).toBe(bytesToHex(encryptedData));
    expect(rotatedKey.kemId).toBe('kek-v2');

    // Can decrypt with new KEK
    const dec = await envelopeEncrypt.decrypt(encryptedData, rotatedKey, newKek);
    expect(new TextDecoder().decode(dec)).toBe('very sensitive');

    // Cannot decrypt with old KEK + rotated key
    await expect(
      envelopeEncrypt.decrypt(encryptedData, rotatedKey, oldKek)
    ).rejects.toBeDefined();
  });

  it('roundtrip 1MB payload', async () => {
    const kek = randomKey256();
    const pt  = new Uint8Array(1024 * 1024).fill(0x55);
    const { encryptedData, encryptedKey } = await envelopeEncrypt.encrypt(pt, kek, 'big-kek');
    const dec = await envelopeEncrypt.decrypt(encryptedData, encryptedKey, kek);
    expect(bytesToHex(dec)).toBe(bytesToHex(pt));
  });
});
