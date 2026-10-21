/**
 * Integration tests — end-to-end workflows the README documents.
 */

import {
  aesGcm,
  randomKey256,
  stringToBytes,
  bytesToString,
  KeyStore,
  envelopeEncrypt,
  createEncryptStream,
  createDecryptStream,
  concatBytes,
  hkdf,
  ed25519,
  ecdhX25519,
  sha256,
  hmacSha256,
  LombokCryptoError,
  ErrorCode,
} from '../../src/index.js';

describe('README quick-start flow', () => {
  it('encrypts and decrypts exactly as documented', async () => {
    const key = randomKey256();
    const aad = stringToBytes('ctx');
    const { ciphertext, tag, iv } = await aesGcm.encrypt(stringToBytes('halo lombok'), key, {
      aad,
    });
    const plain = await aesGcm.decrypt(ciphertext, key, iv, tag, { aad });
    expect(bytesToString(plain)).toBe('halo lombok');
  });
});

describe('combined workflow: ECDH → HKDF → KeyStore → envelope → stream', () => {
  it('builds a complete secure channel pipeline', async () => {
    // 1. Two parties agree on a shared secret
    const alice = await ecdhX25519.generateKeyPair();
    const bob = await ecdhX25519.generateKeyPair();
    const sharedA = await ecdhX25519.computeSharedSecret(alice.privateKey, bob.publicKey);
    const sharedB = await ecdhX25519.computeSharedSecret(bob.privateKey, alice.publicKey);
    expect(sharedA).toEqual(sharedB);

    // 2. Derive a KEK through HKDF (documented requirement for shared secrets)
    const kek = await hkdf.sha256(sharedA, undefined, stringToBytes('lombok-envelope-demo'), 32);

    // 3. Sign the transcript with Ed25519
    const signing = await ed25519.generateKeyPair();
    const transcript = await sha256.hash(concatBytes(sharedA, stringToBytes('transcript-v1')));
    const sig = await ed25519.sign(transcript, signing.privateKey);
    expect(await ed25519.verify(transcript, sig, signing.publicKey)).toBe(true);

    // 4. Store the MAC key in a password-protected KeyStore
    const ks = await KeyStore.create({ password: 'integration-demo', m: 1024, r: 8, p: 1 });
    const macKey = await ks.generateKey('mac-1', 'AES-256-GCM');
    const blob = await ks.serialize();
    const reopened = await KeyStore.open(blob, { password: 'integration-demo' });
    expect(await reopened.get('mac-1')).toEqual(macKey);

    // 5. Envelope-encrypt a payload under the KEK
    const payload = stringToBytes('integration payload — rahasia lombok');
    const env = await envelopeEncrypt.encrypt(payload, kek, 'kek-demo', transcript);
    const unwrapped = await envelopeEncrypt.decrypt(
      env.encryptedData,
      env.encryptedKey,
      kek,
      transcript,
    );
    expect(bytesToString(unwrapped)).toBe(bytesToString(payload));

    // 6. MAC the envelope with the KeyStore key
    const mac = await hmacSha256.compute(
      macKey,
      concatBytes(env.encryptedData, stringToBytes('kek-demo')),
    );
    expect(
      await hmacSha256.verify(
        macKey,
        concatBytes(env.encryptedData, stringToBytes('kek-demo')),
        mac,
      ),
    ).toBe(true);

    // 7. Stream-encrypt a larger artifact with the same KEK family
    const big = new Uint8Array(150000);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
    const enc = createEncryptStream({
      algorithm: 'AES-256-GCM',
      key: kek,
      chunkSize: 8192,
      aad: transcript,
    });
    const parts: Uint8Array[] = [];
    for (let off = 0; off < big.length; off += 7000) {
      parts.push(...(await enc.update(big.subarray(off, Math.min(off + 7000, big.length)))));
    }
    parts.push(await enc.final());
    const dec = createDecryptStream({
      algorithm: 'AES-256-GCM',
      key: kek,
      chunkSize: 8192,
      aad: transcript,
    });
    const decParts: Uint8Array[] = [];
    const encBytes = concatBytes(...parts);
    for (let off = 0; off < encBytes.length; off += 5000) {
      decParts.push(
        ...(await dec.update(encBytes.subarray(off, Math.min(off + 5000, encBytes.length)))),
      );
    }
    decParts.push(await dec.final());
    expect(concatBytes(...decParts)).toEqual(big);
  });

  it('error taxonomy flows through user code with instanceof + code', async () => {
    const key = randomKey256();
    const { ciphertext, tag, iv } = await aesGcm.encrypt(new Uint8Array(10), key);
    const tampered = Uint8Array.from(tag);
    tampered[0] ^= 1;
    try {
      await aesGcm.decrypt(ciphertext, key, iv, tampered);
      throw new Error('expected AUTHENTICATION_FAILED');
    } catch (e) {
      expect(e).toBeInstanceOf(LombokCryptoError);
      expect((e as LombokCryptoError).code).toBe(ErrorCode.AUTHENTICATION_FAILED);
      expect((e as LombokCryptoError).algorithm).toBe('AES-GCM');
    }
  });
});
