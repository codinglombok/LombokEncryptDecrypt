/**
 * LombokEncryptDecrypt — cross-language test vector generator.
 *
 * Produces deterministic vectors from fixed inputs for every implemented
 * algorithm family and writes:
 *   - tests/vectors/lombokencryptdecrypt-vectors-v1.json (artifact for ports)
 *   - tests/vectors/vectors-data.ts (TS module used by the vector tests,
 *     so Deno/Bun/jest can import it without JSON-module support)
 *
 * Determinism: every key/IV/plaintext below is a fixed hex constant, so the
 * output is byte-identical across runs and runtimes.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  aesGcm,
  chaCha20Poly1305,
  xchaChaPoly1305,
  aesCbcEncrypt,
  aesXtsEncrypt,
  sha256,
  sha224,
  sha384,
  sha512,
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  shake128,
  shake256,
  sm3,
  blake3,
  hmacSha256,
  hmacSha384,
  hmacSha512,
  cmac,
  hkdf,
  pbkdf2,
  scryptDerive,
  sm4,
  ed25519,
  ecdhX25519,
  envelopeEncrypt,
  bytesToHex,
  hexToBytes,
  stringToBytes,
  bytesToString,
} from '../src/index.js';

const hex = (b: Uint8Array): string => bytesToHex(b);
const FIXED_KEY_32 = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const FIXED_KEY_16 = hexToBytes('000102030405060708090a0b0c0d0e0f');
const FIXED_IV = hexToBytes('000102030405060708090a0b');
const MSG = stringToBytes('halo lombok — cross-language test vector message');

async function main(): Promise<void> {
  const vectors: Record<string, unknown> = {
    meta: {
      name: 'lombokencryptdecrypt-vectors-v1',
      version: 1,
      generatedFrom: 'TypeScript reference implementation v0.1.0',
      note: 'All inputs are fixed constants — outputs must be byte-identical in every language port.',
    },
  };

  // SHA-2
  vectors['sha256'] = hex(await sha256.hash(MSG));
  vectors['sha224'] = hex(await sha224.hash(MSG));
  vectors['sha384'] = hex(await sha384.hash(MSG));
  vectors['sha512'] = hex(await sha512.hash(MSG));
  // SHA-3 / SHAKE
  vectors['sha3_224'] = hex(await sha3_224.hash(MSG));
  vectors['sha3_256'] = hex(await sha3_256.hash(MSG));
  vectors['sha3_384'] = hex(await sha3_384.hash(MSG));
  vectors['sha3_512'] = hex(await sha3_512.hash(MSG));
  vectors['shake128_64'] = hex(await shake128.hash(MSG, 64));
  vectors['shake256_64'] = hex(await shake256.hash(MSG, 64));
  // SM3 / BLAKE3
  vectors['sm3'] = hex(sm3.hash(MSG));
  vectors['blake3'] = hex(await blake3.hash(MSG));
  vectors['blake3_keyed'] = hex(await blake3.keyed(FIXED_KEY_32, MSG));
  // HMAC / CMAC
  vectors['hmac_sha256'] = hex(await hmacSha256.compute(FIXED_KEY_32, MSG));
  vectors['hmac_sha384'] = hex(await hmacSha384.compute(FIXED_KEY_32, MSG));
  vectors['hmac_sha512'] = hex(await hmacSha512.compute(FIXED_KEY_32, MSG));
  vectors['cmac_aes128'] = hex(cmac.compute(FIXED_KEY_16, MSG));
  vectors['cmac_aes256'] = hex(cmac.compute(FIXED_KEY_32, MSG));
  // KDF
  vectors['hkdf_sha256_32'] = hex(
    await hkdf.sha256(MSG, hexToBytes('a0a1a2a3a4a5a6a7a8a9'), stringToBytes('lombok-info'), 32),
  );
  vectors['pbkdf2_sha256'] = hex(
    await pbkdf2.sha256('lombok-password', hexToBytes('b0b1b2b3b4b5b6b7'), 1000, 32),
  );
  vectors['scrypt_n1024'] = hex(
    await scryptDerive('lombok-password', 'NaCl', { N: 1024, r: 8, p: 16, dkLen: 32 }),
  );
  // AEAD
  const gcm = await aesGcm.encrypt(MSG, FIXED_KEY_32, { iv: FIXED_IV, aad: stringToBytes('ctx') });
  vectors['aes_256_gcm'] = {
    ciphertext: hex(gcm.ciphertext),
    tag: hex(gcm.tag),
    iv: hex(gcm.iv),
  };
  const chacha = await chaCha20Poly1305.encrypt(MSG, FIXED_KEY_32, {
    nonce: FIXED_IV,
    aad: stringToBytes('ctx'),
  });
  vectors['chacha20_poly1305'] = {
    ciphertext: hex(chacha.ciphertext),
    tag: hex(chacha.tag),
    nonce: hex(chacha.iv),
  };
  const xnonce = hexToBytes('404142434445464748494a4b4c4d4e4f5051525354555657');
  const xchacha = await xchaChaPoly1305.encrypt(MSG, FIXED_KEY_32, {
    iv: xnonce,
    aad: stringToBytes('ctx'),
  });
  vectors['xchacha20_poly1305'] = {
    ciphertext: hex(xchacha.ciphertext),
    tag: hex(xchacha.tag),
    nonce: hex(xchacha.iv),
  };
  // CBC / XTS / SM4
  const cbc = await aesCbcEncrypt(
    MSG,
    FIXED_KEY_32,
    hexToBytes('000102030405060708090a0b0c0d0e0f'),
  );
  vectors['aes_256_cbc'] = { ciphertext: hex(cbc.ciphertext), iv: hex(cbc.iv) };
  const xtsPt = new Uint8Array(96);
  for (let i = 0; i < 96; i++) xtsPt[i] = (i * 7 + 1) & 0xff;
  vectors['aes_128_xts'] = hex(await aesXtsEncrypt(xtsPt, new Uint8Array(32), 1n));
  vectors['sm4_ecb'] = hex(sm4.ecb(FIXED_KEY_16, hexToBytes('0123456789abcdeffedcba9876543210')));
  // Ed25519 (deterministic from seed) + X25519
  const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  const kp = await ed25519.fromSeed(seed);
  const sig = await ed25519.sign(MSG, kp.privateKey);
  vectors['ed25519'] = { publicKey: hex(kp.publicKey), signature: hex(sig) };
  const alicePriv = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const bobPub = hexToBytes('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  vectors['x25519'] = hex(await ecdhX25519.computeSharedSecret(alicePriv, bobPub));
  // Envelope (deterministic only in structure — DEK is random, so store shape)
  const env = await envelopeEncrypt.encrypt(MSG, FIXED_KEY_32, 'kek-1', stringToBytes('ctx'));
  const round = await envelopeEncrypt.decrypt(
    env.encryptedData,
    env.encryptedKey,
    FIXED_KEY_32,
    stringToBytes('ctx'),
  );
  vectors['envelope_roundtrip'] = bytesToString(round) === bytesToString(MSG);

  const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..');
  const vectorsDir = join(rootDir, 'tests', 'vectors');
  mkdirSync(vectorsDir, { recursive: true });

  const jsonPath = join(vectorsDir, 'lombokencryptdecrypt-vectors-v1.json');
  writeFileSync(jsonPath, JSON.stringify(vectors, null, 2) + '\n');

  const tsPath = join(vectorsDir, 'vectors-data.ts');
  writeFileSync(
    tsPath,
    '// GENERATED by scripts/generate-vectors.ts — do not edit by hand.\n' +
      '// Regenerate with: npm run generate:vectors\n' +
      'export const VECTORS_V1 = ' +
      JSON.stringify(vectors, null, 2) +
      ' as const;\n',
  );

  console.log(`wrote ${jsonPath}`);
  console.log(`wrote ${tsPath}`);
  console.log(`${Object.keys(vectors).length - 2} vector entries`);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
