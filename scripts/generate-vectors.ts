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
  aesCbc,
  aesEcb,
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
import { md5 } from '../src/legacy/md5.js';
import { rc4 } from '../src/legacy/rc4.js';

const hex = (b: Uint8Array): string => bytesToHex(b);
const FIXED_KEY_32 = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const FIXED_KEY_24 = hexToBytes('000102030405060708090a0b0c0d0e0f1011121314151617');
const FIXED_KEY_16 = hexToBytes('000102030405060708090a0b0c0d0e0f');
const FIXED_IV = hexToBytes('000102030405060708090a0b');
const FIXED_IV_16 = hexToBytes('000102030405060708090a0b0c0d0e0f');
const MSG = stringToBytes('halo lombok — cross-language test vector message');
const CTX = stringToBytes('ctx');
const PATTERN_48 = hexToBytes(
  '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
);
const PATTERN_1000 = (() => {
  const out = new Uint8Array(1000);
  for (let i = 0; i < out.length; i++) out[i] = (i * 29 + 5) & 0xff;
  return out;
})();

async function main(): Promise<void> {
  const vectors: Record<string, unknown> = {
    _meta: { version: 1, library: 'LombokEncryptDecrypt' },
    meta: {
      name: 'lombokencryptdecrypt-vectors-v1',
      version: 1,
      generatedFrom: 'TypeScript reference implementation v0.1.0',
      note: 'All inputs are fixed constants — outputs must be byte-identical in every language port.',
    },
  };

  // SHA-2 (arrays so ports can verify multiple input lengths)
  const SHA_INPUTS: Array<[string, Uint8Array]> = [
    ['empty', new Uint8Array(0)],
    ['one', hexToBytes('00')],
    ['msg', MSG],
    ['pattern-1000', PATTERN_1000],
  ];
  vectors['sha256'] = await Promise.all(
    SHA_INPUTS.map(async ([id, input]) => ({ id, input: hex(input), output: hex(await sha256.hash(input)) })),
  );
  vectors['sha384'] = await Promise.all(
    SHA_INPUTS.map(async ([id, input]) => ({ id, input: hex(input), output: hex(await sha384.hash(input)) })),
  );
  vectors['sha512'] = await Promise.all(
    SHA_INPUTS.map(async ([id, input]) => ({ id, input: hex(input), output: hex(await sha512.hash(input)) })),
  );
  vectors['sha224'] = hex(await sha224.hash(MSG));
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
  vectors['hmac_sha256'] = [
    { id: 'hmac-key32-msg', key: hex(FIXED_KEY_32), message: hex(MSG), output: hex(await hmacSha256.compute(FIXED_KEY_32, MSG)) },
    { id: 'hmac-key16-one', key: hex(FIXED_KEY_16), message: '00', output: hex(await hmacSha256.compute(FIXED_KEY_16, hexToBytes('00'))) },
  ];
  vectors['hmac_sha384'] = hex(await hmacSha384.compute(FIXED_KEY_32, MSG));
  vectors['hmac_sha512'] = hex(await hmacSha512.compute(FIXED_KEY_32, MSG));
  vectors['cmac_aes128'] = hex(cmac.compute(FIXED_KEY_16, MSG));
  vectors['cmac_aes256'] = hex(cmac.compute(FIXED_KEY_32, MSG));
  // KDF
  vectors['hkdf_sha256'] = [
    {
      id: 'hkdf-32',
      ikm: hex(MSG),
      salt: 'a0a1a2a3a4a5a6a7a8a9',
      info: hex(CTX),
      length: 32,
      okm: hex(await hkdf.sha256(MSG, hexToBytes('a0a1a2a3a4a5a6a7a8a9'), CTX, 32)),
    },
    {
      id: 'hkdf-64-empty-salt',
      ikm: hex(MSG),
      salt: '',
      info: '',
      length: 64,
      okm: hex(await hkdf.sha256(MSG, new Uint8Array(0), new Uint8Array(0), 64)),
    },
  ];
  vectors['hkdf_sha256_32'] = hex(
    await hkdf.sha256(MSG, hexToBytes('a0a1a2a3a4a5a6a7a8a9'), stringToBytes('lombok-info'), 32),
  );
  vectors['pbkdf2_sha256'] = hex(
    await pbkdf2.sha256('lombok-password', hexToBytes('b0b1b2b3b4b5b6b7'), 1000, 32),
  );
  vectors['scrypt_n1024'] = hex(
    await scryptDerive('lombok-password', 'NaCl', { N: 1024, r: 8, p: 16, dkLen: 32 }),
  );
  // AEAD (array schema for cross-language conformance)
  vectors['aes_gcm'] = await Promise.all(
    (
      [
        ['AES-128-GCM', FIXED_KEY_16],
        ['AES-192-GCM', FIXED_KEY_24],
        ['AES-256-GCM', FIXED_KEY_32],
      ] as Array<[string, Uint8Array]>
    ).map(async ([algorithm, key], i) => {
      const r = await aesGcm.encrypt(MSG, key, { iv: FIXED_IV, aad: CTX });
      return {
        id: `aes-gcm-${i + 1}`,
        algorithm,
        key: hex(key),
        iv: hex(FIXED_IV),
        aad: hex(CTX),
        plaintext: hex(MSG),
        ciphertext: hex(r.ciphertext),
        tag: hex(r.tag),
      };
    }),
  );
  vectors['chacha20_poly1305'] = await Promise.all(
    [MSG, new Uint8Array(0)].map(async (pt, i) => {
      const r = await chaCha20Poly1305.encrypt(pt, FIXED_KEY_32, {
        nonce: FIXED_IV,
        aad: i === 0 ? CTX : new Uint8Array(0),
      });
      return {
        id: i === 0 ? 'chacha-msg' : 'chacha-empty',
        key: hex(FIXED_KEY_32),
        nonce: hex(FIXED_IV),
        aad: i === 0 ? hex(CTX) : '',
        pt: hex(pt),
        ct: hex(r.ciphertext),
        tag: hex(r.tag),
      };
    }),
  );
  const gcm = await aesGcm.encrypt(MSG, FIXED_KEY_32, { iv: FIXED_IV, aad: CTX });
  vectors['aes_256_gcm'] = {
    ciphertext: hex(gcm.ciphertext),
    tag: hex(gcm.tag),
    iv: hex(gcm.iv),
  };
  const xnonce = hexToBytes('404142434445464748494a4b4c4d4e4f5051525354555657');
  const xchacha = await xchaChaPoly1305.encrypt(MSG, FIXED_KEY_32, {
    iv: xnonce,
    aad: CTX,
  });
  vectors['xchacha20_poly1305'] = {
    ciphertext: hex(xchacha.ciphertext),
    tag: hex(xchacha.tag),
    nonce: hex(xchacha.iv),
  };
  // CBC / ECB (sync block-mode facade) + MD5 / RC4 legacy vectors
  vectors['aes_cbc'] = [
    {
      id: 'cbc-none',
      key: hex(FIXED_KEY_32),
      iv: hex(FIXED_IV_16),
      plaintext: hex(PATTERN_48),
      ciphertext: hex(aesCbc.encrypt(FIXED_KEY_32, FIXED_IV_16, PATTERN_48, { padding: 'none' })),
      padding: 'none',
    },
    {
      id: 'cbc-pkcs7',
      key: hex(FIXED_KEY_32),
      iv: hex(FIXED_IV_16),
      plaintext: hex(MSG),
      ciphertext: hex(aesCbc.encrypt(FIXED_KEY_32, FIXED_IV_16, MSG)),
      padding: 'pkcs7',
    },
  ];
  vectors['aes_ecb'] = [
    {
      id: 'ecb-none',
      key: hex(FIXED_KEY_16),
      plaintext: hex(PATTERN_48),
      ciphertext: hex(aesEcb.encrypt(FIXED_KEY_16, PATTERN_48)),
      padding: 'none',
    },
    {
      id: 'ecb-pkcs7',
      key: hex(FIXED_KEY_16),
      plaintext: hex(MSG),
      ciphertext: hex(aesEcb.encrypt(FIXED_KEY_16, MSG, { padding: 'pkcs7' })),
      padding: 'pkcs7',
    },
  ];
  vectors['md5'] = SHA_INPUTS.map(([id, input]) => ({ id, input: hex(input), output: hex(md5.hashSync(input)) }));
  vectors['rc4'] = [
    {
      id: 'rc4-key16-msg',
      key: hex(FIXED_KEY_16),
      plaintext: hex(MSG),
      ciphertext: hex(rc4(FIXED_KEY_16, MSG)),
    },
    {
      id: 'rc4-key32-pattern',
      key: hex(FIXED_KEY_32),
      plaintext: hex(PATTERN_48),
      ciphertext: hex(rc4(FIXED_KEY_32, PATTERN_48)),
    },
  ];
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
  const sigEmpty = await ed25519.sign(new Uint8Array(0), kp.privateKey);
  vectors['ed25519'] = [
    {
      id: 'ed25519-seed-msg',
      private_key: hex(seed),
      public_key: hex(kp.publicKey),
      message: hex(MSG),
      signature: hex(sig),
    },
    {
      id: 'ed25519-seed-empty',
      private_key: hex(seed),
      public_key: hex(kp.publicKey),
      message: '',
      signature: hex(sigEmpty),
    },
  ];
  const alicePriv = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const bobPub = hexToBytes('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  vectors['x25519'] = hex(await ecdhX25519.computeSharedSecret(alicePriv, bobPub));
  // Envelope (deterministic only in structure — DEK is random, so store shape)
  const env = await envelopeEncrypt.encrypt(MSG, FIXED_KEY_32, 'kek-1', CTX);
  const round = await envelopeEncrypt.decrypt(
    env.encryptedData,
    env.encryptedKey,
    FIXED_KEY_32,
    CTX,
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
