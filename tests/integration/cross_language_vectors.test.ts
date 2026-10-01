/**
 * LombokEncryptDecrypt — Cross-Language Test Vector Verification
 *
 * Verifies that the TypeScript implementation produces byte-identical output
 * to the shared test vectors in lombokencryptdecrypt-vectors-v1.json.
 * All other language ports must pass the same vectors in their own CI.
 */

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { aesGcm } from '../../src/modes/gcm.js';
import { chaCha20Poly1305 } from '../../src/core/chacha/chacha20.js';
import { ed25519 } from '../../src/core/ecc/ed25519.js';
import { hmacSha256 } from '../../src/mac/hmac.js';
import { hkdf } from '../../src/kdf/hkdf.js';
import { hexToBytes, bytesToHex } from '../../src/utils/encoding.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = resolve(__dirname, '../vectors/lombokencryptdecrypt-vectors-v1.json');

interface VectorFile {
  _meta: { version: number; library: string };
  aes_gcm: Array<{
    id: string; algorithm: string; key: string; iv: string;
    aad: string; plaintext: string; ciphertext: string; tag: string;
  }>;
  chacha20_poly1305: Array<{
    id: string; key: string; nonce: string; aad: string;
    pt: string; ct: string; tag: string;
  }>;
  sha256: Array<{ id: string; input: string; output: string }>;
  ed25519: Array<{
    id: string; private_key: string; public_key: string; message: string; signature: string;
  }>;
  hmac_sha256: Array<{ id: string; key: string; message: string; output: string }>;
  hkdf_sha256: Array<{
    id: string; ikm: string; salt: string; info: string; length: number; okm: string;
  }>;
}

const vectors: VectorFile = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));

describe('Cross-Language Test Vectors — TypeScript Reference Implementation', () => {

  describe('AES-GCM vectors', () => {
    for (const v of vectors.aes_gcm) {
      it(`${v.id} — encrypt`, async () => {
        const key       = hexToBytes(v.key);
        const iv        = hexToBytes(v.iv);
        const aad       = v.aad ? hexToBytes(v.aad) : undefined;
        const plaintext = v.plaintext ? hexToBytes(v.plaintext) : new Uint8Array(0);

        const result = await aesGcm.encrypt(plaintext, key, { iv, aad });
        expect(bytesToHex(result.ciphertext)).toBe(v.ciphertext);
        expect(bytesToHex(result.tag)).toBe(v.tag);
      });

      it(`${v.id} — decrypt`, async () => {
        const key        = hexToBytes(v.key);
        const iv         = hexToBytes(v.iv);
        const aad        = v.aad ? hexToBytes(v.aad) : undefined;
        const ciphertext = v.ciphertext ? hexToBytes(v.ciphertext) : new Uint8Array(0);
        const tag        = hexToBytes(v.tag);
        const expected   = v.plaintext ? hexToBytes(v.plaintext) : new Uint8Array(0);

        const pt = await aesGcm.decrypt(ciphertext, key, iv, tag, { aad });
        expect(bytesToHex(pt)).toBe(bytesToHex(expected));
      });
    }
  });

  describe('ChaCha20-Poly1305 vectors', () => {
    for (const v of vectors.chacha20_poly1305) {
      it(`${v.id} — encrypt`, async () => {
        const key   = hexToBytes(v.key);
        const nonce = hexToBytes(v.nonce);
        const aad   = v.aad ? hexToBytes(v.aad) : undefined;
        const pt    = hexToBytes(v.pt);

        const result = await chaCha20Poly1305.encrypt(pt, key, { iv: nonce, aad });
        expect(bytesToHex(result.ciphertext)).toBe(v.ct);
        expect(bytesToHex(result.tag)).toBe(v.tag);
      });

      it(`${v.id} — decrypt`, async () => {
        const key   = hexToBytes(v.key);
        const nonce = hexToBytes(v.nonce);
        const aad   = v.aad ? hexToBytes(v.aad) : undefined;
        const ct    = hexToBytes(v.ct);
        const tag   = hexToBytes(v.tag);
        const expected = hexToBytes(v.pt);

        const pt = await chaCha20Poly1305.decrypt(ct, key, nonce, tag, { aad });
        expect(bytesToHex(pt)).toBe(bytesToHex(expected));
      });
    }
  });

  describe('Ed25519 vectors', () => {
    for (const v of vectors.ed25519) {
      it(`${v.id} — sign`, async () => {
        const privateKey = hexToBytes(v.private_key);
        const message    = v.message ? hexToBytes(v.message) : new Uint8Array(0);
        const sig        = await ed25519.sign(message, privateKey);
        expect(bytesToHex(sig)).toBe(v.signature);
      });

      it(`${v.id} — verify`, async () => {
        const publicKey = hexToBytes(v.public_key);
        const message   = v.message ? hexToBytes(v.message) : new Uint8Array(0);
        const signature = hexToBytes(v.signature);
        const valid     = await ed25519.verify(message, signature, publicKey);
        expect(valid).toBe(true);
      });
    }
  });

  describe('HMAC-SHA256 vectors', () => {
    for (const v of vectors.hmac_sha256) {
      it(v.id, async () => {
        const key     = hexToBytes(v.key);
        const message = hexToBytes(v.message);
        const mac     = await hmacSha256.compute(key, message);
        expect(bytesToHex(mac)).toBe(v.output);
      });
    }
  });

  describe('HKDF-SHA256 vectors', () => {
    for (const v of vectors.hkdf_sha256) {
      it(v.id, async () => {
        const ikm  = hexToBytes(v.ikm);
        const salt = v.salt ? hexToBytes(v.salt) : undefined;
        const info = v.info ? hexToBytes(v.info) : new Uint8Array(0);
        const okm  = await hkdf.derive(ikm, { hash: 'SHA-256', salt, info, outputLength: v.length });
        expect(bytesToHex(okm)).toBe(v.okm);
      });
    }
  });

  it('vector file metadata', () => {
    expect(vectors._meta.library).toBe('LombokEncryptDecrypt');
    expect(vectors._meta.version).toBe(1);
  });
});
