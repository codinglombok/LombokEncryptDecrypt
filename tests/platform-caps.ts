/**
 * Runtime capability probes for OpenSSL-interop test gating.
 *
 * The library itself is pure TypeScript; these probes only decide whether a
 * given runtime can serve as the *reference* implementation for
 * cross-checks (e.g. Deno's node:crypto polyfill lacks SM3, ChaCha20-Poly1305
 * and even AES-GCM via createCipheriv, while Bun's BoringSSL lacks X448).
 */

import { createCipheriv, createHash, generateKeyPairSync } from 'node:crypto';
import type { CipherGCM } from 'node:crypto';

function probe(fn: () => unknown): boolean {
  try {
    fn();
    return true;
  } catch {
    return false;
  }
}

/**
 * Probe every key size the interop tests iterate over — runtimes such as
 * Deno's node:crypto polyfill support aes-128/256 but reject aes-192.
 */
function probeAllAes(mode: 'gcm' | 'cbc'): boolean {
  return [128, 192, 256].every((bits) =>
    probe(() => {
      const name = `aes-${bits}-${mode}`;
      const key = new Uint8Array(bits / 8);
      const iv = new Uint8Array(mode === 'gcm' ? 12 : 16);
      const c = createCipheriv(name, key, iv) as CipherGCM;
      if (mode === 'gcm') {
        c.setAAD(new Uint8Array(4));
        c.update(new Uint8Array(4));
        c.final();
        c.getAuthTag();
      } else {
        c.setAutoPadding(false);
        if (c.update(new Uint8Array(16)).length !== 16) throw new Error('short output');
      }
    }),
  );
}

/** OpenSSL-compatible AES-GCM via node:crypto (all key sizes). */
export const hasNodeAesGcm = probeAllAes('gcm');

/** OpenSSL-compatible SM3 digest. */
export const hasNodeSm3 = probe(() => createHash('sm3').update('x').digest());

/** OpenSSL-compatible ChaCha20-Poly1305 via node:crypto. */
export const hasNodeChacha = probe(() =>
  createCipheriv('chacha20-poly1305', new Uint8Array(32), new Uint8Array(12), {
    authTagLength: 16,
  }),
);

/** X448 key generation (absent in Bun's BoringSSL). */
export const hasX448 = probe(() => generateKeyPairSync('x448'));

/** CBC without padding quirks (node:crypto present, all key sizes). */
export const hasNodeAesCbc = probeAllAes('cbc');
