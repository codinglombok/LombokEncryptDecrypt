import { aesXtsEncrypt, aesXtsDecrypt } from './modes/xts.js';

export const xtsAes = { encrypt: aesXtsEncrypt, decrypt: aesXtsDecrypt };
export {
  aesXtsEncrypt as xtsEncryptSector,
  aesXtsDecrypt as xtsDecryptSector,
} from './modes/xts.js';
export { aesGcm } from './modes/gcm.js';
export { chaCha20Poly1305 } from './modes/chacha.js';
export { xchaChaPoly1305 } from './core/chacha/xchacha20.js';
export { sm4 } from './core/sm/sm4.js';
export { aesCbc, aesEcb } from './modes/cbc.js';
