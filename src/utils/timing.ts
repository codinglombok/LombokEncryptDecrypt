/**
 * LombokEncryptDecrypt — Constant-Time Utilities
 *
 * All MAC and signature verification MUST use timingSafeEqual.
 * Never use === or Array equality for comparing secrets.
 *
 * @module utils/timing
 */

/**
 * Constant-time comparison of two Uint8Arrays.
 * Returns true only if both arrays have the same length and content.
 * Runs in O(n) time regardless of where the first difference occurs.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    // Lengths differ — still do a dummy loop to avoid timing leak
    // (attacker might be able to detect early return via timing)
    let dummy = 0;
    for (let i = 0; i < a.byteLength; i++) {
      dummy |= (a[i] ?? 0);
    }
    return dummy === -1;  // always false, but compiler won't optimise away loop
  }

  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Constant-time selection: returns a if condition is true, b otherwise.
 * Avoids branch prediction leaks.
 */
export function ctSelect(condition: boolean, a: number, b: number): number {
  const mask = -(condition ? 1 : 0) | 0;   // 0xFFFFFFFF or 0x00000000
  return ((mask & a) | (~mask & b)) | 0;
}

/**
 * Constant-time conditional byte array copy.
 * Copies src into dst if condition is true, else leaves dst unchanged.
 * Both arrays must have the same length.
 */
export function ctConditionalCopy(condition: boolean, dst: Uint8Array, src: Uint8Array): void {
  const mask = condition ? 0xFF : 0x00;
  for (let i = 0; i < dst.length; i++) {
    dst[i] = ((dst[i] ?? 0) & ~mask) | ((src[i] ?? 0) & mask);
  }
}

/**
 * Zeroize (securely wipe) a Uint8Array.
 * Uses a loop that the JS engine cannot optimise away.
 */
export function zeroize(data: Uint8Array): void {
  for (let i = 0; i < data.length; i++) {
    data[i] = 0;
  }
  // Prevent dead-code elimination: read one byte back (opaque to optimiser)
  void data[0];
}

/**
 * Zeroize and copy: copy src to a new array, then zeroize src.
 */
export function zeroizeAfterCopy(src: Uint8Array): Uint8Array {
  const copy = new Uint8Array(src);
  zeroize(src);
  return copy;
}
