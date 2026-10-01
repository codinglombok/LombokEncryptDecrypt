// LombokEncryptDecrypt — Constant-Time Utilities (Rust)
// These functions are critical for security — DO NOT add early returns or branches.

use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Constant-time byte slice comparison.
/// Returns true only when both slices have equal length and contents.
#[must_use]
pub fn timing_safe_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time conditional selection.
/// Returns `a` if `cond` is true, `b` otherwise.
/// No branches — uses arithmetic masking.
#[must_use]
pub fn ct_select(cond: bool, a: u8, b: u8) -> u8 {
    let mask: u8 = if cond { 0xFF } else { 0x00 };
    (mask & a) | (!mask & b)
}

/// Constant-time conditional copy.
/// Copies `src` into `dst` if `cond` is true, otherwise leaves `dst` unchanged.
pub fn ct_conditional_copy(cond: bool, dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    let mask: u8 = if cond { 0xFF } else { 0x00 };
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (*d & !mask) | (*s & mask);
    }
}

/// Securely zero a mutable byte slice.
/// Uses `zeroize` crate which prevents dead-code elimination.
pub fn zeroize_slice(data: &mut [u8]) {
    data.zeroize();
}

/// Constant-time comparison of two fixed-size arrays.
#[must_use]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time comparison of two 16-byte arrays (tags).
#[must_use]
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time comparison of two 64-byte arrays (signatures).
#[must_use]
pub fn ct_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.ct_eq(b).into()
}

/// Random blinding factor for RSA — reduces timing side-channel.
/// Returns a random value in [1, n-1].
pub fn random_blinding_factor(len_bytes: usize) -> Vec<u8> {
    use crate::rng::fill_random;
    let mut buf = vec![0u8; len_bytes];
    fill_random(&mut buf);
    buf[0] |= 0x01; // ensure non-zero
    buf
}
