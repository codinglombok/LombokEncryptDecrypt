// LombokEncryptDecrypt — AES-NI + NEON acceleration
// Reference: NIST FIPS 197, Intel AES-NI whitepaper

use crate::ct::zeroize_slice;

/// AES round key schedule (software fallback or AES-NI)
#[derive(Clone)]
pub struct AesKey {
    /// Round keys (11/13/15 × 16 bytes for 128/192/256-bit key)
    pub round_keys: Vec<[u8; 16]>,
    pub key_bits: usize,
}

impl Drop for AesKey {
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            zeroize_slice(rk);
        }
    }
}

#[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
mod aes_ni_impl {
    use core::arch::x86_64::*;
    use super::AesKey;

    /// AES-256 key expansion using AES-NI intrinsics
    /// # Safety
    /// Requires `aes` and `sse4.1` CPU features.
    #[target_feature(enable = "aes,sse4.1")]
    pub unsafe fn expand_key_256(key: &[u8; 32]) -> AesKey {
        let mut round_keys = Vec::with_capacity(15);
        let mut k0 = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        let mut k1 = _mm_loadu_si128(key[16..].as_ptr() as *const __m128i);
        let mut store = [0u8; 16];

        macro_rules! push {
            ($k:expr) => {
                _mm_storeu_si128(store.as_mut_ptr() as *mut __m128i, $k);
                round_keys.push(store);
            };
        }

        push!(k0); push!(k1);

        macro_rules! expand {
            ($rcon:expr, $k0:ident, $k1:ident) => {{
                let tmp = _mm_aeskeygenassist_si128($k1, $rcon);
                let tmp = _mm_shuffle_epi32(tmp, 0xFF);
                $k0 = _mm_xor_si128($k0, _mm_slli_si128($k0, 4));
                $k0 = _mm_xor_si128($k0, _mm_slli_si128($k0, 8));
                $k0 = _mm_xor_si128($k0, tmp);
                push!($k0);
                let tmp2 = _mm_aeskeygenassist_si128($k0, 0);
                let tmp2 = _mm_shuffle_epi32(tmp2, 0xAA);
                $k1 = _mm_xor_si128($k1, _mm_slli_si128($k1, 4));
                $k1 = _mm_xor_si128($k1, _mm_slli_si128($k1, 8));
                $k1 = _mm_xor_si128($k1, tmp2);
                push!($k1);
            }};
        }

        expand!(0x01, k0, k1); expand!(0x02, k0, k1); expand!(0x04, k0, k1);
        expand!(0x08, k0, k1); expand!(0x10, k0, k1); expand!(0x20, k0, k1);
        // Final round key (AES-256 has 15 round keys total)
        let tmp = _mm_aeskeygenassist_si128(k1, 0x40);
        let tmp = _mm_shuffle_epi32(tmp, 0xFF);
        k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 4));
        k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 8));
        k0 = _mm_xor_si128(k0, tmp);
        push!(k0);

        AesKey { round_keys, key_bits: 256 }
    }

    /// AES-NI single-block encrypt
    /// # Safety
    /// Requires `aes` and `sse2` CPU features.
    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn aes_encrypt_block_ni(block: &[u8; 16], key: &AesKey) -> [u8; 16] {
        let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        let nr = key.round_keys.len() - 1;

        state = _mm_xor_si128(state, _mm_loadu_si128(key.round_keys[0].as_ptr() as *const __m128i));
        for i in 1..nr {
            state = _mm_aesenc_si128(state, _mm_loadu_si128(key.round_keys[i].as_ptr() as *const __m128i));
        }
        state = _mm_aesenclast_si128(state, _mm_loadu_si128(key.round_keys[nr].as_ptr() as *const __m128i));

        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, state);
        out
    }

    /// AES-NI GCM encrypt — processes 4 blocks in parallel (pipeline)
    #[target_feature(enable = "aes,sse2,pclmulqdq")]
    pub unsafe fn aes_gcm_encrypt_4blocks_ni(
        blocks: &[[u8; 16]; 4],
        key: &AesKey,
    ) -> [[u8; 16]; 4] {
        let mut states: [__m128i; 4] = [
            _mm_loadu_si128(blocks[0].as_ptr() as *const __m128i),
            _mm_loadu_si128(blocks[1].as_ptr() as *const __m128i),
            _mm_loadu_si128(blocks[2].as_ptr() as *const __m128i),
            _mm_loadu_si128(blocks[3].as_ptr() as *const __m128i),
        ];

        let rk0 = _mm_loadu_si128(key.round_keys[0].as_ptr() as *const __m128i);
        for s in &mut states { *s = _mm_xor_si128(*s, rk0); }

        let nr = key.round_keys.len() - 1;
        for i in 1..nr {
            let rk = _mm_loadu_si128(key.round_keys[i].as_ptr() as *const __m128i);
            for s in &mut states { *s = _mm_aesenc_si128(*s, rk); }
        }
        let rk_last = _mm_loadu_si128(key.round_keys[nr].as_ptr() as *const __m128i);
        for s in &mut states { *s = _mm_aesenclast_si128(*s, rk_last); }

        let mut out = [[0u8; 16]; 4];
        for (i, s) in states.iter().enumerate() {
            _mm_storeu_si128(out[i].as_mut_ptr() as *mut __m128i, *s);
        }
        out
    }
}

#[cfg(all(feature = "neon", target_arch = "aarch64"))]
mod aes_neon_impl {
    use core::arch::aarch64::*;
    use super::AesKey;

    /// AES single-block encrypt using ARM AES instructions
    /// # Safety
    /// Requires `aes` CPU feature.
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_encrypt_block_neon(block: &[u8; 16], key: &AesKey) -> [u8; 16] {
        let mut state = vld1q_u8(block.as_ptr());
        let nr = key.round_keys.len() - 1;

        // AddRoundKey(0)
        state = veorq_u8(state, vld1q_u8(key.round_keys[0].as_ptr()));

        // Rounds 1..nr-1: SubBytes + ShiftRows + MixColumns + AddRoundKey
        for i in 1..nr {
            state = vaeseq_u8(state, vdupq_n_u8(0)); // SubBytes + ShiftRows
            state = vaesmcq_u8(state);               // MixColumns
            state = veorq_u8(state, vld1q_u8(key.round_keys[i].as_ptr())); // AddRoundKey
        }

        // Final round (no MixColumns)
        state = vaeseq_u8(state, vdupq_n_u8(0));
        state = veorq_u8(state, vld1q_u8(key.round_keys[nr].as_ptr()));

        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), state);
        out
    }
}

// ── Public dispatch function ──────────────────────────────────────────────

/// Encrypt a single AES block, dispatching to AES-NI/NEON/software.
pub fn encrypt_block(block: &[u8; 16], key: &AesKey) -> [u8; 16] {
    #[cfg(all(feature = "aes-ni", target_arch = "x86_64"))]
    if crate::has_aes_ni() {
        return unsafe { aes_ni_impl::aes_encrypt_block_ni(block, key) };
    }

    #[cfg(all(feature = "neon", target_arch = "aarch64"))]
    {
        return unsafe { aes_neon_impl::aes_encrypt_block_neon(block, key) };
    }

    // Software fallback — calls the pure Rust AES implementation
    crate::aes::software::encrypt_block(block, key)
}
