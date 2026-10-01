/**
 * LombokEncryptDecrypt — C/C++ Public Header
 * Universal encrypt/decrypt library (C API via cbindgen from Rust core)
 * License: Apache-2.0 | Author: codinglombok | Version: 0.1.0
 *
 * Usage (C):
 *   #include <lombokencryptdecrypt/lombokencryptdecrypt.h>
 *   // Link with -llombokencryptdecrypt
 *
 * Usage (CMake):
 *   find_package(LombokEncryptDecrypt REQUIRED)
 *   target_link_libraries(mytarget LombokEncryptDecrypt::lombokencryptdecrypt)
 */

#ifndef LOMBOKENCRYPTDECRYPT_H
#define LOMBOKENCRYPTDECRYPT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Version ─────────────────────────────────────────────────────────── */

#define LED_VERSION_MAJOR 0
#define LED_VERSION_MINOR 1
#define LED_VERSION_PATCH 0
#define LED_VERSION_STR   "0.1.0"

const char* led_version(void);

/* ── Error codes ─────────────────────────────────────────────────────── */

typedef enum {
    LED_OK                      = 0,
    LED_ERR_INVALID_KEY_SIZE    = 1,
    LED_ERR_INVALID_IV_SIZE     = 2,
    LED_ERR_INVALID_TAG_SIZE    = 3,
    LED_ERR_INVALID_INPUT       = 4,
    LED_ERR_AUTHENTICATION_FAIL = 5,
    LED_ERR_BUFFER_TOO_SMALL    = 6,
    LED_ERR_NOT_SUPPORTED       = 7,
    LED_ERR_INTERNAL            = 99,
} led_error_t;

/** Get a human-readable description for an error code. */
const char* led_error_string(led_error_t err);

/* ── AES-GCM ─────────────────────────────────────────────────────────── */

/**
 * AES-GCM encrypt.
 *
 * @param plaintext      Input data
 * @param plaintext_len  Length of input data
 * @param key            AES key (16, 24, or 32 bytes)
 * @param key_len        Key length in bytes
 * @param iv             12-byte IV (must be random and unique per encryption)
 * @param aad            Additional authenticated data (may be NULL)
 * @param aad_len        AAD length (0 if aad is NULL)
 * @param ciphertext     Output buffer (must be at least plaintext_len bytes)
 * @param tag            Output 16-byte authentication tag
 *
 * @return LED_OK on success, error code otherwise
 */
led_error_t led_aes_gcm_encrypt(
    const uint8_t* plaintext,  size_t plaintext_len,
    const uint8_t* key,        size_t key_len,
    const uint8_t  iv[12],
    const uint8_t* aad,        size_t aad_len,
    uint8_t*       ciphertext,          /* out: must be ≥ plaintext_len */
    uint8_t        tag[16]              /* out */
);

/**
 * AES-GCM decrypt and verify.
 *
 * @param ciphertext     Encrypted data
 * @param ciphertext_len Length of ciphertext
 * @param key            AES key
 * @param key_len        Key length
 * @param iv             12-byte IV used during encryption
 * @param tag            16-byte authentication tag from encryption
 * @param aad            Additional authenticated data (may be NULL)
 * @param aad_len        AAD length
 * @param plaintext      Output buffer (must be ≥ ciphertext_len bytes)
 *
 * @return LED_OK on success, LED_ERR_AUTHENTICATION_FAIL on tag mismatch
 */
led_error_t led_aes_gcm_decrypt(
    const uint8_t* ciphertext,  size_t ciphertext_len,
    const uint8_t* key,         size_t key_len,
    const uint8_t  iv[12],
    const uint8_t  tag[16],
    const uint8_t* aad,         size_t aad_len,
    uint8_t*       plaintext              /* out: must be ≥ ciphertext_len */
);

/* ── ChaCha20-Poly1305 ───────────────────────────────────────────────── */

led_error_t led_chacha20_poly1305_encrypt(
    const uint8_t* plaintext,  size_t plaintext_len,
    const uint8_t  key[32],
    const uint8_t  nonce[12],
    const uint8_t* aad,        size_t aad_len,
    uint8_t*       ciphertext,
    uint8_t        tag[16]
);

led_error_t led_chacha20_poly1305_decrypt(
    const uint8_t* ciphertext,  size_t ciphertext_len,
    const uint8_t  key[32],
    const uint8_t  nonce[12],
    const uint8_t  tag[16],
    const uint8_t* aad,         size_t aad_len,
    uint8_t*       plaintext
);

/* ── Ed25519 ─────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t private_key[32]; /* 32-byte seed */
    uint8_t public_key[32];  /* 32-byte compressed point */
} led_ed25519_keypair_t;

led_error_t led_ed25519_generate_keypair(led_ed25519_keypair_t* keypair);

led_error_t led_ed25519_sign(
    const uint8_t* message,      size_t message_len,
    const uint8_t  private_key[32],
    uint8_t        signature[64]  /* out */
);

/**
 * @return true if signature is valid, false otherwise
 */
bool led_ed25519_verify(
    const uint8_t* message,      size_t message_len,
    const uint8_t  signature[64],
    const uint8_t  public_key[32]
);

/* ── ML-KEM-768 (Kyber) ──────────────────────────────────────────────── */

#define LED_KYBER768_PK_SIZE  1184
#define LED_KYBER768_SK_SIZE  2400
#define LED_KYBER768_CT_SIZE  1088
#define LED_KYBER768_SS_SIZE  32

typedef struct {
    uint8_t public_key[LED_KYBER768_PK_SIZE];
    uint8_t secret_key[LED_KYBER768_SK_SIZE];
} led_kyber768_keypair_t;

typedef struct {
    uint8_t ciphertext[LED_KYBER768_CT_SIZE];
    uint8_t shared_secret[LED_KYBER768_SS_SIZE];
} led_kyber768_encap_result_t;

led_error_t led_kyber768_generate_keypair(led_kyber768_keypair_t* keypair);
led_error_t led_kyber768_encapsulate(const uint8_t pk[LED_KYBER768_PK_SIZE], led_kyber768_encap_result_t* result);
led_error_t led_kyber768_decapsulate(
    const uint8_t ct[LED_KYBER768_CT_SIZE],
    const uint8_t sk[LED_KYBER768_SK_SIZE],
    uint8_t       shared_secret[LED_KYBER768_SS_SIZE]
);

/* ── Hash functions ──────────────────────────────────────────────────── */

/** SHA-256: output is always 32 bytes */
led_error_t led_sha256(const uint8_t* data, size_t len, uint8_t output[32]);

/** SHA-512: output is always 64 bytes */
led_error_t led_sha512(const uint8_t* data, size_t len, uint8_t output[64]);

/** SHA3-256: output is always 32 bytes */
led_error_t led_sha3_256(const uint8_t* data, size_t len, uint8_t output[32]);

/** BLAKE3: output_len bytes (recommended 32) */
led_error_t led_blake3(const uint8_t* data, size_t data_len, uint8_t* output, size_t output_len);

/** SM3 (GM/T 0004): output is always 32 bytes */
led_error_t led_sm3(const uint8_t* data, size_t len, uint8_t output[32]);

/* ── MAC ─────────────────────────────────────────────────────────────── */

/** HMAC-SHA256: output is always 32 bytes */
led_error_t led_hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* message, size_t message_len,
    uint8_t output[32]
);

/** Constant-time HMAC-SHA256 verification */
bool led_hmac_sha256_verify(
    const uint8_t* key, size_t key_len,
    const uint8_t* message, size_t message_len,
    const uint8_t  expected[32]
);

/* ── KDF ─────────────────────────────────────────────────────────────── */

/** HKDF-SHA256 (RFC 5869) */
led_error_t led_hkdf_sha256(
    const uint8_t* ikm,  size_t ikm_len,
    const uint8_t* salt, size_t salt_len,
    const uint8_t* info, size_t info_len,
    uint8_t*       output, size_t output_len
);

/** PBKDF2-SHA256 (RFC 8018) */
led_error_t led_pbkdf2_sha256(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt,     size_t salt_len,
    uint32_t       iterations,
    uint8_t*       output,   size_t output_len
);

/**
 * Argon2id hash (RFC 9106).
 * @param output_phc Output buffer for PHC string (at least 128 bytes)
 */
led_error_t led_argon2id_hash(
    const uint8_t* password, size_t password_len,
    uint32_t m_cost,  /* memory in KiB */
    uint32_t t_cost,  /* time cost */
    uint32_t p_cost,  /* parallelism */
    char*    output_phc, size_t output_phc_len
);

/** Constant-time Argon2id verify */
bool led_argon2id_verify(const char* phc_hash, const uint8_t* password, size_t password_len);

/* ── Random ──────────────────────────────────────────────────────────── */

/** Fill buffer with CSPRNG bytes. */
led_error_t led_random_bytes(uint8_t* buf, size_t len);

/* ── Constant-time comparison ────────────────────────────────────────── */

/** Constant-time memory comparison (no short-circuit). */
bool led_timing_safe_equal(const uint8_t* a, const uint8_t* b, size_t len);

/* ── Capability detection ────────────────────────────────────────────── */

typedef struct {
    bool has_aes_ni;
    bool has_sha_ni;
    bool has_avx2;
    bool has_neon;
    bool has_post_quantum;
} led_capabilities_t;

led_capabilities_t led_get_capabilities(void);

#ifdef __cplusplus
} /* extern "C" */

/* ── C++ wrapper ─────────────────────────────────────────────────────── */

#include <vector>
#include <string>
#include <tuple>
#include <stdexcept>

namespace LombokEncryptDecrypt {

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(led_error_t code, const std::string& msg)
        : std::runtime_error(msg), code_(code) {}
    led_error_t code() const noexcept { return code_; }
private:
    led_error_t code_;
};

inline void check(led_error_t err) {
    if (err != LED_OK) throw CryptoError(err, led_error_string(err));
}

class AesGcm {
public:
    struct EncryptResult { std::vector<uint8_t> ciphertext, tag, iv; };

    static EncryptResult encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        std::vector<uint8_t> iv = {},
        const std::vector<uint8_t>& aad = {}
    ) {
        if (iv.empty()) {
            iv.resize(12);
            check(led_random_bytes(iv.data(), 12));
        }
        std::vector<uint8_t> ct(plaintext.size());
        std::vector<uint8_t> tag(16);
        check(led_aes_gcm_encrypt(
            plaintext.data(), plaintext.size(),
            key.data(), key.size(),
            iv.data(),
            aad.empty() ? nullptr : aad.data(), aad.size(),
            ct.data(), tag.data()
        ));
        return {ct, tag, iv};
    }

    static std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& aad = {}
    ) {
        std::vector<uint8_t> pt(ciphertext.size());
        check(led_aes_gcm_decrypt(
            ciphertext.data(), ciphertext.size(),
            key.data(), key.size(),
            iv.data(), tag.data(),
            aad.empty() ? nullptr : aad.data(), aad.size(),
            pt.data()
        ));
        return pt;
    }

    static std::vector<uint8_t> generateKey(int bits = 256) {
        std::vector<uint8_t> key(bits / 8);
        check(led_random_bytes(key.data(), key.size()));
        return key;
    }
};

} /* namespace LombokEncryptDecrypt */

#endif /* __cplusplus */
#endif /* LOMBOKENCRYPTDECRYPT_H */
