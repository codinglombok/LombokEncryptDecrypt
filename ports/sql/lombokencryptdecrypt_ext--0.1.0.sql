-- lombokencryptdecrypt_ext--0.1.0.sql
-- LombokEncryptDecrypt PostgreSQL Extension
-- Schema: lombok_crypto
-- License: Apache-2.0

\echo Use "CREATE EXTENSION lombokencryptdecrypt_ext" to load this file. \quit

CREATE SCHEMA IF NOT EXISTS lombok_crypto;

-- ============================================================
-- AES-256-GCM Encrypt / Decrypt
-- ============================================================

-- aes_gcm_encrypt(plaintext, key_hex, aad)
-- Returns bytea: 12-byte IV || ciphertext || 16-byte tag
CREATE OR REPLACE FUNCTION lombok_crypto.aes_gcm_encrypt(
    plaintext  bytea,
    key_hex    text,
    aad        bytea DEFAULT NULL
)
RETURNS bytea
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_aes_gcm_encrypt'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

COMMENT ON FUNCTION lombok_crypto.aes_gcm_encrypt IS
'AES-256-GCM encrypt. key_hex must be 64 hex chars (256-bit). Returns IV||ciphertext||tag.';

-- aes_gcm_decrypt(ciphertext_with_iv_tag, key_hex, aad)
CREATE OR REPLACE FUNCTION lombok_crypto.aes_gcm_decrypt(
    ciphertext bytea,
    key_hex    text,
    aad        bytea DEFAULT NULL
)
RETURNS bytea
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_aes_gcm_decrypt'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

COMMENT ON FUNCTION lombok_crypto.aes_gcm_decrypt IS
'AES-256-GCM decrypt. Raises exception on authentication failure.';

-- ============================================================
-- HMAC-SHA256
-- ============================================================

CREATE OR REPLACE FUNCTION lombok_crypto.hmac_sha256(
    message  bytea,
    key_hex  text
)
RETURNS bytea
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_hmac_sha256'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

COMMENT ON FUNCTION lombok_crypto.hmac_sha256 IS
'HMAC-SHA-256. Returns 32-byte MAC.';

-- ============================================================
-- HMAC-SHA512
-- ============================================================

CREATE OR REPLACE FUNCTION lombok_crypto.hmac_sha512(
    message  bytea,
    key_hex  text
)
RETURNS bytea
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_hmac_sha512'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

COMMENT ON FUNCTION lombok_crypto.hmac_sha512 IS
'HMAC-SHA-512. Returns 64-byte MAC.';

-- ============================================================
-- Argon2id Password Hashing (for password columns)
-- ============================================================

-- argon2id_hash(password, salt_hex, m_cost, t_cost, p_cost)
-- Default: m=65536 (64MB), t=3, p=4
CREATE OR REPLACE FUNCTION lombok_crypto.argon2id_hash(
    password  text,
    salt_hex  text,
    m_cost    integer DEFAULT 65536,
    t_cost    integer DEFAULT 3,
    p_cost    integer DEFAULT 4
)
RETURNS text  -- PHC string format: $argon2id$v=19$m=...$...
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_argon2id_hash'
LANGUAGE C IMMUTABLE PARALLEL SAFE;

COMMENT ON FUNCTION lombok_crypto.argon2id_hash IS
'Argon2id password hash. Returns PHC string format. m_cost in KiB (default 65536 = 64MB).';

-- argon2id_verify(phc_hash, password)
CREATE OR REPLACE FUNCTION lombok_crypto.argon2id_verify(
    phc_hash  text,
    password  text
)
RETURNS boolean
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_argon2id_verify'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

COMMENT ON FUNCTION lombok_crypto.argon2id_verify IS
'Verify password against Argon2id PHC string. Constant-time comparison.';

-- ============================================================
-- SHA-256 / SHA-512 / BLAKE3
-- ============================================================

CREATE OR REPLACE FUNCTION lombok_crypto.sha256(data bytea)
RETURNS bytea
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_sha256'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION lombok_crypto.sha512(data bytea)
RETURNS bytea
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_sha512'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION lombok_crypto.blake3(data bytea)
RETURNS bytea
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_blake3'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

-- ============================================================
-- ChaCha20-Poly1305 Encrypt / Decrypt
-- ============================================================

CREATE OR REPLACE FUNCTION lombok_crypto.chacha20_poly1305_encrypt(
    plaintext  bytea,
    key_hex    text,
    aad        bytea DEFAULT NULL
)
RETURNS bytea  -- 12-byte nonce || ciphertext || 16-byte tag
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_chacha20_poly1305_encrypt'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION lombok_crypto.chacha20_poly1305_decrypt(
    ciphertext bytea,
    key_hex    text,
    aad        bytea DEFAULT NULL
)
RETURNS bytea
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_chacha20_poly1305_decrypt'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

-- ============================================================
-- Key Generation Helpers
-- ============================================================

-- Generate a cryptographically secure random key (hex)
CREATE OR REPLACE FUNCTION lombok_crypto.gen_key(bits integer DEFAULT 256)
RETURNS text  -- hex string
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_gen_key'
LANGUAGE C VOLATILE STRICT PARALLEL RESTRICTED;

COMMENT ON FUNCTION lombok_crypto.gen_key IS
'Generate a CSPRNG key. bits = 128, 192, or 256. Returns hex string.';

-- Generate a random salt (hex)
CREATE OR REPLACE FUNCTION lombok_crypto.gen_salt(bytes integer DEFAULT 16)
RETURNS text
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_gen_salt'
LANGUAGE C VOLATILE STRICT PARALLEL RESTRICTED;

-- ============================================================
-- Timing-Safe Comparison
-- ============================================================

CREATE OR REPLACE FUNCTION lombok_crypto.constant_time_eq(a bytea, b bytea)
RETURNS boolean
AS '$libdir/lombokencryptdecrypt_ext', 'lombok_constant_time_eq'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

COMMENT ON FUNCTION lombok_crypto.constant_time_eq IS
'Constant-time byte comparison. Use for MAC/HMAC verification to prevent timing attacks.';

-- ============================================================
-- Grant usage to public (configurable)
-- ============================================================
GRANT USAGE ON SCHEMA lombok_crypto TO PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA lombok_crypto TO PUBLIC;
