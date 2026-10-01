# LombokEncryptDecrypt — PostgreSQL Extension Makefile
# License: Apache-2.0

MODULE_big   = lombokencryptdecrypt_ext
EXTENSION    = lombokencryptdecrypt_ext
DATA         = lombokencryptdecrypt_ext--0.1.0.sql
PGFILEDESC   = "LombokEncryptDecrypt — AES-GCM/HMAC/Argon2id UDFs"

OBJS = \
	src/aes_gcm_udf.o \
	src/hmac_udf.o \
	src/argon2_udf.o \
	src/sha_udf.o \
	src/chacha_udf.o \
	src/random_udf.o

PG_CONFIG    ?= pg_config
PGXS         := $(shell $(PG_CONFIG) --pgxs)

# Rust static library (built via cargo)
RUST_LIB     = ../../target/release/liblombokencryptdecrypt.a

# Extra libraries
PG_LIBS      = -lssl -lcrypto
SHLIB_LINK   += $(RUST_LIB) $(PG_LIBS)

# Build flags
PG_CPPFLAGS  = -I../../ports/cpp/include
CFLAGS       += -O2 -Wall -Wextra -std=c11

include $(PGXS)

# ── Rust core build ───────────────────────────────────────────────────────

.PHONY: rust-core
rust-core:
	cd ../.. && cargo build --release --features "c_bindings" && echo "✅ Rust core built"

all: rust-core $(MODULE_big).so

# ── pgxnclient packaging ──────────────────────────────────────────────────

PGXN_VERSION = 0.1.0
PGXN_DIST    = lombokencryptdecrypt-$(PGXN_VERSION).zip

.PHONY: bundle
bundle:
	pgxn bundle
	@echo "✅ PGXN bundle: $(PGXN_DIST)"

.PHONY: release-pgxn
release-pgxn: bundle
	pgxn release $(PGXN_DIST)

# ── Test via pg_regress ───────────────────────────────────────────────────

REGRESS      = basic_encrypt decrypt_verify hmac argon2 sha
REGRESS_OPTS = --inputdir=test

test: installcheck

# ── Cleanup ───────────────────────────────────────────────────────────────

distclean: clean
	rm -f $(PGXN_DIST)
