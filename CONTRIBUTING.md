# Contributing to LombokEncryptDecrypt

Thank you for contributing! Please read this before opening a PR.

## Ground Rules

1. **No external crypto dependencies in core** — zero-dep is a hard requirement. The `core/` module must compile without any third-party packages.
2. **NIST test vectors required** — every new algorithm must pass NIST CAVP/ACVP or RFC-published test vectors. No exceptions.
3. **Constant-time for all secret-dependent operations** — no secret-dependent branches, no secret-dependent memory access. Verified by `dudect` for new primitives.
4. **Cross-language parity** — a change to the TypeScript implementation must be reflected in the Rust crate. Port changes propagate to other languages in the next sprint.
5. **Coverage ≥ 95%** — PRs that drop coverage below 95% will not be merged.
6. **Apache 2.0 only** — do not introduce MIT-only, GPL, or proprietary licensed code.

## Development Setup

```bash
# Clone
git clone https://github.com/codinglombok/LombokEncryptDecrypt.git
cd LombokEncryptDecrypt

# TypeScript
npm install
npm run build
npm test

# Rust
cargo build --features full
cargo test --features full
cargo clippy --features full -- -D warnings

# WASM
cd src-rust && wasm-pack build --target web
```

## Adding a New Algorithm

1. Create `src/core/<name>/<name>.ts` with pure TypeScript implementation
2. Add NIST/RFC test vectors to `tests/vectors/`
3. Create `tests/unit/<name>.test.ts` with full vector coverage
4. Add Rust implementation in `src-rust/<name>.rs`
5. Add to `src/index.ts` barrel export
6. Update `docs/API.md`
7. Update `CHANGELOG.md` under `[Unreleased]`

## Adding a Language Port

1. Implement in `ports/<language>/`
2. Add cross-language vector test in `tests/integration/cross_language_vectors.test.ts`
3. Add port CI workflow in `.github/workflows/<language>.yml`
4. Add publish workflow in `.github/workflows/publish_<registry>.yml`
5. Update `docs/masterplan_repo.md` and `map/strukture_folder_repo.md`

## Commit Convention

```
feat(aes-gcm): add AES-256-GCM streaming mode
fix(kyber): correct NTT butterfly indexing
test(ed25519): add RFC 8032 test vector #5
docs(api): document keystore.rotate() method
chore(ci): add PHP 8.4 to test matrix
```

## Pull Request Checklist

- [ ] NIST/RFC test vectors pass
- [ ] `npm test` passes (all Node versions)
- [ ] `cargo test --features full` passes
- [ ] `cargo clippy` — no warnings
- [ ] `npm run lint` — no warnings
- [ ] Coverage ≥ 95%
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] No new external dependencies introduced in core
- [ ] Side-channel analysis done (if touching crypto primitives)
