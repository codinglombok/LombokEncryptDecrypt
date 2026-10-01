# Security Policy — LombokEncryptDecrypt

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Active |
| < 0.1.0 | ❌ No     |

## Reporting a Vulnerability

**DO NOT** file a public GitHub issue for security vulnerabilities.

### Private Disclosure (Preferred)

Use GitHub's private security advisory:  
👉 **https://github.com/codinglombok/LombokEncryptDecrypt/security/advisories/new**

Or email: **security@codinglombok.dev**

Include:
- Affected module and version
- Vulnerability category (timing side-channel, incorrect authentication, etc.)
- Proof-of-concept (keep private — do not post publicly)
- CVSS score estimate if known
- Suggested fix if available

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgement | ≤ 48 hours |
| Initial assessment | ≤ 5 business days |
| Fix + patch release | ≤ 30 days (critical), ≤ 90 days (moderate) |
| Public disclosure | Coordinated with reporter |

## Legacy Algorithm Policy

The following algorithms are present for interoperability only and are **disabled by default**:

| Algorithm | Risk | Default | Enable with |
|-----------|------|---------|-------------|
| MD5 | Broken (collision) | ❌ Disabled | `{ legacy: true }` |
| SHA-1 | Weak | ❌ Disabled | `{ legacy: true }` |
| RC4 | Broken | ❌ Disabled | `{ legacy: true }` |
| RSA-PKCS1v1.5 | Padding oracle risk | ❌ Disabled | `{ legacy: true }` |
| DES / 3DES | Too short key | ❌ Not included | N/A |

**FIPS mode** (`{ fips: true }`) disables all legacy algorithms and enforces the NIST FIPS 140-3 algorithm set.

## Side-Channel Resistance

All crypto-critical code paths are:
- **Constant-time** — no secret-dependent branches or memory access patterns
- **Blinded** — RSA operations use random blinding factors per call
- **Masked** — AES S-box computed with randomized masking (DPA countermeasure)
- **Statistically verified** — `dudect` leakage test runs in nightly CI for AES-GCM, RSA-OAEP, Ed25519, Kyber768

To run side-channel tests locally:
```bash
cargo test --features full -- dudect --nocapture
```

## CVE History

No known CVEs at v0.1.0 release (2026-09-18).

All dependencies audited:
```bash
npm audit --audit-level=moderate
cargo audit --deny warnings
safety check  # Python
govulncheck ./...  # Go
```
