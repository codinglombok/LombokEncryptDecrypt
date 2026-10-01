---
name: Feature Request
about: Suggest a new algorithm, platform support, or feature
title: '[FEAT] '
labels: ['enhancement']
assignees: []
---

## Feature Category

- [ ] New Algorithm (symmetric / asymmetric / hash / MAC / KDF)
- [ ] New Post-Quantum Algorithm
- [ ] New Language Port
- [ ] New Platform Support (OS / hardware / embedded)
- [ ] New Registry / Package Manager
- [ ] Performance Improvement
- [ ] API Improvement (ergonomics, types, naming)
- [ ] Key Management Enhancement
- [ ] Hardware Integration (HSM / TPM / TEE)
- [ ] Streaming / Large File
- [ ] Compliance / Standards (FIPS / PCI-DSS / HIPAA)
- [ ] Documentation

---

## Description

A clear description of the feature you'd like to see.

## Algorithm / Standard (if applicable)

- Algorithm name:
- Standard reference: (e.g. NIST FIPS 203, RFC 9180, GM/T 0003)
- Test vectors available: Yes / No

## Use Case

Who needs this? Describe a concrete use case:

> Example: "I'm building a FIDO2 passkey server and need CBOR-encoded COSE keys imported directly into the KeyStore."

## Proposed API (TypeScript sketch)

```typescript
// TypeScript sketch of the desired API
import { newFeature } from 'lombokencryptdecrypt';

const result = await newFeature.doThing(input, key);
```

## Cross-Language Priority

Which language ports are most important for this feature?

- [ ] TypeScript / JavaScript
- [ ] Rust
- [ ] Python
- [ ] Go
- [ ] PHP
- [ ] Java / Kotlin
- [ ] .NET / C#
- [ ] Swift (iOS/macOS)
- [ ] C / C++
- [ ] SQL (PostgreSQL)
- [ ] Perl

## Alternatives Considered

Other approaches you've considered or existing libraries that partially solve this.

## Additional Context

Any other context, links, or references.
