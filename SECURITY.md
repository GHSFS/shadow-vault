# Security Policy

## Supported Versions

Security updates are applied to the latest release series on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest (`0.x`) | :white_check_mark: |
| `< 0.1.0` | :x:                |

## Cryptographic & Memory Safety Invariants

1. **Key Material Hygiene**: All passphrases, derived keys, intermediate KDF buffers, and decrypted payloads are wiped from memory on drop via `zeroize`.
2. **Authenticated Encryption**: All containers verify integrity and authenticity using ChaCha20-Poly1305 AEAD or HMAC/CRC-32 layers prior to exposing plaintext.
3. **Constant-Time Verification**: Authentication tags, MACs, and sensitive token comparisons execute in constant time to mitigate side-channel timing attacks.
4. **Bounds & Overflow Protection**: Binary container parsers enforce strict length checks and saturating/checked arithmetic on untrusted headers.

## Reporting a Vulnerability

If you discover a potential security issue, memory safety bug, or cryptographic flaw:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal reproduction case.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
