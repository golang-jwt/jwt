# Security Policy

## Supported Versions

As of November 2024 (and until this document is updated), the latest version `v5` is supported. In critical cases, we might supply back-ported patches for `v4`.

## Reporting a Vulnerability

If you think you found a vulnerability, and even if you are not sure, please report it a [GitHub Security Advisory](https://github.com/golang-jwt/jwt/security/advisories/new). Please try be explicit, describe steps to reproduce the security issue with code example(s).

You will receive a response within a timely manner. If the issue is confirmed, we will do our best to release a patch as soon as possible given the complexity of the problem.

## Public Discussions

Please avoid publicly discussing a potential security vulnerability.

Let's take this offline and find a solution first, this limits the potential impact as much as possible.

We appreciate your help!

## Post-Quantum Security

Φ-JWT supports NIST PQC Falcon-512 signatures via liboqs integration.

### Supported Algorithms
- **PhiFalcon512-Real**: Falcon-512 via liboqs CGO (Production)
- **PhiFalcon512**: Simulated Falcon-512 (Testing)
- **PhiDilithium2**: Simulated Dilithium-2 (Testing)

### Reporting PQC Vulnerabilities
For vulnerabilities in the post-quantum implementation, contact:
- GitHub: @primordialomegazero
- Phi-DNA: divine noise 40-bit, Lyapunov λ=-0.4812
