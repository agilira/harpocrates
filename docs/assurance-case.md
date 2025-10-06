# Security Assurance Case

## Overview

This document provides a comprehensive security assurance case for Harpocrates, demonstrating how the project meets its security requirements through systematic analysis of threats, trust boundaries, secure design principles, and mitigation of common implementation weaknesses.

## 1. Threat Model

### 1.1 Assets Protected
- **Encryption Keys**: AES-256 keys for data protection
- **Plaintext Data**: Sensitive data being encrypted/decrypted
- **Key Derivation Materials**: Passwords, salts, and derived keys
- **HSM Communications**: Secure channels to hardware security modules

### 1.2 Threat Actors
- **External Attackers**: Remote attackers attempting cryptographic breaks
- **Local Attackers**: Users with system access attempting key extraction
- **Insider Threats**: Malicious developers or operators
- **Supply Chain Attackers**: Compromise of dependencies or build pipeline

### 1.3 Attack Vectors
- **Cryptographic Attacks**: Brute force, side-channel, timing attacks
- **Memory Attacks**: Cold boot, memory dumps, heap spray attacks
- **Input Manipulation**: Malformed data, buffer overflows, injection attacks
- **Implementation Flaws**: Logic bugs, race conditions, error handling failures
- **Dependency Exploitation**: Vulnerabilities in external libraries
- **Build-time Attacks**: Compiler backdoors, supply chain poisoning

### 1.4 Security Objectives
- **Confidentiality**: Encrypted data must remain protected even if ciphertext is compromised
- **Integrity**: Tampering with encrypted data must be detectable
- **Availability**: Cryptographic operations must resist denial-of-service attacks
- **Key Security**: Encryption keys must be protected throughout their lifecycle
- **Forward Secrecy**: Compromise of current keys must not affect past communications

## 2. Trust Boundaries

### 2.1 Application Boundary
**Trusted**: Harpocrates library code and Go standard library
**Untrusted**: All external inputs (data to encrypt, keys from users, configuration)

**Controls**:
- Strict input validation using allowlist approach
- Type safety through Go's type system
- Bounds checking on all array/slice operations

### 2.2 Memory Boundary
**Trusted**: Process memory space during active operations
**Untrusted**: Persistent storage, swap files, memory dumps

**Controls**:
- Secure memory zeroization with `Zeroize()` function
- Minimal key lifetime in memory
- No key material in error messages or logs

### 2.3 Cryptographic Boundary
**Trusted**: NIST-approved AES-256-GCM algorithm and crypto/rand
**Untrusted**: User-provided algorithms, deprecated crypto functions

**Controls**:
- Single, vetted cryptographic algorithm (AES-256-GCM)
- Cryptographically secure random number generation
- No support for deprecated or weak algorithms

### 2.4 Dependency Boundary
**Trusted**: Go standard library, vetted AGILira libraries
**Untrusted**: Third-party dependencies, system libraries

**Controls**:
- Minimal external dependencies (5 direct dependencies)
- Automated vulnerability scanning with `govulncheck`
- Dependency pinning with cryptographic checksums in `go.sum`

### 2.5 HSM Boundary
**Trusted**: HSM hardware and authenticated plugin communication
**Untrusted**: Network communication, plugin processes

**Controls**:
- gRPC with TLS for secure communication
- Plugin architecture with process isolation
- Hardware attestation and secure key generation

## 3. Secure Design Principles Applied

### 3.1 Economy of Mechanism (Simplicity)
**Implementation**:
- Single cryptographic algorithm (AES-256-GCM) reduces attack surface
- Minimal API with core functions `EncryptBytes`/`DecryptBytes`
- Clear separation of concerns between encryption, key management, and HSM integration

**Evidence**: [README.md](../README.md) - Simple API design with minimal functions

### 3.2 Fail-Safe Defaults
**Implementation**:
- Secure cryptographic parameters by default (AES-256, Argon2id)
- Explicit error handling with no silent failures
- Automatic memory zeroization on key destruction

**Evidence**: [encryption.go](../encryption.go) - Default parameters and error handling

### 3.3 Complete Mediation
**Implementation**:
- Every cryptographic operation validates inputs through `ValidateKey()`
- All external inputs pass through allowlist validation
- No bypass mechanisms for security checks

**Evidence**: [keyutils.go](../keyutils.go#L233) - Input validation functions

### 3.4 Open Design
**Implementation**:
- Open source codebase with public security documentation
- Use of standard, published cryptographic algorithms
- Transparent security design and threat model

**Evidence**: This document and [security.md](security.md)

### 3.5 Separation of Privilege
**Implementation**:
- Dual-KEK architecture for zero-downtime key rotation
- Separate roles for key generation, encryption, and HSM operations
- Plugin architecture isolates HSM operations from core library

**Evidence**: [README.md](../README.md#zero-downtime-key-rotation) - Key rotation architecture

### 3.6 Least Common Mechanism
**Implementation**:
- Buffer pooling with isolation between operations
- Context separation for different encryption contexts
- Process isolation for HSM plugin operations

**Evidence**: Performance optimizations with security isolation maintained

### 3.7 Defense in Depth
**Implementation**:
- Multiple validation layers (input → crypto → output)
- Static analysis + dynamic testing + red team testing
- Memory protection + cryptographic protection + access controls

**Evidence**: [Makefile](../Makefile) - Multiple security checking tools

## 4. Common Implementation Weaknesses Countered

### 4.1 Buffer Overflows (CWE-120)
**Mitigation**:
- Go language memory safety with bounds checking
- Strict input validation rejecting oversized inputs
- No unsafe memory operations or pointer arithmetic

**Evidence**: [crypto_security_test.go](../crypto_security_test.go#L440) - Buffer overflow tests

### 4.2 Use After Free (CWE-416)
**Mitigation**:
- Go garbage collector prevents use-after-free
- Explicit memory zeroization before deallocation
- No manual memory management

**Evidence**: Go language guarantees + `Zeroize()` function implementation

### 4.3 Integer Overflows (CWE-190)
**Mitigation**:
- Go language overflow detection in debug mode
- Explicit size validation for all length parameters
- Use of fixed-size cryptographic primitives

**Evidence**: [keyutils_test.go](../keyutils_test.go) - Negative size validation tests

### 4.4 Injection Attacks (CWE-77, CWE-89)
**Mitigation**:
- Pure cryptographic library with no command execution
- No SQL or command injection vectors
- Binary-safe operations throughout

**Evidence**: Library design - no system interaction beyond crypto operations

### 4.5 Information Disclosure (CWE-200)
**Mitigation**:
- Structured error messages without internal state
- Build-time path removal with `-trimpath`
- No key material in logs or error outputs

**Evidence**: [build.sh](../build.sh) - Hardening build flags

### 4.6 Timing Attacks (CWE-208)
**Mitigation**:
- AES-GCM hardware acceleration with constant-time implementation
- Go crypto/subtle for constant-time comparisons
- No conditional operations based on secret data

**Evidence**: Use of crypto/aes and crypto/cipher standard implementations

### 4.7 Weak Cryptography (CWE-327)
**Mitigation**:
- NIST-approved AES-256-GCM algorithm only
- Cryptographically secure random number generation
- No support for deprecated algorithms (DES, MD5, etc.)

**Evidence**: [encryption.go](../encryption.go) - Algorithm selection

### 4.8 Insufficient Randomness (CWE-338)
**Mitigation**:
- crypto/rand for all random number generation
- Unique nonce generation for each encryption
- No predictable seed values or PRNG usage

**Evidence**: [keyutils.go](../keyutils.go) - Random generation functions

### 4.9 Race Conditions (CWE-362)
**Mitigation**:
- Thread-safe cryptographic operations
- Immutable key material during operations
- Buffer pooling with proper synchronization

**Evidence**: [crypto_concurrent_test.go](../crypto_concurrent_test.go) - Concurrency tests

### 4.10 Memory Leaks (CWE-401)
**Mitigation**:
- Go garbage collector for automatic memory management
- Explicit zeroization of sensitive data
- Buffer pooling to reduce allocation overhead

**Evidence**: Memory management design and `Zeroize()` implementation

## 5. Verification and Testing

### 5.1 Static Analysis
- **staticcheck**: Go-specific static analysis for common bugs
- **gosec**: Security-focused static analysis scanner
- **govulncheck**: Vulnerability database scanning

### 5.2 Dynamic Testing
- **Unit tests**: 90%+ code coverage with comprehensive test suite
- **Fuzz testing**: Go native fuzzer for edge case discovery
- **Integration tests**: End-to-end cryptographic workflows

### 5.3 Security Testing
- **Red team testing**: Proactive security assessment by security experts
- **Boundary testing**: Edge cases and limit conditions
- **Stress testing**: Performance under load and resource constraints

### 5.4 Continuous Integration
- All security checks run on every commit
- Automated dependency vulnerability scanning
- Release signing with GitHub attestations

**Evidence**: [.github/workflows/ci.yml](../.github/workflows/ci.yml) - CI pipeline

## 6. Compliance and Standards

### 6.1 Cryptographic Standards
- **NIST FIPS 197**: AES encryption algorithm
- **NIST SP 800-38D**: GCM mode of operation
- **NIST SP 800-132**: PBKDF2 recommendation
- **RFC 9106**: Argon2 password hashing

### 6.2 Security Standards
- **ISO/IEC 27001**: Information security management principles
- **NIST Cybersecurity Framework**: Security controls and practices
- **OWASP ASVS**: Application security verification standard

### 6.3 Development Standards
- **OpenSSF Best Practices**: Badge compliance (Gold level achieved)
- **Secure SDLC**: Security integrated throughout development lifecycle
- **Supply Chain Security**: SLSA framework principles

## 7. Conclusion

This assurance case demonstrates that Harpocrates meets its security requirements through:

1. **Comprehensive threat modeling** covering all relevant attack vectors
2. **Clear trust boundaries** with appropriate controls at each boundary
3. **Systematic application** of secure design principles
4. **Proactive mitigation** of common implementation weaknesses
5. **Multi-layered verification** through testing and analysis
6. **Compliance** with relevant security and cryptographic standards

The combination of secure-by-design architecture, comprehensive testing, and continuous security monitoring provides high assurance that Harpocrates achieves its security objectives and protects against identified threats.

---

**Document Version**: 1.0  
**Last Updated**: October 6, 2025  
**Next Review**: April 6, 2026

---

Harpocrates • an AGILira library