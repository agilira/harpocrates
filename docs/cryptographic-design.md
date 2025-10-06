# Cryptographic Design Document

## Executive Summary

Harpocrates implements the **NEMESIS** (Network Enhanced Multi-Encryption Security Implementation System) cryptographic library, designed for high-security applications requiring authenticated encryption with additional data (AEAD) capabilities, secure key management, and resistance to side-channel attacks.

## Architecture Overview

### Design Principles

1. **Defense in Depth**: Multiple cryptographic layers with algorithm agility
2. **Zero-Trust Security**: All inputs validated, no implicit trust assumptions
3. **Side-Channel Resistance**: Implementation designed to resist timing and cache attacks
4. **Forward Secrecy**: Key rotation mechanisms prevent retrospective compromise
5. **Secure by Default**: Conservative defaults, explicit configuration for reduced security

### Cryptographic Components

```
┌─────────────────────────────────────────────────────────────┐
│                    NEMESIS Architecture                     │
├─────────────────────────────────────────────────────────────┤
│  Application Layer                                          │
│  ┌─────────────────┐  ┌─────────────────┐                 │
│  │  Encrypt/Decrypt │  │  Key Management │                 │
│  │     Interface   │  │    Interface    │                 │
│  └─────────────────┘  └─────────────────┘                 │
├─────────────────────────────────────────────────────────────┤
│  Cryptographic Abstraction Layer                           │
│  ┌─────────────────┐  ┌─────────────────┐                 │
│  │ AEAD Operations │  │ Key Derivation  │                 │
│  │   (AES-GCM)     │  │   (Argon2id)    │                 │
│  │   [Cached]      │  │    (PBKDF2)     │                 │
│  └─────────────────┘  └─────────────────┘                 │
├─────────────────────────────────────────────────────────────┤
│  Security Layer                                            │
│  ┌─────────────────┐  ┌─────────────────┐                 │
│  │  Memory Safety  │  │   Secure RNG    │                 │
│  │   Management    │  │  (crypto/rand)  │                 │
│  └─────────────────┘  └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

## Cryptographic Algorithms

### Authenticated Encryption with Additional Data (AEAD)

#### AES-256-GCM (Sole Implementation)
- **Algorithm**: Advanced Encryption Standard in Galois/Counter Mode
- **Key Size**: 256 bits (32 bytes) - **KeySize constant**
- **Nonce Size**: 96 bits (12 bytes) - NIST SP 800-38D recommendation
- **Tag Size**: 128 bits (16 bytes)
- **Security Level**: ~128-bit security against quantum attacks (post-quantum considerations)
- **Performance**: 1.31M+ operations per second with cipher caching optimization

**Implementation Details**:
- **Cipher Caching**: Global cipher cache with sync.RWMutex for performance optimization
- **Buffer Pooling**: Memory-efficient nonce generation using buffer pools
- **Hardware Acceleration**: Utilizes AES-NI when available for optimal performance
- **Concurrent Safety**: All operations are thread-safe with proper synchronization

**Rationale**: AES-GCM was selected as the sole AEAD implementation for Harpocrates based on:
1. **Performance**: Excellent hardware acceleration support via AES-NI instructions
2. **Security**: Well-vetted algorithm with strong authenticated encryption properties  
3. **Standardization**: NIST-approved and widely adopted in enterprise environments
4. **Simplicity**: Single algorithm reduces attack surface and complexity
5. **NEMESIS Requirements**: Optimized for high-throughput vault operations (1M+ ops/sec target met)

### Key Derivation Functions

#### Argon2id (Primary KDF)
- **Memory Cost**: 64MB (DefaultMemory = 64)
- **Time Cost**: 3 passes (DefaultTime = 3)
- **Parallelism**: 4 threads (DefaultThreads = 4)
- **Salt Size**: Variable (user-provided, recommended 32+ bytes)
- **Output Length**: Variable (typically 32 bytes for AES-256)
- **Algorithm Variant**: Argon2id (hybrid of Argon2i and Argon2d)

**Pre-configured Parameter Sets**:
- **NemesisKDFParams()**: Time=2, Memory=64MB, Threads=4 (optimized for high-throughput)
- **HighSecurityKDFParams()**: Time=5, Memory=128MB, Threads=4 (maximum security)
- **FastKDFParams()**: Time=1, Memory=32MB, Threads=2 (development/testing)

#### PBKDF2-SHA256 (Legacy Support - Deprecated)
- **Hash Function**: SHA-256
- **Salt Size**: Variable (user-provided, recommended 32+ bytes)
- **Iteration Count**: Typically 100,000+ (example from tests)
- **Output Key Length**: Variable (typically 32 bytes)
- **Status**: Deprecated - kept for backward compatibility only

#### HKDF-SHA256 (Key Expansion)
- **Use Case**: High-entropy key derivation (KEK→DEK expansion in NEMESIS)
- **Hash Function**: SHA-256
- **Salt**: Optional (nil allowed)
- **Info**: Optional context parameter
- **Output Length**: Up to 255 * 32 bytes maximum

### Random Number Generation

#### Cryptographically Secure Pseudorandom Number Generator (CSPRNG)
- **Source**: Go's `crypto/rand` package
- **Entropy Source**: OS-provided entropy (`/dev/urandom`, CryptGenRandom, etc.)
- **Used For**: 
  - Cryptographic key generation
  - Nonce/IV generation  
  - Salt generation
  - Secure token generation

## Security Properties

### Confidentiality
- **Semantic Security**: Indistinguishability under chosen-plaintext attack (IND-CPA)
- **Key Recovery**: Resistance against key recovery attacks
- **Side-Channel Resistance**: Constant-time implementations where possible

### Integrity and Authenticity
- **Authentication**: Existential unforgeability under chosen-message attack (EUF-CMA)
- **Integrity**: Detection of any unauthorized modifications
- **Additional Data**: Authentication of associated metadata without encryption

### Forward Secrecy
- **Zero-Downtime Key Rotation**: Dual-KEK architecture with Prepare→Validate→Commit phases
- **Key Management**: KEK (Key Encryption Key) and DEK (Data Encryption Key) separation
- **Perfect Forward Secrecy**: Compromise of long-term keys does not compromise past sessions
- **Key Erasure**: Secure memory wiping with Zeroize() function
- **Automated Rollback**: Emergency rollback capability for failed rotations

## Implementation Security

### Side-Channel Attack Resistance

#### Timing Attack Mitigation
- Constant-time comparison for authentication tags
- Fixed-time key derivation operations
- Avoiding conditional branches based on secret data

#### Cache Attack Mitigation  
- AES-NI hardware acceleration when available
- Table-free implementations for software fallback
- Memory access pattern independence from secret data

### Memory Safety

#### Secure Memory Management
- Explicit memory zeroing for sensitive data
- Stack-allocated sensitive data where possible
- Go's garbage collector limitations mitigated through:
  - Immediate zeroing after use
  - Limited lifetime of sensitive variables
  - Secure allocator considerations for future versions

#### Buffer Management
- Bounds checking for all buffer operations
- Input validation before cryptographic operations
- Preventing buffer overflow and underflow conditions

## Key Management

### Key Lifecycle

1. **Generation**: CSPRNG-based key generation via GenerateKey()
2. **Derivation**: Argon2id/PBKDF2/HKDF for password-based or key expansion
3. **Storage**: External secure storage (not in library scope) + HSM integration
4. **Usage**: KEK/DEK separation with limited lifetime
5. **Rotation**: Zero-downtime key rotation with dual-KEK architecture
6. **Validation**: ValidateKey() for integrity checking  
7. **Fingerprinting**: GetKeyFingerprint() for identification
8. **Destruction**: Explicit memory wiping with Zeroize()

### Key Derivation Strategy

```
Password/Master Key
       │
       ▼
Argon2id KDF (Primary) / PBKDF2 (Legacy) / HKDF (Key Expansion)
       │
       ▼ 
KEK (Key Encryption Key) ─────┐
       │                      │
       ▼                      │ (Zero-Downtime Rotation)
DEK (Data Encryption Key) ────┘
       │
       ▼
AES-256-GCM AEAD Operations (with Cipher Caching)
```

## Threat Model

### Attacker Capabilities

#### Passive Attackers
- **Ciphertext Analysis**: Access to encrypted data
- **Side-Channel Observation**: Timing, power, electromagnetic emanations
- **Traffic Analysis**: Pattern observation of encrypted communications

#### Active Attackers  
- **Chosen-Plaintext Attacks**: Ability to encrypt arbitrary plaintexts
- **Chosen-Ciphertext Attacks**: Ability to attempt decryption of crafted ciphertexts
- **Replay Attacks**: Retransmission of valid encrypted messages

#### System-Level Attackers
- **Memory Access**: Limited read access to process memory
- **Race Conditions**: Concurrent access to cryptographic operations
- **Resource Exhaustion**: Attempts to cause denial of service

### Trust Boundaries

#### Trusted Components
- Go runtime and standard library cryptographic implementations
- Operating system entropy sources
- Hardware cryptographic accelerators (AES-NI)

#### Untrusted Components  
- All input data (plaintext, additional data, keys from external sources)
- Network transport mechanisms
- External storage systems
- Application code using the library

## Compliance and Standards

### Standards Compliance
- **NIST SP 800-38D**: AES-GCM implementation guidelines (strictly followed)
- **RFC 8018**: PBKDF2 specification (legacy support)
- **RFC 9106**: Argon2 specification (primary KDF)
- **FIPS 140-2**: Cryptographic module security requirements (design consideration)
- **PKCS#11**: HSM integration compliance (via plugin architecture)

### Security Guidelines
- **OWASP Cryptographic Storage Cheat Sheet**: Key storage recommendations
- **NIST Cybersecurity Framework**: Risk management alignment
- **Common Criteria**: Security evaluation methodology (future consideration)

## Cryptographic Review Process

### Internal Review
1. **Design Review**: Architecture and algorithm selection validation
2. **Implementation Review**: Code-level security assessment  
3. **Testing Review**: Security test coverage validation
4. **Documentation Review**: Completeness and accuracy verification

### External Review (Planned)
1. **Independent Cryptographic Review**: Third-party cryptographer assessment
2. **Penetration Testing**: Professional security testing
3. **Academic Collaboration**: University research partnerships
4. **Bug Bounty Program**: Community-driven security validation

### Review Documentation
- Review findings and remediation
- Security assumptions validation
- Implementation verification against design
- Test coverage adequacy assessment

## Performance Considerations

### Optimization Strategy
- Hardware acceleration utilization (AES-NI, AVX)
- Algorithm selection based on platform capabilities
- Memory-efficient implementations
- Parallelization where cryptographically safe

### Benchmarking
- Throughput measurements across platforms
- Latency profiling for real-time applications
- Memory usage optimization
- Constant-time validation testing

### Hardware Security Modules (HSM)
- **Plugin Architecture**: HSM interface implemented via go-plugins
- **PKCS#11**: Hardware device support (SafeNet, Thales, etc.)
- **Cloud HSM**: AWS CloudHSM, Azure Key Vault integration capabilities
- **Capabilities**: Key generation, encryption/decryption, key derivation, random generation
- **FIPS 140-2**: Level 3/4 compliance support for regulated environments
- **Implementation**: HSM interface available, integration via plugin system

---

**Document Version**: 1.0  
**Last Updated**: October 6, 2025  
**Next Review**: January 6, 2026  
**Approved By**: AGILira Security Team  
**Classification**: Public