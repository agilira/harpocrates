# Harpocrates Cryptographic Library - Threat Model

## Executive Summary

This document provides a comprehensive threat model for the Harpocrates cryptographic library using STRIDE methodology combined with PASTA (Process for Attack Simulation and Threat Analysis). Harpocrates is a high-performance Go cryptographic library implementing AES-256-GCM encryption with advanced performance optimizations including cipher caching and buffer pooling.

## System Overview

### Core Architecture
- **Primary Algorithm**: AES-256-GCM (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode)
- **Key Derivation**: Argon2id (primary), PBKDF2-SHA256 (deprecated), HKDF-SHA256 (key expansion)
- **Performance Optimizations**: Cipher caching, buffer pooling, sync.RWMutex for thread safety
- **Error Handling**: Structured error system with security-focused error codes

### API Surface
The library exposes the following public functions:

**Core Encryption Functions:**
- `EncryptBytes(plaintext []byte, key []byte) (string, error)` - Binary data encryption
- `DecryptBytes(encryptedText string, key []byte) ([]byte, error)` - Binary data decryption
- `EncryptBytesWithAAD(plaintext []byte, key []byte, aad []byte) (string, error)` - Binary encryption with AAD
- `DecryptBytesWithAAD(encryptedText string, key []byte, aad []byte) ([]byte, error)` - Binary decryption with AAD

**String-based Functions:**
- `Encrypt(plaintext string, key []byte) (string, error)` - String encryption
- `Decrypt(encryptedText string, key []byte) (string, error)` - String decryption  
- `EncryptWithAAD(plaintext string, key []byte, aad string) (string, error)` - String encryption with AAD
- `DecryptWithAAD(encryptedText string, key []byte, aad string) (string, error)` - String decryption with AAD

**Key Derivation Functions:**
- `DeriveKey(password, salt []byte, keyLen int, params *KDFParams) ([]byte, error)` - Configurable Argon2id
- `DeriveKeyDefault(password, salt []byte, keyLen int) ([]byte, error)` - Default Argon2id parameters
- `DeriveKeyWithParams(password, salt []byte, time, memoryMB, threads, keyLen int) ([]byte, error)` - Direct parameter control
- `DeriveKeyPBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error)` - Legacy PBKDF2 (deprecated)
- `DeriveKeyHKDF(masterKey, salt, info []byte, keyLen int) ([]byte, error)` - HKDF key expansion
- `DeriveKeyHKDFDefault(masterKey []byte, keyLen int) ([]byte, error)` - Simplified HKDF

## STRIDE Threat Analysis

### Spoofing (S)
**Threat**: Authentication bypass through key impersonation or weak key derivation

**Attack Vectors:**
- Weak password-based key derivation allowing brute force attacks
- Salt reuse enabling rainbow table attacks
- Insufficient entropy in key generation

**Mitigations Implemented:**
- Argon2id with secure defaults (time=3, memory=64MB, threads=4) for password-based key derivation
- Mandatory salt requirement for all KDF functions
- HKDF-SHA256 for high-entropy key expansion scenarios
- Cryptographically secure random number generation for salts and IVs

**Residual Risk**: LOW - Strong KDF parameters resist practical brute force attacks

### Tampering (T)
**Threat**: Data modification during storage or transmission

**Attack Vectors:**
- Ciphertext modification without detection
- IV/nonce manipulation
- AAD bypass in authenticated encryption

**Mitigations Implemented:**
- AES-256-GCM provides built-in authentication and integrity protection
- Additional Authenticated Data (AAD) support for context binding
- Structured error handling prevents information leakage during decryption failures

**Residual Risk**: VERY LOW - GCM mode provides cryptographic integrity protection

### Repudiation (R)
**Threat**: Denial of cryptographic operations or data authenticity

**Attack Vectors:**
- Claims of unauthorized encryption/decryption
- Disputes over data authenticity

**Mitigations Implemented:**
- Deterministic key derivation enables operation reproducibility
- Comprehensive audit logging recommendations in documentation
- Clear error handling for operation tracking

**Residual Risk**: LOW - Application-level logging required for complete non-repudiation

### Information Disclosure (I)
**Threat**: Unauthorized access to sensitive data or cryptographic material

**Attack Vectors:**
- Memory dumps exposing keys or plaintext
- Timing attacks on cryptographic operations
- Side-channel attacks through cache analysis
- Error message information leakage

**Mitigations Implemented:**
- Buffer pooling with secure memory management
- Cipher caching with sync.RWMutex for thread safety
- Generic error messages preventing cryptanalytic information leakage
- Immediate key material clearing (Go GC handles sensitive data cleanup)

**Residual Risk**: MEDIUM - Memory protection depends on runtime environment and OS-level security

### Denial of Service (D)
**Threat**: Service disruption through resource exhaustion

**Attack Vectors:**
- Memory exhaustion through large encryption requests
- CPU exhaustion through expensive key derivation parameters
- Concurrent access bottlenecks

**Mitigations Implemented:**
- Buffer pooling prevents memory allocation DoS
- Configurable Argon2id parameters allow tuning for environment constraints
- RWMutex enables concurrent read operations while protecting cipher cache
- Input validation prevents oversized operation attempts

**Residual Risk**: LOW - Performance optimizations provide natural DoS resistance

### Elevation of Privilege (E)
**Threat**: Gaining unauthorized access through cryptographic weaknesses

**Attack Vectors:**
- Cryptographic algorithm weaknesses
- Implementation vulnerabilities
- Key management failures

**Mitigations Implemented:**
- NIST-approved AES-256-GCM algorithm
- Argon2id winner of Password Hashing Competition
- RFC 5869 compliant HKDF implementation
- Comprehensive security testing including fuzz testing and static analysis

**Residual Risk**: VERY LOW - Use of proven, standardized cryptographic algorithms

## Advanced Threat Scenarios

### Scenario 1: High-Frequency Encryption Service
**Context**: Web service performing 10,000+ encryptions/second
**Primary Threats**: DoS through resource exhaustion, timing attacks
**Mitigations**: Cipher caching, buffer pooling, consistent timing through GCM
**Monitoring**: CPU usage, memory allocation patterns, response time distribution

### Scenario 2: Multi-Tenant Key Derivation
**Context**: Deriving user-specific keys in shared environment
**Primary Threats**: Cross-tenant key disclosure, timing correlation
**Mitigations**: Isolated salt generation per tenant, consistent Argon2id parameters
**Monitoring**: Memory usage per derivation, timing analysis across users

### Scenario 3: Long-term Data Protection
**Context**: Encrypting data for 10+ year retention
**Primary Threats**: Algorithm deprecation, key compromise
**Mitigations**: AES-256 with expected 100+ year security margin, key rotation capabilities
**Monitoring**: Cryptographic algorithm security advisories, key age tracking

## Security Controls Matrix

| Control Category | Implementation | Effectiveness | Verification Method |
|-----------------|----------------|---------------|-------------------|
| Cryptographic Strength | AES-256-GCM | HIGH | Algorithm standardization |
| Key Derivation | Argon2id + HKDF | HIGH | Parameter validation testing |
| Memory Protection | Buffer pooling | MEDIUM | Memory analysis tools |
| Concurrency Safety | sync.RWMutex | HIGH | Race condition testing |
| Error Handling | Structured errors | HIGH | Information leakage testing |
| Input Validation | Parameter checking | HIGH | Fuzzing and boundary testing |

## Compliance and Standards

### Cryptographic Standards Compliance
- **NIST FIPS 197**: AES algorithm implementation
- **NIST SP 800-38D**: GCM mode specification
- **RFC 9106**: Argon2 key derivation specification
- **RFC 5869**: HKDF key derivation specification

### Security Testing Requirements
- Static analysis with gosec and CodeQL
- Fuzz testing for input validation
- Vulnerability scanning with govulncheck
- Race condition testing for concurrent operations

## Operational Security Recommendations

### Key Management
1. Use unique salts for each key derivation operation
2. Implement proper key rotation schedules (recommend 90-day maximum)
3. Store derived keys in secure memory when possible
4. Clear sensitive memory immediately after use

### Monitoring and Alerting
1. Monitor unusual patterns in encryption/decryption volumes
2. Track key derivation timing for potential side-channel attacks
3. Alert on cryptographic operation failures exceeding baseline rates
4. Log all administrative operations affecting cryptographic configuration

### Incident Response
1. Immediate key rotation procedures for suspected compromises
2. Forensic analysis capabilities for cryptographic operation logs
3. Secure communication channels for security incident coordination
4. Recovery procedures for encrypted data with compromised keys

## Risk Assessment Summary

| Risk Category | Likelihood | Impact | Risk Level | Mitigation Priority |
|--------------|------------|---------|------------|-------------------|
| Algorithm Weakness | Very Low | Very High | LOW | Continuous monitoring |
| Implementation Bug | Low | High | MEDIUM | Regular security auditing |
| Side-channel Attack | Medium | Medium | MEDIUM | Runtime protection |
| Key Compromise | Low | Very High | MEDIUM | Strong key management |
| DoS Attack | Medium | Low | LOW | Performance monitoring |

## Conclusion

The Harpocrates cryptographic library demonstrates strong security posture through implementation of proven cryptographic algorithms, comprehensive input validation, and performance-focused security optimizations. The primary residual risks are environmental (memory protection, key management) rather than cryptographic, requiring operational security controls for complete threat mitigation.

Regular security reviews, continuous monitoring, and adherence to operational security recommendations will maintain the library's security effectiveness in production environments.

---
*Document Version: 1.0*  
*Last Updated: January 2025*  
*Classification: Internal Security Documentation*