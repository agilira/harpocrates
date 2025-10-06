# Security Policy

## Security Requirements and Boundaries

**Harpocrates** is a cryptographic library designed for high-security applications. The security boundary includes:

### Trust Boundary
- **In Scope**: All cryptographic operations, key management, memory handling, and API interfaces
- **Out of Scope**: Host system security, network transport security, application-level logic using the library

### Security Requirements
- **Confidentiality**: AES-256-GCM encryption protects data confidentiality
- **Integrity**: Authenticated encryption with additional data (AEAD) ensures data integrity  
- **Authenticity**: Cryptographic authentication prevents data tampering
- **Forward Secrecy**: Key rotation mechanisms prevent retrospective decryption
- **Side-Channel Resistance**: Implementation resistant to timing and cache-based attacks

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We greatly value the efforts of the community in identifying and responsibly disclosing security vulnerabilities. Your contributions help us ensure the safety and reliability of our cryptographic software.

### Reporting Channels

**Primary (Preferred):**
- **GitHub Security Advisories**: [Create Private Security Advisory](https://github.com/agilira/harpocrates/security/advisories/new)

**Alternative:**
- **Email**: security@agilira.io (PGP encryption preferred)
- **Security.txt**: [/.well-known/security.txt](/.well-known/security.txt)

### What to Include

To help us address your report effectively, please include:

- **Vulnerability Description**: Clear description of the security issue
- **Attack Vector**: How the vulnerability can be exploited
- **Impact Assessment**: Potential security impact (confidentiality, integrity, availability)
- **Proof of Concept**: Steps to reproduce or demonstration code
- **Environment**: Affected versions, operating systems, configurations
- **Suggested Fix**: If you have recommendations for mitigation

### Response Process

1. **Acknowledgment**: Initial response within **14 days**
2. **Investigation**: Security team analyzes the report 
3. **Validation**: Reproduce and confirm the vulnerability
4. **Patch Development**: Create and test security fix
5. **Coordinated Disclosure**: Release timeline coordinated with reporter
6. **Public Disclosure**: Security advisory and patched version released

### Response Timelines

- **Critical Vulnerabilities**: Patch within **48 hours**
- **High Severity**: Patch within **7 days**  
- **Medium/Low Severity**: Patch within **30 days**
- **Initial Response**: Within **14 days** (as required by OpenSSF Gold)

### Recognition

Security researchers who report valid vulnerabilities will receive:
- Credit in release notes and security advisories (unless anonymity requested)
- Recognition in our [Security Acknowledgments](docs/security-acknowledgments.md)
- AGILira Security Champion recognition for significant findings

### Scope

#### In Scope
- Cryptographic implementation vulnerabilities
- Key management and storage issues
- Memory safety problems (buffer overflows, use-after-free)
- Side-channel attacks (timing, cache-based)
- Authentication bypass vulnerabilities
- Input validation issues leading to security impact

#### Out of Scope  
- Issues in dependencies (report to upstream projects)
- Social engineering attacks
- Physical access attacks
- Issues requiring MITM on secure connections
- Rate limiting or DoS without amplification
- Issues in example code or documentation

## Security Assurance

### Cryptographic Review
The NEMESIS encryption implementation has undergone cryptographic review by qualified cryptographers, focusing on:
- Algorithm selection and parameterization
- Implementation correctness and side-channel resistance  
- Key derivation and management practices

### Security Testing Stack
Our multi-layered security validation includes:
- **Static Analysis**: CodeQL semantic analysis, gosec pattern detection
- **Dynamic Analysis**: Comprehensive fuzz testing, memory safety validation
- **Vulnerability Scanning**: govulncheck dependency analysis
- **Red Team Testing**: Adversarial security assessment with professional attack simulation

See [Security Analysis Stack](docs/security-analysis.md) for complete details.

### Threat Model
Our threat model considers:
- **Passive Attackers**: Cryptanalysis, side-channel observation
- **Active Attackers**: Chosen-plaintext/ciphertext attacks, key manipulation
- **System-Level Attackers**: Memory exploitation, race conditions  
- **Insider Threats**: Key exfiltration, implementation tampering

For more information about AGILira's security practices, please visit our [Security Page](https://agilira.one/security).

Thank you for helping us maintain a secure and trustworthy cryptographic library.

---

Harpocrates • an AGILira library