# Security Analysis Stack

Harpocrates employs a comprehensive multi-layered security analysis approach:

## Static Analysis Security Testing (SAST)

### 1. **gosec** - Pattern-Based Analysis
- **Type**: Rule-based static analyzer  
- **Strengths**: Fast, specific Go security patterns
- **Focus**: Known vulnerability patterns, misuse of crypto APIs
- **Run**: Every CI build

### 2. **CodeQL** - Semantic Analysis  
- **Type**: Semantic code analysis engine
- **Strengths**: Data flow analysis, taint tracking, complex vulnerability discovery
- **Focus**: Logic flaws, data flow vulnerabilities, supply chain security
- **Run**: Weekly + every PR to main

### 3. **staticcheck** - Code Quality
- **Type**: Static analysis for correctness and performance
- **Strengths**: Go-specific issues, performance problems
- **Focus**: Code quality, potential bugs, performance anti-patterns
- **Run**: Every CI build

## Dynamic Analysis

### 4. **govulncheck** - Dependency Scanning
- **Type**: Vulnerability database scanner
- **Strengths**: Known CVEs in dependencies
- **Focus**: Supply chain security, vulnerable dependencies  
- **Run**: Every CI build + weekly

### 5. **Fuzz Testing** - Runtime Security
- **Type**: Property-based testing with random inputs
- **Strengths**: Edge case discovery, crash detection
- **Focus**: Input validation, memory safety, panic conditions
- **Run**: On-demand + periodic extended runs

## Red Team Security Testing

### 6. **Advanced Red Team Analysis** - Adversarial Security Testing
- **Type**: Comprehensive adversarial security assessment
- **Implementation**: `crypto_security_test.go` - Professional red team test suite
- **Scope**: Multi-vector attack simulation against cryptographic operations
- **Methodology**: Threat modeling with specific attack vector analysis

**Attack Vectors Tested:**
- **Key Rotation State Machine Attacks**: Race condition exploitation in zero-downtime rotation
- **Advanced Timing Analysis**: Statistical timing side-channel detection with high-precision measurements  
- **Memory Management Exploitation**: Buffer pool exhaustion and use-after-free conditions
- **Weak Key Detection**: Cryptographic strength validation against malicious key patterns
- **Nonce Reuse Attacks**: Cryptographic oracle attacks and IV collision detection
- **AAD Manipulation**: Authenticated encryption bypass attempts (NEMESIS vault focus)
- **Buffer Overflow Testing**: Malformed input handling and bounds checking validation
- **Information Leakage Analysis**: Error message content analysis and side-channel detection

**Professional Red Team Features:**
- **Comprehensive Threat Model**: Based on CWE classifications and NEMESIS security requirements
- **Statistical Analysis**: Advanced timing measurements with t-test significance testing
- **Concurrent Attack Simulation**: Multi-threaded race condition exploitation
- **Memory Safety Testing**: Buffer lifecycle validation and cleanup verification
- **Eeal World Attack Patterns**: Real-world attack scenarios specific to cryptographic libraries

## Why This Stack?

**Comprehensive Coverage**: Each tool catches different types of vulnerabilities:
- **gosec**: Obvious crypto misuse
- **CodeQL**: Subtle logic flaws and data flow issues  
- **govulncheck**: Third-party vulnerabilities
- **Fuzzing**: Runtime edge cases
- **Red Team Testing**: Advanced adversarial attack simulation

**Defense in Depth**: Multiple analysis techniques provide layered security validation.

**Industry Standard**: This stack matches security requirements for cryptographic libraries in regulated environments.

**Red Team Validation**: Professional adversarial testing validates security against sophisticated attack scenarios that automated tools cannot simulate.

## Red Team Testing Execution

The red team security testing can be executed with:

```bash
# Run comprehensive red team security analysis
go test -v -run TestSecurity crypto_security_test.go

# Run specific attack vector tests
go test -v -run TestSecurity_WeakKeyDetection
go test -v -run TestSecurity_TimingAttacks
go test -v -run TestSecurity_KeyRotationStateMachine
go test -v -run TestSecurity_AdvancedTimingAnalysis
go test -v -run TestSecurity_MemoryManagementExploitation

# Include in security validation workflow
make security  # Includes red team tests in comprehensive security check
```

**Red Team Test Categories:**
1. **Cryptographic Attacks**: Weak keys, nonce reuse, AAD manipulation
2. **Side-Channel Attacks**: Timing analysis, information leakage
3. **System-Level Attacks**: Memory exploitation, buffer overflow, race conditions
4. **State Machine Attacks**: Key rotation logic exploitation (NEMESIS-specific)
5. **Input Validation Attacks**: Malformed data handling, boundary condition exploitation

## Security Reports

Security analysis results are available in:
- GitHub Security tab (CodeQL findings)
- CI workflow logs (gosec, staticcheck, govulncheck)
- Artifacts (detailed SARIF reports)

For security issues, please see our [Security Policy](../SECURITY.md).