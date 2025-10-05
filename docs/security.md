# Security Considerations

## Cryptographic Algorithms

### Encryption
- **AES-256-GCM**: Used for authenticated encryption, providing both confidentiality and integrity
- **Nonce**: 12-byte random nonce generated for each encryption operation
- **Authentication**: GCM mode provides built-in authentication to prevent tampering

### Key Derivation
- **Argon2id**: Primary key derivation function, resistant to ASIC/FPGA attacks
- **PBKDF2-SHA256**: Legacy support (deprecated, use Argon2id instead)
- **Secure defaults**: Pre-configured parameters provide strong protection

### Random Number Generation
- **crypto/rand**: Cryptographically secure random number generation
- **Nonce generation**: Each encryption uses a unique random nonce
- **Key generation**: Keys are generated using secure random sources

## Security Features

### Memory Management
- **Secure zeroization**: `Zeroize()` function securely wipes sensitive data from memory
- **No key logging**: Keys are never logged or stored in plain text
- **Minimal exposure**: Keys are only held in memory for the minimum time necessary

### Input Validation
- **Key size validation**: Ensures 32-byte keys for AES-256
- **Parameter validation**: All function parameters are validated before use
- **Error handling**: Comprehensive error handling prevents information leakage

### Error Handling
- **No sensitive data in errors**: Error messages never contain sensitive information
- **Consistent error types**: Standard Go errors for maximum compatibility
- **Rich error details**: Optional integration with `github.com/agilira/go-errors`

## Security Tool Exclusions

This library uses static analysis tools (gosec) for security validation. Some rules are excluded with documented justification:

### G115 (Integer Overflow Conversion)
**Excluded for Argon2 parameter type conversions.**

These conversions are safe because:
1. **Parameter validation**: Parameters are validated before conversion (time > 0, memory > 0, threads > 0)
2. **API requirements**: Argon2 library expects specific types (uint32, uint8)
3. **Safe ranges**: Our validation ensures values are within safe ranges for Argon2id
4. **Necessary conversions**: These conversions are necessary for the Argon2 API and do not represent security vulnerabilities

### Configuration
The exclusions are configured in `.gosec` file:
```json
{
    "exclude": ["G115"],
    "G115": {
        "description": "Integer overflow conversion warnings for Argon2 parameters are false positives. These conversions are necessary for the Argon2 API and are safe due to parameter validation."
    }
}
```

## Security Features

### Memory Protection
- **Secure zeroization**: All sensitive data is securely wiped from memory using `Zeroize()`
- **No key logging**: Keys are never logged or stored in plain text
- **Minimal exposure**: Keys are only held in memory for the minimum time necessary
- **Stack protection**: Sensitive data is cleared from stack variables

### Input Validation
- **Key size validation**: Ensures 32-byte keys for AES-256
- **Parameter validation**: All function parameters are validated before use
- **Range checking**: Argon2 parameters are validated for safe ranges
- **Type safety**: Strong typing prevents common cryptographic mistakes

### Error Handling
- **No information leakage**: Error messages never contain sensitive information
- **Consistent error types**: Standard Go errors for maximum compatibility
- **Rich error details**: Optional integration with `github.com/agilira/go-errors`
- **Graceful degradation**: Functions fail securely without exposing internal state

## Best Practices

### Key Management
- **Generate keys securely**: Use `GenerateKey()` for cryptographically secure keys
- **Store keys safely**: Never store keys in plain text or log files
- **Zeroize after use**: Always call `Zeroize()` on sensitive data after use
- **Validate keys**: Use `ValidateKey()` to ensure correct key size

### Password-based Key Derivation
- **Use Argon2id**: Prefer `DeriveKey()` or `DeriveKeyDefault()` over PBKDF2
- **Use unique salts**: Never reuse salts across different keys
- **Use secure parameters**: Use the provided secure defaults unless you have specific requirements

### Encryption/Decryption
- **Use authenticated encryption**: Always use the provided AES-256-GCM functions
- **Handle errors properly**: Check for errors and handle them appropriately
- **Validate inputs**: Ensure inputs are valid before encryption/decryption

## Threat Model

This library is designed to protect against:
- **Passive attacks**: Eavesdropping and data interception
- **Active attacks**: Data tampering and modification
- **Brute force attacks**: Password guessing and key enumeration
- **Side-channel attacks**: Timing attacks and memory analysis
- **Implementation attacks**: Common cryptographic implementation mistakes

## Security Audits

The library undergoes regular security analysis:
- **Static analysis**: Automated security scanning with gosec
- **Code review**: Manual security review of all changes
- **Testing**: Comprehensive test coverage including security edge cases
- **Dependency analysis**: Regular updates of cryptographic dependencies

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:
1. **Do not disclose publicly**: Do not post to public forums or issue trackers
2. **Contact directly**: Report to the maintainers privately
3. **Provide details**: Include sufficient information to reproduce the issue
4. **Allow time**: Give maintainers time to assess and fix the issue

## Compliance

This library is designed to meet common security requirements:
- **NIST guidelines**: Follows NIST cryptographic standards
- **OWASP recommendations**: Implements OWASP security best practices
- **Industry standards**: Complies with common industry security standards


---

Harpocrates • an AGILira library