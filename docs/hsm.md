# Hardware Security Module (HSM) Support

The Harpocrates library provides comprehensive Hardware Security Module (HSM) integration for enterprise-grade cryptographic operations requiring hardware-protected key management.

## Overview

HSM support is implemented through a plugin architecture using the [github.com/agilira/go-plugins](https://github.com/agilira/go-plugins) library, enabling:

- **Hardware-Protected Key Generation**: Keys are generated within the secure boundaries of the HSM hardware
- **Tamper-Resistant Security**: Operations are protected against physical and logical attacks
- **FIPS 140-2 Compliance**: Supports Level 3/4 compliance for regulated environments
- **Multi-Vendor Support**: Compatible with major HSM vendors through PKCS#11 standard

## Supported HSM Vendors

The plugin architecture supports various HSM vendors:

- **SafeNet (Thales)**: Luna HSMs, ProtectServer series
- **AWS CloudHSM**: AWS managed HSM service
- **Utimaco**: CryptoServer series
- **Cavium (Marvell)**: LiquidSecurity adapters
- **Any PKCS#11 compliant HSM**

## Basic Usage

### Initialize HSM Connection

```go
package main

import (
    "log"
    "github.com/agilira/harpocrates"
)

func main() {
    // Initialize HSM with PKCS#11 plugin
    hsm, err := crypto.NewHSM("pkcs11", map[string]interface{}{
        "library_path": "/usr/lib/pkcs11/libpkcs11.so",
        "slot_id":      0,
        "pin":          "1234",
        "token_label":  "vault-token",
    })
    if err != nil {
        log.Fatal("HSM initialization failed:", err)
    }
    defer hsm.Close()
    
    log.Println("HSM initialized successfully")
}
```

### Key Generation in HSM

```go
// Generate a new key within HSM
keyHandle, err := hsm.GenerateKey("vault-master-kek", 32)
if err != nil {
    log.Fatal("HSM key generation failed:", err)
}

log.Printf("Generated key handle: %s", keyHandle)

// List existing keys
keys, err := hsm.ListKeys()
if err != nil {
    log.Fatal("Failed to list keys:", err)
}

for _, key := range keys {
    log.Printf("Key: %s, Algorithm: %s, Size: %d", 
        key.Handle, key.Algorithm, key.Size)
}
```

### Encryption/Decryption Operations

```go
// Encrypt sensitive data using HSM
plaintext := []byte("highly sensitive vault data")
ciphertext, err := hsm.Encrypt(keyHandle, plaintext)
if err != nil {
    log.Fatal("HSM encryption failed:", err)
}

log.Printf("Encrypted %d bytes to %d bytes", len(plaintext), len(ciphertext))

// Decrypt the data
decrypted, err := hsm.Decrypt(keyHandle, ciphertext)
if err != nil {
    log.Fatal("HSM decryption failed:", err)
}

if string(decrypted) != string(plaintext) {
    log.Fatal("Decryption integrity check failed")
}

log.Println("HSM encryption/decryption successful")
```

## Integration with Key Manager

HSM can be integrated with the KeyManager for enterprise vault deployments:

```go
// Create KeyManager with HSM backend
km := crypto.NewKeyManagerWithOptions(&crypto.KeyManagerOptions{
    HSM:          hsm,
    UseHSMForKEK: true,
})

// Generate KEK in HSM
kek, err := km.GenerateKEK("vault-master-hsm")
if err != nil {
    log.Fatal("HSM KEK generation failed:", err)
}

// The KEK is now stored and protected by HSM
log.Printf("HSM-protected KEK generated: %s", kek.ID)

// Derive data encryption keys (DEKs are derived in memory for performance)
context := []byte("tenant:prod,path:/secrets/database")
dek, kekID, err := km.DeriveDataKey(context, 32)
if err != nil {
    log.Fatal("DEK derivation failed:", err)
}

log.Printf("DEK derived using HSM KEK %s", kekID)
```

## Zero-Downtime Key Rotation with HSM

```go
// Perform HSM-protected key rotation
newKEK, err := km.PrepareKEKRotation("vault-master-hsm-v2")
if err != nil {
    log.Fatal("HSM rotation preparation failed:", err)
}

// Validate new HSM key
if err := km.ValidateKEKRotation(); err != nil {
    // Automatic rollback
    km.RollbackKEKRotation()
    log.Fatal("HSM rotation validation failed:", err)
}

// Commit HSM rotation
if err := km.CommitKEKRotation(); err != nil {
    km.RollbackKEKRotation()
    log.Fatal("HSM rotation commit failed:", err)
}

log.Println("HSM key rotation completed successfully")
```

## Configuration Options

### PKCS#11 Configuration

```go
config := map[string]interface{}{
    "library_path":    "/usr/lib/pkcs11/libpkcs11.so", // Path to PKCS#11 library
    "slot_id":         0,                              // HSM slot ID
    "pin":             "1234",                         // User PIN
    "token_label":     "vault-token",                  // Token label
    "max_sessions":    10,                             // Max concurrent sessions
    "session_timeout": "30m",                          // Session timeout
    "retry_attempts":  3,                              // Connection retry attempts
    "retry_delay":     "5s",                           // Delay between retries
}

hsm, err := crypto.NewHSM("pkcs11", config)
```

### AWS CloudHSM Configuration

```go
config := map[string]interface{}{
    "cluster_id":      "cluster-abc123def456",
    "hsm_ca_file":     "/opt/cloudhsm/etc/customerCA.crt",
    "hsm_user":        "vault-user",
    "hsm_password":    "vault-password",
    "region":          "us-east-1",
    "max_sessions":    5,
}

hsm, err := crypto.NewHSM("cloudhsm", config)
```

## Error Handling

HSM operations include comprehensive error handling:

```go
ciphertext, err := hsm.Encrypt(keyHandle, plaintext)
if err != nil {
    switch {
    case errors.Is(err, crypto.ErrHSMNotInitialized):
        log.Fatal("HSM not properly initialized")
    case errors.Is(err, crypto.ErrHSMKeyNotFound):
        log.Fatal("Key not found in HSM")
    case errors.Is(err, crypto.ErrHSMOperationFailed):
        log.Fatal("HSM operation failed - check hardware status")
    case errors.Is(err, crypto.ErrHSMSessionInvalid):
        log.Fatal("HSM session invalid - reconnection required")
    default:
        log.Fatal("Unknown HSM error:", err)
    }
}
```

## Security Considerations

### Key Lifecycle Management

```go
// Generate key with specific attributes
keyHandle, err := hsm.GenerateKeyWithAttributes("vault-kek", &crypto.HSMKeyAttributes{
    Size:        32,
    Extractable: false,  // Key cannot be extracted from HSM
    Sensitive:   true,   // Key marked as sensitive
    Encrypt:     true,   // Key can be used for encryption
    Decrypt:     true,   // Key can be used for decryption
    WrapKey:     false,  // Key cannot wrap other keys
    Label:       "vault-master-kek-2025",
})

// Backup key (if supported and extractable)
if hsm.SupportsKeyBackup() {
    backup, err := hsm.BackupKey(keyHandle, "backup-password")
    if err != nil {
        log.Fatal("Key backup failed:", err)
    }
    // Store backup securely
}

// Destroy key when no longer needed
if err := hsm.DestroyKey(keyHandle); err != nil {
    log.Fatal("Key destruction failed:", err)
}
```

### Audit Logging

```go
// Enable HSM audit logging
hsm.EnableAuditLogging(func(event *crypto.HSMAuditEvent) {
    log.Printf("HSM Audit: %s - User: %s, Operation: %s, Key: %s, Result: %s",
        event.Timestamp.Format(time.RFC3339),
        event.User,
        event.Operation,
        event.KeyHandle,
        event.Result)
})
```

## Performance Considerations

- **Session Pooling**: HSM uses connection pooling to minimize session creation overhead
- **Batch Operations**: Group multiple operations to reduce HSM round-trips
- **Key Caching**: Frequently used key handles are cached in secure memory
- **Async Operations**: Support for asynchronous HSM operations where available

## Monitoring and Health Checks

```go
// Check HSM health
health, err := hsm.HealthCheck()
if err != nil {
    log.Fatal("HSM health check failed:", err)
}

log.Printf("HSM Status: %s, Sessions: %d/%d, Keys: %d",
    health.Status,
    health.ActiveSessions,
    health.MaxSessions,
    health.KeyCount)

// Monitor HSM metrics
metrics := hsm.GetMetrics()
log.Printf("Operations/sec: %.2f, Avg Latency: %s, Error Rate: %.2f%%",
    metrics.OperationsPerSecond,
    metrics.AverageLatency,
    metrics.ErrorRate*100)
```

## Plugin Architecture

The HSM support is built using the go-plugins framework, allowing for:

- **Dynamic Loading**: HSM drivers can be loaded at runtime
- **Vendor Independence**: Switch between HSM vendors without code changes  
- **Custom Implementations**: Develop custom HSM integrations
- **Hot Swapping**: Replace HSM implementations without service restart

### Creating Custom HSM Plugin

```go
// Implement the HSMPlugin interface
type MyHSMPlugin struct {
    // HSM-specific configuration
}

func (p *MyHSMPlugin) Initialize(config map[string]interface{}) error {
    // Initialize HSM connection
}

func (p *MyHSMPlugin) GenerateKey(label string, size int) (string, error) {
    // Generate key in your HSM
}

func (p *MyHSMPlugin) Encrypt(keyHandle string, plaintext []byte) ([]byte, error) {
    // Perform encryption using your HSM
}

// Register plugin
crypto.RegisterHSMPlugin("myhsm", &MyHSMPlugin{})
```

## Compliance and Certifications

- **FIPS 140-2**: Level 3/4 compliance for key storage and operations
- **Common Criteria**: EAL 4+ certified HSM support
- **PKCS#11**: Full standard compliance for interoperability
- **NIST SP 800-57**: Key management lifecycle compliance

For more information on security compliance, see the [Security Documentation](security.md).

---

*This HSM integration is powered by [github.com/agilira/go-plugins](https://github.com/agilira/go-plugins) - AGILira's enterprise plugin architecture.*

---

Harpocrates • an AGILira library