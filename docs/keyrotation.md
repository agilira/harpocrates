# Key Management & Zero-Downtime Rotation

This document describes the advanced key management features of Harpocrates, including the zero-downtime key rotation system designed for NEMESIS-grade applications.

## Overview

The key management system provides enterprise-grade key rotation capabilities with zero service interruption. The dual-KEK (Key Encryption Key) architecture ensures that encrypted data remains accessible throughout the rotation process.

## Key Lifecycle States

Keys progress through multiple states during their lifecycle:

- **`StatusPending`** - Newly generated key awaiting validation
- **`StatusValidating`** - Key undergoing validation tests before activation
- **`StatusActive`** - Currently active key for new encryption operations
- **`StatusDeprecated`** - Previous key still available for decryption of legacy data
- **`StatusRevoked`** - Key permanently disabled and zeroed from memory

## Architecture

### Dual-KEK System

The zero-downtime rotation uses a dual-KEK architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Previous KEK  │    │    Active KEK   │    │   Pending KEK   │
│  (StatusDeprecated) │    │  (StatusActive) │    │ (StatusPending) │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │Legacy Decrypt│ │    │ │New Encrypt  │ │    │ │Preparation  │ │
│ │Only         │ │    │ │& Decrypt    │ │    │ │& Validation │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Zero-Downtime Rotation Process

### Three-Phase Rotation

1. **Prepare Phase** - Generate new KEK without impacting current operations
2. **Validate Phase** - Test new KEK with encrypt/decrypt operations  
3. **Commit Phase** - Atomically activate new KEK while preserving old for legacy data

### Automatic Rollback

If any phase fails, the system automatically rolls back to the previous state, ensuring service continuity.

## API Reference

### KeyManager

```go
// Create new key manager
km := crypto.NewKeyManager()
```

### Basic Operations

```go
// Generate and activate a new KEK
kek, err := km.GenerateKEK("purpose")
err = km.ActivateKEK(kek.ID)

// Get current active KEK
currentKEK, err := km.GetCurrentKEK()

// Traditional rotation (brief interruption)
newKEK, err := km.RotateKEK("purpose")
```

### Zero-Downtime Operations

```go
// Complete zero-downtime rotation (automated)
newKEK, err := km.RotateKEKZeroDowntime("purpose")

// Step-by-step zero-downtime rotation (manual control)
pendingKEK, err := km.PrepareKEKRotation("purpose")
err = km.ValidateKEKRotation()
err = km.CommitKEKRotation()

// Emergency rollback
err = km.RollbackKEKRotation()
```

### Management Operations

```go
// List all KEKs with their status
keks := km.ListKEKs()

// Get specific KEK by ID
kek, err := km.GetKEKByID("kek_abc123")

// Revoke a specific KEK
err = km.RevokeKEK("old_kek_id")
```

## Usage Examples

### Automated Zero-Downtime Rotation

```go
package main

import (
    "fmt"
    "log"
    "github.com/agilira/harpocrates"
)

func main() {
    // Initialize key manager
    km := crypto.NewKeyManager()
    
    // Create initial KEK
    initialKEK, err := km.GenerateKEK("app-encryption")
    if err != nil {
        log.Fatal(err)
    }
    
    err = km.ActivateKEK(initialKEK.ID)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Initial KEK: %s (Status: %s)\n", 
        initialKEK.ID, initialKEK.Status)
    
    // Perform zero-downtime rotation
    newKEK, err := km.RotateKEKZeroDowntime("app-encryption")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("New KEK: %s (Status: %s)\n", 
        newKEK.ID, newKEK.Status)
    
    // Verify old KEK is still available for legacy data
    oldKEK, err := km.GetKEKByID(initialKEK.ID)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Old KEK: %s (Status: %s)\n", 
        oldKEK.ID, oldKEK.Status)
}
```

### Manual Step-by-Step Rotation

```go
func manualRotation(km *crypto.KeyManager) error {
    // Phase 1: Prepare new KEK
    fmt.Println("Phase 1: Preparing new KEK...")
    pendingKEK, err := km.PrepareKEKRotation("manual-rotation")
    if err != nil {
        return fmt.Errorf("preparation failed: %w", err)
    }
    
    fmt.Printf("Prepared KEK: %s (Status: %s)\n", 
        pendingKEK.ID, pendingKEK.Status)
    
    // Phase 2: Validate new KEK
    fmt.Println("Phase 2: Validating new KEK...")
    err = km.ValidateKEKRotation()
    if err != nil {
        // Automatic rollback on validation failure
        fmt.Println("Validation failed, rolling back...")
        km.RollbackKEKRotation()
        return fmt.Errorf("validation failed: %w", err)
    }
    
    fmt.Println("Validation successful")
    
    // Phase 3: Commit rotation
    fmt.Println("Phase 3: Committing rotation...")
    err = km.CommitKEKRotation()
    if err != nil {
        // Automatic rollback on commit failure
        fmt.Println("Commit failed, rolling back...")
        km.RollbackKEKRotation()
        return fmt.Errorf("commit failed: %w", err)
    }
    
    fmt.Println("Rotation completed successfully")
    return nil
}
```

### Error Handling and Recovery

```go
func rotationWithRecovery(km *crypto.KeyManager) {
    err := km.RotateKEKZeroDowntime("production-keys")
    if err != nil {
        // Check if rotation is in progress
        keks := km.ListKEKs()
        for _, kek := range keks {
            if kek.Status == crypto.StatusPending || 
               kek.Status == crypto.StatusValidating {
                fmt.Println("Found incomplete rotation, rolling back...")
                km.RollbackKEKRotation()
                break
            }
        }
        
        log.Printf("Rotation failed: %v", err)
        return
    }
    
    fmt.Println("Rotation completed successfully")
}
```

## Best Practices

### When to Rotate Keys

- **Scheduled rotation**: Regular intervals (quarterly, annually)
- **Security incidents**: Suspected key compromise
- **Personnel changes**: Key team member departures
- **Compliance requirements**: Regulatory mandates

### Choosing Rotation Method

- **Use `RotateKEKZeroDowntime()`** for production environments
- **Use step-by-step rotation** when you need validation checkpoints
- **Use traditional `RotateKEK()`** only in development/testing

### Monitoring and Logging

```go
// Monitor rotation status
func monitorRotation(km *crypto.KeyManager) {
    keks := km.ListKEKs()
    
    for _, kek := range keks {
        switch kek.Status {
        case crypto.StatusPending:
            log.Printf("WARNING: Pending KEK found: %s", kek.ID)
        case crypto.StatusValidating:
            log.Printf("INFO: KEK validation in progress: %s", kek.ID)
        case crypto.StatusActive:
            log.Printf("INFO: Active KEK: %s (Created: %s)", 
                kek.ID, kek.CreatedAt)
        case crypto.StatusRevoked:
            log.Printf("INFO: Revoked KEK: %s", kek.ID)
        }
    }
}
```

## Security Considerations

### Memory Safety
- All sensitive key material is automatically zeroed after use
- Revoked keys are immediately removed from memory
- Buffer pooling uses secure memory handling

### Validation Process
- New KEK undergoes encrypt/decrypt testing before activation
- HKDF key derivation validation ensures cryptographic correctness
- Automatic rollback prevents partial rotation states

### Audit Trail
- All key operations generate structured log entries
- Key lifecycle events include timestamps and purposes
- Failed operations are logged with detailed error context

## Performance Characteristics

- **Preparation phase**: ~1ms (key generation + setup)
- **Validation phase**: ~1ms (encrypt/decrypt test cycle)
- **Commit phase**: <1ms (atomic state transition)
- **Memory overhead**: Minimal (dual-KEK only during transition)
- **Service impact**: Zero downtime during entire process

---

*This document covers the key management system. For related topics, see [Encryption & Decryption](encryption.md) and [Security Considerations](security.md).*

---

Harpocrates • an AGILira library