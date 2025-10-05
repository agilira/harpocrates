# Key Derivation Functions (KDF)

This document describes the key derivation features of the `Harpocrates` library, including Argon2id (recommended) and PBKDF2 (legacy).

## Argon2id (Recommended)
### func DeriveKey(password, salt []byte, keyLen int, params *KDFParams) ([]byte, error)
Derives a key from a password and salt using Argon2id with optional custom parameters.

### func DeriveKeyDefault(password, salt []byte, keyLen int) ([]byte, error)
Derives a key using Argon2id with secure default parameters.

### func DeriveKeyWithParams(password, salt []byte, time, memoryMB, threads, keyLen int) ([]byte, error)
Derives a key using Argon2id with custom parameters (legacy function). For new code, consider using `DeriveKey` with a `KDFParams` struct for better readability.

**Parameters:**
- `password`: The input password as a byte slice (must not be empty)
- `salt`: The salt as a byte slice (must not be empty)
- `keyLen`: The desired length of the derived key in bytes (must be > 0)
- `params`: Optional custom parameters (if nil, secure defaults are used)

**Default Parameters:**
- Time: 3 iterations
- Memory: 64 MB
- Threads: 4

**Returns:**
- `[]byte`: The derived key of the specified length
- `error`: Error if any parameter is invalid or derivation fails

**Security Notes:**
- Argon2id is resistant to ASIC/FPGA attacks
- Uses memory-hard functions for better security
- Default parameters provide strong protection
- Use a cryptographically secure random salt (at least 16 bytes)

## Configuration
### KDFParams Struct
```go
type KDFParams struct {
    Time    uint32 `json:"time,omitempty"`    // Number of iterations
    Memory  uint32 `json:"memory,omitempty"`  // Memory usage in MB
    Threads uint8  `json:"threads,omitempty"` // Number of threads
}
```

## Usage Examples

### Basic Key Derivation with Defaults
```go
import "github.com/agilira/harpocrates"

password := []byte("my-secure-password")
salt := []byte("random-salt-123")
key, err := crypto.DeriveKeyDefault(password, salt, 32)
if err != nil {
    // handle error
}
```

### Custom Parameters
```go
params := &crypto.KDFParams{
    Time:    4,   // 4 iterations
    Memory:  128, // 128 MB
    Threads: 2,   // 2 threads
}
key, err := crypto.DeriveKey(password, salt, 32, params)
if err != nil {
    // handle error
}
```

### Using DeriveKeyWithParams (Legacy)
```go
// Direct parameter control (legacy function)
key, err := crypto.DeriveKeyWithParams(password, salt, 4, 128, 2, 32)
if err != nil {
    // handle error
}
```

### Configuration from JSON
```go
type AppConfig struct {
    KDFParams crypto.KDFParams `json:"kdf_params"`
}

var config AppConfig
json.NewDecoder(file).Decode(&config)
key, err := crypto.DeriveKey(password, salt, 32, &config.KDFParams)
```

## PBKDF2 (Legacy)
### func DeriveKeyPBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error)
Derives a key from a password and salt using PBKDF2 with SHA-256.

**Parameters:**
- `password`: The input password as a byte slice (must not be empty)
- `salt`: The salt as a byte slice (must not be empty)
- `iterations`: The number of PBKDF2 iterations (must be > 0, recommended: >= 100,000)
- `keyLen`: The desired length of the derived key in bytes (must be > 0)

**Returns:**
- `[]byte`: The derived key of the specified length
- `error`: Error if any parameter is invalid or derivation fails

**Security Notes:**
- Use at least 100,000 iterations for production use
- Use a cryptographically secure random salt
- The salt should be at least 16 bytes long
- Store the salt alongside the derived key

## Usage Examples

### Basic Key Derivation
```go
import "github.com/agilira/harpocrates"

password := []byte("my-secure-password")
salt := []byte("random-salt-123")
key, err := crypto.DeriveKeyPBKDF2(password, salt, 100000, 32)
if err != nil {
    // handle error
}
```

### Secure Key Derivation with Generated Salt
```go
import (
    "crypto/rand"
    "github.com/agilira/harpocrates"
)

password := []byte("my-password")

// Generate a secure random salt
salt := make([]byte, 32)
_, err := rand.Read(salt)
if err != nil {
    // handle error
}

// Derive key with high iteration count
key, err := crypto.DeriveKeyPBKDF2(password, salt, 200000, 32)
if err != nil {
    // handle error
}

// Store salt alongside key for later verification
// salt and key should be stored securely
```

### Error Handling
```go
key, err := crypto.DeriveKeyPBKDF2(password, salt, iterations, keyLen)
if err != nil {
    // The function returns go-errors with specific codes:
    // - "EMPTY_PASSWORD" for empty password
    // - "EMPTY_SALT" for empty salt
    // - "INVALID_ITERATIONS" for non-positive iterations
    // - "INVALID_KEYLEN" for non-positive key length
    
    // Handle error appropriately
    fmt.Printf("Key derivation failed: %v\n", err)
}
```

## Legacy Support
- **PBKDF2** is maintained for backward compatibility but is deprecated
- **Argon2id** is now the recommended KDF for all new applications
- Consider migrating existing PBKDF2 implementations to Argon2id for better security 

---

Harpocrates • an AGILira library