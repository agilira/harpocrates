# Key Utilities

This document describes the key utility features of the `Harpocrates` library, including key generation, import/export, zeroization, and fingerprinting.

## Key Generation
### func GenerateKey() ([]byte, error)
Generates a cryptographically secure random key of 32 bytes (AES-256).

**Returns:**
- `[]byte`: A 32-byte cryptographically secure random key
- `error`: Error if random generation fails

**Error Codes:**
- `"KEY_GEN_ERROR"` - When random generation fails

**Security Notes:**
- Uses `crypto/rand` for cryptographically secure random generation
- Key is suitable for AES-256 encryption
- Always check for errors in production code

### func GenerateNonce(size int) ([]byte, error)
Generates a cryptographically secure random nonce of the specified size.

**Parameters:**
- `size`: The size of the nonce in bytes (must be > 0)

**Returns:**
- `[]byte`: A cryptographically secure random nonce
- `error`: Error if size is invalid or random generation fails

**Error Codes:**
- `"INVALID_NONCE_SIZE"` - When size is not positive
- `"NONCE_GEN_ERROR"` - When random generation fails

**Security Notes:**
- Uses `crypto/rand` for cryptographically secure random generation
- Size should be appropriate for the encryption mode (12 bytes for GCM)
- Never reuse nonces with the same key

### func ValidateKey(key []byte) error
Checks that a key has the correct size for AES-256 (32 bytes).

**Parameters:**
- `key`: The key to validate

**Returns:**
- `error`: Error if key size is not 32 bytes, nil if valid

**Error Codes:**
- `"INVALID_KEY_SIZE"` - When key size is not 32 bytes

**Usage:**
```go
err := crypto.ValidateKey(key)
if err != nil {
    // Key is invalid
}
```

## Key Import/Export
### func KeyToBase64(key []byte) string
Encodes a key as a base64 string.

### func KeyFromBase64(s string) ([]byte, error)
Decodes a base64 string to a key.

**Error Codes:**
- `"BASE64_DECODE_ERROR"` - When base64 decoding fails

### func KeyToHex(key []byte) string
Encodes a key as a hexadecimal string.

### func KeyFromHex(s string) ([]byte, error)
Decodes a hexadecimal string to a key.

**Error Codes:**
- `"HEX_DECODE_ERROR"` - When hex decoding fails

## Zeroization
### func Zeroize(b []byte)
Securely wipes a byte slice from memory.

## Fingerprinting
### func GetKeyFingerprint(key []byte) string
Generates a non-cryptographic fingerprint for a key.

## Usage Examples

### Basic Key Management
```go
import (
    "fmt"
    "log"
    "github.com/agilira/harpocrates"
)

// Generate a new key
key, err := crypto.GenerateKey()
if err != nil {
    log.Fatal("Failed to generate key:", err)
}

// Validate the key
err = crypto.ValidateKey(key)
if err != nil {
    log.Fatal("Invalid key:", err)
}

// Generate a fingerprint for identification
fingerprint := crypto.GetKeyFingerprint(key)
fmt.Printf("Key fingerprint: %s\n", fingerprint)

// Export key in different formats
base64Key := crypto.KeyToBase64(key)
hexKey := crypto.KeyToHex(key)

fmt.Printf("Base64 key: %s\n", base64Key)
fmt.Printf("Hex key: %s\n", hexKey)

// Import key from base64
restoredKey, err := crypto.KeyFromBase64(base64Key)
if err != nil {
    log.Fatal("Failed to import key:", err)
}

// Verify the restored key matches
if crypto.GetKeyFingerprint(restoredKey) == fingerprint {
    fmt.Println("Key successfully restored and verified")
}

// Securely wipe sensitive data
crypto.Zeroize(key)
crypto.Zeroize(restoredKey)
```

### Working with Nonces
```go
import "github.com/agilira/harpocrates"

// Generate a nonce for AES-GCM (12 bytes is standard)
nonce, err := crypto.GenerateNonce(12)
if err != nil {
    log.Fatal("Failed to generate nonce:", err)
}

fmt.Printf("Generated nonce: %d bytes\n", len(nonce))

// Generate a larger nonce for other purposes
largeNonce, err := crypto.GenerateNonce(32)
if err != nil {
    log.Fatal("Failed to generate large nonce:", err)
}

// Securely wipe nonces after use
crypto.Zeroize(nonce)
crypto.Zeroize(largeNonce)
```

### Key Import/Export with Error Handling
```go
import (
    "errors"
    "github.com/agilira/harpocrates"
)

// Export key as base64
key, _ := crypto.GenerateKey()
base64Key := crypto.KeyToBase64(key)

// Import key with error handling
importedKey, err := crypto.KeyFromBase64(base64Key)
if err != nil {
    log.Fatal("Failed to import key:", err)
}

// Validate imported key
err = crypto.ValidateKey(importedKey)
if err != nil {
    log.Fatal("Imported key is invalid:", err)
}

// Test hex import/export
hexKey := crypto.KeyToHex(key)
hexImportedKey, err := crypto.KeyFromHex(hexKey)
if err != nil {
    log.Fatal("Failed to import hex key:", err)
}

// Verify both methods work
if crypto.GetKeyFingerprint(importedKey) == crypto.GetKeyFingerprint(hexImportedKey) {
    fmt.Println("Both import methods work correctly")
}

// Clean up
crypto.Zeroize(key)
crypto.Zeroize(importedKey)
crypto.Zeroize(hexImportedKey)
```

### Error Handling Examples
```go
import (
    "errors"
    "github.com/agilira/harpocrates"
)

// Test invalid nonce size
_, err := crypto.GenerateNonce(0)
if err != nil {
    fmt.Println("Expected error for zero nonce size:", err)
}

// Test invalid nonce size (negative)
_, err = crypto.GenerateNonce(-1)
if err != nil {
    fmt.Println("Expected error for negative nonce size:", err)
}

// Test invalid base64 key
_, err = crypto.KeyFromBase64("invalid-base64!")
if err != nil {
    fmt.Println("Expected error for invalid base64:", err)
}

// Test invalid hex key
_, err = crypto.KeyFromHex("invalid-hex!")
if err != nil {
    fmt.Println("Expected error for invalid hex:", err)
}

// Test invalid key size
invalidKey := []byte("short-key")
err = crypto.ValidateKey(invalidKey)
if err != nil {
    fmt.Println("Expected error for invalid key size:", err)
}
``` 

---

Harpocrates • an AGILira library