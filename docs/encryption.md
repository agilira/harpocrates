# Encryption & Decryption

This document describes the encryption and decryption features of the `Harpocrates` library, including error handling, usage, and API reference.

## Overview
The library provides secure encryption and decryption using AES-256-GCM. All functions are designed for drop-in compatibility and professional error handling.

## Error Handling
- All functions return standard Go errors for maximum compatibility.
- Internally, errors are enriched using `go-errors` and wrapped with standard errors.
- You can use `errors.Is` for standard error matching, and `errors.As` to extract rich error details if you use `go-errors` in your project.

## Public Errors
- `ErrInvalidKeySize`
- `ErrEmptyPlaintext`
- `ErrCipherInit`
- `ErrGCMInit`
- `ErrNonceGen`
- `ErrBase64Decode`
- `ErrCiphertextShort`
- `ErrDecrypt`

## API Reference

### func Encrypt(plaintext string, key []byte) (string, error)
Encrypts a plaintext string using AES-256-GCM. Returns a base64 encoded string containing the nonce and ciphertext.

### func Decrypt(encryptedText string, key []byte) (string, error)
Decrypts a base64 encoded ciphertext string using AES-256-GCM. Returns the decrypted plaintext string.

## Usage Examples

### Basic Encryption/Decryption
```go
import (
    "fmt"
    "log"
    "github.com/agilira/harpocrates"
)

// Generate a new encryption key
key, err := crypto.GenerateKey()
if err != nil {
    log.Fatal("Failed to generate key:", err)
}

// Encrypt some data
plaintext := "This is sensitive data that needs to be encrypted"
ciphertext, err := crypto.Encrypt(plaintext, key)
if err != nil {
    log.Fatal("Failed to encrypt:", err)
}

fmt.Printf("Encrypted: %s\n", ciphertext[:50]+"...")

// Decrypt the data
decrypted, err := crypto.Decrypt(ciphertext, key)
if err != nil {
    log.Fatal("Failed to decrypt:", err)
}

fmt.Printf("Decrypted: %s\n", decrypted)

// Securely wipe the key from memory
crypto.Zeroize(key)
```

### Error Handling
```go
import (
    "errors"
    "github.com/agilira/harpocrates"
)

// Example of handling different error types
invalidKey := []byte("short-key")
_, err := crypto.Encrypt("test data", invalidKey)
if err != nil {
    if errors.Is(err, crypto.ErrInvalidKeySize) {
        // Handle invalid key size
        fmt.Println("Key size must be 32 bytes")
    } else if errors.Is(err, crypto.ErrCipherInit) {
        // Handle cipher initialization error
        fmt.Println("Failed to initialize cipher")
    }
    // Handle other errors
}

// Example of handling empty encrypted text
validKey, _ := crypto.GenerateKey()
_, err = crypto.Decrypt("", validKey)
if err != nil {
    if errors.Is(err, crypto.ErrEmptyPlaintext) {
        fmt.Println("Encrypted text cannot be empty")
    }
}

// Example of handling corrupted ciphertext
ciphertext, _ := crypto.Encrypt("test data", validKey)
// Corrupt the ciphertext
corrupted := ciphertext[:len(ciphertext)-1] + "X"
_, err = crypto.Decrypt(corrupted, validKey)
if err != nil {
    if errors.Is(err, crypto.ErrDecrypt) {
        fmt.Println("Decryption failed - data may be corrupted")
    }
}

crypto.Zeroize(validKey)
```

### Working with Binary Data
```go
import (
    "bytes"
    "github.com/agilira/harpocrates"
)

// Encrypt binary data (images, files, etc.)
key, _ := crypto.GenerateKey()

// Binary data with null bytes and special characters
binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x00, 0x7F, 0x80, 0x81}

// Encrypt using EncryptBytes (recommended for binary data)
ciphertext, err := crypto.EncryptBytes(binaryData, key)
if err != nil {
    log.Fatal("Failed to encrypt binary data:", err)
}

// Decrypt using DecryptBytes
decryptedData, err := crypto.DecryptBytes(ciphertext, key)
if err != nil {
    log.Fatal("Failed to decrypt binary data:", err)
}

// Verify data integrity
if !bytes.Equal(binaryData, decryptedData) {
    log.Fatal("Binary data mismatch after encryption/decryption")
}

fmt.Println("Binary data encrypted and decrypted successfully")
crypto.Zeroize(key)
```

### Working with JSON Data
```go
import (
    "encoding/json"
    "github.com/agilira/harpocrates"
)

// Encrypt JSON data
type UserData struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    Token    string `json:"token"`
}

userData := UserData{
    Username: "john_doe",
    Email:    "john@example.com",
    Token:    "secret_token_123",
}

// Convert to JSON
jsonData, err := json.Marshal(userData)
if err != nil {
    log.Fatal("Failed to marshal JSON:", err)
}

// Encrypt JSON data using EncryptBytes (recommended for binary data)
key, _ := crypto.GenerateKey()
encryptedJSON, err := crypto.EncryptBytes(jsonData, key)
if err != nil {
    log.Fatal("Failed to encrypt JSON:", err)
}

// Decrypt and unmarshal
decryptedJSON, err := crypto.DecryptBytes(encryptedJSON, key)
if err != nil {
    log.Fatal("Failed to decrypt JSON:", err)
}

var restoredData UserData
err = json.Unmarshal(decryptedJSON, &restoredData)
if err != nil {
    log.Fatal("Failed to unmarshal JSON:", err)
}

fmt.Printf("Restored user: %+v\n", restoredData)
crypto.Zeroize(key)
```

### String vs Binary Data Functions
```go
import "github.com/agilira/harpocrates"

key, _ := crypto.GenerateKey()

// For string data, you can use either approach:
textData := "Hello, World!"

// Option 1: Use Encrypt/Decrypt (convenience functions)
ciphertext1, _ := crypto.Encrypt(textData, key)
decrypted1, _ := crypto.Decrypt(ciphertext1, key)

// Option 2: Use EncryptBytes/DecryptBytes (core functions)
ciphertext2, _ := crypto.EncryptBytes([]byte(textData), key)
decrypted2, _ := crypto.DecryptBytes(ciphertext2, key)

// Both approaches produce the same result
fmt.Println("String approach:", decrypted1)
fmt.Println("Binary approach:", string(decrypted2))

// For binary data, use EncryptBytes/DecryptBytes
binaryData := []byte{0x00, 0x01, 0xFF, 0xFE}
ciphertext3, _ := crypto.EncryptBytes(binaryData, key)
decrypted3, _ := crypto.DecryptBytes(ciphertext3, key)

fmt.Printf("Binary data: %v\n", decrypted3)
crypto.Zeroize(key)
```

## Advanced Error Extraction
If you use `go-errors`, you can extract rich error details:
```go
import (
    "errors"
    goerrors "github.com/agilira/go-errors"
)

_, err := crypto.Encrypt("data", key)
if err != nil {
    var richErr *goerrors.Error
    if errors.As(err, &richErr) {
        fmt.Println(richErr.Code) // error code
        fmt.Println(richErr.Error())
    }
}
``` 

---

Harpocrates • an AGILira library