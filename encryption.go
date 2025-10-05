// encryption.go: Encryption and decryption utilities using AES-256-GCM and other secure algorithms.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"

	goerrors "github.com/agilira/go-errors"
)

// Global cipher cache per performance ottimale - evita aes.NewCipher + cipher.NewGCM overhead
var (
	cipherCacheMu sync.RWMutex
	cipherCache   = make(map[string]cipher.AEAD)
)

// getCachedGCM ritorna un GCM cipher cached per la chiave, o lo crea se necessario
func getCachedGCM(key []byte) (cipher.AEAD, error) {
	keyFingerprint := GetKeyFingerprint(key)

	// Try read-only first per performance
	cipherCacheMu.RLock()
	if gcm, exists := cipherCache[keyFingerprint]; exists {
		cipherCacheMu.RUnlock()
		return gcm, nil
	}
	cipherCacheMu.RUnlock()

	// Create new GCM - need write lock
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Cache it
	cipherCacheMu.Lock()
	cipherCache[keyFingerprint] = gcm
	cipherCacheMu.Unlock()

	return gcm, nil
}

// KeySize is the required key size for AES-256 encryption in bytes.
// AES-256 requires exactly 32 bytes (256 bits) for the encryption key.
const KeySize = 32

// Public standard errors for drop-in compatibility.
// These errors can be used with errors.Is() for error checking.
var (
	// ErrInvalidKeySize is returned when the provided key is not exactly 32 bytes.
	ErrInvalidKeySize = errors.New("crypto: invalid key size")

	// ErrEmptyPlaintext is returned when trying to decrypt an empty string.
	// Note: Empty plaintext is supported for encryption.
	ErrEmptyPlaintext = errors.New("crypto: plaintext cannot be empty")

	// ErrCipherInit is returned when AES cipher initialization fails.
	ErrCipherInit = errors.New("crypto: cipher initialization error")

	// ErrGCMInit is returned when GCM mode initialization fails.
	ErrGCMInit = errors.New("crypto: GCM initialization error")

	// ErrNonceGen is returned when nonce generation fails.
	ErrNonceGen = errors.New("crypto: nonce generation error")

	// ErrBase64Decode is returned when base64 decoding fails.
	ErrBase64Decode = errors.New("crypto: base64 decode error")

	// ErrCiphertextShort is returned when the ciphertext is too short to contain a valid nonce.
	ErrCiphertextShort = errors.New("crypto: ciphertext too short")

	// ErrDecrypt is returned when decryption fails due to authentication failure or corruption.
	ErrDecrypt = errors.New("crypto: decryption error")
)

// Error codes for rich error handling
const (
	ErrCodeInvalidKey   = "CRYPTO_INVALID_KEY"
	ErrCodeEmptyPlain   = "CRYPTO_EMPTY_PLAINTEXT"
	ErrCodeCipherInit   = "CRYPTO_CIPHER_INIT"
	ErrCodeGCMInit      = "CRYPTO_GCM_INIT"
	ErrCodeNonceGen     = "CRYPTO_NONCE_GEN"
	ErrCodeBase64Decode = "CRYPTO_BASE64_DECODE"
	ErrCodeCipherShort  = "CRYPTO_CIPHERTEXT_SHORT"
	ErrCodeDecrypt      = "CRYPTO_DECRYPT"
)

// EncryptBytes encrypts a plaintext byte slice using AES-256-GCM authenticated encryption.
//
// The function uses AES-256 in GCM mode, which provides both confidentiality and authenticity.
// The returned string is base64-encoded and contains the nonce, ciphertext, and authentication tag.
// This is the core encryption function that works with binary data with buffer pooling optimization.
//
// Parameters:
//   - plaintext: The byte slice to encrypt (can be empty)
//   - key: The 32-byte encryption key (must be exactly KeySize bytes)
//
// Returns:
//   - A base64-encoded string containing the encrypted data
//   - An error if encryption fails
//
// Example:
//
//	key, _ := crypto.GenerateKey()
//	data := []byte("sensitive binary data")
//	ciphertext, err := crypto.EncryptBytes(data, key)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println("Encrypted:", ciphertext)
//
// Empty plaintext is supported and will result in a valid ciphertext containing
// only the nonce and authentication tag.
func EncryptBytes(plaintext []byte, key []byte) (string, error) {
	if len(key) != KeySize {
		richErr := goerrors.New(ErrCodeInvalidKey, fmt.Sprintf("invalid key size: must be 32 bytes for AES-256 (got %d)", len(key)))
		return "", fmt.Errorf("%w: %w", ErrInvalidKeySize, richErr)
	}

	// Performance optimization: use cached GCM instead of creating every time
	gcm, err := getCachedGCM(key)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeCipherInit, "failed to get cached cipher")
		return "", fmt.Errorf("%w: %w", ErrCipherInit, richErr)
	}

	// Use buffer pooling for the nonce to reduce allocations
	nonceBuffer := getBuffer(gcm.NonceSize())
	defer putBuffer(nonceBuffer)
	nonce := (*nonceBuffer)[:gcm.NonceSize()]

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		richErr := goerrors.Wrap(err, ErrCodeNonceGen, "failed to generate nonce")
		return "", fmt.Errorf("%w: %w", ErrNonceGen, richErr)
	}

	// Micro-optimization: use buffer pool for ciphertext to reduce allocations
	expectedSize := len(nonce) + len(plaintext) + gcm.Overhead()
	ciphertextBuf := getDynamicBuffer()
	defer putDynamicBuffer(ciphertextBuf)

	// Preallocate capacity to avoid resize during Seal
	if cap(ciphertextBuf) < expectedSize {
		ciphertextBuf = make([]byte, 0, expectedSize) // Only for too small buffers
	}

	// Append nonce first, then seal
	ciphertextBuf = append(ciphertextBuf, nonce...)
	ciphertext := gcm.Seal(ciphertextBuf, nonce, plaintext, nil) // #nosec G407 -- nonce is generated from crypto/rand, not hardcoded
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// EncryptBytesWithAAD encrypts a plaintext byte slice using AES-256-GCM with Additional Authenticated Data.
//
// This function is designed for NEMESIS vault requirements where AAD contains metadata like
// {tenant, path, version, KeyID} for authenticated encryption with context binding.
//
// Parameters:
//   - plaintext: The byte slice to encrypt (can be empty)
//   - key: The 32-byte encryption key (must be exactly KeySize bytes)
//   - aad: Additional Authenticated Data (authenticated but not encrypted)
//
// Returns:
//   - A base64-encoded string containing the encrypted data
//   - An error if encryption fails
//
// Example for NEMESIS:
//
//	key, _ := crypto.GenerateKey()
//	aad := []byte(`{"tenant":"app","path":"/db/pass","version":1,"keyID":"kek_abc123"}`)
//	ciphertext, err := crypto.EncryptBytesWithAAD(secretData, key, aad)
func EncryptBytesWithAAD(plaintext []byte, key []byte, aad []byte) (string, error) {
	if len(key) != KeySize {
		richErr := goerrors.New(ErrCodeInvalidKey, fmt.Sprintf("invalid key size: must be 32 bytes for AES-256 (got %d)", len(key)))
		return "", fmt.Errorf("%w: %w", ErrInvalidKeySize, richErr)
	}

	// Performance optimization: use cached GCM instead of creating every time
	gcm, err := getCachedGCM(key)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeCipherInit, "failed to get cached cipher")
		return "", fmt.Errorf("%w: %w", ErrCipherInit, richErr)
	}

	// Use buffer pooling for the nonce to reduce allocations
	nonceBuffer := getBuffer(gcm.NonceSize())
	defer putBuffer(nonceBuffer)
	nonce := (*nonceBuffer)[:gcm.NonceSize()]

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		richErr := goerrors.Wrap(err, ErrCodeNonceGen, "failed to generate nonce")
		return "", fmt.Errorf("%w: %w", ErrNonceGen, richErr)
	}

	// gcm.Seal with AAD - authenticated but not encrypted
	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad) // #nosec G407 -- nonce is generated from crypto/rand, not hardcoded
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptBytes decrypts a base64-encoded ciphertext string using AES-256-GCM authenticated decryption.
//
// The function verifies the authenticity of the ciphertext using the embedded authentication tag.
// If the ciphertext has been tampered with, the function will return an error.
// This is the core decryption function that returns binary data with buffer pooling optimization.
//
// Parameters:
//   - encryptedText: The base64-encoded encrypted string (cannot be empty)
//   - key: The 32-byte decryption key (must be exactly KeySize bytes)
//
// Returns:
//   - The decrypted plaintext as a byte slice
//   - An error if decryption fails (authentication failure, corruption, or invalid input)
//
// Example:
//
//	key, _ := crypto.GenerateKey()
//	data := []byte("sensitive binary data")
//	ciphertext, _ := crypto.EncryptBytes(data, key)
//	plaintext, err := crypto.DecryptBytes(ciphertext, key)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println("Decrypted:", string(plaintext)) // Output: sensitive binary data
//
// The function will return an error if:
//   - The key size is incorrect
//   - The encrypted text is empty
//   - The base64 decoding fails
//   - The ciphertext is too short
//   - Authentication fails (tampering detected)
func DecryptBytes(encryptedText string, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		richErr := goerrors.New(ErrCodeInvalidKey, fmt.Sprintf("invalid key size: must be 32 bytes for AES-256 (got %d)", len(key)))
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeySize, richErr)
	}
	if encryptedText == "" {
		richErr := goerrors.New(ErrCodeEmptyPlain, "encrypted text cannot be empty")
		return nil, fmt.Errorf("%w: %w", ErrEmptyPlaintext, richErr)
	}

	// uses dynamic buffer pool for ciphertext decoding to reduce allocations
	ciphertextBuffer := getDynamicBuffer()
	defer putDynamicBuffer(ciphertextBuffer)

	// Decode directly into the pooled buffer if possible
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeBase64Decode, "failed to decode base64")
		return nil, fmt.Errorf("%w: %w", ErrBase64Decode, richErr)
	}

	// Performance optimization: use cached GCM instead of creating every time
	gcm, err := getCachedGCM(key)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeCipherInit, "failed to get cached cipher")
		return nil, fmt.Errorf("%w: %w", ErrGCMInit, richErr)
	}
	if len(ciphertext) < gcm.NonceSize() {
		richErr := goerrors.New(ErrCodeCipherShort, "ciphertext too short")
		return nil, fmt.Errorf("%w: %w", ErrCiphertextShort, richErr)
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Use a buffer for the plaintext if possible
	var destBuffer []byte
	if len(ciphertext) <= 64*1024 { // For not too large data
		plaintextBuffer := getDynamicBuffer()
		defer func() {
			// Zero out the plaintext in the buffer before reuse for safety
			for i := range destBuffer {
				destBuffer[i] = 0
			}
			putDynamicBuffer(plaintextBuffer)
		}()
		destBuffer = plaintextBuffer
	}

	plaintext, err := gcm.Open(destBuffer[:0], nonce, ciphertext, nil)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeDecrypt, "failed to decrypt")
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, richErr)
	}

	// Copy the plaintext into a new slice to avoid references to the pooled buffer
	result := make([]byte, len(plaintext))
	copy(result, plaintext)
	return result, nil
}

// DecryptBytesWithAAD decrypts a base64-encoded ciphertext string using AES-256-GCM with Additional Authenticated Data.
//
// This function verifies both the ciphertext authenticity and the AAD integrity.
// If either the ciphertext or AAD has been tampered with, the function will return an error.
// This is designed for NEMESIS vault requirements with metadata authentication.
//
// Parameters:
//   - encryptedText: The base64-encoded encrypted string (cannot be empty)
//   - key: The 32-byte decryption key (must be exactly KeySize bytes)
//   - aad: Additional Authenticated Data (must match encryption AAD)
//
// Returns:
//   - The decrypted plaintext as a byte slice
//   - An error if decryption or AAD verification fails
//
// Example for NEMESIS:
//
//	aad := []byte(`{"tenant":"app","path":"/db/pass","version":1,"keyID":"kek_abc123"}`)
//	decrypted, err := crypto.DecryptBytesWithAAD(ciphertext, key, aad)
func DecryptBytesWithAAD(encryptedText string, key []byte, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		richErr := goerrors.New(ErrCodeInvalidKey, fmt.Sprintf("invalid key size: must be 32 bytes for AES-256 (got %d)", len(key)))
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeySize, richErr)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeBase64Decode, "failed to decode base64")
		return nil, fmt.Errorf("%w: %w", ErrBase64Decode, richErr)
	}

	// Performance optimization: use cached GCM instead of creating every time
	gcm, err := getCachedGCM(key)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeGCMInit, "failed to create GCM")
		return nil, fmt.Errorf("%w: %w", ErrGCMInit, richErr)
	}
	if len(ciphertext) < gcm.NonceSize() {
		richErr := goerrors.New(ErrCodeCipherShort, "ciphertext too short")
		return nil, fmt.Errorf("%w: %w", ErrCiphertextShort, richErr)
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Use a buffer for the plaintext if possible
	var destBuffer []byte
	if len(ciphertext) <= 64*1024 { // For not too large data
		plaintextBuffer := getDynamicBuffer()
		defer func() {
			// Zero out the plaintext in the buffer before reuse for safety
			for i := range destBuffer {
				destBuffer[i] = 0
			}
			putDynamicBuffer(plaintextBuffer)
		}()
		destBuffer = plaintextBuffer
	}

	// Decrypt with AAD verification - if AAD doesn't match, decryption fails
	plaintext, err := gcm.Open(destBuffer[:0], nonce, ciphertext, aad)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeDecrypt, "GCM decryption failed (wrong key, tampered data, or AAD mismatch)")
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, richErr)
	}

	// Copy the plaintext into a new slice to avoid references to the pooled buffer
	result := make([]byte, len(plaintext))
	copy(result, plaintext)
	return result, nil
}

// Encrypt encrypts a plaintext string using AES-256-GCM authenticated encryption.
//
// This is a convenience wrapper around EncryptBytes that works with strings.
// The function uses AES-256 in GCM mode, which provides both confidentiality and authenticity.
// The returned string is base64-encoded and contains the nonce, ciphertext, and authentication tag.
//
// Parameters:
//   - plaintext: The string to encrypt (can be empty)
//   - key: The 32-byte encryption key (must be exactly KeySize bytes)
//
// Returns:
//   - A base64-encoded string containing the encrypted data
//   - An error if encryption fails
//
// Example:
//
//	key, _ := crypto.GenerateKey()
//	ciphertext, err := crypto.Encrypt("sensitive data", key)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println("Encrypted:", ciphertext)
//
// Empty plaintext is supported and will result in a valid ciphertext containing
// only the nonce and authentication tag.
func Encrypt(plaintext string, key []byte) (string, error) {
	// Ottimizzazione micro: usa unsafe conversion per evitare allocazione []byte(plaintext)
	// Sicuro perché EncryptBytes non modifica il contenuto
	return EncryptBytes([]byte(plaintext), key) // Manteniamo conversione safe per ora
}

// Decrypt decrypts a base64-encoded ciphertext string using AES-256-GCM authenticated decryption.
//
// This is a convenience wrapper around DecryptBytes that works with strings.
// The function verifies the authenticity of the ciphertext using the embedded authentication tag.
// If the ciphertext has been tampered with, the function will return an error.
//
// Parameters:
//   - encryptedText: The base64-encoded encrypted string (cannot be empty)
//   - key: The 32-byte decryption key (must be exactly KeySize bytes)
//
// Returns:
//   - The decrypted plaintext string
//   - An error if decryption fails (authentication failure, corruption, or invalid input)
//
// Example:
//
//	key, _ := crypto.GenerateKey()
//	ciphertext, _ := crypto.Encrypt("sensitive data", key)
//	plaintext, err := crypto.Decrypt(ciphertext, key)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println("Decrypted:", plaintext) // Output: sensitive data
//
// The function will return an error if:
//   - The key size is incorrect
//   - The encrypted text is empty
//   - The base64 decoding fails
//   - The ciphertext is too short
//   - Authentication fails (tampering detected)
func Decrypt(encryptedText string, key []byte) (string, error) {
	plaintext, err := DecryptBytes(encryptedText, key)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// EncryptWithAAD encrypts a plaintext string using AES-256-GCM with Additional Authenticated Data.
//
// This is a convenience wrapper around EncryptBytesWithAAD that works with strings.
// Designed for NEMESIS vault requirements where AAD contains metadata for context binding.
//
// Parameters:
//   - plaintext: The string to encrypt (can be empty)
//   - key: The 32-byte encryption key (must be exactly KeySize bytes)
//   - aad: Additional Authenticated Data as string (authenticated but not encrypted)
//
// Returns:
//   - A base64-encoded string containing the encrypted data
//   - An error if encryption fails
//
// Example for NEMESIS:
//
//	key, _ := crypto.GenerateKey()
//	aad := `{"tenant":"app","path":"/db/pass","version":1,"keyID":"kek_abc123"}`
//	ciphertext, err := crypto.EncryptWithAAD("secret-password", key, aad)
func EncryptWithAAD(plaintext string, key []byte, aad string) (string, error) {
	return EncryptBytesWithAAD([]byte(plaintext), key, []byte(aad))
}

// DecryptWithAAD decrypts a base64-encoded ciphertext string using AES-256-GCM with Additional Authenticated Data.
//
// This is a convenience wrapper around DecryptBytesWithAAD that works with strings.
// Verifies both ciphertext authenticity and AAD integrity for NEMESIS requirements.
//
// Parameters:
//   - encryptedText: The base64-encoded encrypted string (cannot be empty)
//   - key: The 32-byte decryption key (must be exactly KeySize bytes)
//   - aad: Additional Authenticated Data as string (must match encryption AAD)
//
// Returns:
//   - The decrypted plaintext string
//   - An error if decryption or AAD verification fails
//
// Example for NEMESIS:
//
//	aad := `{"tenant":"app","path":"/db/pass","version":1,"keyID":"kek_abc123"}`
//	plaintext, err := crypto.DecryptWithAAD(ciphertext, key, aad)
func DecryptWithAAD(encryptedText string, key []byte, aad string) (string, error) {
	plaintext, err := DecryptBytesWithAAD(encryptedText, key, []byte(aad))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
