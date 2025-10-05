// keyutils.go: Key utilities for import/export, zeroization, and fingerprinting.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	goerrors "github.com/agilira/go-errors"
)

// KeyToBase64 encodes a key as a base64 string.
//
// This function is useful for storing keys in text-based formats like JSON or configuration files.
// The returned string is safe to use in URLs and other text contexts.
//
// Parameters:
//   - key: The key to encode (can be any byte slice)
//
// Returns:
//   - A base64-encoded string representation of the key
//
// Example:
//
//	key, _ := crypto.GenerateKey()
//	base64Key := crypto.KeyToBase64(key)
//	fmt.Println("Base64 key:", base64Key)
func KeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// KeyFromBase64 decodes a base64 string to a key.
//
// This function is the inverse of KeyToBase64 and is useful for loading keys
// from text-based storage formats like JSON or configuration files.
//
// Parameters:
//   - s: The base64-encoded string to decode
//
// Returns:
//   - The decoded key as a byte slice
//   - An error if the base64 decoding fails
//
// Example:
//
//	base64Key := "dGVzdC1rZXktZGF0YS0xMjM0NTY3ODkwYWJjZGVm"
//	key, err := crypto.KeyFromBase64(base64Key)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println("Decoded key length:", len(key))
func KeyFromBase64(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, goerrors.Wrap(err, "BASE64_DECODE_ERROR", "failed to decode base64 key")
	}
	return key, nil
}

// KeyToHex encodes a key as a hexadecimal string.
//
// This function is useful for displaying keys in a human-readable format
// or storing them in text-based formats. The returned string contains only
// lowercase hexadecimal characters (0-9, a-f).
//
// Parameters:
//   - key: The key to encode (can be any byte slice)
//
// Returns:
//   - A hexadecimal string representation of the key
//
// Example:
//
//	key, _ := crypto.GenerateKey()
//	hexKey := crypto.KeyToHex(key)
//	fmt.Println("Hex key:", hexKey)
func KeyToHex(key []byte) string {
	return hex.EncodeToString(key)
}

// KeyFromHex decodes a hexadecimal string to a key.
//
// This function is the inverse of KeyToHex and is useful for loading keys
// from hexadecimal representations. The input string can contain both
// uppercase and lowercase hexadecimal characters.
//
// Parameters:
//   - s: The hexadecimal string to decode
//
// Returns:
//   - The decoded key as a byte slice
//   - An error if the hexadecimal decoding fails
//
// Example:
//
//	hexKey := "746573742d6b65792d646174612d31323334353637383930616263646566"
//	key, err := crypto.KeyFromHex(hexKey)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println("Decoded key length:", len(key))
func KeyFromHex(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, goerrors.Wrap(err, "HEX_DECODE_ERROR", "failed to decode hex key")
	}
	return key, nil
}

// Zeroize securely wipes a byte slice from memory.
//
// This function overwrites all bytes in the slice with zeros to prevent
// sensitive data from remaining in memory after use. This is important
// for security when dealing with cryptographic keys and other sensitive data.
//
// Note: This function modifies the original slice in place.
//
// Parameters:
//   - b: The byte slice to zeroize
//
// Example:
//
//	key, _ := crypto.GenerateKey()
//	// Use the key for encryption/decryption
//	ciphertext, _ := crypto.Encrypt("data", key)
//	// Securely wipe the key from memory
//	crypto.Zeroize(key)
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GetKeyFingerprint generates a fingerprint for a key (non-cryptographic).
//
// This function creates a short, human-readable identifier for a key by computing
// the SHA-256 hash and taking the first 8 bytes. This provides better collision
// resistance than using just the first few bytes of the key while maintaining speed.
//
// The fingerprint is useful for logging, debugging, and identifying keys without
// exposing the actual key material.
//
// Parameters:
//   - key: The key to generate a fingerprint for
//
// Returns:
//   - A 16-character hexadecimal string representing the fingerprint
//   - An empty string if the key is empty
//
// Example:
//
//	key, _ := crypto.GenerateKey()
//	fingerprint := crypto.GetKeyFingerprint(key)
//	fmt.Println("Key fingerprint:", fingerprint) // e.g., "a1b2c3d4e5f67890"
//
// Uses the first 8 bytes of SHA-256 for better collision resistance while maintaining speed.
func GetKeyFingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	hash := sha256.Sum256(key)
	return fmt.Sprintf("%016x", hash[:8])
}

// GenerateKey generates a cryptographically secure random key of KeySize bytes.
//
// This function creates a new 32-byte (256-bit) key suitable for AES-256 encryption.
// The key is generated using the cryptographically secure random number generator
// provided by the operating system.
//
// Returns:
//   - A 32-byte key as a byte slice
//   - An error if key generation fails
//
// Example:
//
//	key, err := crypto.GenerateKey()
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println("Generated key length:", len(key)) // Output: 32
//
// The generated key is suitable for use with Encrypt and Decrypt functions.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, goerrors.Wrap(err, "KEY_GEN_ERROR", "failed to generate key")
	}
	return key, nil
}

// GenerateNonce generates a cryptographically secure random nonce of the given size.
//
// A nonce (number used once) is a random value that should be used only once
// for each encryption operation. This function generates a cryptographically
// secure random nonce suitable for use with AES-GCM encryption.
//
// Parameters:
//   - size: The desired size of the nonce in bytes (must be positive)
//
// Returns:
//   - A byte slice containing the random nonce
//   - An error if nonce generation fails
//
// Example:
//
//	nonce, err := crypto.GenerateNonce(12) // 12 bytes is standard for AES-GCM
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println("Generated nonce length:", len(nonce)) // Output: 12
//
// For AES-GCM, a 12-byte nonce is recommended for optimal security and performance.
func GenerateNonce(size int) ([]byte, error) {
	if size <= 0 {
		return nil, goerrors.New("INVALID_NONCE_SIZE", "nonce size must be positive")
	}
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, goerrors.Wrap(err, "NONCE_GEN_ERROR", "failed to generate nonce")
	}
	return nonce, nil
}

// ValidateKey checks that a key has the correct size for AES-256.
//
// This function verifies that the provided key is exactly 32 bytes (256 bits),
// which is required for AES-256 encryption. It's useful for validating keys
// before using them with the Encrypt and Decrypt functions.
//
// Parameters:
//   - key: The key to validate
//
// Returns:
//   - An error if the key size is incorrect, nil if valid
//
// Example:
//
//	key, _ := crypto.GenerateKey()
//	err := crypto.ValidateKey(key)
//	if err != nil {
//		log.Fatal("Invalid key:", err)
//	}
//	fmt.Println("Key is valid for AES-256")
//
// The function will return an error if the key is not exactly 32 bytes.
func ValidateKey(key []byte) error {
	if len(key) != KeySize {
		return goerrors.New("INVALID_KEY_SIZE", fmt.Sprintf("key size must be %d bytes for AES-256, got %d", KeySize, len(key)))
	}
	return nil
}
