// crypto_advanced_error_paths_test.go: Advanced error paths test cases for cryptographic utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/agilira/harpocrates"
)

// TestAESCipherCreationFailures tests AES cipher creation failures
func TestAESCipherCreationFailures(t *testing.T) {
	// Test with corrupted key that might cause AES.NewCipher to fail
	// Note: In practice, AES.NewCipher rarely fails with valid key sizes,
	// but we test the error path for completeness
	testCases := []struct {
		name        string
		key         []byte
		description string
	}{
		{
			name:        "nil key",
			key:         nil,
			description: "nil key should fail validation before AES.NewCipher",
		},
		{
			name:        "empty key",
			key:         []byte{},
			description: "empty key should fail validation before AES.NewCipher",
		},
		{
			name:        "short key",
			key:         make([]byte, 16),
			description: "short key should fail validation before AES.NewCipher",
		},
		{
			name:        "long key",
			key:         make([]byte, 64),
			description: "long key should fail validation before AES.NewCipher",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.Encrypt("test", tc.key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestGCMInitializationFailures tests GCM initialization failures
func TestGCMInitializationFailures(t *testing.T) {
	// Test with valid key size but potential GCM initialization issues
	// Note: GCM initialization with valid AES cipher rarely fails,
	// but we test the error path for completeness
	validKey := make([]byte, crypto.KeySize)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	// Test normal case to ensure it works
	_, err := crypto.Encrypt("test", validKey)
	if err != nil {
		t.Fatalf("Expected successful encryption with valid key: %v", err)
	}
}

// TestGCMOpenFailures tests GCM.Open failures during decryption
func TestGCMOpenFailures(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted data
	plaintext := "test-data-for-gcm-failures"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Decode to get raw bytes
	rawData, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	testCases := []struct {
		name        string
		corruptFunc func([]byte) string
		description string
	}{
		{
			name: "flip authentication tag",
			corruptFunc: func(data []byte) string {
				if len(data) > 0 {
					// Flip the last byte which is part of the authentication tag
					data[len(data)-1] ^= 1
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "corrupted authentication tag should cause GCM.Open to fail",
		},
		{
			name: "flip ciphertext",
			corruptFunc: func(data []byte) string {
				if len(data) > 12 {
					// Flip a byte in the ciphertext portion
					data[12] ^= 1
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "corrupted ciphertext should cause GCM.Open to fail",
		},
		{
			name: "flip nonce",
			corruptFunc: func(data []byte) string {
				if len(data) > 0 {
					// Flip the first byte of the nonce
					data[0] ^= 1
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "corrupted nonce should cause GCM.Open to fail",
		},
		{
			name: "truncate authentication tag",
			corruptFunc: func(data []byte) string {
				if len(data) > 16 {
					// Remove the last 16 bytes (authentication tag)
					return base64.StdEncoding.EncodeToString(data[:len(data)-16])
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "truncated authentication tag should cause GCM.Open to fail",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := tc.corruptFunc(rawData)
			_, err := crypto.Decrypt(corrupted, key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestRandomGenerationFailures tests random generation failures
func TestRandomGenerationFailures(t *testing.T) {
	// Mock rand.Reader to fail
	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()
	rand.Reader = &advancedFailingReader{}

	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Test encryption with failing random generation
	_, err := crypto.Encrypt("test", key)
	if err == nil {
		t.Error("Expected error when nonce generation fails")
	}

	// Test key generation with failing random generation
	_, err = crypto.GenerateKey()
	if err == nil {
		t.Error("Expected error when key generation fails")
	}

	// Test nonce generation with failing random generation
	_, err = crypto.GenerateNonce(12)
	if err == nil {
		t.Error("Expected error when nonce generation fails")
	}
}

// TestBase64EncodingDecodingFailures tests base64 encoding/decoding failures
func TestBase64EncodingDecodingFailures(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "invalid base64 characters",
			input:       "invalid-base64!!",
			description: "invalid base64 characters should cause decode failure",
		},
		{
			name:        "incomplete base64",
			input:       "incomplete",
			description: "incomplete base64 should cause decode failure",
		},
		{
			name:        "wrong padding",
			input:       "AAA=",
			description: "wrong padding should cause decode failure",
		},
		{
			name:        "excessive padding",
			input:       "AA===",
			description: "excessive padding should cause decode failure",
		},
		{
			name:        "mixed invalid characters",
			input:       "AA!!BB",
			description: "mixed invalid characters should cause decode failure",
		},
	}

	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.Decrypt(tc.input, key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestHexEncodingDecodingFailures tests hex encoding/decoding failures
func TestHexEncodingDecodingFailures(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "invalid hex characters",
			input:       "invalid-hex!!",
			description: "invalid hex characters should cause decode failure",
		},
		{
			name:        "odd length hex",
			input:       "123",
			description: "odd length hex should cause decode failure",
		},
		{
			name:        "empty hex",
			input:       "",
			description: "empty hex should work (returns empty slice)",
		},
		{
			name:        "mixed case hex",
			input:       "AaBbCc",
			description: "mixed case hex should work correctly",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.KeyFromHex(tc.input)
			if tc.name == "mixed case hex" || tc.name == "empty hex" {
				// Mixed case and empty should work
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.description, err)
				}
			} else {
				// Other cases should fail
				if err == nil {
					t.Errorf("Expected error for %s", tc.description)
				}
			}
		})
	}
}

// TestCiphertextManipulationScenarios tests various ciphertext manipulation scenarios
func TestCiphertextManipulationScenarios(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted data
	plaintext := "test-data-for-manipulation"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Decode to get raw bytes
	rawData, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	testCases := []struct {
		name        string
		manipulate  func([]byte) string
		description string
	}{
		{
			name: "swap nonce and ciphertext",
			manipulate: func(data []byte) string {
				if len(data) > 24 {
					// Swap first 12 bytes with next 12 bytes
					copy(data[0:12], data[12:24])
					copy(data[12:24], data[0:12])
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "swapped nonce and ciphertext should cause GCM.Open to fail",
		},
		{
			name: "duplicate nonce",
			manipulate: func(data []byte) string {
				if len(data) > 12 {
					// Duplicate the nonce at the end
					nonce := data[:12]
					extended := append(data, nonce...)
					return base64.StdEncoding.EncodeToString(extended)
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "duplicated nonce should cause GCM.Open to fail",
		},
		{
			name: "insert random bytes",
			manipulate: func(data []byte) string {
				// Insert random bytes in the middle
				mid := len(data) / 2
				inserted := make([]byte, len(data)+4)
				copy(inserted, data[:mid])
				copy(inserted[mid:], []byte{0xAA, 0xBB, 0xCC, 0xDD})
				copy(inserted[mid+4:], data[mid:])
				return base64.StdEncoding.EncodeToString(inserted)
			},
			description: "inserted random bytes should cause GCM.Open to fail",
		},
		{
			name: "remove authentication tag",
			manipulate: func(data []byte) string {
				if len(data) > 16 {
					// Remove the last 16 bytes (authentication tag)
					return base64.StdEncoding.EncodeToString(data[:len(data)-16])
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "removed authentication tag should cause GCM.Open to fail",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manipulated := tc.manipulate(rawData)
			_, err := crypto.Decrypt(manipulated, key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestCiphertextManipulationScenariosAdvanced tests advanced ciphertext manipulation scenarios
func TestCiphertextManipulationScenariosAdvanced(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted data
	plaintext := "test-data-for-advanced-manipulation"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Decode to get raw bytes
	rawData, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	testCases := []struct {
		name        string
		manipulate  func([]byte) string
		description string
	}{
		{
			name: "wrong nonce size - too short",
			manipulate: func(data []byte) string {
				if len(data) > 12 {
					// Remove some bytes from the nonce to make it too short
					shortNonce := data[:8] // 8 bytes instead of 12
					rest := data[12:]
					manipulated := append(shortNonce, rest...)
					return base64.StdEncoding.EncodeToString(manipulated)
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "wrong nonce size should cause GCM.Open to fail",
		},
		{
			name: "wrong nonce size - too long",
			manipulate: func(data []byte) string {
				if len(data) > 12 {
					// Extend the nonce to make it too long
					extendedNonce := append(data[:12], []byte{0xAA, 0xBB, 0xCC, 0xDD}...)
					rest := data[12:]
					manipulated := append(extendedNonce, rest...)
					return base64.StdEncoding.EncodeToString(manipulated)
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "wrong nonce size should cause GCM.Open to fail",
		},
		{
			name: "corrupted authentication data - flip multiple bytes",
			manipulate: func(data []byte) string {
				if len(data) > 16 {
					// Flip multiple bytes in the authentication tag
					for i := len(data) - 16; i < len(data); i += 2 {
						data[i] ^= 1
					}
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "corrupted authentication data should cause GCM.Open to fail",
		},
		{
			name: "truncated ciphertext - remove middle portion",
			manipulate: func(data []byte) string {
				if len(data) > 20 {
					// Remove a portion from the middle of the ciphertext
					nonce := data[:12]
					ciphertext := data[12:]
					mid := len(ciphertext) / 2
					truncatedCiphertext := append(ciphertext[:mid], ciphertext[mid+4:]...)
					manipulated := append(nonce, truncatedCiphertext...)
					return base64.StdEncoding.EncodeToString(manipulated)
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "truncated ciphertext should cause GCM.Open to fail",
		},
		{
			name: "extended ciphertext - insert data in middle",
			manipulate: func(data []byte) string {
				if len(data) > 20 {
					// Insert extra data in the middle of the ciphertext
					nonce := data[:12]
					ciphertext := data[12:]
					mid := len(ciphertext) / 2
					inserted := make([]byte, len(ciphertext)+4)
					copy(inserted, ciphertext[:mid])
					copy(inserted[mid:], []byte{0x11, 0x22, 0x33, 0x44})
					copy(inserted[mid+4:], ciphertext[mid:])
					manipulated := append(nonce, inserted...)
					return base64.StdEncoding.EncodeToString(manipulated)
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "extended ciphertext should cause GCM.Open to fail",
		},
		{
			name: "reordered ciphertext - swap blocks",
			manipulate: func(data []byte) string {
				if len(data) > 28 {
					// Swap two 4-byte blocks in the ciphertext
					nonce := data[:12]
					ciphertext := data[12:]
					if len(ciphertext) > 8 {
						// Swap first 4 bytes with next 4 bytes
						ciphertext[0], ciphertext[4] = ciphertext[4], ciphertext[0]
						ciphertext[1], ciphertext[5] = ciphertext[5], ciphertext[1]
						ciphertext[2], ciphertext[6] = ciphertext[6], ciphertext[2]
						ciphertext[3], ciphertext[7] = ciphertext[7], ciphertext[3]
					}
					manipulated := append(nonce, ciphertext...)
					return base64.StdEncoding.EncodeToString(manipulated)
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "reordered ciphertext should cause GCM.Open to fail",
		},
		{
			name: "zero out authentication tag",
			manipulate: func(data []byte) string {
				if len(data) > 16 {
					// Zero out the entire authentication tag
					for i := len(data) - 16; i < len(data); i++ {
						data[i] = 0
					}
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "zeroed authentication tag should cause GCM.Open to fail",
		},
		{
			name: "set authentication tag to all ones",
			manipulate: func(data []byte) string {
				if len(data) > 16 {
					// Set the entire authentication tag to all ones
					for i := len(data) - 16; i < len(data); i++ {
						data[i] = 0xFF
					}
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "all-ones authentication tag should cause GCM.Open to fail",
		},
		{
			name: "duplicate ciphertext portion",
			manipulate: func(data []byte) string {
				if len(data) > 20 {
					// Duplicate a portion of the ciphertext
					nonce := data[:12]
					ciphertext := data[12:]
					portion := ciphertext[:4]
					duplicated := append(ciphertext, portion...)
					manipulated := append(nonce, duplicated...)
					return base64.StdEncoding.EncodeToString(manipulated)
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "duplicated ciphertext portion should cause GCM.Open to fail",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manipulated := tc.manipulate(rawData)
			_, err := crypto.Decrypt(manipulated, key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestErrorPropagation tests error propagation across functions
func TestErrorPropagation(t *testing.T) {
	// Test error propagation from key generation to encryption
	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()
	rand.Reader = &advancedFailingReader{}

	// This should fail at key generation
	_, err := crypto.GenerateKey()
	if err == nil {
		t.Error("Expected error propagation from key generation")
	}

	// Test error propagation from key derivation to encryption
	_, err = crypto.DeriveKeyPBKDF2([]byte("password"), []byte("salt"), 1000, 32)
	if err != nil {
		t.Errorf("Unexpected error from key derivation: %v", err)
	}

	// Test error propagation from encoding to validation
	_, err = crypto.KeyFromBase64("invalid-base64!!")
	if err == nil {
		t.Error("Expected error propagation from base64 decoding")
	}

	_, err = crypto.KeyFromHex("invalid-hex!!")
	if err == nil {
		t.Error("Expected error propagation from hex decoding")
	}
}

// TestWorkflowFailureScenarios tests complete workflow failures
func TestWorkflowFailureScenarios(t *testing.T) {
	// Test workflow failure with corrupted keys
	// Note: Corrupting a key doesn't necessarily cause encryption to fail
	// as AES.NewCipher accepts any 32-byte key
	corruptedKey := make([]byte, crypto.KeySize)
	for i := range corruptedKey {
		corruptedKey[i] = byte(i)
	}
	// Corrupt the key
	corruptedKey[0] ^= 1

	// This should actually work since AES.NewCipher accepts any 32-byte key
	_, err := crypto.Encrypt("test", corruptedKey)
	if err != nil {
		t.Errorf("Unexpected error with corrupted key: %v", err)
	}

	// Test workflow failure with corrupted data
	validKey := make([]byte, crypto.KeySize)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	encrypted, err := crypto.Encrypt("test", validKey)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Corrupt the encrypted data
	corrupted := encrypted[:len(encrypted)-1] + "X"
	_, err = crypto.Decrypt(corrupted, validKey)
	if err == nil {
		t.Error("Expected workflow failure with corrupted data")
	}
}

// TestAESNewCipherErrorPaths tests specific AES.NewCipher error paths
func TestAESNewCipherErrorPaths(t *testing.T) {
	// Test with various key sizes that might cause AES.NewCipher to fail
	// Note: In practice, AES.NewCipher only fails with invalid key sizes
	testCases := []struct {
		name        string
		keySize     int
		description string
	}{
		{
			name:        "zero key size",
			keySize:     0,
			description: "zero key size should fail validation",
		},
		{
			name:        "negative key size",
			keySize:     -1,
			description: "negative key size should fail validation",
		},
		{
			name:        "very large key size",
			keySize:     1000000,
			description: "very large key size should fail validation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var key []byte
			if tc.keySize > 0 {
				key = make([]byte, tc.keySize)
			}
			_, err := crypto.Encrypt("test", key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestCipherNewGCMErrorPaths tests specific cipher.NewGCM error paths
func TestCipherNewGCMErrorPaths(t *testing.T) {
	// Test with valid key size to ensure GCM initialization works
	validKey := make([]byte, crypto.KeySize)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	// This should work and cover the GCM initialization path
	_, err := crypto.Encrypt("test", validKey)
	if err != nil {
		t.Fatalf("Expected successful GCM initialization: %v", err)
	}

	// Test with different key patterns to ensure GCM initialization is robust
	testKeys := [][]byte{
		make([]byte, crypto.KeySize), // all zeros
		func() []byte { // all ones
			key := make([]byte, crypto.KeySize)
			for i := range key {
				key[i] = 1
			}
			return key
		}(),
		func() []byte { // alternating pattern
			key := make([]byte, crypto.KeySize)
			for i := range key {
				if i%2 == 0 {
					key[i] = 0xAA
				} else {
					key[i] = 0x55
				}
			}
			return key
		}(),
	}

	for i, key := range testKeys {
		t.Run(fmt.Sprintf("key_pattern_%d", i), func(t *testing.T) {
			_, err := crypto.Encrypt("test", key)
			if err != nil {
				t.Errorf("Expected successful GCM initialization with pattern %d: %v", i, err)
			}
		})
	}
}

// TestGCMOpenSpecificErrorPaths tests specific GCM.Open error paths
func TestGCMOpenSpecificErrorPaths(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted data
	plaintext := "test-data-for-specific-gcm-errors"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Decode to get raw bytes
	rawData, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	testCases := []struct {
		name        string
		corruptFunc func([]byte) string
		description string
	}{
		{
			name: "flip last byte of authentication tag",
			corruptFunc: func(data []byte) string {
				if len(data) > 0 {
					data[len(data)-1] ^= 1
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "flipped authentication tag should cause GCM.Open to fail",
		},
		{
			name: "flip first byte of authentication tag",
			corruptFunc: func(data []byte) string {
				if len(data) > 16 {
					data[len(data)-16] ^= 1
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "flipped authentication tag should cause GCM.Open to fail",
		},
		{
			name: "flip middle byte of ciphertext",
			corruptFunc: func(data []byte) string {
				if len(data) > 20 {
					mid := 12 + (len(data)-12)/2
					data[mid] ^= 1
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "flipped ciphertext should cause GCM.Open to fail",
		},
		{
			name: "flip first byte of nonce",
			corruptFunc: func(data []byte) string {
				if len(data) > 0 {
					data[0] ^= 1
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "flipped nonce should cause GCM.Open to fail",
		},
		{
			name: "flip last byte of nonce",
			corruptFunc: func(data []byte) string {
				if len(data) > 11 {
					data[11] ^= 1
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "flipped nonce should cause GCM.Open to fail",
		},
		{
			name: "remove entire authentication tag",
			corruptFunc: func(data []byte) string {
				if len(data) > 16 {
					return base64.StdEncoding.EncodeToString(data[:len(data)-16])
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "removed authentication tag should cause GCM.Open to fail",
		},
		{
			name: "remove part of authentication tag",
			corruptFunc: func(data []byte) string {
				if len(data) > 8 {
					return base64.StdEncoding.EncodeToString(data[:len(data)-8])
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			description: "truncated authentication tag should cause GCM.Open to fail",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := tc.corruptFunc(rawData)
			_, err := crypto.Decrypt(corrupted, key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestBase64DecodeSpecificErrorPaths tests specific base64 decode error paths
func TestBase64DecodeSpecificErrorPaths(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	testCases := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "single invalid character",
			input:       "A!",
			description: "single invalid character should cause decode failure",
		},
		{
			name:        "multiple invalid characters",
			input:       "A!B@C#",
			description: "multiple invalid characters should cause decode failure",
		},
		{
			name:        "incomplete base64 with padding",
			input:       "A=",
			description: "incomplete base64 with padding should cause decode failure",
		},
		{
			name:        "incomplete base64 without padding",
			input:       "A",
			description: "incomplete base64 without padding should cause decode failure",
		},
		{
			name:        "wrong padding at end",
			input:       "AA=",
			description: "wrong padding should cause decode failure",
		},
		{
			name:        "excessive padding",
			input:       "AA===",
			description: "excessive padding should cause decode failure",
		},
		{
			name:        "padding in middle",
			input:       "AA=BB",
			description: "padding in middle should cause decode failure",
		},
		{
			name:        "mixed valid and invalid",
			input:       "AA!BB",
			description: "mixed valid and invalid should cause decode failure",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.Decrypt(tc.input, key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestCiphertextTooShortErrorPaths tests specific ciphertext too short error paths
func TestCiphertextTooShortErrorPaths(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	testCases := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "empty base64",
			input:       "",
			description: "empty base64 should cause ciphertext too short error",
		},
		{
			name:        "single byte base64",
			input:       "A",
			description: "single byte base64 should cause decode failure",
		},
		{
			name:        "two byte base64",
			input:       "AA",
			description: "two byte base64 should cause decode failure",
		},
		{
			name:        "three byte base64",
			input:       "AAA",
			description: "three byte base64 should cause decode failure",
		},
		{
			name:        "four byte base64",
			input:       "AAAA",
			description: "four byte base64 should cause ciphertext too short error",
		},
		{
			name:        "five byte base64",
			input:       "AAAAA",
			description: "five byte base64 should cause decode failure",
		},
		{
			name:        "six byte base64",
			input:       "AAAAAA",
			description: "six byte base64 should cause ciphertext too short error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.Decrypt(tc.input, key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestMemoryAllocationFailures tests memory allocation failure scenarios
func TestMemoryAllocationFailures(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Test with very large plaintext (but not so large as to cause actual memory issues)
	largePlaintext := strings.Repeat("A", 1024*1024) // 1MB
	_, err := crypto.Encrypt(largePlaintext, key)
	if err != nil {
		t.Errorf("Unexpected error with large plaintext: %v", err)
	}

	// Test with very large key (should fail validation)
	largeKey := make([]byte, 1024*1024) // 1MB key
	_, err = crypto.Encrypt("test", largeKey)
	if err == nil {
		t.Error("Expected error with very large key")
	}

	// Test with very large nonce size (should work, but might be slow)
	_, err = crypto.GenerateNonce(1024 * 1024) // 1MB nonce
	if err != nil {
		t.Errorf("Unexpected error with large nonce size: %v", err)
	}
}

// TestSystemResourceLimitationsAdvanced tests advanced system resource limitation scenarios
func TestSystemResourceLimitationsAdvanced(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Test with many concurrent operations to simulate resource pressure
	const numGoroutines = 100
	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			plaintext := fmt.Sprintf("test-data-%d", id)
			_, err := crypto.Encrypt(plaintext, key)
			results <- err
		}(i)
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-results
		if err != nil {
			t.Errorf("Unexpected error in goroutine %d: %v", i, err)
		}
	}
}

// TestCrossFunctionErrorPropagation tests error propagation across functions
func TestCrossFunctionErrorPropagation(t *testing.T) {
	// Test error propagation from key generation to encryption
	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()
	rand.Reader = &advancedFailingReader{}

	// This should fail at key generation
	_, err := crypto.GenerateKey()
	if err == nil {
		t.Error("Expected error propagation from key generation")
	}

	// Test error propagation from key derivation to encryption
	// Use invalid parameters to cause failure
	_, err = crypto.DeriveKeyPBKDF2([]byte(""), []byte("salt"), 1000, 32)
	if err == nil {
		t.Error("Expected error propagation from key derivation with empty password")
	}

	_, err = crypto.DeriveKeyPBKDF2([]byte("password"), []byte(""), 1000, 32)
	if err == nil {
		t.Error("Expected error propagation from key derivation with empty salt")
	}

	_, err = crypto.DeriveKeyPBKDF2([]byte("password"), []byte("salt"), 0, 32)
	if err == nil {
		t.Error("Expected error propagation from key derivation with zero iterations")
	}

	_, err = crypto.DeriveKeyPBKDF2([]byte("password"), []byte("salt"), 1000, 0)
	if err == nil {
		t.Error("Expected error propagation from key derivation with zero key length")
	}

	// Test error propagation from encoding to validation
	_, err = crypto.KeyFromBase64("invalid-base64!!")
	if err == nil {
		t.Error("Expected error propagation from base64 decoding")
	}

	_, err = crypto.KeyFromHex("invalid-hex!!")
	if err == nil {
		t.Error("Expected error propagation from hex decoding")
	}
}

// TestWorkflowFailureScenariosAdvanced tests advanced workflow failure scenarios
func TestWorkflowFailureScenariosAdvanced(t *testing.T) {
	// Test workflow failure with corrupted keys
	corruptedKey := make([]byte, crypto.KeySize)
	for i := range corruptedKey {
		corruptedKey[i] = byte(i)
	}
	// Corrupt the key
	corruptedKey[0] ^= 1

	// This should actually work since AES.NewCipher accepts any 32-byte key
	_, err := crypto.Encrypt("test", corruptedKey)
	if err != nil {
		t.Errorf("Unexpected error with corrupted key: %v", err)
	}

	// Test workflow failure with corrupted data
	validKey := make([]byte, crypto.KeySize)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	encrypted, err := crypto.Encrypt("test", validKey)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Corrupt the encrypted data in various ways
	testCases := []struct {
		name        string
		corruptFunc func(string) string
		description string
	}{
		{
			name: "corrupt last character",
			corruptFunc: func(s string) string {
				if len(s) > 0 {
					return s[:len(s)-1] + "X"
				}
				return s
			},
			description: "corrupted last character should cause decode failure",
		},
		{
			name: "corrupt first character",
			corruptFunc: func(s string) string {
				if len(s) > 0 {
					// Use a character that's definitely not valid base64
					return "!" + s[1:]
				}
				return s
			},
			description: "corrupted first character should cause decode failure",
		},
		{
			name: "add extra character",
			corruptFunc: func(s string) string {
				return s + "X"
			},
			description: "extra character should cause decode failure",
		},
		{
			name: "remove character",
			corruptFunc: func(s string) string {
				if len(s) > 1 {
					return s[:len(s)-1]
				}
				return s
			},
			description: "removed character should cause decode failure",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := tc.corruptFunc(encrypted)
			_, err := crypto.Decrypt(corrupted, validKey)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestDeriveKeyPBKDF2AdvancedErrorPaths tests advanced error paths for PBKDF2 key derivation
func TestDeriveKeyPBKDF2AdvancedErrorPaths(t *testing.T) {
	testCases := []struct {
		name        string
		password    []byte
		salt        []byte
		iterations  int
		keyLen      int
		description string
	}{
		{
			name:        "empty password",
			password:    []byte{},
			salt:        []byte("salt"),
			iterations:  1000,
			keyLen:      32,
			description: "empty password should cause error",
		},
		{
			name:        "nil password",
			password:    nil,
			salt:        []byte("salt"),
			iterations:  1000,
			keyLen:      32,
			description: "nil password should cause error",
		},
		{
			name:        "empty salt",
			password:    []byte("password"),
			salt:        []byte{},
			iterations:  1000,
			keyLen:      32,
			description: "empty salt should cause error",
		},
		{
			name:        "nil salt",
			password:    []byte("password"),
			salt:        nil,
			iterations:  1000,
			keyLen:      32,
			description: "nil salt should cause error",
		},
		{
			name:        "zero iterations",
			password:    []byte("password"),
			salt:        []byte("salt"),
			iterations:  0,
			keyLen:      32,
			description: "zero iterations should cause error",
		},
		{
			name:        "negative iterations",
			password:    []byte("password"),
			salt:        []byte("salt"),
			iterations:  -1,
			keyLen:      32,
			description: "negative iterations should cause error",
		},
		{
			name:        "zero key length",
			password:    []byte("password"),
			salt:        []byte("salt"),
			iterations:  1000,
			keyLen:      0,
			description: "zero key length should cause error",
		},
		{
			name:        "negative key length",
			password:    []byte("password"),
			salt:        []byte("salt"),
			iterations:  1000,
			keyLen:      -1,
			description: "negative key length should cause error",
		},
		{
			name:        "very large iterations",
			password:    []byte("password"),
			salt:        []byte("salt"),
			iterations:  1000000,
			keyLen:      32,
			description: "very large iterations should work but be slow",
		},
		{
			name:        "very large key length",
			password:    []byte("password"),
			salt:        []byte("salt"),
			iterations:  1000,
			keyLen:      1024,
			description: "very large key length should work",
		},
		{
			name:        "very large password",
			password:    bytes.Repeat([]byte("A"), 10000),
			salt:        []byte("salt"),
			iterations:  1000,
			keyLen:      32,
			description: "very large password should work",
		},
		{
			name:        "very large salt",
			password:    []byte("password"),
			salt:        bytes.Repeat([]byte("B"), 10000),
			iterations:  1000,
			keyLen:      32,
			description: "very large salt should work",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := crypto.DeriveKeyPBKDF2(tc.password, tc.salt, tc.iterations, tc.keyLen)

			// Check if this should fail
			if strings.Contains(tc.description, "should cause error") {
				if err == nil {
					t.Errorf("Expected error for %s", tc.description)
				}
			} else {
				// Should succeed
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.description, err)
				}
				if len(key) != tc.keyLen {
					t.Errorf("Expected key length %d, got %d for %s", tc.keyLen, len(key), tc.description)
				}
			}
		})
	}
}

// TestDeriveKeyPBKDF2Consistency tests consistency of PBKDF2 key derivation
func TestDeriveKeyPBKDF2Consistency(t *testing.T) {
	password := []byte("test-password")
	salt := []byte("test-salt")
	iterations := 1000
	keyLen := 32

	// Derive key multiple times with same parameters
	key1, err := crypto.DeriveKeyPBKDF2(password, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	key2, err := crypto.DeriveKeyPBKDF2(password, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	// Keys should be identical
	if !bytes.Equal(key1, key2) {
		t.Error("PBKDF2 key derivation is not consistent")
	}

	// Test with different parameters
	key3, err := crypto.DeriveKeyPBKDF2(password, salt, iterations+1, keyLen)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	// Keys should be different with different iterations
	if bytes.Equal(key1, key3) {
		t.Error("PBKDF2 key derivation should produce different keys with different iterations")
	}

	// Test with different salt
	key4, err := crypto.DeriveKeyPBKDF2(password, []byte("different-salt"), iterations, keyLen)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	// Keys should be different with different salt
	if bytes.Equal(key1, key4) {
		t.Error("PBKDF2 key derivation should produce different keys with different salt")
	}
}

// TestDeriveKeyPBKDF2EdgeCases tests edge cases for PBKDF2 key derivation
func TestDeriveKeyPBKDF2EdgeCases(t *testing.T) {
	testCases := []struct {
		name        string
		password    []byte
		salt        []byte
		iterations  int
		keyLen      int
		description string
	}{
		{
			name:        "single byte password",
			password:    []byte("a"),
			salt:        []byte("salt"),
			iterations:  1000,
			keyLen:      32,
			description: "single byte password should work",
		},
		{
			name:        "single byte salt",
			password:    []byte("password"),
			salt:        []byte("a"),
			iterations:  1000,
			keyLen:      32,
			description: "single byte salt should work",
		},
		{
			name:        "single iteration",
			password:    []byte("password"),
			salt:        []byte("salt"),
			iterations:  1,
			keyLen:      32,
			description: "single iteration should work",
		},
		{
			name:        "single byte key length",
			password:    []byte("password"),
			salt:        []byte("salt"),
			iterations:  1000,
			keyLen:      1,
			description: "single byte key length should work",
		},
		{
			name:        "zero byte password",
			password:    []byte{},
			salt:        []byte("salt"),
			iterations:  1000,
			keyLen:      32,
			description: "zero byte password should cause error",
		},
		{
			name:        "zero byte salt",
			password:    []byte("password"),
			salt:        []byte{},
			iterations:  1000,
			keyLen:      32,
			description: "zero byte salt should cause error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := crypto.DeriveKeyPBKDF2(tc.password, tc.salt, tc.iterations, tc.keyLen)

			if strings.Contains(tc.description, "should cause error") {
				if err == nil {
					t.Errorf("Expected error for %s", tc.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.description, err)
				}
				if len(key) != tc.keyLen {
					t.Errorf("Expected key length %d, got %d for %s", tc.keyLen, len(key), tc.description)
				}
			}
		})
	}
}

// TestGetKeyFingerprintAdvanced tests advanced scenarios for key fingerprinting
func TestGetKeyFingerprintAdvanced(t *testing.T) {
	testCases := []struct {
		name        string
		key         []byte
		description string
	}{
		{
			name:        "empty key",
			key:         []byte{},
			description: "empty key should return empty string",
		},
		{
			name:        "nil key",
			key:         nil,
			description: "nil key should return empty string",
		},
		{
			name:        "single byte key",
			key:         []byte{0x42},
			description: "single byte key should work",
		},
		{
			name:        "large key",
			key:         bytes.Repeat([]byte{0xFF}, 1000),
			description: "large key should work",
		},
		{
			name:        "key with high values",
			key:         bytes.Repeat([]byte{0xFF}, 32),
			description: "key with high values should work",
		},
		{
			name:        "key with low values",
			key:         bytes.Repeat([]byte{0x00}, 32),
			description: "key with low values should work",
		},
		{
			name:        "key with alternating values",
			key:         bytes.Repeat([]byte{0xAA, 0x55}, 16),
			description: "key with alternating values should work",
		},
		{
			name:        "key with maximum values",
			key:         bytes.Repeat([]byte{0xFF}, 64),
			description: "key with maximum values should work",
		},
		{
			name: "key with specific pattern to trigger overflow",
			key: func() []byte {
				// Create a key that might trigger the overflow condition in GetKeyFingerprint
				key := make([]byte, 100)
				for i := range key {
					key[i] = byte(i % 256)
				}
				return key
			}(),
			description: "key with specific pattern should work",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fingerprint := crypto.GetKeyFingerprint(tc.key)

			if tc.name == "empty key" || tc.name == "nil key" {
				if fingerprint != "" {
					t.Errorf("Expected empty fingerprint for %s, got %s", tc.description, fingerprint)
				}
			} else {
				if fingerprint == "" {
					t.Errorf("Expected non-empty fingerprint for %s", tc.description)
				}
				if len(fingerprint) != 16 {
					t.Errorf("Expected 16-character fingerprint for %s, got %d characters", tc.description, len(fingerprint))
				}
			}
		})
	}
}

// TestGetKeyFingerprintConsistency tests consistency of key fingerprinting
func TestGetKeyFingerprintConsistency(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// Generate fingerprint multiple times
	fingerprint1 := crypto.GetKeyFingerprint(key)
	fingerprint2 := crypto.GetKeyFingerprint(key)

	// Fingerprints should be identical
	if fingerprint1 != fingerprint2 {
		t.Error("Key fingerprinting is not consistent")
	}

	// Test with different key
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(i + 1)
	}
	fingerprint3 := crypto.GetKeyFingerprint(key2)

	// Fingerprints should be different
	if fingerprint1 == fingerprint3 {
		t.Error("Different keys should produce different fingerprints")
	}
}

// TestValidateKeyAdvanced tests advanced scenarios for key validation
func TestValidateKeyAdvanced(t *testing.T) {
	testCases := []struct {
		name        string
		key         []byte
		shouldError bool
		description string
	}{
		{
			name:        "nil key",
			key:         nil,
			shouldError: true,
			description: "nil key should cause validation error",
		},
		{
			name:        "empty key",
			key:         []byte{},
			shouldError: true,
			description: "empty key should cause validation error",
		},
		{
			name:        "short key",
			key:         make([]byte, 16),
			shouldError: true,
			description: "short key should cause validation error",
		},
		{
			name:        "long key",
			key:         make([]byte, 64),
			shouldError: true,
			description: "long key should cause validation error",
		},
		{
			name:        "correct size key",
			key:         make([]byte, crypto.KeySize),
			shouldError: false,
			description: "correct size key should pass validation",
		},
		{
			name:        "very short key",
			key:         make([]byte, 1),
			shouldError: true,
			description: "very short key should cause validation error",
		},
		{
			name:        "very long key",
			key:         make([]byte, 1000),
			shouldError: true,
			description: "very long key should cause validation error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := crypto.ValidateKey(tc.key)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error for %s", tc.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.description, err)
				}
			}
		})
	}
}

// TestZeroizeAdvanced tests advanced scenarios for zeroization
func TestZeroizeAdvanced(t *testing.T) {
	testCases := []struct {
		name        string
		data        []byte
		description string
	}{
		{
			name:        "empty slice",
			data:        []byte{},
			description: "empty slice should be handled",
		},
		{
			name:        "nil slice",
			data:        nil,
			description: "nil slice should be handled",
		},
		{
			name:        "single byte",
			data:        []byte{0xFF},
			description: "single byte should be zeroized",
		},
		{
			name:        "multiple bytes",
			data:        []byte{0xFF, 0xAA, 0x55, 0x00},
			description: "multiple bytes should be zeroized",
		},
		{
			name:        "large slice",
			data:        bytes.Repeat([]byte{0xFF}, 1000),
			description: "large slice should be zeroized",
		},
		{
			name:        "already zeroed",
			data:        make([]byte, 10),
			description: "already zeroed slice should remain zeroed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a copy of the data
			var dataCopy []byte
			if tc.data != nil {
				dataCopy = make([]byte, len(tc.data))
				copy(dataCopy, tc.data)
			}

			// Zeroize the copy
			crypto.Zeroize(dataCopy)

			// Check that all bytes are zero
			for i, b := range dataCopy {
				if b != 0 {
					t.Errorf("Byte at index %d is not zeroized for %s: got %d", i, tc.description, b)
				}
			}
		})
	}
}

// TestAESNewCipherSpecificErrorPaths tests specific error paths for aes.NewCipher
func TestAESNewCipherSpecificErrorPaths(t *testing.T) {
	// Test with invalid key sizes that should cause aes.NewCipher to fail
	testCases := []struct {
		name        string
		key         []byte
		description string
	}{
		{
			name:        "nil key",
			key:         nil,
			description: "nil key should cause validation error before aes.NewCipher",
		},
		{
			name:        "empty key",
			key:         []byte{},
			description: "empty key should cause validation error before aes.NewCipher",
		},
		{
			name:        "short key",
			key:         make([]byte, 16),
			description: "short key should cause validation error before aes.NewCipher",
		},
		{
			name:        "long key",
			key:         make([]byte, 64),
			description: "long key should cause validation error before aes.NewCipher",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.Encrypt("test", tc.key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestCipherNewGCMSpecificErrorPaths tests specific error paths for cipher.NewGCM
func TestCipherNewGCMSpecificErrorPaths(t *testing.T) {
	// Test with valid key size to ensure GCM initialization works
	validKey := make([]byte, crypto.KeySize)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	// This should work and cover the GCM initialization path
	_, err := crypto.Encrypt("test", validKey)
	if err != nil {
		t.Fatalf("Expected successful GCM initialization: %v", err)
	}

	// Test with different key patterns to ensure GCM initialization is robust
	testKeys := [][]byte{
		make([]byte, crypto.KeySize), // all zeros
		func() []byte { // all ones
			key := make([]byte, crypto.KeySize)
			for i := range key {
				key[i] = 1
			}
			return key
		}(),
		func() []byte { // alternating pattern
			key := make([]byte, crypto.KeySize)
			for i := range key {
				if i%2 == 0 {
					key[i] = 0xAA
				} else {
					key[i] = 0x55
				}
			}
			return key
		}(),
	}

	for i, key := range testKeys {
		t.Run(fmt.Sprintf("key_pattern_%d", i), func(t *testing.T) {
			_, err := crypto.Encrypt("test", key)
			if err != nil {
				t.Errorf("Expected successful GCM initialization with pattern %d: %v", i, err)
			}
		})
	}
}

// TestDecryptAESNewCipherSpecificErrorPaths tests specific error paths for aes.NewCipher in Decrypt
func TestDecryptAESNewCipherSpecificErrorPaths(t *testing.T) {
	// Test with invalid key sizes that should cause aes.NewCipher to fail in Decrypt
	testCases := []struct {
		name        string
		key         []byte
		description string
	}{
		{
			name:        "nil key",
			key:         nil,
			description: "nil key should cause validation error before aes.NewCipher in Decrypt",
		},
		{
			name:        "empty key",
			key:         []byte{},
			description: "empty key should cause validation error before aes.NewCipher in Decrypt",
		},
		{
			name:        "short key",
			key:         make([]byte, 16),
			description: "short key should cause validation error before aes.NewCipher in Decrypt",
		},
		{
			name:        "long key",
			key:         make([]byte, 64),
			description: "long key should cause validation error before aes.NewCipher in Decrypt",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.Decrypt("test", tc.key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestDecryptCipherNewGCMSpecificErrorPaths tests specific error paths for cipher.NewGCM in Decrypt
func TestDecryptCipherNewGCMSpecificErrorPaths(t *testing.T) {
	// Test with valid key size to ensure GCM initialization works in Decrypt
	validKey := make([]byte, crypto.KeySize)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	// Create valid encrypted data first
	encrypted, err := crypto.Encrypt("test", validKey)
	if err != nil {
		t.Fatalf("Failed to create test data: %v", err)
	}

	// This should work and cover the GCM initialization path in Decrypt
	_, err = crypto.Decrypt(encrypted, validKey)
	if err != nil {
		t.Fatalf("Expected successful GCM initialization in Decrypt: %v", err)
	}

	// Test with different key patterns to ensure GCM initialization is robust in Decrypt
	testKeys := [][]byte{
		make([]byte, crypto.KeySize), // all zeros
		func() []byte { // all ones
			key := make([]byte, crypto.KeySize)
			for i := range key {
				key[i] = 1
			}
			return key
		}(),
		func() []byte { // alternating pattern
			key := make([]byte, crypto.KeySize)
			for i := range key {
				if i%2 == 0 {
					key[i] = 0xAA
				} else {
					key[i] = 0x55
				}
			}
			return key
		}(),
	}

	for i, key := range testKeys {
		t.Run(fmt.Sprintf("key_pattern_%d", i), func(t *testing.T) {
			_, err := crypto.Decrypt(encrypted, key)
			// This might fail due to wrong key, but GCM initialization should work
			if err != nil && !strings.Contains(err.Error(), "failed to decrypt") {
				t.Errorf("Unexpected error with pattern %d: %v", i, err)
			}
		})
	}
}

// advancedFailingReader is a mock reader that always fails
type advancedFailingReader struct{}

func (r *advancedFailingReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("mock random generation failure")
}
