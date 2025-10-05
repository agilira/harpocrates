// crypto_boundary_test.go: Boundary test cases for cryptographic utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/agilira/harpocrates"
)

// TestGetKeyFingerprintOverflow tests GetKeyFingerprint with keys that could cause overflow
func TestGetKeyFingerprintOverflow(t *testing.T) {
	// Test with key that has high byte values to trigger overflow condition
	overflowKey := make([]byte, crypto.KeySize)
	for i := range overflowKey {
		overflowKey[i] = 255 // Maximum byte value
	}

	fingerprint := crypto.GetKeyFingerprint(overflowKey)
	if fingerprint == "" {
		t.Error("Expected non-empty fingerprint for overflow key")
	}

	// Test with key that has specific pattern to trigger overflow
	patternKey := make([]byte, crypto.KeySize)
	for i := range patternKey {
		patternKey[i] = byte(255 - i) // Decreasing values
	}

	fingerprint2 := crypto.GetKeyFingerprint(patternKey)
	if fingerprint2 == "" {
		t.Error("Expected non-empty fingerprint for pattern key")
	}

	// Verify fingerprints are different
	if fingerprint == fingerprint2 {
		t.Error("Expected different fingerprints for different keys")
	}
}

// TestGetKeyFingerprintEdgeCases tests GetKeyFingerprint with various edge cases
func TestGetKeyFingerprintEdgeCases(t *testing.T) {
	// Test with single byte key
	singleByteKey := []byte{255}
	fingerprint := crypto.GetKeyFingerprint(singleByteKey)
	if fingerprint == "" {
		t.Error("Expected non-empty fingerprint for single byte key")
	}

	// Test with two byte key
	twoByteKey := []byte{255, 255}
	fingerprint2 := crypto.GetKeyFingerprint(twoByteKey)
	if fingerprint2 == "" {
		t.Error("Expected non-empty fingerprint for two byte key")
	}

	// Test with key that has alternating high/low values
	alternatingKey := make([]byte, crypto.KeySize)
	for i := range alternatingKey {
		if i%2 == 0 {
			alternatingKey[i] = 255
		} else {
			alternatingKey[i] = 0
		}
	}

	fingerprint3 := crypto.GetKeyFingerprint(alternatingKey)
	if fingerprint3 == "" {
		t.Error("Expected non-empty fingerprint for alternating key")
	}

	// Verify all fingerprints are different
	if fingerprint == fingerprint2 || fingerprint == fingerprint3 || fingerprint2 == fingerprint3 {
		t.Error("Expected different fingerprints for different keys")
	}
}

// TestEncryptWithInvalidKeySizes tests encryption with various invalid key sizes
func TestEncryptWithInvalidKeySizes(t *testing.T) {
	testCases := []struct {
		name     string
		keySize  int
		expected bool // true if error expected
	}{
		{"nil key", 0, true},
		{"empty key", 0, true},
		{"1 byte key", 1, true},
		{"16 byte key", 16, true},
		{"24 byte key", 24, true},
		{"31 byte key", 31, true},
		{"33 byte key", 33, true},
		{"48 byte key", 48, true},
		{"64 byte key", 64, true},
		{"32 byte key", 32, false}, // valid
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var key []byte
			if tc.keySize > 0 {
				key = make([]byte, tc.keySize)
				for i := range key {
					key[i] = byte(i)
				}
			}

			_, err := crypto.Encrypt("test", key)
			if tc.expected && err == nil {
				t.Error("Expected error for invalid key size")
			}
			if !tc.expected && err != nil {
				t.Errorf("Unexpected error for valid key size: %v", err)
			}
		})
	}
}

// TestDecryptWithInvalidKeySizes tests decryption with various invalid key sizes
func TestDecryptWithInvalidKeySizes(t *testing.T) {
	// Create valid encrypted data first
	validKey := make([]byte, crypto.KeySize)
	for i := range validKey {
		validKey[i] = byte(i)
	}
	encrypted, err := crypto.Encrypt("test", validKey)
	if err != nil {
		t.Fatalf("Failed to create test encrypted data: %v", err)
	}

	testCases := []struct {
		name     string
		keySize  int
		expected bool // true if error expected
	}{
		{"nil key", 0, true},
		{"empty key", 0, true},
		{"1 byte key", 1, true},
		{"16 byte key", 16, true},
		{"24 byte key", 24, true},
		{"31 byte key", 31, true},
		{"33 byte key", 33, true},
		{"48 byte key", 48, true},
		{"64 byte key", 64, true},
		{"32 byte key", 32, false}, // valid
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var key []byte
			if tc.keySize > 0 {
				key = make([]byte, tc.keySize)
				for i := range key {
					key[i] = byte(i)
				}
			}

			_, err := crypto.Decrypt(encrypted, key)
			if tc.expected && err == nil {
				t.Error("Expected error for invalid key size")
			}
			if !tc.expected && err != nil {
				t.Errorf("Unexpected error for valid key size: %v", err)
			}
		})
	}
}

// TestDecryptWithCorruptedGCMData tests decryption with corrupted GCM data
func TestDecryptWithCorruptedGCMData(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted data
	plaintext := "test-data-for-corruption"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Test with various corruption scenarios
	testCases := []struct {
		name        string
		corruptFunc func(string) string
	}{
		{
			name: "flip last byte",
			corruptFunc: func(s string) string {
				if len(s) > 0 {
					return s[:len(s)-1] + string(s[len(s)-1]^1)
				}
				return s
			},
		},
		{
			name: "flip middle byte",
			corruptFunc: func(s string) string {
				if len(s) > 2 {
					mid := len(s) / 2
					return s[:mid] + string(s[mid]^1) + s[mid+1:]
				}
				return s
			},
		},
		{
			name: "add extra byte",
			corruptFunc: func(s string) string {
				return s + "X"
			},
		},
		{
			name: "remove last byte",
			corruptFunc: func(s string) string {
				if len(s) > 0 {
					return s[:len(s)-1]
				}
				return s
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := tc.corruptFunc(encrypted)
			_, err := crypto.Decrypt(corrupted, key)
			if err == nil {
				t.Error("Expected error for corrupted GCM data")
			}
		})
	}
}

// TestDecryptWithInvalidBase64EdgeCases tests decryption with edge case base64 inputs
func TestDecryptWithInvalidBase64EdgeCases(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	testCases := []struct {
		name        string
		base64Input string
		description string
	}{
		{"empty string", "", "empty base64"},
		{"single char", "A", "incomplete base64"},
		{"two chars", "AA", "incomplete base64"},
		{"three chars", "AAA", "incomplete base64"},
		{"invalid chars", "AA==AA", "invalid padding"},
		{"too much padding", "AA===", "excessive padding"},
		{"wrong padding", "AAA=", "wrong padding"},
		{"non-base64 chars", "AA!!", "invalid characters"},
		{"partial padding", "AA=", "partial padding"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.Decrypt(tc.base64Input, key)
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
			}
		})
	}
}

// TestEncryptWithMinimumValidInputs tests encryption with minimum valid inputs
func TestEncryptWithMinimumValidInputs(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Test with single character
	encrypted, err := crypto.Encrypt("a", key)
	if err != nil {
		t.Fatalf("Failed to encrypt single character: %v", err)
	}

	decrypted, err := crypto.Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt single character: %v", err)
	}

	if decrypted != "a" {
		t.Fatalf("Single character round-trip failed: expected 'a', got '%s'", decrypted)
	}

	// Test with minimum key (all zeros)
	minKey := make([]byte, crypto.KeySize)
	encrypted, err = crypto.Encrypt("test", minKey)
	if err != nil {
		t.Fatalf("Failed to encrypt with minimum key: %v", err)
	}

	decrypted, err = crypto.Decrypt(encrypted, minKey)
	if err != nil {
		t.Fatalf("Failed to decrypt with minimum key: %v", err)
	}

	if decrypted != "test" {
		t.Fatalf("Minimum key round-trip failed: expected 'test', got '%s'", decrypted)
	}
}

// TestDecryptWithMinimumValidInputs tests decryption with minimum valid inputs
func TestDecryptWithMinimumValidInputs(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create minimal valid encrypted data
	encrypted, err := crypto.Encrypt("a", key)
	if err != nil {
		t.Fatalf("Failed to create minimal encrypted data: %v", err)
	}

	// Test decryption
	decrypted, err := crypto.Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt minimal data: %v", err)
	}

	if decrypted != "a" {
		t.Fatalf("Minimal data round-trip failed: expected 'a', got '%s'", decrypted)
	}
}

// TestEncryptWithMaximumInputSizes tests encryption with maximum allowed input sizes
func TestEncryptWithMaximumInputSizes(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Test with very large plaintext (1MB)
	largePlaintext := make([]byte, 1024*1024)
	for i := range largePlaintext {
		largePlaintext[i] = byte(i % 256)
	}

	encrypted, err := crypto.Encrypt(string(largePlaintext), key)
	if err != nil {
		t.Fatalf("Failed to encrypt large plaintext: %v", err)
	}

	decrypted, err := crypto.Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt large plaintext: %v", err)
	}

	if decrypted != string(largePlaintext) {
		t.Fatalf("Large plaintext round-trip failed")
	}

	// Test with maximum key (all 255 values)
	maxKey := make([]byte, crypto.KeySize)
	for i := range maxKey {
		maxKey[i] = 255
	}

	encrypted, err = crypto.Encrypt("test", maxKey)
	if err != nil {
		t.Fatalf("Failed to encrypt with maximum key: %v", err)
	}

	decrypted, err = crypto.Decrypt(encrypted, maxKey)
	if err != nil {
		t.Fatalf("Failed to decrypt with maximum key: %v", err)
	}

	if decrypted != "test" {
		t.Fatalf("Maximum key round-trip failed")
	}
}

// TestDecryptWithMaximumInputSizes tests decryption with maximum allowed input sizes
func TestDecryptWithMaximumInputSizes(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create large encrypted data
	largePlaintext := make([]byte, 512*1024) // 512KB
	for i := range largePlaintext {
		largePlaintext[i] = byte(i % 256)
	}

	encrypted, err := crypto.Encrypt(string(largePlaintext), key)
	if err != nil {
		t.Fatalf("Failed to create large encrypted data: %v", err)
	}

	// Test decryption
	decrypted, err := crypto.Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt large data: %v", err)
	}

	if decrypted != string(largePlaintext) {
		t.Fatalf("Large data round-trip failed")
	}
}

// TestDecryptWithAdvancedCorruptedData tests decryption with advanced corrupted data structures
func TestDecryptWithAdvancedCorruptedData(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted data
	plaintext := "test-data-for-advanced-corruption"
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
	}{
		{
			name: "corrupt nonce",
			corruptFunc: func(data []byte) string {
				if len(data) > 12 {
					data[0] ^= 1 // Flip first byte of nonce
				}
				return base64.StdEncoding.EncodeToString(data)
			},
		},
		{
			name: "corrupt ciphertext",
			corruptFunc: func(data []byte) string {
				if len(data) > 12 {
					data[12] ^= 1 // Flip first byte of ciphertext
				}
				return base64.StdEncoding.EncodeToString(data)
			},
		},
		{
			name: "truncate nonce",
			corruptFunc: func(data []byte) string {
				if len(data) > 12 {
					return base64.StdEncoding.EncodeToString(data[:11]) // Remove last byte of nonce
				}
				return base64.StdEncoding.EncodeToString(data)
			},
		},
		{
			name: "truncate ciphertext",
			corruptFunc: func(data []byte) string {
				if len(data) > 12 {
					return base64.StdEncoding.EncodeToString(data[:len(data)-1]) // Remove last byte
				}
				return base64.StdEncoding.EncodeToString(data)
			},
		},
		{
			name: "swap nonce and ciphertext",
			corruptFunc: func(data []byte) string {
				if len(data) > 24 {
					// Swap first 12 bytes with next 12 bytes
					copy(data[0:12], data[12:24])
					copy(data[12:24], data[0:12])
				}
				return base64.StdEncoding.EncodeToString(data)
			},
		},
		{
			name: "zero out nonce",
			corruptFunc: func(data []byte) string {
				if len(data) > 12 {
					for i := 0; i < 12; i++ {
						data[i] = 0
					}
				}
				return base64.StdEncoding.EncodeToString(data)
			},
		},
		{
			name: "zero out ciphertext",
			corruptFunc: func(data []byte) string {
				if len(data) > 12 {
					for i := 12; i < len(data); i++ {
						data[i] = 0
					}
				}
				return base64.StdEncoding.EncodeToString(data)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := tc.corruptFunc(rawData)
			_, err := crypto.Decrypt(corrupted, key)
			if err == nil {
				t.Error("Expected error for corrupted data")
			}
		})
	}
}

// TestSystemResourceLimitations tests behavior under system resource limitations
func TestSystemResourceLimitations(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Test with very large number of concurrent operations
	const numGoroutines = 100
	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			plaintext := fmt.Sprintf("test-data-%d", id)
			encrypted, err := crypto.Encrypt(plaintext, key)
			if err != nil {
				results <- fmt.Errorf("encryption failed: %v", err)
				return
			}

			decrypted, err := crypto.Decrypt(encrypted, key)
			if err != nil {
				results <- fmt.Errorf("decryption failed: %v", err)
				return
			}

			if decrypted != plaintext {
				results <- fmt.Errorf("round-trip failed: expected %s, got %s", plaintext, decrypted)
				return
			}

			results <- nil
		}(i)
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		if err := <-results; err != nil {
			t.Errorf("Concurrent operation failed: %v", err)
		}
	}
}

// TestErrorMessageAccuracy tests accuracy and consistency of error messages
func TestErrorMessageAccuracy(t *testing.T) {
	testCases := []struct {
		name        string
		testFunc    func() error
		expectedErr string
		description string
	}{
		{
			name: "invalid key size 16 bytes",
			testFunc: func() error {
				key := make([]byte, 16)
				_, err := crypto.Encrypt("test", key)
				return err
			},
			expectedErr: "invalid key size: must be 32 bytes for AES-256 (got 16)",
			description: "should report correct key size requirement",
		},
		{
			name: "invalid key size 64 bytes",
			testFunc: func() error {
				key := make([]byte, 64)
				_, err := crypto.Encrypt("test", key)
				return err
			},
			expectedErr: "invalid key size: must be 32 bytes for AES-256 (got 64)",
			description: "should report correct key size requirement",
		},

		{
			name: "empty encrypted text",
			testFunc: func() error {
				key := make([]byte, crypto.KeySize)
				_, err := crypto.Decrypt("", key)
				return err
			},
			expectedErr: "encrypted text cannot be empty",
			description: "should report empty encrypted text error",
		},
		{
			name: "invalid base64",
			testFunc: func() error {
				key := make([]byte, crypto.KeySize)
				_, err := crypto.Decrypt("invalid-base64!!", key)
				return err
			},
			expectedErr: "failed to decode base64",
			description: "should report base64 decode error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.testFunc()
			if err == nil {
				t.Errorf("Expected error for %s", tc.description)
				return
			}

			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Errorf("Error message mismatch for %s: expected to contain '%s', got '%s'",
					tc.description, tc.expectedErr, err.Error())
			}
		})
	}
}

// TestBoundaryConditionsWithMinimumValidInputs tests boundary conditions with minimum valid inputs
func TestBoundaryConditionsWithMinimumValidInputs(t *testing.T) {
	// Test with minimum valid key (all zeros)
	minKey := make([]byte, crypto.KeySize)

	// Test with single byte plaintext
	encrypted, err := crypto.Encrypt("a", minKey)
	if err != nil {
		t.Fatalf("Failed to encrypt with minimum key: %v", err)
	}

	decrypted, err := crypto.Decrypt(encrypted, minKey)
	if err != nil {
		t.Fatalf("Failed to decrypt with minimum key: %v", err)
	}

	if decrypted != "a" {
		t.Fatalf("Minimum key round-trip failed: expected 'a', got '%s'", decrypted)
	}

	// Test with minimum valid nonce size (12 bytes for GCM)
	// This is handled internally by the GCM implementation
	encrypted, err = crypto.Encrypt("test", minKey)
	if err != nil {
		t.Fatalf("Failed to encrypt with minimum nonce: %v", err)
	}

	decrypted, err = crypto.Decrypt(encrypted, minKey)
	if err != nil {
		t.Fatalf("Failed to decrypt with minimum nonce: %v", err)
	}

	if decrypted != "test" {
		t.Fatalf("Minimum nonce round-trip failed: expected 'test', got '%s'", decrypted)
	}
}

// TestCorruptedDataStructures tests with corrupted data structures
func TestCorruptedDataStructures(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted data
	plaintext := "test-data-for-corruption"
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
	}{
		{
			name: "completely random data",
			corruptFunc: func(data []byte) string {
				randomData := make([]byte, len(data))
				for i := range randomData {
					randomData[i] = byte(i * 7 % 256) // Pseudo-random pattern
				}
				return base64.StdEncoding.EncodeToString(randomData)
			},
		},
		{
			name: "all zeros",
			corruptFunc: func(data []byte) string {
				zeroData := make([]byte, len(data))
				return base64.StdEncoding.EncodeToString(zeroData)
			},
		},
		{
			name: "all ones",
			corruptFunc: func(data []byte) string {
				oneData := make([]byte, len(data))
				for i := range oneData {
					oneData[i] = 1
				}
				return base64.StdEncoding.EncodeToString(oneData)
			},
		},
		{
			name: "repeated pattern",
			corruptFunc: func(data []byte) string {
				patternData := make([]byte, len(data))
				for i := range patternData {
					patternData[i] = byte(i % 4) // Repeating 0,1,2,3 pattern
				}
				return base64.StdEncoding.EncodeToString(patternData)
			},
		},
		{
			name: "inverted data",
			corruptFunc: func(data []byte) string {
				invertedData := make([]byte, len(data))
				for i := range invertedData {
					invertedData[i] = ^data[i] // Bitwise NOT
				}
				return base64.StdEncoding.EncodeToString(invertedData)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			corrupted := tc.corruptFunc(rawData)
			_, err := crypto.Decrypt(corrupted, key)
			if err == nil {
				t.Error("Expected error for corrupted data structure")
			}
		})
	}
}
