// crypto_stress_test.go: Stress test cases for cryptographic utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"strings"
	"testing"

	"github.com/agilira/harpocrates"
)

// TestVeryLargeDataSets tests encryption/decryption with very large data
func TestVeryLargeDataSets(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Test with 1MB of data
	largeData := strings.Repeat("This is a large piece of data for stress testing. ", 20000)
	if len(largeData) < 1000000 {
		t.Fatalf("Large data not big enough: %d bytes", len(largeData))
	}

	encrypted, err := crypto.Encrypt(largeData, key)
	if err != nil {
		t.Fatalf("Failed to encrypt large data: %v", err)
	}

	decrypted, err := crypto.Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt large data: %v", err)
	}

	if decrypted != largeData {
		t.Fatal("Large data encryption/decryption mismatch")
	}
}

// TestRapidKeyGenerationCycles tests rapid key generation
func TestRapidKeyGenerationCycles(t *testing.T) {
	const numKeys = 100
	keys := make([][]byte, numKeys)

	for i := 0; i < numKeys; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("Key generation %d failed: %v", i, err)
		}
		if len(key) != crypto.KeySize {
			t.Fatalf("Key %d has wrong size: got %d, want %d", i, len(key), crypto.KeySize)
		}
		keys[i] = key
	}

	// Verify all keys are different
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if string(keys[i]) == string(keys[j]) {
				t.Errorf("Duplicate keys found at indices %d and %d", i, j)
			}
		}
	}
}

// TestRapidNonceGenerationCycles tests rapid nonce generation
func TestRapidNonceGenerationCycles(t *testing.T) {
	const numNonces = 100
	const nonceSize = 12
	nonces := make([][]byte, numNonces)

	for i := 0; i < numNonces; i++ {
		nonce, err := crypto.GenerateNonce(nonceSize)
		if err != nil {
			t.Fatalf("Nonce generation %d failed: %v", i, err)
		}
		if len(nonce) != nonceSize {
			t.Fatalf("Nonce %d has wrong size: got %d, want %d", i, len(nonce), nonceSize)
		}
		nonces[i] = nonce
	}

	// Verify all nonces are different
	for i := 0; i < len(nonces); i++ {
		for j := i + 1; j < len(nonces); j++ {
			if string(nonces[i]) == string(nonces[j]) {
				t.Errorf("Duplicate nonces found at indices %d and %d", i, j)
			}
		}
	}
}

// TestMaximumAllowedParameters tests with maximum allowed parameters
func TestMaximumAllowedParameters(t *testing.T) {
	// Test with maximum reasonable nonce size
	maxNonceSize := 1024
	nonce, err := crypto.GenerateNonce(maxNonceSize)
	if err != nil {
		t.Fatalf("Failed to generate large nonce: %v", err)
	}
	if len(nonce) != maxNonceSize {
		t.Fatalf("Large nonce has wrong size: got %d, want %d", len(nonce), maxNonceSize)
	}

	// Test PBKDF2 with maximum reasonable parameters
	password := []byte("test-password")
	salt := []byte("test-salt")
	key, err := crypto.DeriveKeyPBKDF2(password, salt, 10000, 1024)
	if err != nil {
		t.Fatalf("Failed to derive large key: %v", err)
	}
	if len(key) != 1024 {
		t.Fatalf("Large key has wrong size: got %d, want 1024", len(key))
	}
}

// TestResourceCleanupScenarios tests resource cleanup
func TestResourceCleanupScenarios(t *testing.T) {
	// Test that zeroize works correctly under stress
	const numIterations = 1000
	for i := 0; i < numIterations; i++ {
		key := make([]byte, crypto.KeySize)
		for j := range key {
			key[j] = byte(i + j)
		}

		// Verify key has non-zero values
		hasNonZero := false
		for _, b := range key {
			if b != 0 {
				hasNonZero = true
				break
			}
		}
		if !hasNonZero {
			t.Fatalf("Key should have non-zero values at iteration %d", i)
		}

		// Zeroize and verify
		crypto.Zeroize(key)
		for j, b := range key {
			if b != 0 {
				t.Errorf("Zeroize failed at iteration %d, position %d: got %d", i, j, b)
			}
		}
	}
}

// TestMemoryUsagePatterns tests memory usage patterns
func TestMemoryUsagePatterns(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Test with many small encryptions
	const numSmallEncryptions = 1000
	for i := 0; i < numSmallEncryptions; i++ {
		plaintext := "small-data-" + string(rune(i))
		encrypted, err := crypto.Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Small encryption %d failed: %v", i, err)
		}
		decrypted, err := crypto.Decrypt(encrypted, key)
		if err != nil {
			t.Fatalf("Small decryption %d failed: %v", i, err)
		}
		if decrypted != plaintext {
			t.Fatalf("Small data round-trip %d failed", i)
		}
	}

	// Test with many key generations
	const numKeyGenerations = 500
	for i := 0; i < numKeyGenerations; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("Key generation %d failed: %v", i, err)
		}
		if len(key) != crypto.KeySize {
			t.Fatalf("Key %d has wrong size: got %d, want %d", i, len(key), crypto.KeySize)
		}
	}
}

// TestStressEncryptionDecryption tests stress encryption/decryption
func TestStressEncryptionDecryption(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	const numOperations = 500
	for i := 0; i < numOperations; i++ {
		// Generate different plaintext for each iteration
		plaintext := strings.Repeat("stress-test-", 10) + string(rune(i%256))

		encrypted, err := crypto.Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Stress encryption %d failed: %v", i, err)
		}

		decrypted, err := crypto.Decrypt(encrypted, key)
		if err != nil {
			t.Fatalf("Stress decryption %d failed: %v", i, err)
		}

		if decrypted != plaintext {
			t.Fatalf("Stress round-trip %d failed: expected %s, got %s", i, plaintext, decrypted)
		}
	}
}
