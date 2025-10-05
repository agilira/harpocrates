// encryption_vault_test.go: Test cases for Vault Encryption functions.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// TestEncryptBytesWithAAD_VaultSecurity tests EncryptBytesWithAAD (73.3% → 85%+)
// AAD encryption is critical for vault data integrity
func TestEncryptBytesWithAAD_VaultSecurity(t *testing.T) {
	// Generate a proper 256-bit key for testing
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i) // Deterministic key for testing
	}

	t.Run("StandardAADEncryption", func(t *testing.T) {
		plaintext := []byte("vault-secret-data")
		aad := []byte("vault-context-auth")

		encrypted, err := EncryptBytesWithAAD(plaintext, key, aad)
		if err != nil {
			t.Fatalf("EncryptBytesWithAAD failed: %v", err)
		}

		if encrypted == "" {
			t.Error("EncryptBytesWithAAD must return non-empty result")
		}

		// Verify we can decrypt back
		decrypted, err := DecryptBytesWithAAD(encrypted, key, aad)
		if err != nil {
			t.Fatalf("DecryptBytesWithAAD failed: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Error("Decrypted data must match original plaintext")
		}
	})

	t.Run("EmptyAADHandling", func(t *testing.T) {
		plaintext := []byte("vault-data-no-aad")

		// Test with nil AAD
		encrypted1, err := EncryptBytesWithAAD(plaintext, key, nil)
		if err != nil {
			t.Errorf("EncryptBytesWithAAD with nil AAD failed: %v", err)
		}

		// Test with empty AAD
		encrypted2, err := EncryptBytesWithAAD(plaintext, key, []byte{})
		if err != nil {
			t.Errorf("EncryptBytesWithAAD with empty AAD failed: %v", err)
		}

		// Both should be valid but different (different nonces)
		if encrypted1 == encrypted2 {
			t.Error("Different AAD calls should produce different results")
		}
	})

	t.Run("ErrorPathValidation", func(t *testing.T) {
		plaintext := []byte("test-data")
		aad := []byte("test-aad")

		// Test with invalid key sizes (NOT 32 bytes)
		invalidKeys := [][]byte{
			nil,              // nil key
			{},               // empty key
			make([]byte, 15), // Too short
			make([]byte, 16), // AES-128 size (not AES-256)
			make([]byte, 17), // Wrong size
			make([]byte, 24), // AES-192 size
			make([]byte, 31), // Almost AES-256
			make([]byte, 33), // Too long
			make([]byte, 64), // Double AES-256 size
		}

		for i, invalidKey := range invalidKeys {
			_, err := EncryptBytesWithAAD(plaintext, invalidKey, aad)
			if err == nil {
				t.Errorf("EncryptBytesWithAAD should fail with invalid key #%d (len=%d)", i, len(invalidKey))
			}
		}

		// Test with nil plaintext (should work)
		_, err := EncryptBytesWithAAD(nil, key, aad)
		if err != nil {
			t.Errorf("EncryptBytesWithAAD should handle nil plaintext: %v", err)
		}
	})

	t.Run("AADVariations", func(t *testing.T) {
		plaintext := []byte("vault-test-data")

		// Test with various AAD sizes and contents
		aadTests := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("medium-length-aad-content"),
			make([]byte, 1000),       // Large AAD
			{0x00, 0xFF, 0xAA, 0x55}, // Binary AAD (simplified)
		}

		for i, aad := range aadTests {
			encrypted, err := EncryptBytesWithAAD(plaintext, key, aad)
			if err != nil {
				t.Errorf("EncryptBytesWithAAD with AAD variation #%d failed: %v", i, err)
				continue
			}

			// Verify decryption works with same AAD
			decrypted, err := DecryptBytesWithAAD(encrypted, key, aad)
			if err != nil {
				t.Errorf("DecryptBytesWithAAD with AAD variation #%d failed: %v", i, err)
				continue
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("AAD variation #%d: decrypted data mismatch", i)
			}
		}
	})

	t.Run("VaultGradeFailurePaths", func(t *testing.T) {
		// VAULT REQUIREMENT: Test every possible failure scenario
		// No vault can afford untested error paths

		plaintext := []byte("critical-vault-secret")
		aad := []byte("vault-integrity-context")
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 42)
		}

		// Test 1: Corrupted/invalid keys that might pass length check but fail GCM
		corruptedKeys := [][]byte{
			make([]byte, 32), // All zeros - potentially problematic
		}

		// Fill with patterns that might cause GCM issues
		for i := range corruptedKeys[0] {
			corruptedKeys[0][i] = 0x00 // All zero key
		}

		// Add more problematic key patterns
		pattern1 := make([]byte, 32)
		for i := range pattern1 {
			pattern1[i] = 0xFF // All ones
		}
		corruptedKeys = append(corruptedKeys, pattern1)

		pattern2 := make([]byte, 32)
		for i := range pattern2 {
			pattern2[i] = byte(i % 2) // Alternating 0,1 pattern
		}
		corruptedKeys = append(corruptedKeys, pattern2)

		// Test encryption with potentially problematic but valid-length keys
		for i, testKey := range corruptedKeys {
			_, err := EncryptBytesWithAAD(plaintext, testKey, aad)
			// These should either succeed or fail gracefully, not panic
			if err != nil {
				// Error is acceptable, but must be meaningful
				if !strings.Contains(err.Error(), "cipher") && !strings.Contains(err.Error(), "failed") {
					t.Errorf("Corrupted key %d error should be meaningful: %v", i, err)
				}
			}
		}

		// Test 2: Extreme plaintext sizes
		extremePlaintexts := [][]byte{
			nil,                        // nil plaintext
			{},                         // empty plaintext
			make([]byte, 1024*1024),    // 1MB plaintext
			make([]byte, 10*1024*1024), // 10MB plaintext (stress test)
		}

		for i, extremeText := range extremePlaintexts {
			if len(extremeText) > 0 {
				// Fill with test pattern
				for j := range extremeText {
					extremeText[j] = byte((i * j) % 256)
				}
			}

			_, err := EncryptBytesWithAAD(extremeText, key, aad)
			if err != nil {
				t.Errorf("Extreme plaintext %d (size=%d) should be handled: %v", i, len(extremeText), err)
			}
		}

		// Test 3: Extreme AAD sizes and contents
		extremeAADs := [][]byte{
			make([]byte, 64*1024),   // 64KB AAD
			make([]byte, 1024*1024), // 1MB AAD (extreme)
		}

		for i, extremeAAD := range extremeAADs {
			// Fill with varied patterns
			for j := range extremeAAD {
				extremeAAD[j] = byte((i*j + 123) % 256)
			}

			_, err := EncryptBytesWithAAD(plaintext, key, extremeAAD)
			if err != nil {
				t.Errorf("Extreme AAD %d (size=%d) should be handled: %v", i, len(extremeAAD), err)
			}
		}

		// Test 4: Concurrent access patterns (vault must be thread-safe)
		// Multiple goroutines using same key simultaneously
		const numGoroutines = 10
		errChan := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				testData := append(plaintext, byte(id))
				testAAD := append(aad, byte(id))
				_, err := EncryptBytesWithAAD(testData, key, testAAD)
				errChan <- err
			}(i)
		}

		// Collect results
		for i := 0; i < numGoroutines; i++ {
			err := <-errChan
			if err != nil {
				t.Errorf("Concurrent encryption %d failed: %v", i, err)
			}
		}
	})
}

// TestDecryptWithKEK_VaultSecurity tests DecryptWithKEK (75.0% → 85%+)
// KEK-based decryption is critical for vault data access security
func TestDecryptWithKEK_VaultSecurity(t *testing.T) {
	t.Run("SuccessfulDecryption", func(t *testing.T) {
		km := NewKeyManager()

		// Generate and activate KEK
		kek, err := km.GenerateKEK("vault-decrypt-test")
		if err != nil {
			t.Fatalf("Failed to generate KEK: %v", err)
		}

		err = km.ActivateKEK(kek.ID)
		if err != nil {
			t.Fatalf("Failed to activate KEK: %v", err)
		}

		// Encrypt data with the KEK
		plaintext := "vault-secret-data-for-decryption"
		encrypted, err := Encrypt(plaintext, kek.Key)
		if err != nil {
			t.Fatalf("Failed to encrypt test data: %v", err)
		}

		// Test DecryptWithKEK
		decrypted, err := km.DecryptWithKEK(encrypted, kek.ID)
		if err != nil {
			t.Errorf("DecryptWithKEK failed: %v", err)
		}

		if decrypted != plaintext {
			t.Errorf("Decrypted data mismatch: expected '%s', got '%s'", plaintext, decrypted)
		}
	})

	t.Run("NonExistentKEKID", func(t *testing.T) {
		km := NewKeyManager()

		// Test with invalid KEK ID
		_, err := km.DecryptWithKEK("fake-encrypted-data", "non-existent-kek-id")
		if err == nil {
			t.Error("DecryptWithKEK should fail with non-existent KEK ID")
		}

		if !strings.Contains(err.Error(), "failed to get KEK") {
			t.Errorf("Error should indicate KEK retrieval failure, got: %v", err)
		}
	})

	t.Run("MultipleKEKDecryption", func(t *testing.T) {
		km := NewKeyManager()

		// Generate multiple KEKs
		kek1, err := km.GenerateKEK("vault-decrypt-kek1")
		if err != nil {
			t.Fatalf("Failed to generate KEK 1: %v", err)
		}

		kek2, err := km.GenerateKEK("vault-decrypt-kek2")
		if err != nil {
			t.Fatalf("Failed to generate KEK 2: %v", err)
		}

		// Encrypt different data with different KEKs
		data1 := "secret-data-for-kek1"
		data2 := "secret-data-for-kek2"

		encrypted1, err := Encrypt(data1, kek1.Key)
		if err != nil {
			t.Fatalf("Failed to encrypt data1: %v", err)
		}

		encrypted2, err := Encrypt(data2, kek2.Key)
		if err != nil {
			t.Fatalf("Failed to encrypt data2: %v", err)
		}

		// Test decryption with correct KEK IDs
		decrypted1, err := km.DecryptWithKEK(encrypted1, kek1.ID)
		if err != nil {
			t.Errorf("DecryptWithKEK for KEK1 failed: %v", err)
		}

		decrypted2, err := km.DecryptWithKEK(encrypted2, kek2.ID)
		if err != nil {
			t.Errorf("DecryptWithKEK for KEK2 failed: %v", err)
		}

		if decrypted1 != data1 {
			t.Errorf("KEK1 decryption mismatch: expected '%s', got '%s'", data1, decrypted1)
		}

		if decrypted2 != data2 {
			t.Errorf("KEK2 decryption mismatch: expected '%s', got '%s'", data2, decrypted2)
		}

		// Test cross-decryption (should fail)
		_, err = km.DecryptWithKEK(encrypted1, kek2.ID)
		if err == nil {
			t.Error("Cross-KEK decryption should fail")
		}
	})

	t.Run("InvalidEncryptedData", func(t *testing.T) {
		km := NewKeyManager()

		// Generate KEK for testing
		kek, err := km.GenerateKEK("vault-invalid-data-test")
		if err != nil {
			t.Fatalf("Failed to generate KEK: %v", err)
		}

		// Test with various invalid encrypted data
		invalidData := []string{
			"",
			"invalid-base64-!@#$%^&*()",
			"dGVzdA==", // Valid base64 but not valid ciphertext
			"not-base64-at-all",
		}

		for i, data := range invalidData {
			_, err := km.DecryptWithKEK(data, kek.ID)
			if err == nil {
				t.Errorf("DecryptWithKEK should fail with invalid data #%d: '%s'", i, data)
			}
		}
	})
}
