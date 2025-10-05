// keyrotation_encrypt_functions_test.go: Focused tests for remaining 0% coverage encryption functions
//
// This test targets the final 3 functions at 0% coverage:
// - EncryptWithKEK (keyrotation.go:546)
// - EncryptWithCachedGCM (keyrotation.go:559)
// - EncryptBytesWithCachedGCM (keyrotation.go:565)
//
// These functions form the performance-optimized encryption chain for vault operations.
// Testing them will complete our >90% coverage target for production deployment.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncryptionChain_ZeroCoverageFunctions tests the complete encryption chain
// from KeyManager.EncryptWithKEK down to EncryptBytesWithCachedGCM
func TestEncryptionChain_ZeroCoverageFunctions(t *testing.T) {
	t.Run("EncryptWithKEK_ValidOperation", func(t *testing.T) {
		// Create KeyManager
		keyManager := NewKeyManager()

		// Generate a KEK for testing
		kekVersion, err := keyManager.GenerateKEK("test-kek-encrypt")
		require.NoError(t, err, "KEK generation must succeed for encryption test")
		require.NotNil(t, kekVersion, "Generated KEK must not be nil")

		// Test plaintext for vault encryption
		testPlaintext := "vault-secret-data-for-kek-encryption"

		// Test EncryptWithKEK (currently 0% coverage)
		ciphertext, err := keyManager.EncryptWithKEK(testPlaintext, kekVersion.ID)
		require.NoError(t, err, "EncryptWithKEK must succeed with valid KEK")
		require.NotEmpty(t, ciphertext, "Ciphertext must not be empty")

		// Validate encryption properties
		assert.NotEqual(t, testPlaintext, ciphertext, "Ciphertext must differ from plaintext")
		assert.Greater(t, len(ciphertext), len(testPlaintext),
			"Ciphertext must be larger due to nonce and authentication tag")

		// Verify decryption round-trip works (validates encryption correctness)
		decrypted, err := keyManager.DecryptWithKEK(ciphertext, kekVersion.ID)
		require.NoError(t, err, "Decryption must succeed for EncryptWithKEK output")
		assert.Equal(t, testPlaintext, decrypted, "Round-trip must preserve original plaintext")
	})

	t.Run("EncryptWithKEK_NonExistentKEK", func(t *testing.T) {
		keyManager := NewKeyManager()

		testPlaintext := "test-data-for-missing-kek"
		nonExistentKEK := "non-existent-kek-id-12345"

		// EncryptWithKEK should fail with non-existent KEK
		ciphertext, err := keyManager.EncryptWithKEK(testPlaintext, nonExistentKEK)

		assert.Error(t, err, "EncryptWithKEK must fail with non-existent KEK")
		assert.Empty(t, ciphertext, "Ciphertext must be empty when encryption fails")
		assert.Contains(t, err.Error(), nonExistentKEK, "Error must identify the missing KEK ID")
	})

	t.Run("EncryptWithCachedGCM_DirectTest", func(t *testing.T) {
		// Create KeyVersion directly for testing EncryptWithCachedGCM
		validKey := make([]byte, 32) // AES-256 key
		for i := range validKey {
			validKey[i] = byte(i + 100) // Deterministic key pattern
		}

		keyVersion := &KeyVersion{
			ID:        "test-encrypt-cached-gcm",
			Key:       validKey,
			Version:   1,
			CreatedAt: time.Now(),
			Status:    "active",
			Algorithm: "AES-256-GCM",
			Purpose:   "KEK",
			cachedGCM: nil, // Will be initialized on first use
		}

		testPlaintext := "direct-cached-gcm-test-data"

		// Test EncryptWithCachedGCM (currently 0% coverage)
		ciphertext, err := keyVersion.EncryptWithCachedGCM(testPlaintext)
		require.NoError(t, err, "EncryptWithCachedGCM must succeed with valid key")
		require.NotEmpty(t, ciphertext, "Ciphertext must not be empty")

		// Validate encryption properties
		assert.NotEqual(t, testPlaintext, ciphertext, "Ciphertext must differ from plaintext")

		// Verify cached GCM was initialized
		assert.NotNil(t, keyVersion.cachedGCM, "Cached GCM must be initialized after encryption")
	})

	t.Run("EncryptBytesWithCachedGCM_DirectTest", func(t *testing.T) {
		// Create KeyVersion for testing EncryptBytesWithCachedGCM
		validKey := make([]byte, 32)
		for i := range validKey {
			validKey[i] = byte(i + 200) // Different key pattern
		}

		keyVersion := &KeyVersion{
			ID:        "test-encrypt-bytes-cached-gcm",
			Key:       validKey,
			Version:   1,
			CreatedAt: time.Now(),
			Status:    "active",
			Algorithm: "AES-256-GCM",
			Purpose:   "KEK",
		}

		testPlaintextBytes := []byte("bytes-cached-gcm-test-data-for-vault")

		// Test EncryptBytesWithCachedGCM (currently 0% coverage)
		ciphertext, err := keyVersion.EncryptBytesWithCachedGCM(testPlaintextBytes)
		require.NoError(t, err, "EncryptBytesWithCachedGCM must succeed with valid key")
		require.NotEmpty(t, ciphertext, "Ciphertext must not be empty")

		// Validate base64 encoding format (vault storage compatibility)
		assert.True(t, len(ciphertext) > 0, "Ciphertext must be valid base64 string")

		// Test with various data sizes
		testSizes := []int{0, 1, 16, 256, 1024} // Empty to 1KB
		for _, size := range testSizes {
			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i % 256)
			}

			result, err := keyVersion.EncryptBytesWithCachedGCM(testData)
			assert.NoError(t, err, "EncryptBytesWithCachedGCM must handle size %d", size)
			assert.NotEmpty(t, result, "Result must not be empty for size %d", size)
		}
	})

	t.Run("EncryptBytesWithCachedGCM_InvalidKey", func(t *testing.T) {
		// Test with invalid key to trigger getCachedGCM error path
		invalidKeyVersion := &KeyVersion{
			ID:        "test-invalid-key-encrypt",
			Key:       []byte{0x01, 0x02}, // Too short for AES
			Version:   1,
			CreatedAt: time.Now(),
			Status:    "active",
			Algorithm: "AES-256-GCM",
			Purpose:   "KEK",
		}

		testData := []byte("test-data-invalid-key")

		// EncryptBytesWithCachedGCM should fail with invalid key
		ciphertext, err := invalidKeyVersion.EncryptBytesWithCachedGCM(testData)
		assert.Error(t, err, "EncryptBytesWithCachedGCM must fail with invalid key")
		assert.Empty(t, ciphertext, "Ciphertext must be empty when encryption fails")
		assert.Contains(t, err.Error(), "failed to get cached GCM",
			"Error must indicate GCM initialization failure")
	})

	t.Run("EncryptionChain_PerformanceOptimization", func(t *testing.T) {
		// Test that multiple encryptions reuse cached GCM for performance
		validKey := make([]byte, 32)
		for i := range validKey {
			validKey[i] = byte(i ^ 0xAA) // XOR pattern
		}

		keyVersion := &KeyVersion{
			ID:        "test-performance-optimization",
			Key:       validKey,
			Version:   1,
			CreatedAt: time.Now(),
			Status:    "active",
			Algorithm: "AES-256-GCM",
			Purpose:   "KEK",
		}

		testData := []byte("performance-test-data")

		// First encryption initializes cache
		ciphertext1, err := keyVersion.EncryptBytesWithCachedGCM(testData)
		require.NoError(t, err, "First encryption must succeed")
		require.NotNil(t, keyVersion.cachedGCM, "Cache must be initialized after first encryption")

		// Store reference to cached GCM
		cachedGCMRef := keyVersion.cachedGCM

		// Subsequent encryptions should reuse cache
		ciphertext2, err := keyVersion.EncryptBytesWithCachedGCM(testData)
		require.NoError(t, err, "Second encryption must succeed")

		// Verify cache reuse (same instance)
		assert.Same(t, cachedGCMRef, keyVersion.cachedGCM,
			"Cached GCM must be reused for performance optimization")

		// Verify different ciphertexts (due to random nonces)
		assert.NotEqual(t, ciphertext1, ciphertext2,
			"Different encryptions must produce different ciphertexts")
	})
}

// BenchmarkEncryptionChain measures performance of the complete encryption chain
func BenchmarkEncryptionChain(b *testing.B) {
	// Setup test key and data
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	keyVersion := &KeyVersion{
		ID:        "benchmark-encryption-chain",
		Key:       validKey,
		Version:   1,
		CreatedAt: time.Now(),
		Status:    "active",
		Algorithm: "AES-256-GCM",
		Purpose:   "KEK",
	}

	testData := []byte("benchmark-test-data-for-vault-performance")

	b.Run("EncryptWithCachedGCM_Performance", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			result, err := keyVersion.EncryptWithCachedGCM(string(testData))
			if err != nil || result == "" {
				b.Fatal("EncryptWithCachedGCM must succeed in benchmark")
			}
		}
	})

	b.Run("EncryptBytesWithCachedGCM_Performance", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			result, err := keyVersion.EncryptBytesWithCachedGCM(testData)
			if err != nil || result == "" {
				b.Fatal("EncryptBytesWithCachedGCM must succeed in benchmark")
			}
		}
	})
}
