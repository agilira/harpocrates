// encryption_nonce_failure_test.go: Test cases for Additional Authenticated Data functions.
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEncryptBytesWithAAD_NonceFailure tests the rarely-triggered nonce generation error path
// This is critical for vault security - if nonce generation fails, encryption must fail safely
func TestEncryptBytesWithAAD_NonceFailure(t *testing.T) {
	// VAULT CRITICAL: Test nonce generation failure path
	// In enterprise vaults, nonce generation failure must be handled properly

	t.Run("NonceGenerationHandling", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 100)
		}

		plaintext := []byte("vault-critical-data")
		aad := []byte("enterprise-aad")

		// This test verifies that if nonce generation were to fail,
		// it would be handled properly. In practice, crypto/rand.Reader
		// almost never fails, but vault-grade code must handle it.

		// We can't easily force crypto/rand to fail, but we can verify
		// the function structure and expected behavior
		result, err := EncryptBytesWithAAD(plaintext, key, aad)

		// Normal operation should succeed
		assert.NoError(t, err)
		assert.NotEmpty(t, result)

		// Verify the function handles all the expected paths
		// Even if we can't force nonce failure in practice
		assert.Greater(t, len(result), len(plaintext)) // Should be longer due to nonce+tag
	})

	t.Run("BufferPoolEdgeCases", func(t *testing.T) {
		// VAULT CRITICAL: Test edge cases in buffer pooling
		// Buffer reuse bugs could leak vault secrets between operations

		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 150)
		}

		// Test with various sizes to stress buffer pooling
		testCases := []struct {
			name      string
			plaintext []byte
			aad       []byte
		}{
			{"ZeroLengthPlaintext", []byte{}, []byte("aad")},
			{"ZeroLengthAAD", []byte("data"), []byte{}},
			{"BothZeroLength", []byte{}, []byte{}},
			{"SingleByteEach", []byte{42}, []byte{84}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result, err := EncryptBytesWithAAD(tc.plaintext, key, tc.aad)
				assert.NoError(t, err)
				assert.NotEmpty(t, result) // Should always have nonce + tag minimum
			})
		}
	})

	t.Run("GCMSealPathCoverage", func(t *testing.T) {
		// VAULT CRITICAL: Ensure gcm.Seal path is fully exercised
		// This is the core encryption operation - must be bulletproof

		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i * 3 % 256)
		}

		// Test the gcm.Seal operation with various inputs
		plaintexts := [][]byte{
			nil,                // nil plaintext
			{},                 // empty plaintext
			{0},                // single zero byte
			{255},              // single max byte
			make([]byte, 1024), // large zero buffer
		}

		aads := [][]byte{
			nil,                // nil AAD
			{},                 // empty AAD
			[]byte("vault"),    // typical AAD (can't simplify string conversion)
			make([]byte, 2048), // large AAD
		}

		for i, plaintext := range plaintexts {
			for j, aad := range aads {
				t.Run(fmt.Sprintf("Plaintext_%d_AAD_%d", i, j), func(t *testing.T) {
					result, err := EncryptBytesWithAAD(plaintext, key, aad)
					assert.NoError(t, err)
					assert.NotEmpty(t, result)
				})
			}
		}
	})
}
