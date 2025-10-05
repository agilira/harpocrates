// keyrotation_cachedgcm_test.go: Focused test for getCachedGCM function (0% coverage)
//
// This targeted test ensures the getCachedGCM function is properly covered for vault security.
// We test this function in isolation to avoid structural complexities and focus on the
// specific caching logic critical for performance optimization.
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

// TestKeyVersion_getCachedGCM_Focused validates cached GCM initialization and retrieval
// This function is critical for vault performance optimization - 500k ops/sec target
func TestKeyVersion_getCachedGCM_Focused(t *testing.T) {
	t.Run("getCachedGCM_InitializesOnFirstCall", func(t *testing.T) {
		// Create KeyVersion with valid AES-256 key
		validKey := make([]byte, 32) // 256-bit AES key
		for i := range validKey {
			validKey[i] = byte(i)
		}

		keyVersion := &KeyVersion{
			ID:        "test-cached-gcm-init",
			Key:       validKey,
			Version:   1,
			CreatedAt: time.Now(),
			Status:    "active",
			Algorithm: "AES-256-GCM",
			Purpose:   "KEK",
			cachedGCM: nil, // Start with nil cache to test initialization
		}

		// First call should initialize cached GCM
		gcm, err := keyVersion.getCachedGCM()
		require.NoError(t, err, "getCachedGCM must succeed with valid key material")
		require.NotNil(t, gcm, "Cached GCM must be initialized on first access")

		// Validate GCM properties for AES-256-GCM
		assert.Equal(t, 12, gcm.NonceSize(), "GCM nonce size must be 12 bytes for AES-GCM standard")
		assert.Equal(t, 16, gcm.Overhead(), "GCM overhead must be 16 bytes for authentication tag")

		// Verify cache is populated after initialization
		assert.NotNil(t, keyVersion.cachedGCM, "KeyVersion must cache GCM instance after initialization")
		assert.Same(t, gcm, keyVersion.cachedGCM, "Returned GCM must be the cached instance")
	})

	t.Run("getCachedGCM_ReturnsCachedInstanceOnSubsequentCalls", func(t *testing.T) {
		// Create KeyVersion with different key pattern for test isolation
		validKey := make([]byte, 32)
		for i := range validKey {
			validKey[i] = byte(i ^ 0x5A) // XOR pattern for uniqueness
		}

		keyVersion := &KeyVersion{
			ID:        "test-cached-gcm-reuse",
			Key:       validKey,
			Version:   2,
			CreatedAt: time.Now(),
			Status:    "active",
			Algorithm: "AES-256-GCM",
			Purpose:   "KEK",
			cachedGCM: nil,
		}

		// First call initializes cache
		gcm1, err1 := keyVersion.getCachedGCM()
		require.NoError(t, err1, "First getCachedGCM call must succeed")
		require.NotNil(t, gcm1, "First call must return valid GCM instance")

		// Second call should return same cached instance (performance optimization)
		gcm2, err2 := keyVersion.getCachedGCM()
		require.NoError(t, err2, "Subsequent getCachedGCM calls must succeed")
		require.NotNil(t, gcm2, "Subsequent calls must return valid GCM instance")

		// Verify same instance is returned for performance optimization
		assert.Same(t, gcm1, gcm2, "getCachedGCM must return same instance for caching optimization")
		assert.Same(t, keyVersion.cachedGCM, gcm2, "Returned GCM must be the internally cached instance")
	})

	t.Run("getCachedGCM_HandlesInvalidKeyMaterial", func(t *testing.T) {
		invalidKeyTestCases := []struct {
			name        string
			keyMaterial []byte
			description string
		}{
			{
				name:        "EmptyKey",
				keyMaterial: []byte{},
				description: "Empty key material should cause GCM initialization failure",
			},
			{
				name:        "TooShortKey",
				keyMaterial: []byte{0x01, 0x02, 0x03, 0x04}, // 4 bytes, too short for AES
				description: "Key shorter than AES minimum should cause initialization failure",
			},
			{
				name:        "InvalidAESKeySize",
				keyMaterial: make([]byte, 15), // 15 bytes, invalid AES key size
				description: "Non-standard AES key size should cause initialization failure",
			},
		}

		// Initialize non-empty test keys with patterns
		for i := range invalidKeyTestCases[2].keyMaterial {
			invalidKeyTestCases[2].keyMaterial[i] = byte(i + 42)
		}

		for _, tc := range invalidKeyTestCases {
			t.Run(tc.name, func(t *testing.T) {
				keyVersion := &KeyVersion{
					ID:        "test-invalid-key-" + tc.name,
					Key:       tc.keyMaterial,
					Version:   1,
					CreatedAt: time.Now(),
					Status:    "active",
					Algorithm: "AES-256-GCM",
					Purpose:   "KEK",
					cachedGCM: nil,
				}

				// getCachedGCM should handle initialization failure gracefully
				gcm, err := keyVersion.getCachedGCM()
				assert.Error(t, err, "getCachedGCM must fail with invalid key material: %s", tc.description)
				assert.Nil(t, gcm, "GCM instance must be nil when initialization fails")
				assert.Nil(t, keyVersion.cachedGCM, "Cache must remain nil when initialization fails")
				assert.Contains(t, err.Error(), "failed to create AES cipher",
					"Error message must indicate AES cipher creation failure")
			})
		}
	})
}
