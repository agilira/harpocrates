// validate_kek_paths_test.go: tests to increase code path coverage in KEK validation
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"testing"
)

// TestValidateKEKRotation_ErrorPathsCoverage attempts to reach remaining error paths
// These tests use creative approaches to trigger hard-to-reach error conditions
func TestValidateKEKRotation_ErrorPathsCoverage(t *testing.T) {

	t.Run("ZeroKey_DeriveFailure", func(t *testing.T) {
		// VAULT CRITICAL: Test with all-zero key
		km := NewKeyManager()

		// All-zero key might cause issues in some HKDF implementations
		zeroKey := make([]byte, 32)
		// Leave as all zeros

		km.pendingKEK = &KeyVersion{
			ID:     "zero-key-test",
			Key:    zeroKey,
			Status: StatusPending,
		}

		err := km.ValidateKEKRotation()
		// Even zero keys should work with HKDF, but let's verify behavior
		if err != nil {
			if km.pendingKEK.Status != StatusRevoked {
				t.Error("Failed zero-key validation must revoke KEK")
			}
		} else {
			if km.pendingKEK.Status != StatusValidating {
				t.Error("Successful zero-key validation should promote KEK")
			}
		}
	})

	t.Run("RepeatedPattern_WeakKey", func(t *testing.T) {
		// VAULT CRITICAL: Test with repeated pattern key
		km := NewKeyManager()

		// Create key with repeated pattern that might cause crypto issues
		patternKey := make([]byte, 32)
		for i := range patternKey {
			patternKey[i] = 0xAA // All same byte
		}

		km.pendingKEK = &KeyVersion{
			ID:     "pattern-key-test",
			Key:    patternKey,
			Status: StatusPending,
		}

		err := km.ValidateKEKRotation()
		// Pattern keys should still work with AES-GCM
		if err != nil {
			if km.pendingKEK.Status != StatusRevoked {
				t.Error("Failed pattern validation must revoke KEK")
			}
		} else {
			if km.pendingKEK.Status != StatusValidating {
				t.Error("Successful pattern validation should promote KEK")
			}
		}
	})

	t.Run("VeryShortKey_EdgeCase", func(t *testing.T) {
		// VAULT CRITICAL: Test with minimum viable key
		km := NewKeyManager()

		// Single byte key - should work with HKDF expansion
		shortKey := []byte{0x42}

		km.pendingKEK = &KeyVersion{
			ID:     "single-byte-key",
			Key:    shortKey,
			Status: StatusPending,
		}

		err := km.ValidateKEKRotation()
		// HKDF should expand this to 32 bytes successfully
		if err != nil {
			if km.pendingKEK.Status != StatusRevoked {
				t.Error("Failed short-key validation must revoke KEK")
			}
		} else {
			if km.pendingKEK.Status != StatusValidating {
				t.Error("Successful short-key validation should promote KEK")
			}
		}
	})

	// Since we can't easily trigger EncryptBytes/DecryptBytes failures,
	// let's create comprehensive tests that exercise all possible code paths
	t.Run("ComprehensivePath_AllValidations", func(t *testing.T) {
		// VAULT CRITICAL: Exercise as many code paths as possible
		km := NewKeyManager()

		// Test multiple scenarios in sequence to increase path coverage
		testCases := []struct {
			name string
			key  []byte
		}{
			{"random-strong", []byte("this-is-a-very-strong-crypto-key")},
			{"crypto-pattern", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}},
			{"alternating", []byte{0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
				0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
				0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
				0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00}},
		}

		for _, tc := range testCases {
			km.pendingKEK = &KeyVersion{
				ID:     tc.name + "-comprehensive",
				Key:    tc.key,
				Status: StatusPending,
			}

			err := km.ValidateKEKRotation()
			if err != nil {
				t.Errorf("Comprehensive test %s failed: %v", tc.name, err)
			}

			if km.pendingKEK.Status != StatusValidating {
				t.Errorf("Comprehensive test %s should promote to StatusValidating", tc.name)
			}
		}
	})

	t.Run("SequentialValidations_StateTransitions", func(t *testing.T) {
		// VAULT CRITICAL: Test state transition edge cases
		km := NewKeyManager()

		// Generate multiple KEKs and validate them in sequence
		for i := 0; i < 3; i++ {
			kek, err := km.GenerateKEK("sequential-validation")
			if err != nil {
				t.Fatalf("Failed to generate sequential KEK: %v", err)
			}

			km.pendingKEK = kek
			km.pendingKEK.Status = StatusPending

			err = km.ValidateKEKRotation()
			if err != nil {
				t.Errorf("Sequential validation %d failed: %v", i, err)
			}

			// Verify state transition
			if km.pendingKEK.Status != StatusValidating {
				t.Errorf("Sequential validation %d should reach StatusValidating", i)
			}
		}
	})
}
