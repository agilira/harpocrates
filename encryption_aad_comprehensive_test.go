// encryption_aad_comprehensive_test.go: Comprehensive tests for AAD encryption error paths
//
// This test suite focuses on improving coverage for EncryptBytesWithAAD (73.3% → 100%)
// and DecryptBytesWithAAD (83.9% → 100%) by testing all error scenarios and edge cases
// critical for vault security validation.
//
// AAD (Additional Authenticated Data) is crucial for vault metadata authentication
// without encryption - these functions must handle all error conditions correctly.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncryptBytesWithAAD_ErrorPaths validates all error conditions in AAD encryption
// These error paths are critical for vault security - malformed inputs must be rejected correctly
func TestEncryptBytesWithAAD_ErrorPaths(t *testing.T) {
	// Valid test data for comparison
	validKey := make([]byte, 32) // 256-bit key
	for i := range validKey {
		validKey[i] = byte(i)
	}
	validPlaintext := []byte("sensitive-vault-data-for-aad-testing")
	validAAD := []byte(`{"tenant":"vault","operation":"encrypt","keyID":"test123"}`)

	t.Run("EncryptBytesWithAAD_RejectsInvalidKeySizes", func(t *testing.T) {
		invalidKeySizes := []struct {
			name    string
			keySize int
			desc    string
		}{
			{
				name:    "EmptyKey",
				keySize: 0,
				desc:    "Empty key must be rejected for security compliance",
			},
			{
				name:    "ShortKey",
				keySize: 16, // 128-bit instead of required 256-bit
				desc:    "Short key must be rejected - vault requires AES-256",
			},
			{
				name:    "LongKey",
				keySize: 48, // 384-bit exceeds AES-256 requirement
				desc:    "Oversized key must be rejected for specification compliance",
			},
			{
				name:    "SlightlyWrongKey",
				keySize: 31, // Almost correct but still invalid
				desc:    "Near-miss key size must be rejected for strict validation",
			},
		}

		for _, tc := range invalidKeySizes {
			t.Run(tc.name, func(t *testing.T) {
				invalidKey := make([]byte, tc.keySize)
				for i := range invalidKey {
					invalidKey[i] = byte(i + 42) // Non-zero pattern
				}

				// Attempt encryption with invalid key
				ciphertext, err := EncryptBytesWithAAD(validPlaintext, invalidKey, validAAD)

				// Validate error response
				assert.Error(t, err, "EncryptBytesWithAAD must reject invalid key size: %s", tc.desc)
				assert.Empty(t, ciphertext, "Ciphertext must be empty when encryption fails")
				assert.ErrorIs(t, err, ErrInvalidKeySize, "Error must indicate invalid key size")
				assert.Contains(t, err.Error(), "invalid key size",
					"Error message must clearly indicate key size issue")
			})
		}
	})

	t.Run("EncryptBytesWithAAD_HandlesVariousAADSizes", func(t *testing.T) {
		// Test various AAD sizes to ensure no buffer overflow vulnerabilities
		aadTestCases := []struct {
			name string
			aad  []byte
			desc string
		}{
			{
				name: "EmptyAAD",
				aad:  []byte{},
				desc: "Empty AAD should be valid - no additional authentication data",
			},
			{
				name: "SmallAAD",
				aad:  []byte(`{"key":"val"}`),
				desc: "Small JSON AAD should be handled correctly",
			},
			{
				name: "LargeAAD",
				aad:  make([]byte, 4096), // 4KB AAD
				desc: "Large AAD should not cause buffer issues",
			},
			{
				name: "VaultTypicalAAD",
				aad:  []byte(`{"tenant":"production","path":"/db/credentials","version":42,"rotation":"2025-01-01","keyID":"kek_vault_primary_123"}`),
				desc: "Typical vault metadata AAD should work correctly",
			},
		}

		// Initialize large AAD with pattern
		for i := range aadTestCases[2].aad {
			aadTestCases[2].aad[i] = byte(i % 256)
		}

		for _, tc := range aadTestCases {
			t.Run(tc.name, func(t *testing.T) {
				// Encryption should succeed with valid key regardless of AAD size
				ciphertext, err := EncryptBytesWithAAD(validPlaintext, validKey, tc.aad)
				require.NoError(t, err, "EncryptBytesWithAAD must handle AAD size: %s", tc.desc)
				require.NotEmpty(t, ciphertext, "Valid encryption must produce non-empty ciphertext")

				// Verify decryption with same AAD succeeds
				decrypted, err := DecryptBytesWithAAD(ciphertext, validKey, tc.aad)
				require.NoError(t, err, "Decryption must succeed with matching AAD")
				assert.Equal(t, validPlaintext, decrypted,
					"Decrypted plaintext must match original for AAD case: %s", tc.name)

				// Verify decryption with different AAD fails (authentication check)
				differentAAD := make([]byte, len(tc.aad)+1)
				copy(differentAAD, tc.aad)
				differentAAD[len(differentAAD)-1] = 0xFF // Modify AAD

				_, err = DecryptBytesWithAAD(ciphertext, validKey, differentAAD)
				assert.Error(t, err, "Decryption must fail with modified AAD for authentication integrity")
			})
		}
	})

	t.Run("EncryptBytesWithAAD_HandlesVariousPlaintextSizes", func(t *testing.T) {
		plaintextSizes := []struct {
			name string
			size int
			desc string
		}{
			{
				name: "EmptyPlaintext",
				size: 0,
				desc: "Empty plaintext encryption should succeed",
			},
			{
				name: "SingleByte",
				size: 1,
				desc: "Single byte plaintext should encrypt correctly",
			},
			{
				name: "VaultSecretSize",
				size: 256,
				desc: "Typical vault secret size should work efficiently",
			},
			{
				name: "LargeDocument",
				size: 32 * 1024, // 32KB
				desc: "Large document encryption should handle memory correctly",
			},
		}

		for _, tc := range plaintextSizes {
			t.Run(tc.name, func(t *testing.T) {
				testPlaintext := make([]byte, tc.size)
				for i := range testPlaintext {
					testPlaintext[i] = byte(i ^ 0x42) // Pattern for validation
				}

				// Test encryption
				ciphertext, err := EncryptBytesWithAAD(testPlaintext, validKey, validAAD)
				require.NoError(t, err, "Encryption must handle plaintext size: %s", tc.desc)

				// Validate ciphertext properties
				if tc.size > 0 {
					assert.NotEqual(t, string(testPlaintext), ciphertext,
						"Ciphertext must differ from plaintext")
				}

				// Verify round-trip decryption
				decrypted, err := DecryptBytesWithAAD(ciphertext, validKey, validAAD)
				require.NoError(t, err, "Decryption must succeed for size: %s", tc.desc)
				assert.Equal(t, testPlaintext, decrypted,
					"Round-trip must preserve plaintext for size: %s", tc.name)
			})
		}
	})
}

// TestDecryptBytesWithAAD_ErrorPaths validates all error conditions in AAD decryption
// These paths ensure vault security by correctly rejecting malformed or tampered ciphertexts
func TestDecryptBytesWithAAD_ErrorPaths(t *testing.T) {
	// Setup valid test data
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i + 128) // Different pattern from encrypt tests
	}
	validAAD := []byte(`{"vault":"production","type":"credential"}`)
	testPlaintext := []byte("vault-credential-for-decryption-testing")

	// Create valid ciphertext for comparison tests
	validCiphertext, err := EncryptBytesWithAAD(testPlaintext, validKey, validAAD)
	require.NoError(t, err, "Setup encryption must succeed")

	t.Run("DecryptBytesWithAAD_RejectsInvalidKeySizes", func(t *testing.T) {
		invalidKeySizes := []struct {
			name    string
			keySize int
		}{
			{"EmptyKey", 0},
			{"ShortKey", 24},
			{"LongKey", 40},
			{"AlmostCorrectKey", 31},
		}

		for _, tc := range invalidKeySizes {
			t.Run(tc.name, func(t *testing.T) {
				invalidKey := make([]byte, tc.keySize)
				for i := range invalidKey {
					invalidKey[i] = byte(i + 200)
				}

				// Attempt decryption with invalid key size
				plaintext, err := DecryptBytesWithAAD(validCiphertext, invalidKey, validAAD)

				assert.Error(t, err, "DecryptBytesWithAAD must reject invalid key size")
				assert.Nil(t, plaintext, "Plaintext must be nil when decryption fails")
				assert.ErrorIs(t, err, ErrInvalidKeySize, "Error must indicate key size issue")
			})
		}
	})

	t.Run("DecryptBytesWithAAD_RejectsInvalidBase64", func(t *testing.T) {
		invalidBase64Cases := []struct {
			name       string
			ciphertext string
			desc       string
		}{
			{
				name:       "InvalidCharacters",
				ciphertext: "This-is-not-base64@#$%",
				desc:       "Non-base64 characters must be rejected",
			},
			{
				name:       "IncompleteBase64",
				ciphertext: "YWJjZGVmZ2hpams", // Missing padding
				desc:       "Incomplete base64 must be rejected",
			},
			{
				name:       "EmptyString",
				ciphertext: "",
				desc:       "Empty ciphertext string causes short ciphertext error",
			},
			{
				name:       "InvalidPadding",
				ciphertext: "YWJjZA===", // Too much padding
				desc:       "Invalid base64 padding must be rejected",
			},
		}

		for _, tc := range invalidBase64Cases {
			t.Run(tc.name, func(t *testing.T) {
				plaintext, err := DecryptBytesWithAAD(tc.ciphertext, validKey, validAAD)

				assert.Error(t, err, "DecryptBytesWithAAD must reject invalid base64: %s", tc.desc)
				assert.Nil(t, plaintext, "Plaintext must be nil for invalid base64")
				if tc.name == "EmptyString" {
					// Empty string gets decoded as empty bytes, then fails as short ciphertext
					assert.ErrorIs(t, err, ErrCiphertextShort, "Empty string causes short ciphertext error")
				} else {
					assert.ErrorIs(t, err, ErrBase64Decode, "Error must indicate base64 decode failure")
				}
			})
		}
	})

	t.Run("DecryptBytesWithAAD_RejectsShortCiphertext", func(t *testing.T) {
		// Create ciphertext that's too short (less than GCM nonce size)
		shortCiphertextCases := []struct {
			name string
			data []byte
			desc string
		}{
			{
				name: "SingleByte",
				data: []byte{0x42},
				desc: "Single byte ciphertext must be rejected",
			},
			{
				name: "FewBytes",
				data: []byte{0x01, 0x02, 0x03, 0x04},
				desc: "Ciphertext shorter than nonce must be rejected",
			},
			{
				name: "AlmostNonceSize",
				data: make([]byte, 11), // GCM nonce is 12 bytes
				desc: "Ciphertext just under nonce size must be rejected",
			},
		}

		// Initialize test data
		for i := range shortCiphertextCases[2].data {
			shortCiphertextCases[2].data[i] = byte(i)
		}

		for _, tc := range shortCiphertextCases {
			t.Run(tc.name, func(t *testing.T) {
				shortCiphertext := base64.StdEncoding.EncodeToString(tc.data)

				plaintext, err := DecryptBytesWithAAD(shortCiphertext, validKey, validAAD)

				assert.Error(t, err, "DecryptBytesWithAAD must reject short ciphertext: %s", tc.desc)
				assert.Nil(t, plaintext, "Plaintext must be nil for short ciphertext")
				assert.ErrorIs(t, err, ErrCiphertextShort, "Error must indicate ciphertext too short")
			})
		}
	})

	t.Run("DecryptBytesWithAAD_RejectsTamperedCiphertext", func(t *testing.T) {
		// Decode valid ciphertext to tamper with it
		validCiphertextBytes, err := base64.StdEncoding.DecodeString(validCiphertext)
		require.NoError(t, err, "Valid ciphertext must decode for tampering test")

		tamperingCases := []struct {
			name   string
			modify func([]byte) []byte
			desc   string
		}{
			{
				name: "ModifyFirstByte",
				modify: func(data []byte) []byte {
					modified := make([]byte, len(data))
					copy(modified, data)
					modified[0] ^= 0xFF // Flip bits in first byte
					return modified
				},
				desc: "Tampering with nonce should cause authentication failure",
			},
			{
				name: "ModifyLastByte",
				modify: func(data []byte) []byte {
					modified := make([]byte, len(data))
					copy(modified, data)
					modified[len(modified)-1] ^= 0xFF // Flip bits in last byte (auth tag area)
					return modified
				},
				desc: "Tampering with authentication tag should cause failure",
			},
			{
				name: "ModifyMiddleByte",
				modify: func(data []byte) []byte {
					modified := make([]byte, len(data))
					copy(modified, data)
					if len(modified) > 20 {
						modified[20] ^= 0x01 // Flip one bit in ciphertext area
					}
					return modified
				},
				desc: "Tampering with ciphertext should cause authentication failure",
			},
		}

		for _, tc := range tamperingCases {
			t.Run(tc.name, func(t *testing.T) {
				tamperedBytes := tc.modify(validCiphertextBytes)
				tamperedCiphertext := base64.StdEncoding.EncodeToString(tamperedBytes)

				plaintext, err := DecryptBytesWithAAD(tamperedCiphertext, validKey, validAAD)

				assert.Error(t, err, "DecryptBytesWithAAD must reject tampered ciphertext: %s", tc.desc)
				assert.Nil(t, plaintext, "Plaintext must be nil for tampered ciphertext")
				// Note: GCM authentication failures typically result in cipher.AEAD errors
			})
		}
	})

	t.Run("DecryptBytesWithAAD_ValidatesAADAuthentication", func(t *testing.T) {
		// Test that AAD authentication is properly enforced
		originalAAD := []byte(`{"operation":"encrypt","keyID":"test123"}`)
		modifiedAADs := []struct {
			name string
			aad  []byte
			desc string
		}{
			{
				name: "DifferentAAD",
				aad:  []byte(`{"operation":"decrypt","keyID":"test123"}`),
				desc: "Different AAD must cause authentication failure",
			},
			{
				name: "EmptyAAD",
				aad:  []byte{},
				desc: "Empty AAD when original had data must fail authentication",
			},
			{
				name: "ExtraDataAAD",
				aad:  []byte(`{"operation":"encrypt","keyID":"test123","extra":"data"}`),
				desc: "AAD with extra data must fail authentication",
			},
		}

		// Create ciphertext with original AAD
		testData := []byte("aad-authentication-test-data")
		originalCiphertext, err := EncryptBytesWithAAD(testData, validKey, originalAAD)
		require.NoError(t, err, "Encryption with original AAD must succeed")

		// Verify decryption works with correct AAD
		decrypted, err := DecryptBytesWithAAD(originalCiphertext, validKey, originalAAD)
		require.NoError(t, err, "Decryption must succeed with correct AAD")
		assert.Equal(t, testData, decrypted, "Correct AAD must produce correct plaintext")

		// Test that modified AADs fail authentication
		for _, tc := range modifiedAADs {
			t.Run(tc.name, func(t *testing.T) {
				plaintext, err := DecryptBytesWithAAD(originalCiphertext, validKey, tc.aad)

				assert.Error(t, err, "DecryptBytesWithAAD must reject modified AAD: %s", tc.desc)
				assert.Nil(t, plaintext, "Plaintext must be nil when AAD authentication fails")
			})
		}
	})
}

// BenchmarkAADEncryptionDecryption measures performance of AAD operations for vault use
func BenchmarkAADEncryptionDecryption(t *testing.B) {
	// Setup benchmark data
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	plaintext := make([]byte, 1024) // 1KB typical vault secret size
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("Failed to generate random plaintext: %v", err)
	}

	aad := []byte(`{"tenant":"production","path":"/database/credentials","version":42,"keyID":"kek_primary_vault_001"}`)

	t.Run("EncryptBytesWithAAD_Performance", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ciphertext, err := EncryptBytesWithAAD(plaintext, key, aad)
			if err != nil || ciphertext == "" {
				b.Fatal("EncryptBytesWithAAD must succeed in benchmark")
			}
		}
	})

	// Pre-encrypt for decryption benchmark
	ciphertext, err := EncryptBytesWithAAD(plaintext, key, aad)
	require.NoError(t, err)

	t.Run("DecryptBytesWithAAD_Performance", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decrypted, err := DecryptBytesWithAAD(ciphertext, key, aad)
			if err != nil || len(decrypted) == 0 {
				b.Fatal("DecryptBytesWithAAD must succeed in benchmark")
			}
		}
	})
}
