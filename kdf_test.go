// kdf_test.go: Test cases for key derivation utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/agilira/harpocrates"
)

// TestDeriveKey_Valid tests the new Argon2-based DeriveKey function
func TestDeriveKey_Valid(t *testing.T) {
	pw := []byte("my-secure-password")
	salt := []byte("random-salt-123")

	key, err := crypto.DeriveKey(pw, salt, 32, nil)
	if err != nil {
		t.Fatalf("DeriveKey() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Test that key is not all zeros
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Generated key should not be all zeros")
	}
}

// TestDeriveKey_InvalidParams tests DeriveKey with invalid parameters
func TestDeriveKey_InvalidParams(t *testing.T) {
	_, err := crypto.DeriveKey(nil, []byte("salt"), 32, nil)
	if err == nil {
		t.Error("Expected error for nil password")
	}

	_, err = crypto.DeriveKey([]byte("pw"), nil, 32, nil)
	if err == nil {
		t.Error("Expected error for nil salt")
	}

	_, err = crypto.DeriveKey([]byte("pw"), []byte("salt"), 0, nil)
	if err == nil {
		t.Error("Expected error for zero key length")
	}

	_, err = crypto.DeriveKey([]byte("pw"), []byte("salt"), -1, nil)
	if err == nil {
		t.Error("Expected error for negative key length")
	}
}

// TestDeriveKey_DifferentSalts tests that different salts produce different keys
func TestDeriveKey_DifferentSalts(t *testing.T) {
	pw := []byte("my-password")
	salt1 := []byte("salt-1")
	salt2 := []byte("salt-2")

	key1, _ := crypto.DeriveKey(pw, salt1, 32, nil)
	key2, _ := crypto.DeriveKey(pw, salt2, 32, nil)

	if bytes.Equal(key1, key2) {
		t.Error("Keys should be different for different salts")
	}
}

// TestDeriveKey_Consistency tests that same parameters produce same key
func TestDeriveKey_Consistency(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")
	keyLen := 32

	key1, err := crypto.DeriveKey(pw, salt, keyLen, nil)
	if err != nil {
		t.Fatalf("First DeriveKey() error: %v", err)
	}

	key2, err := crypto.DeriveKey(pw, salt, keyLen, nil)
	if err != nil {
		t.Fatalf("Second DeriveKey() error: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("Same parameters should produce same key")
	}
}

// TestDeriveKeyDefault tests the convenience function for default parameters
func TestDeriveKeyDefault(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")

	key, err := crypto.DeriveKeyDefault(pw, salt, 32)
	if err != nil {
		t.Fatalf("DeriveKeyDefault() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}
}

// TestDeriveKeyWithParams tests the custom parameters function
func TestDeriveKeyWithParams(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")

	key, err := crypto.DeriveKeyWithParams(pw, salt, 1, 16, 1, 32)
	if err != nil {
		t.Fatalf("DeriveKeyWithParams() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}
}

// TestDeriveKeyWithParams_InvalidParams tests DeriveKeyWithParams with invalid parameters
func TestDeriveKeyWithParams_InvalidParams(t *testing.T) {
	pw := []byte("password")
	salt := []byte("salt")

	testCases := []struct {
		name                          string
		time, memory, threads, keyLen int
	}{
		{"zero time", 0, 16, 1, 32},
		{"negative time", -1, 16, 1, 32},
		{"zero memory", 1, 0, 1, 32},
		{"negative memory", 1, -1, 1, 32},
		{"zero threads", 1, 16, 0, 32},
		{"negative threads", 1, 16, -1, 32},
		{"zero key length", 1, 16, 1, 0},
		{"negative key length", 1, 16, 1, -1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.DeriveKeyWithParams(pw, salt, tc.time, tc.memory, tc.threads, tc.keyLen)
			if err == nil {
				t.Error("Expected error for invalid parameters")
			}
		})
	}
}

// TestDeriveKeyPBKDF2_Valid tests PBKDF2 key derivation (backward compatibility)
func TestDeriveKeyPBKDF2_Valid(t *testing.T) {
	pw := []byte("my-secure-password")
	salt := []byte("random-salt-123")

	key, err := crypto.DeriveKeyPBKDF2(pw, salt, 100_000, 32)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}
}

// TestDeriveKeyPBKDF2_InvalidParams tests PBKDF2 with invalid parameters
func TestDeriveKeyPBKDF2_InvalidParams(t *testing.T) {
	_, err := crypto.DeriveKeyPBKDF2(nil, []byte("salt"), 100_000, 32)
	if err == nil {
		t.Error("Expected error for nil password")
	}

	_, err = crypto.DeriveKeyPBKDF2([]byte("pw"), nil, 100_000, 32)
	if err == nil {
		t.Error("Expected error for nil salt")
	}

	_, err = crypto.DeriveKeyPBKDF2([]byte("pw"), []byte("salt"), 0, 32)
	if err == nil {
		t.Error("Expected error for zero iterations")
	}

	_, err = crypto.DeriveKeyPBKDF2([]byte("pw"), []byte("salt"), 100_000, 0)
	if err == nil {
		t.Error("Expected error for zero key length")
	}
}

// TestDeriveKeyPBKDF2_DifferentSalts tests that different salts produce different keys with PBKDF2
func TestDeriveKeyPBKDF2_DifferentSalts(t *testing.T) {
	pw := []byte("my-password")
	salt1 := []byte("salt-1")
	salt2 := []byte("salt-2")

	key1, _ := crypto.DeriveKeyPBKDF2(pw, salt1, 100_000, 32)
	key2, _ := crypto.DeriveKeyPBKDF2(pw, salt2, 100_000, 32)

	if bytes.Equal(key1, key2) {
		t.Error("Keys should be different for different salts")
	}
}

// TestDeriveKeyPBKDF2_VariousIterationCounts tests PBKDF2 with different iteration counts
func TestDeriveKeyPBKDF2_VariousIterationCounts(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")
	iterationsList := []int{1, 100, 1000, 10000, 100000}

	for _, iterations := range iterationsList {
		t.Run(fmt.Sprintf("iterations_%d", iterations), func(t *testing.T) {
			key, err := crypto.DeriveKeyPBKDF2(pw, salt, iterations, 32)
			if err != nil {
				t.Fatalf("DeriveKeyPBKDF2() error: %v", err)
			}

			if len(key) != 32 {
				t.Errorf("Expected key length 32, got %d", len(key))
			}
		})
	}
}

// TestDeriveKeyPBKDF2_VariousKeyLengths tests PBKDF2 with different key lengths
func TestDeriveKeyPBKDF2_VariousKeyLengths(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")
	keyLengths := []int{16, 24, 32, 48, 64}

	for _, keyLen := range keyLengths {
		t.Run(fmt.Sprintf("keylen_%d", keyLen), func(t *testing.T) {
			key, err := crypto.DeriveKeyPBKDF2(pw, salt, 1000, keyLen)
			if err != nil {
				t.Fatalf("DeriveKeyPBKDF2() error: %v", err)
			}

			if len(key) != keyLen {
				t.Errorf("Expected key length %d, got %d", keyLen, len(key))
			}
		})
	}
}

// TestDeriveKeyPBKDF2_NegativeParameters tests PBKDF2 with negative parameters
func TestDeriveKeyPBKDF2_NegativeParameters(t *testing.T) {
	pw := []byte("password")
	salt := []byte("salt")

	_, err := crypto.DeriveKeyPBKDF2(pw, salt, -1, 32)
	if err == nil {
		t.Error("Expected error for negative iterations")
	}

	_, err = crypto.DeriveKeyPBKDF2(pw, salt, 1000, -1)
	if err == nil {
		t.Error("Expected error for negative key length")
	}
}

// TestDeriveKeyPBKDF2_VeryLargeParameters tests PBKDF2 with very large parameters
func TestDeriveKeyPBKDF2_VeryLargeParameters(t *testing.T) {
	pw := []byte("password")
	salt := []byte("salt")

	// Test with very large iteration count
	key, err := crypto.DeriveKeyPBKDF2(pw, salt, 1000000, 32)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Test with very large key length
	key, err = crypto.DeriveKeyPBKDF2(pw, salt, 1000, 1024)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2() error: %v", err)
	}

	if len(key) != 1024 {
		t.Errorf("Expected key length 1024, got %d", len(key))
	}
}

// TestDeriveKeyPBKDF2_Consistency tests that same parameters produce same key with PBKDF2
func TestDeriveKeyPBKDF2_Consistency(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")
	iterations := 1000
	keyLen := 32

	key1, err := crypto.DeriveKeyPBKDF2(pw, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("First DeriveKeyPBKDF2() error: %v", err)
	}

	key2, err := crypto.DeriveKeyPBKDF2(pw, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("Second DeriveKeyPBKDF2() error: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("Same parameters should produce same key")
	}
}

// TestDeriveKeyWithCustomParams tests DeriveKey with custom parameters
func TestDeriveKeyWithCustomParams(t *testing.T) {
	password := []byte("test-password")
	salt := []byte("test-salt")

	// Test with custom parameters
	params := &crypto.KDFParams{
		Time:    2,
		Memory:  64,
		Threads: 2,
	}

	key, err := crypto.DeriveKey(password, salt, 32, params)
	if err != nil {
		t.Fatalf("DeriveKey() error: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Test with partial custom parameters (some fields zero)
	paramsPartial := &crypto.KDFParams{
		Time:    3,
		Memory:  0, // Will use default
		Threads: 0, // Will use default
	}

	key2, err := crypto.DeriveKey(password, salt, 32, paramsPartial)
	if err != nil {
		t.Fatalf("DeriveKey() with partial params error: %v", err)
	}
	if len(key2) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key2))
	}

	// Keys should be different due to different parameters
	if bytes.Equal(key, key2) {
		t.Error("Expected different keys for different parameters")
	}
}

// TestDeriveKeyHKDF_Valid tests basic HKDF functionality
func TestDeriveKeyHKDF_Valid(t *testing.T) {
	masterKey := []byte("this-is-a-test-master-key-32-byte") // 32 bytes
	salt := []byte("test-salt")
	info := []byte("nemesis-dek-v1")

	key, err := crypto.DeriveKeyHKDF(masterKey, salt, info, 32)
	if err != nil {
		t.Fatalf("DeriveKeyHKDF failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Test deterministic: same inputs = same output
	key2, err := crypto.DeriveKeyHKDF(masterKey, salt, info, 32)
	if err != nil {
		t.Fatalf("DeriveKeyHKDF failed on second call: %v", err)
	}

	if !bytes.Equal(key, key2) {
		t.Error("HKDF should be deterministic")
	}
}

// TestDeriveKeyHKDF_DifferentOutputs tests that different inputs produce different outputs
func TestDeriveKeyHKDF_DifferentOutputs(t *testing.T) {
	masterKey := []byte("this-is-a-test-master-key-32-byte")

	// Same master key, different info should produce different keys
	key1, _ := crypto.DeriveKeyHKDF(masterKey, nil, []byte("context-1"), 32)
	key2, _ := crypto.DeriveKeyHKDF(masterKey, nil, []byte("context-2"), 32)

	if bytes.Equal(key1, key2) {
		t.Error("Different info should produce different keys")
	}

	// Same master key, different salt should produce different keys
	key3, _ := crypto.DeriveKeyHKDF(masterKey, []byte("salt-1"), nil, 32)
	key4, _ := crypto.DeriveKeyHKDF(masterKey, []byte("salt-2"), nil, 32)

	if bytes.Equal(key3, key4) {
		t.Error("Different salt should produce different keys")
	}
}

// TestDeriveKeyHKDF_InvalidParams tests error handling
func TestDeriveKeyHKDF_InvalidParams(t *testing.T) {
	validKey := []byte("valid-master-key-32-bytes-long!!!")

	tests := []struct {
		name      string
		masterKey []byte
		keyLen    int
		wantError string
	}{
		{
			name:      "empty master key",
			masterKey: []byte{},
			keyLen:    32,
			wantError: "INVALID_MASTER_KEY",
		},
		{
			name:      "nil master key",
			masterKey: nil,
			keyLen:    32,
			wantError: "INVALID_MASTER_KEY",
		},
		{
			name:      "zero key length",
			masterKey: validKey,
			keyLen:    0,
			wantError: "INVALID_KEYLEN",
		},
		{
			name:      "negative key length",
			masterKey: validKey,
			keyLen:    -1,
			wantError: "INVALID_KEYLEN",
		},
		{
			name:      "key length too large",
			masterKey: validKey,
			keyLen:    255*32 + 1,
			wantError: "INVALID_KEYLEN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.DeriveKeyHKDF(tt.masterKey, nil, nil, tt.keyLen)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			// Check that error contains the expected code
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("Expected error containing %q, got %q", tt.wantError, err.Error())
			}
		})
	}
}

// TestDeriveKeyHKDFDefault tests the default wrapper function
func TestDeriveKeyHKDFDefault(t *testing.T) {
	masterKey := []byte("test-master-key-for-default-func")

	key, err := crypto.DeriveKeyHKDFDefault(masterKey, 32)
	if err != nil {
		t.Fatalf("DeriveKeyHKDFDefault failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Should be equivalent to calling DeriveKeyHKDF with nil salt and info
	key2, err := crypto.DeriveKeyHKDF(masterKey, nil, nil, 32)
	if err != nil {
		t.Fatalf("DeriveKeyHKDF failed: %v", err)
	}

	if !bytes.Equal(key, key2) {
		t.Error("DeriveKeyHKDFDefault should match DeriveKeyHKDF with nil salt/info")
	}
}

// TestDeriveKeyHKDF_VariousLengths tests different output key lengths
func TestDeriveKeyHKDF_VariousLengths(t *testing.T) {
	masterKey := []byte("test-master-key-for-length-tests")

	lengths := []int{16, 24, 32, 48, 64, 128}

	for _, length := range lengths {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			key, err := crypto.DeriveKeyHKDF(masterKey, nil, nil, length)
			if err != nil {
				t.Fatalf("Failed to derive key of length %d: %v", length, err)
			}

			if len(key) != length {
				t.Errorf("Expected length %d, got %d", length, len(key))
			}
		})
	}
}

// TestDeriveKeyHKDF_NEMESISEnvelopePattern tests NEMESIS-specific usage pattern
func TestDeriveKeyHKDF_NEMESISEnvelopePattern(t *testing.T) {
	// Simulate NEMESIS envelope encryption: KEK → multiple DEKs
	kek := []byte("nemesis-master-key-32-bytes-long")

	// Derive DEK for different tenants/contexts
	dek1, err := crypto.DeriveKeyHKDF(kek, nil, []byte("tenant-1-dek"), 32)
	if err != nil {
		t.Fatalf("Failed to derive DEK for tenant-1: %v", err)
	}

	dek2, err := crypto.DeriveKeyHKDF(kek, nil, []byte("tenant-2-dek"), 32)
	if err != nil {
		t.Fatalf("Failed to derive DEK for tenant-2: %v", err)
	}

	auditKey, err := crypto.DeriveKeyHKDF(kek, nil, []byte("audit-key"), 32)
	if err != nil {
		t.Fatalf("Failed to derive audit key: %v", err)
	}

	// All keys should be different
	if bytes.Equal(dek1, dek2) {
		t.Error("DEK1 and DEK2 should be different")
	}
	if bytes.Equal(dek1, auditKey) {
		t.Error("DEK1 and audit key should be different")
	}
	if bytes.Equal(dek2, auditKey) {
		t.Error("DEK2 and audit key should be different")
	}

	// Keys should be repeatable
	dek1Repeat, _ := crypto.DeriveKeyHKDF(kek, nil, []byte("tenant-1-dek"), 32)
	if !bytes.Equal(dek1, dek1Repeat) {
		t.Error("HKDF should be deterministic")
	}
}

// TestDeriveKeyHKDF_EdgeCases tests edge cases and boundary conditions
func TestDeriveKeyHKDF_EdgeCases(t *testing.T) {
	masterKey := []byte("edge-case-master-key-for-testing")

	// Empty salt and info (both nil)
	key1, err := crypto.DeriveKeyHKDF(masterKey, nil, nil, 32)
	if err != nil {
		t.Fatalf("Failed with nil salt and info: %v", err)
	}

	// Empty salt and info (both empty slices)
	key2, err := crypto.DeriveKeyHKDF(masterKey, []byte{}, []byte{}, 32)
	if err != nil {
		t.Fatalf("Failed with empty salt and info: %v", err)
	}

	// Both should work, and nil salt is converted to zero salt internally
	// So they should actually be equal
	if !bytes.Equal(key1, key2) {
		t.Error("nil salt/info should equal empty salt/info after normalization")
	}

	// Very small key length
	smallKey, err := crypto.DeriveKeyHKDF(masterKey, nil, nil, 1)
	if err != nil {
		t.Fatalf("Failed with 1-byte key: %v", err)
	}
	if len(smallKey) != 1 {
		t.Errorf("Expected 1-byte key, got %d bytes", len(smallKey))
	}

	// Maximum safe key length
	maxKey, err := crypto.DeriveKeyHKDF(masterKey, nil, nil, 255*32)
	if err != nil {
		t.Fatalf("Failed with maximum key length: %v", err)
	}
	if len(maxKey) != 255*32 {
		t.Errorf("Expected %d-byte key, got %d bytes", 255*32, len(maxKey))
	}
}
