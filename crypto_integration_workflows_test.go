// crypto_integration_workflows_test.go: Integration test cases for cryptographic utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"testing"

	"github.com/agilira/harpocrates"
)

// TestKeyDerivationEncryptionWorkflow tests key derivation + encryption workflow
func TestKeyDerivationEncryptionWorkflow(t *testing.T) {
	password := []byte("user-password-123")
	salt := []byte("unique-salt-for-user")
	plaintext := "sensitive-data-to-encrypt"

	// Step 1: Derive key from password
	derivedKey, err := crypto.DeriveKeyDefault(password, salt, crypto.KeySize)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	// Step 2: Encrypt data with derived key
	encrypted, err := crypto.Encrypt(plaintext, derivedKey)
	if err != nil {
		t.Fatalf("Failed to encrypt with derived key: %v", err)
	}

	// Step 3: Decrypt data with derived key
	decrypted, err := crypto.Decrypt(encrypted, derivedKey)
	if err != nil {
		t.Fatalf("Failed to decrypt with derived key: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("Workflow round-trip failed: expected %s, got %s", plaintext, decrypted)
	}

	// Step 4: Verify key fingerprint
	fingerprint := crypto.GetKeyFingerprint(derivedKey)
	if fingerprint == "" {
		t.Error("Expected non-empty fingerprint for derived key")
	}

	// Step 5: Test with wrong password
	wrongPassword := []byte("wrong-password")
	wrongKey, err := crypto.DeriveKeyDefault(wrongPassword, salt, crypto.KeySize)
	if err != nil {
		t.Fatalf("Failed to derive wrong key: %v", err)
	}

	_, err = crypto.Decrypt(encrypted, wrongKey)
	if err == nil {
		t.Error("Expected error when decrypting with wrong derived key")
	}
}

// TestKeyGenerationFingerprintingWorkflow tests key generation + fingerprinting workflow
func TestKeyGenerationFingerprintingWorkflow(t *testing.T) {
	// Step 1: Generate multiple keys
	const numKeys = 10
	keys := make([][]byte, numKeys)
	fingerprints := make([]string, numKeys)

	for i := 0; i < numKeys; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}
		keys[i] = key

		// Step 2: Generate fingerprint for each key
		fingerprint := crypto.GetKeyFingerprint(key)
		fingerprints[i] = fingerprint

		if fingerprint == "" {
			t.Errorf("Expected non-empty fingerprint for key %d", i)
		}
	}

	// Step 3: Verify all fingerprints are unique
	for i := 0; i < len(fingerprints); i++ {
		for j := i + 1; j < len(fingerprints); j++ {
			if fingerprints[i] == fingerprints[j] {
				t.Errorf("Duplicate fingerprints found at indices %d and %d: %s", i, j, fingerprints[i])
			}
		}
	}

	// Step 4: Test fingerprint consistency
	for i, key := range keys {
		fingerprint1 := crypto.GetKeyFingerprint(key)
		fingerprint2 := crypto.GetKeyFingerprint(key)
		if fingerprint1 != fingerprint2 {
			t.Errorf("Fingerprint inconsistency for key %d: %s vs %s", i, fingerprint1, fingerprint2)
		}
	}
}

// TestEncodingValidationWorkflow tests encoding + validation workflow
func TestEncodingValidationWorkflow(t *testing.T) {
	// Step 1: Generate key
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Step 2: Validate original key
	err = crypto.ValidateKey(key)
	if err != nil {
		t.Fatalf("Failed to validate original key: %v", err)
	}

	// Step 3: Encode to base64
	base64Key := crypto.KeyToBase64(key)
	if base64Key == "" {
		t.Fatal("Expected non-empty base64 encoding")
	}

	// Step 4: Decode from base64
	decodedKey, err := crypto.KeyFromBase64(base64Key)
	if err != nil {
		t.Fatalf("Failed to decode base64 key: %v", err)
	}

	// Step 5: Validate decoded key
	err = crypto.ValidateKey(decodedKey)
	if err != nil {
		t.Fatalf("Failed to validate decoded key: %v", err)
	}

	// Step 6: Verify round-trip
	if string(key) != string(decodedKey) {
		t.Fatal("Base64 round-trip failed")
	}

	// Step 7: Test hex encoding workflow
	hexKey := crypto.KeyToHex(key)
	if hexKey == "" {
		t.Fatal("Expected non-empty hex encoding")
	}

	decodedHexKey, err := crypto.KeyFromHex(hexKey)
	if err != nil {
		t.Fatalf("Failed to decode hex key: %v", err)
	}

	err = crypto.ValidateKey(decodedHexKey)
	if err != nil {
		t.Fatalf("Failed to validate hex decoded key: %v", err)
	}

	if string(key) != string(decodedHexKey) {
		t.Fatal("Hex round-trip failed")
	}
}

// TestErrorPropagationWorkflow tests error propagation across functions
func TestErrorPropagationWorkflow(t *testing.T) {
	// Test error propagation from invalid key to encryption
	invalidKey := []byte("too-short")
	_, err := crypto.Encrypt("test", invalidKey)
	if err == nil {
		t.Error("Expected error when encrypting with invalid key")
	}

	// Test error propagation from invalid key to decryption
	validKey := make([]byte, crypto.KeySize)
	for i := range validKey {
		validKey[i] = byte(i)
	}
	encrypted, err := crypto.Encrypt("test", validKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	_, err = crypto.Decrypt(encrypted, invalidKey)
	if err == nil {
		t.Error("Expected error when decrypting with invalid key")
	}

	// Test error propagation from invalid encoding to validation
	invalidBase64 := "not-valid-base64"
	_, err = crypto.KeyFromBase64(invalidBase64)
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	// Test error propagation from invalid hex to validation
	invalidHex := "not-valid-hex"
	_, err = crypto.KeyFromHex(invalidHex)
	if err == nil {
		t.Error("Expected error for invalid hex")
	}
}

// TestResourceManagementWorkflow tests resource management across operations
func TestResourceManagementWorkflow(t *testing.T) {
	// Step 1: Generate key
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Step 2: Encrypt data
	plaintext := "sensitive-data"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Step 3: Decrypt data
	decrypted, err := crypto.Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Fatal("Round-trip failed")
	}

	// Step 4: Generate fingerprint
	fingerprint := crypto.GetKeyFingerprint(key)
	if fingerprint == "" {
		t.Error("Expected non-empty fingerprint")
	}

	// Step 5: Encode key
	base64Key := crypto.KeyToBase64(key)
	if base64Key == "" {
		t.Fatal("Expected non-empty base64 encoding")
	}

	// Step 6: Zeroize key (resource cleanup)
	crypto.Zeroize(key)

	// Step 7: Verify key is zeroized
	for i, b := range key {
		if b != 0 {
			t.Errorf("Key not properly zeroized at position %d: got %d", i, b)
		}
	}

	// Step 8: Verify fingerprint still works (should be different for zeroized key)
	newFingerprint := crypto.GetKeyFingerprint(key)
	if newFingerprint == "" {
		t.Error("Expected non-empty fingerprint for zeroized key")
	}
	// Verify fingerprint is different (since key is now all zeros)
	if newFingerprint == fingerprint {
		t.Error("Expected different fingerprint for zeroized key")
	}
}

// TestBoundaryConditionsWorkflow tests boundary conditions across functions
func TestBoundaryConditionsWorkflow(t *testing.T) {
	// Test with minimum valid inputs
	minKey := make([]byte, crypto.KeySize)
	for i := range minKey {
		minKey[i] = 0
	}

	err := crypto.ValidateKey(minKey)
	if err != nil {
		t.Fatalf("Failed to validate minimum key: %v", err)
	}

	// Test empty plaintext encryption (now supported)
	emptyEncrypted, err := crypto.Encrypt("", minKey)
	if err != nil {
		t.Fatalf("Failed to encrypt empty plaintext: %v", err)
	}
	if emptyEncrypted == "" {
		t.Error("Expected non-empty ciphertext for empty plaintext")
	}

	// Verify empty plaintext round-trip
	emptyDecrypted, err := crypto.Decrypt(emptyEncrypted, minKey)
	if err != nil {
		t.Fatalf("Failed to decrypt empty plaintext: %v", err)
	}
	if emptyDecrypted != "" {
		t.Errorf("Expected empty string after decrypt, got: %q", emptyDecrypted)
	}

	// Test with single character plaintext
	encrypted, err := crypto.Encrypt("a", minKey)
	if err != nil {
		t.Fatalf("Failed to encrypt single character: %v", err)
	}

	decrypted, err := crypto.Decrypt(encrypted, minKey)
	if err != nil {
		t.Fatalf("Failed to decrypt single character: %v", err)
	}

	if decrypted != "a" {
		t.Fatalf("Single character round-trip failed: expected 'a', got '%s'", decrypted)
	}

	// Test fingerprint with minimum key
	fingerprint := crypto.GetKeyFingerprint(minKey)
	if fingerprint == "" {
		t.Error("Expected non-empty fingerprint for minimum key")
	}
}
