// crypto_integration_test.go: Integration test cases for cryptographic utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"testing"

	"github.com/agilira/harpocrates"
)

func TestEncryptDecrypt_Integration(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	testCases := []string{
		"password123",
		"super-secret-api-key-2024",
		"database-connection-string",
		"jwt-secret-key-for-authentication",
		"aws-access-key-id:AKIAIOSFODNN7EXAMPLE",
		"ssh-private-key-content",
		"credit-card-number:4111-1111-1111-1111",
		"social-security-number:123-45-6789",
		"medical-record-id:MR-2024-001",
		"legal-document-hash:sha256-abc123def456",
	}
	for i, plaintext := range testCases {
		t.Run(plaintext, func(t *testing.T) {
			encrypted, err := crypto.Encrypt(plaintext, key)
			if err != nil {
				t.Errorf("Failed to encrypt test case %d: %v", i, err)
				return
			}
			decrypted, err := crypto.Decrypt(encrypted, key)
			if err != nil {
				t.Errorf("Failed to decrypt test case %d: %v", i, err)
				return
			}
			if decrypted != plaintext {
				t.Errorf("Roundtrip mismatch for test case %d: expected %s, got %s", i, plaintext, decrypted)
			}
		})
	}
}

func TestKeyRotation_Integration(t *testing.T) {
	oldKey := make([]byte, crypto.KeySize)
	for i := range oldKey {
		oldKey[i] = byte(i)
	}
	newKey := make([]byte, crypto.KeySize)
	for i := range newKey {
		newKey[i] = byte(255 - i)
	}
	plaintext := "sensitive-data-that-needs-migration"
	encrypted, err := crypto.Encrypt(plaintext, oldKey)
	if err != nil {
		t.Fatalf("Failed to encrypt with old key: %v", err)
	}
	decrypted, err := crypto.Decrypt(encrypted, oldKey)
	if err != nil {
		t.Fatalf("Failed to decrypt with old key: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("Decryption with old key failed: expected %s, got %s", plaintext, decrypted)
	}
	_, err = crypto.Decrypt(encrypted, newKey)
	if err == nil {
		t.Error("Expected error when decrypting with wrong key")
	}
	reEncrypted, err := crypto.Encrypt(plaintext, newKey)
	if err != nil {
		t.Fatalf("Failed to re-encrypt with new key: %v", err)
	}
	reDecrypted, err := crypto.Decrypt(reEncrypted, newKey)
	if err != nil {
		t.Fatalf("Failed to decrypt with new key: %v", err)
	}
	if reDecrypted != plaintext {
		t.Fatalf("Decryption with new key failed: expected %s, got %s", plaintext, reDecrypted)
	}
}

func TestMultipleKeys_Integration(t *testing.T) {
	keys := make([][]byte, 5)
	for i := range keys {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}
		keys[i] = key
	}
	plaintext := "data-encrypted-with-multiple-keys"
	encryptedData := make([]string, len(keys))
	for i, key := range keys {
		encrypted, err := crypto.Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Failed to encrypt with key %d: %v", i, err)
		}
		encryptedData[i] = encrypted
	}
	for i, key := range keys {
		decrypted, err := crypto.Decrypt(encryptedData[i], key)
		if err != nil {
			t.Fatalf("Failed to decrypt with key %d: %v", i, err)
		}
		if decrypted != plaintext {
			t.Fatalf("Decryption mismatch with key %d: expected %s, got %s", i, plaintext, decrypted)
		}
	}
	for i, key := range keys {
		for j, encrypted := range encryptedData {
			if i != j {
				_, err := crypto.Decrypt(encrypted, key)
				if err == nil {
					t.Errorf("Expected error when decrypting data %d with key %d", j, i)
				}
			}
		}
	}
}

func TestLargeData_Integration(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	largeData := ""
	for i := 0; i < 5000; i++ {
		largeData += "This is a large piece of data that needs to be encrypted securely. "
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

func TestFingerprintConsistency_Integration(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	fingerprints := make([]string, 10)
	for i := range fingerprints {
		fingerprints[i] = crypto.GetKeyFingerprint(key)
	}
	firstFingerprint := fingerprints[0]
	for i, fp := range fingerprints {
		if fp != firstFingerprint {
			t.Errorf("Fingerprint inconsistency at index %d: expected %s, got %s", i, firstFingerprint, fp)
		}
	}
	key2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}
	fingerprint2 := crypto.GetKeyFingerprint(key2)
	if fingerprint2 == firstFingerprint {
		t.Error("Different keys should have different fingerprints")
	}
}
