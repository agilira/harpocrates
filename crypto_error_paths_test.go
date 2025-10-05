// crypto_error_paths_test.go: Test cases for error paths in cryptographic utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"crypto/rand"
	"testing"

	"github.com/agilira/harpocrates"
)

// Using failingReader from crypto_edge_test.go

// TestEncryptNonceGenerationFailure tests encryption when nonce generation fails
func TestEncryptNonceGenerationFailure(t *testing.T) {
	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()
	rand.Reader = &failingReader{}

	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	_, err := crypto.Encrypt("test data", key)
	if err == nil {
		t.Error("Expected error when nonce generation fails")
	}
}

// TestDecryptInvalidBase64 tests decryption with invalid base64 input
func TestDecryptInvalidBase64(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	invalidBase64 := "not-valid-base64!!"
	_, err := crypto.Decrypt(invalidBase64, key)
	if err == nil {
		t.Error("Expected error for invalid base64 input")
	}
}

// TestDecryptCorruptedCiphertext tests decryption with corrupted ciphertext
func TestDecryptCorruptedCiphertext(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted data first
	plaintext := "test data"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Corrupt the ciphertext by flipping some bits
	corrupted := encrypted[:len(encrypted)-4] + "XXXX"
	_, err = crypto.Decrypt(corrupted, key)
	if err == nil {
		t.Error("Expected error for corrupted ciphertext")
	}
}

// TestDecryptTruncatedCiphertext tests decryption with truncated ciphertext
func TestDecryptTruncatedCiphertext(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted data first
	plaintext := "test data"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Truncate the ciphertext
	truncated := encrypted[:len(encrypted)/2]
	_, err = crypto.Decrypt(truncated, key)
	if err == nil {
		t.Error("Expected error for truncated ciphertext")
	}
}

// TestDecryptWrongKey tests decryption with wrong key
func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, crypto.KeySize)
	key2 := make([]byte, crypto.KeySize)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(255 - i)
	}

	plaintext := "test data"
	encrypted, err := crypto.Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	_, err = crypto.Decrypt(encrypted, key2)
	if err == nil {
		t.Error("Expected error when decrypting with wrong key")
	}
}

// TestDecryptEmptyCiphertext tests decryption with empty ciphertext
func TestDecryptEmptyCiphertext(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	_, err := crypto.Decrypt("", key)
	if err == nil {
		t.Error("Expected error for empty ciphertext")
	}
}

// TestDecryptCiphertextTooShort tests decryption with ciphertext shorter than nonce size
func TestDecryptCiphertextTooShort(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create a very short base64 string that would decode to less than nonce size
	shortBase64 := "AA==" // decodes to 1 byte, much less than GCM nonce size
	_, err := crypto.Decrypt(shortBase64, key)
	if err == nil {
		t.Error("Expected error for ciphertext too short")
	}
}

// TestDecryptGCMAuthenticationFailure tests GCM authentication failure scenarios
func TestDecryptGCMAuthenticationFailure(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Create valid encrypted data first
	plaintext := "test data"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Modify the ciphertext to cause GCM authentication failure
	// This simulates tampering with the encrypted data
	modified := encrypted[:len(encrypted)-8] + "XXXXXXXX"
	_, err = crypto.Decrypt(modified, key)
	if err == nil {
		t.Error("Expected GCM authentication failure for tampered ciphertext")
	}
}

// TestDecryptNonceExtractionEdgeCases tests edge cases in nonce extraction
func TestDecryptNonceExtractionEdgeCases(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Test with ciphertext exactly at nonce size boundary
	// This should trigger the "ciphertext too short" error
	exactNonceSize := "AAAAAAAAAAAAAAAAAAAAAA==" // 16 bytes base64, exactly GCM nonce size
	_, err := crypto.Decrypt(exactNonceSize, key)
	if err == nil {
		t.Error("Expected error for ciphertext with only nonce")
	}
}

// TestEncryptEmptyPlaintext tests encryption with empty plaintext
func TestEncryptEmptyPlaintext(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Empty plaintext should now be supported
	ciphertext, err := crypto.Encrypt("", key)
	if err != nil {
		t.Errorf("Unexpected error for empty plaintext: %v", err)
	}
	if ciphertext == "" {
		t.Error("Expected non-empty ciphertext for empty plaintext")
	}

	// Verify we can decrypt it back
	decrypted, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		t.Errorf("Failed to decrypt empty plaintext: %v", err)
	}
	if decrypted != "" {
		t.Errorf("Expected empty string after decrypt, got: %q", decrypted)
	}
}

// TestEncryptNilKey tests encryption with nil key
func TestEncryptNilKey(t *testing.T) {
	_, err := crypto.Encrypt("test data", nil)
	if err == nil {
		t.Error("Expected error for nil key")
	}
}

// TestDecryptNilKey tests decryption with nil key
func TestDecryptNilKey(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := "test data"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	_, err = crypto.Decrypt(encrypted, nil)
	if err == nil {
		t.Error("Expected error for nil key")
	}
}
