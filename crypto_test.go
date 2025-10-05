// crypto_test.go: Test cases for cryptographic utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/agilira/harpocrates"
)

func TestEncrypt_Unit(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := "test-secret-value"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if encrypted == "" {
		t.Error("Expected non-empty encrypted value")
	}
	if encrypted == plaintext {
		t.Error("Expected encrypted value to be different from original")
	}

	// Test empty plaintext encryption (now supported)
	emptyEncrypted, err := crypto.Encrypt("", key)
	if err != nil {
		t.Errorf("Unexpected error for empty plaintext: %v", err)
	}
	if emptyEncrypted == "" {
		t.Error("Expected non-empty ciphertext for empty plaintext")
	}

	// Verify empty plaintext round-trip
	emptyDecrypted, err := crypto.Decrypt(emptyEncrypted, key)
	if err != nil {
		t.Errorf("Failed to decrypt empty plaintext: %v", err)
	}
	if emptyDecrypted != "" {
		t.Errorf("Expected empty string after decrypt, got: %q", emptyDecrypted)
	}
	_, err = crypto.Encrypt(plaintext, nil)
	if err == nil {
		t.Error("Expected error for nil key")
	}
	_, err = crypto.Encrypt(plaintext, []byte{})
	if err == nil {
		t.Error("Expected error for empty key")
	}
	shortKey := make([]byte, 16)
	_, err = crypto.Encrypt(plaintext, shortKey)
	if err == nil {
		t.Error("Expected error for short key")
	}
	longKey := make([]byte, 64)
	_, err = crypto.Encrypt(plaintext, longKey)
	if err == nil {
		t.Error("Expected error for long key")
	}
}

func TestDecrypt_Unit(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := "test-secret-value"
	encrypted, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	decrypted, err := crypto.Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Expected decrypted value %s, got %s", plaintext, decrypted)
	}
	_, err = crypto.Decrypt("", key)
	if err == nil {
		t.Error("Expected error for empty encrypted text")
	}
	_, err = crypto.Decrypt(encrypted, nil)
	if err == nil {
		t.Error("Expected error for nil key")
	}
	_, err = crypto.Decrypt(encrypted, []byte{})
	if err == nil {
		t.Error("Expected error for empty key")
	}
	shortKey := make([]byte, 16)
	_, err = crypto.Decrypt(encrypted, shortKey)
	if err == nil {
		t.Error("Expected error for short key")
	}
	longKey := make([]byte, 64)
	_, err = crypto.Decrypt(encrypted, longKey)
	if err == nil {
		t.Error("Expected error for long key")
	}
	wrongKey := make([]byte, crypto.KeySize)
	for i := range wrongKey {
		wrongKey[i] = byte(255 - i)
	}
	_, err = crypto.Decrypt(encrypted, wrongKey)
	if err == nil {
		t.Error("Expected error when decrypting with wrong key")
	}
}

func TestGenerateKey_Unit(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	if len(key) != crypto.KeySize {
		t.Errorf("Expected key length %d, got %d", crypto.KeySize, len(key))
	}
	key2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}
	if len(key2) != crypto.KeySize {
		t.Errorf("Expected second key length %d, got %d", crypto.KeySize, len(key2))
	}
	if bytes.Equal(key, key2) {
		t.Error("Generated keys should be different")
	}
}

func TestGenerateNonce_Unit(t *testing.T) {
	nonceSize := 12
	nonce, err := crypto.GenerateNonce(nonceSize)
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}
	if len(nonce) != nonceSize {
		t.Errorf("Expected nonce length %d, got %d", nonceSize, len(nonce))
	}
	_, err = crypto.GenerateNonce(-1)
	if err == nil {
		t.Error("Expected error for negative nonce size")
	}
	_, err = crypto.GenerateNonce(0)
	if err == nil {
		t.Error("Expected error for zero nonce size")
	}
	nonce2, err := crypto.GenerateNonce(nonceSize)
	if err != nil {
		t.Fatalf("Failed to generate second nonce: %v", err)
	}
	if len(nonce2) != nonceSize {
		t.Errorf("Expected second nonce length %d, got %d", nonceSize, len(nonce2))
	}
	if bytes.Equal(nonce, nonce2) {
		t.Error("Generated nonces should be different")
	}
}

func TestValidateKey_Unit(t *testing.T) {
	validKey := make([]byte, crypto.KeySize)
	err := crypto.ValidateKey(validKey)
	if err != nil {
		t.Errorf("Expected no error for valid key size, got %v", err)
	}
	invalidSizes := []int{16, 24, 48, 64}
	for _, size := range invalidSizes {
		invalidKey := make([]byte, size)
		err := crypto.ValidateKey(invalidKey)
		if err == nil {
			t.Errorf("Expected error for key size %d", size)
		}
	}
	err = crypto.ValidateKey(nil)
	if err == nil {
		t.Error("Expected error for nil key")
	}
	err = crypto.ValidateKey([]byte{})
	if err == nil {
		t.Error("Expected error for empty key")
	}
}

func TestGetKeyFingerprint_Unit(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	fingerprint := crypto.GetKeyFingerprint(key)
	if fingerprint == "" {
		t.Error("Expected non-empty fingerprint")
	}
	key2 := make([]byte, crypto.KeySize)
	for i := range key2 {
		key2[i] = byte(255 - i)
	}
	fingerprint2 := crypto.GetKeyFingerprint(key2)
	if fingerprint2 == "" {
		t.Error("Expected non-empty fingerprint for second key")
	}
	if fingerprint == fingerprint2 {
		t.Error("Expected different fingerprints for different keys")
	}
	fingerprint3 := crypto.GetKeyFingerprint([]byte{})
	if fingerprint3 != "" {
		t.Error("Expected empty fingerprint for empty key")
	}
	fingerprint4 := crypto.GetKeyFingerprint(nil)
	if fingerprint4 != "" {
		t.Error("Expected empty fingerprint for nil key")
	}
}
