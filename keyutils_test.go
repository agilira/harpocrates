// keyutils_test.go: Test cases for key utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"fmt"
	"testing"

	"crypto/rand"

	"github.com/agilira/harpocrates"
)

func TestGenerateKey_ValidLength(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	defer crypto.Zeroize(key) // Zero-out sensitive test data
	if len(key) != crypto.KeySize {
		t.Errorf("Expected key length %d, got %d", crypto.KeySize, len(key))
	}
}

func TestGenerateNonce_ValidAndInvalid(t *testing.T) {
	nonce, err := crypto.GenerateNonce(12)
	if err != nil {
		t.Fatalf("GenerateNonce() error: %v", err)
	}
	if len(nonce) != 12 {
		t.Errorf("Expected nonce length 12, got %d", len(nonce))
	}
	_, err = crypto.GenerateNonce(0)
	if err == nil {
		t.Error("Expected error for zero nonce size")
	}
	_, err = crypto.GenerateNonce(-5)
	if err == nil {
		t.Error("Expected error for negative nonce size")
	}
}

func TestValidateKey(t *testing.T) {
	validKey := make([]byte, crypto.KeySize)
	if err := crypto.ValidateKey(validKey); err != nil {
		t.Errorf("Expected valid key, got error: %v", err)
	}
	invalidKey := make([]byte, 10)
	if err := crypto.ValidateKey(invalidKey); err == nil {
		t.Error("Expected error for invalid key size")
	}
}

func TestKeyBase64RoundTrip(t *testing.T) {
	key, _ := crypto.GenerateKey()
	defer crypto.Zeroize(key) // Zero-out sensitive test data
	b64 := crypto.KeyToBase64(key)
	restored, err := crypto.KeyFromBase64(b64)
	if err != nil {
		t.Fatalf("KeyFromBase64() error: %v", err)
	}
	defer crypto.Zeroize(restored) // Zero-out restored key
	if string(key) != string(restored) {
		t.Errorf("Base64 round-trip failed: expected %x, got %x", key, restored)
	}
	_, err = crypto.KeyFromBase64("not-base64!!")
	if err == nil {
		t.Error("Expected error for invalid base64 input")
	}
}

func TestKeyHexRoundTrip(t *testing.T) {
	key, _ := crypto.GenerateKey()
	hexStr := crypto.KeyToHex(key)
	restored, err := crypto.KeyFromHex(hexStr)
	if err != nil {
		t.Fatalf("KeyFromHex() error: %v", err)
	}
	if string(key) != string(restored) {
		t.Errorf("Hex round-trip failed: expected %x, got %x", key, restored)
	}
	_, err = crypto.KeyFromHex("nothex!!")
	if err == nil {
		t.Error("Expected error for invalid hex input")
	}
}

func TestZeroize(t *testing.T) {
	key := []byte("sensitive-data")
	crypto.Zeroize(key)
	for _, b := range key {
		if b != 0 {
			t.Error("Zeroize failed: found non-zero byte")
		}
	}
}

func TestGetKeyFingerprint(t *testing.T) {
	key1 := []byte("key-one-123456789012345678901234")
	key2 := []byte("key-two-123456789012345678901234")
	fp1 := crypto.GetKeyFingerprint(key1)
	fp2 := crypto.GetKeyFingerprint(key2)
	if fp1 == fp2 {
		t.Error("Expected different fingerprints for different keys")
	}
	if crypto.GetKeyFingerprint(nil) != "" {
		t.Error("Expected empty fingerprint for nil key")
	}
	if crypto.GetKeyFingerprint([]byte{}) != "" {
		t.Error("Expected empty fingerprint for empty key")
	}
}

// TestKeyBase64EdgeCases tests base64 encoding/decoding with edge cases
func TestKeyBase64EdgeCases(t *testing.T) {
	// Test with zero-length key
	emptyKey := []byte{}
	b64 := crypto.KeyToBase64(emptyKey)
	if b64 != "" {
		t.Errorf("Expected empty base64 for empty key, got %s", b64)
	}

	restored, err := crypto.KeyFromBase64(b64)
	if err != nil {
		t.Errorf("Expected no error for empty base64, got %v", err)
	}
	if len(restored) != 0 {
		t.Errorf("Expected empty key from empty base64, got length %d", len(restored))
	}

	// Test with special characters in key
	specialKey := []byte{0, 255, 128, 64, 32, 16, 8, 4, 2, 1}
	b64 = crypto.KeyToBase64(specialKey)
	restored, err = crypto.KeyFromBase64(b64)
	if err != nil {
		t.Fatalf("KeyFromBase64() error: %v", err)
	}
	if string(specialKey) != string(restored) {
		t.Errorf("Special key round-trip failed: expected %x, got %x", specialKey, restored)
	}
}

// TestKeyHexEdgeCases tests hex encoding/decoding with edge cases
func TestKeyHexEdgeCases(t *testing.T) {
	// Test with zero-length key
	emptyKey := []byte{}
	hexStr := crypto.KeyToHex(emptyKey)
	if hexStr != "" {
		t.Errorf("Expected empty hex for empty key, got %s", hexStr)
	}

	restored, err := crypto.KeyFromHex(hexStr)
	if err != nil {
		t.Errorf("Expected no error for empty hex, got %v", err)
	}
	if len(restored) != 0 {
		t.Errorf("Expected empty key from empty hex, got length %d", len(restored))
	}

	// Test with special characters in key
	specialKey := []byte{0, 255, 128, 64, 32, 16, 8, 4, 2, 1}
	hexStr = crypto.KeyToHex(specialKey)
	restored, err = crypto.KeyFromHex(hexStr)
	if err != nil {
		t.Fatalf("KeyFromHex() error: %v", err)
	}
	if string(specialKey) != string(restored) {
		t.Errorf("Special key round-trip failed: expected %x, got %x", specialKey, restored)
	}
}

// TestInvalidEncodingInputs tests various invalid encoding inputs
func TestInvalidEncodingInputs(t *testing.T) {
	// Test invalid base64 inputs
	invalidBase64Inputs := []string{
		"not-base64!!",
		"AA=AA", // invalid padding
		"AA===", // too much padding
		"AA",    // incomplete
		"AAA",   // incomplete
		"AAAAA", // incomplete
	}

	for _, input := range invalidBase64Inputs {
		_, err := crypto.KeyFromBase64(input)
		if err == nil {
			t.Errorf("Expected error for invalid base64 input: %s", input)
		}
	}

	// Test invalid hex inputs
	invalidHexInputs := []string{
		"nothex!!",
		"AAA", // incomplete
		"GG",  // invalid characters
		"ZZ",  // invalid characters
		"123", // odd length
	}

	for _, input := range invalidHexInputs {
		_, err := crypto.KeyFromHex(input)
		if err == nil {
			t.Errorf("Expected error for invalid hex input: %s", input)
		}
	}
}

// TestZeroizeThoroughly tests zeroize functionality more thoroughly
func TestZeroizeThoroughly(t *testing.T) {
	// Test with various key contents
	testCases := [][]byte{
		[]byte("sensitive-data"),
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{255, 255, 255, 255, 255},
		{128, 64, 32, 16, 8, 4, 2, 1},
	}

	for i, key := range testCases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			// Make a copy to avoid modifying the original
			keyCopy := make([]byte, len(key))
			copy(keyCopy, key)

			crypto.Zeroize(keyCopy)

			for j, b := range keyCopy {
				if b != 0 {
					t.Errorf("Zeroize failed at position %d: expected 0, got %d", j, b)
				}
			}
		})
	}

	// Test with nil and empty slices
	crypto.Zeroize(nil)      // Should not panic
	crypto.Zeroize([]byte{}) // Should not panic
}

// TestGenerateKeyWithMockedRandomFailure tests key generation with mocked random failures
func TestGenerateKeyWithMockedRandomFailure(t *testing.T) {
	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()
	rand.Reader = &failingReader{}

	_, err := crypto.GenerateKey()
	if err == nil {
		t.Error("Expected error when random generation fails")
	}
}

// TestGenerateNonceWithMockedRandomFailure tests nonce generation with mocked random failures
func TestGenerateNonceWithMockedRandomFailure(t *testing.T) {
	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()
	rand.Reader = &failingReader{}

	_, err := crypto.GenerateNonce(12)
	if err == nil {
		t.Error("Expected error when random generation fails")
	}
}
