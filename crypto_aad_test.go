// crypto_aad_test.go: Test cases for Additional Authenticated Data functions.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"bytes"
	"testing"

	crypto "github.com/agilira/harpocrates"
)

func TestEncryptDecryptWithAAD_Basic(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := "sensitive vault secret"
	aad := `{"tenant":"test","path":"/db/pass","version":1,"keyID":"kek_123"}`

	// Test string functions
	ciphertext, err := crypto.EncryptWithAAD(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	decrypted, err := crypto.DecryptWithAAD(ciphertext, key, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text doesn't match: expected %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptDecryptBytesWithAAD_Basic(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("binary vault data")
	aad := []byte(`{"tenant":"vault","path":"/secrets/api","version":2,"keyID":"kek_456"}`)

	// Test bytes functions
	ciphertext, err := crypto.EncryptBytesWithAAD(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptBytesWithAAD failed: %v", err)
	}

	decrypted, err := crypto.DecryptBytesWithAAD(ciphertext, key, aad)
	if err != nil {
		t.Fatalf("DecryptBytesWithAAD failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted bytes don't match: expected %v, got %v", plaintext, decrypted)
	}
}

func TestAAD_Mismatch(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := "test data"
	correctAAD := `{"tenant":"app","path":"/test","version":1}`
	wrongAAD := `{"tenant":"app","path":"/test","version":2}`

	// Encrypt with correct AAD
	ciphertext, err := crypto.EncryptWithAAD(plaintext, key, correctAAD)
	if err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	// Try to decrypt with wrong AAD - should fail
	_, err = crypto.DecryptWithAAD(ciphertext, key, wrongAAD)
	if err == nil {
		t.Error("Expected decryption to fail with wrong AAD, but it succeeded")
	}

	// Decrypt with correct AAD - should work
	decrypted, err := crypto.DecryptWithAAD(ciphertext, key, correctAAD)
	if err != nil {
		t.Fatalf("DecryptWithAAD with correct AAD failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text doesn't match: expected %q, got %q", plaintext, decrypted)
	}
}

func TestAAD_EmptyAAD(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := "test with empty AAD"
	emptyAAD := ""

	// Test with empty AAD
	ciphertext, err := crypto.EncryptWithAAD(plaintext, key, emptyAAD)
	if err != nil {
		t.Fatalf("EncryptWithAAD with empty AAD failed: %v", err)
	}

	decrypted, err := crypto.DecryptWithAAD(ciphertext, key, emptyAAD)
	if err != nil {
		t.Fatalf("DecryptWithAAD with empty AAD failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text doesn't match: expected %q, got %q", plaintext, decrypted)
	}

	// Try with non-empty AAD - should fail
	_, err = crypto.DecryptWithAAD(ciphertext, key, "non-empty")
	if err == nil {
		t.Error("Expected decryption to fail when AAD doesn't match")
	}
}

func TestAAD_NilAAD(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("test with nil AAD")

	// Test with nil AAD
	ciphertext, err := crypto.EncryptBytesWithAAD(plaintext, key, nil)
	if err != nil {
		t.Fatalf("EncryptBytesWithAAD with nil AAD failed: %v", err)
	}

	decrypted, err := crypto.DecryptBytesWithAAD(ciphertext, key, nil)
	if err != nil {
		t.Fatalf("DecryptBytesWithAAD with nil AAD failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted bytes don't match: expected %v, got %v", plaintext, decrypted)
	}
}

func TestAAD_NEMESIS_Pattern(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// Test realistic NEMESIS AAD pattern
	testCases := []struct {
		name      string
		tenant    string
		path      string
		version   int
		keyID     string
		plaintext string
	}{
		{
			name:      "Database Password",
			tenant:    "production",
			path:      "/db/postgres/password",
			version:   1,
			keyID:     "kek_abc123def456",
			plaintext: "super-secret-db-password",
		},
		{
			name:      "API Key",
			tenant:    "staging",
			path:      "/api/third-party/token",
			version:   3,
			keyID:     "kek_789xyz012",
			plaintext: "sk-1234567890abcdef",
		},
		{
			name:      "Certificate",
			tenant:    "security",
			path:      "/tls/internal/cert",
			version:   2,
			keyID:     "kek_cert_rotation_v2",
			plaintext: "-----BEGIN CERTIFICATE-----\nMIIB...",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create NEMESIS-style AAD
			aad := []byte(`{"tenant":"` + tc.tenant + `","path":"` + tc.path +
				`","version":` + string(rune(tc.version+'0')) + `,"keyID":"` + tc.keyID + `"}`)

			// Encrypt
			ciphertext, err := crypto.EncryptBytesWithAAD([]byte(tc.plaintext), key, aad)
			if err != nil {
				t.Fatalf("EncryptBytesWithAAD failed: %v", err)
			}

			// Decrypt
			decrypted, err := crypto.DecryptBytesWithAAD(ciphertext, key, aad)
			if err != nil {
				t.Fatalf("DecryptBytesWithAAD failed: %v", err)
			}

			if string(decrypted) != tc.plaintext {
				t.Errorf("Decrypted text doesn't match: expected %q, got %q",
					tc.plaintext, string(decrypted))
			}

			// Test that modifying AAD breaks decryption
			wrongAAD := []byte(`{"tenant":"` + tc.tenant + `","path":"` + tc.path +
				`","version":` + string(rune(tc.version+'1')) + `,"keyID":"` + tc.keyID + `"}`)

			_, err = crypto.DecryptBytesWithAAD(ciphertext, key, wrongAAD)
			if err == nil {
				t.Error("Expected decryption to fail with modified AAD")
			}
		})
	}
}

func TestAAD_InvalidInputs(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	aad := "valid-aad"

	// Test invalid key sizes
	invalidKeys := [][]byte{
		nil,
		{},
		make([]byte, 16), // AES-128
		make([]byte, 24), // AES-192
		make([]byte, 64), // Too long
	}

	for i, invalidKey := range invalidKeys {
		_, err := crypto.EncryptWithAAD("test", invalidKey, aad)
		if err == nil {
			t.Errorf("Test %d: Expected error with invalid key size %d", i, len(invalidKey))
		}

		_, err = crypto.DecryptWithAAD("dGVzdA==", invalidKey, aad)
		if err == nil {
			t.Errorf("Test %d: Expected error with invalid key size %d", i, len(invalidKey))
		}
	}

	// Test empty encrypted text
	_, err := crypto.DecryptWithAAD("", key, aad)
	if err == nil {
		t.Error("Expected error with empty encrypted text")
	}
}

func TestAAD_CompatibilityWithRegularFunctions(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := "compatibility test"

	// Encrypt without AAD using regular function
	ciphertext1, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Regular Encrypt failed: %v", err)
	}

	// Encrypt with empty AAD using AAD function
	ciphertext2, err := crypto.EncryptWithAAD(plaintext, key, "")
	if err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	// Regular ciphertext should be compatible with AAD decryption using empty AAD
	decryptedAAD, err := crypto.DecryptWithAAD(ciphertext1, key, "")
	if err != nil {
		t.Fatalf("Regular ciphertext should be compatible with AAD decryption (empty AAD): %v", err)
	}
	if decryptedAAD != plaintext {
		t.Errorf("Cross-decryption mismatch: expected %q, got %q", plaintext, decryptedAAD)
	}

	// AAD ciphertext should be compatible with regular decryption when AAD was empty
	decryptedRegular, err := crypto.Decrypt(ciphertext2, key)
	if err != nil {
		t.Fatalf("AAD ciphertext (empty AAD) should be compatible with regular decryption: %v", err)
	}
	if decryptedRegular != plaintext {
		t.Errorf("Cross-decryption mismatch: expected %q, got %q", plaintext, decryptedRegular)
	}

	// But AAD ciphertext with non-empty AAD should NOT be compatible with regular decryption
	ciphertext3, err := crypto.EncryptWithAAD(plaintext, key, "non-empty-aad")
	if err != nil {
		t.Fatalf("EncryptWithAAD with non-empty AAD failed: %v", err)
	}

	_, err = crypto.Decrypt(ciphertext3, key)
	if err == nil {
		t.Error("Expected regular decryption to fail with AAD ciphertext (non-empty AAD)")
	}

	// Proper decryption should work
	decrypted1, err := crypto.Decrypt(ciphertext1, key)
	if err != nil {
		t.Fatalf("Regular Decrypt failed: %v", err)
	}

	decrypted2, err := crypto.DecryptWithAAD(ciphertext2, key, "")
	if err != nil {
		t.Fatalf("DecryptWithAAD failed: %v", err)
	}

	if decrypted1 != plaintext || decrypted2 != plaintext {
		t.Errorf("Decryption mismatch: expected %q, got regular=%q, aad=%q",
			plaintext, decrypted1, decrypted2)
	}
}
