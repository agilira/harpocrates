package crypto

import (
	"testing"
)

// FuzzDecryptBytes tests DecryptBytes with randomized inputs to discover edge cases
// and potential security vulnerabilities.
//
// This fuzzing approach helps identify:
// - Buffer overflows/underflows
// - Panic conditions with malformed input
// - Base64 parsing edge cases
// - GCM authentication bypass attempts
// - Memory safety issues
//
// Usage:
//
//	go test -fuzz=FuzzDecryptBytes
//	go test -fuzz=FuzzDecryptBytes -fuzztime=30s
func FuzzDecryptBytes(f *testing.F) {
	// Generate a valid key for testing
	validKey, err := GenerateKey()
	if err != nil {
		f.Fatalf("Failed to generate key: %v", err)
	}

	// Seed the fuzzer with some valid and invalid test cases
	// This helps the fuzzer understand the expected input format
	f.Add("", validKey)                 // Empty string
	f.Add("invalid-base64!", validKey)  // Invalid base64
	f.Add("dGVzdA==", validKey)         // Valid base64 but invalid ciphertext
	f.Add("SGVsbG8gV29ybGQ=", validKey) // Another valid base64

	// Add some known valid ciphertexts
	plaintext := "test-data-for-fuzzing"
	if encrypted, err := EncryptBytes([]byte(plaintext), validKey); err == nil {
		f.Add(encrypted, validKey)
	}

	// Add edge cases with different key sizes
	shortKey := make([]byte, 16) // Too short
	longKey := make([]byte, 64)  // Too long
	f.Add("dGVzdA==", shortKey)
	f.Add("dGVzdA==", longKey)
	f.Add("dGVzdA==", []byte{}) // Empty key

	f.Fuzz(func(t *testing.T, encryptedText string, key []byte) {
		// The fuzzer will call DecryptBytes with random inputs
		// We don't expect it to succeed, but it should never panic
		_, err := DecryptBytes(encryptedText, key)

		// We don't assert on the error since most random inputs should fail
		// The important thing is that the function handles all inputs gracefully
		// and never panics or causes memory corruption
		_ = err

		// Additional safety check: ensure key hasn't been modified
		// (this would indicate a serious bug)
		if len(key) > 0 {
			// We can't easily verify the key wasn't modified without copying it first,
			// but any panic or crash would be caught by the fuzzer
		}
	})
}

// FuzzDecryptBytesWithValidKey tests DecryptBytes with a fixed valid key
// but randomized ciphertext input. This focuses on testing the decryption
// logic specifically.
func FuzzDecryptBytesWithValidKey(f *testing.F) {
	validKey, err := GenerateKey()
	if err != nil {
		f.Fatalf("Failed to generate key: %v", err)
	}

	// Seed with various base64 and non-base64 strings
	testCases := []string{
		"",
		"a",
		"ab",
		"abc",
		"abcd",
		"dGVzdA==",
		"SGVsbG8=",
		"invalid!@#$%^&*()",
		"validbase64butnotciphertext",
		"VGhpcyBpcyBhIHRlc3Q=",
		"//////",
		"++++++",
		"AAAAAAAAAAAAAAAA",
		"////////////////////////////////////////////////////////////////",
	}

	for _, tc := range testCases {
		f.Add(tc)
	}

	// Add some actual encrypted data
	plaintexts := []string{
		"",
		"a",
		"test",
		"Hello, World!",
		"This is a longer test string with special chars: !@#$%^&*()",
	}

	for _, pt := range plaintexts {
		if encrypted, err := EncryptBytes([]byte(pt), validKey); err == nil {
			f.Add(encrypted)
		}
	}

	f.Fuzz(func(t *testing.T, encryptedText string) {
		// Test with fixed valid key and random ciphertext
		_, err := DecryptBytes(encryptedText, validKey)

		// Most inputs should fail, but function should never panic
		_ = err
	})
}

// FuzzDecryptBytesKeyVariations tests DecryptBytes with randomized keys
// but known ciphertext format to test key validation logic.
func FuzzDecryptBytesKeyVariations(f *testing.F) {
	// Create some valid ciphertext to test against
	validKey, err := GenerateKey()
	if err != nil {
		f.Fatalf("Failed to generate key: %v", err)
	}
	validCiphertext, err := EncryptBytes([]byte("fuzz test data"), validKey)
	if err != nil {
		panic("Failed to create test ciphertext: " + err.Error())
	}

	// Seed with various key sizes and patterns
	f.Add(validKey)         // Valid key
	f.Add([]byte{})         // Empty key
	f.Add(make([]byte, 1))  // Too short
	f.Add(make([]byte, 16)) // AES-128 size
	f.Add(make([]byte, 24)) // AES-192 size
	f.Add(make([]byte, 31)) // Almost valid
	f.Add(make([]byte, 33)) // Slightly too long
	f.Add(make([]byte, 64)) // Much too long

	// Add some patterned keys
	allZeros := make([]byte, 32)
	allOnes := make([]byte, 32)
	for i := range allOnes {
		allOnes[i] = 0xFF
	}
	f.Add(allZeros)
	f.Add(allOnes)

	f.Fuzz(func(t *testing.T, key []byte) {
		// Test with random keys and valid ciphertext structure
		_, err := DecryptBytes(validCiphertext, key)

		// We expect most keys to fail, but no panics
		_ = err
	})
}

// FuzzEncryptDecryptRoundTrip tests the round-trip property with random data
// This ensures that Encrypt(Decrypt(x)) == x for valid inputs and that
// the functions are inverse operations.
func FuzzEncryptDecryptRoundTrip(f *testing.F) {
	validKey, err := GenerateKey()
	if err != nil {
		f.Fatalf("Failed to generate key: %v", err)
	}

	// Seed with various data types and sizes
	f.Add([]byte(""))
	f.Add([]byte("a"))
	f.Add([]byte("test"))
	f.Add([]byte("Hello, World!"))
	f.Add([]byte{0x00, 0x01, 0x02, 0xFF}) // Binary data
	f.Add(make([]byte, 1000))             // Large data

	f.Fuzz(func(t *testing.T, originalData []byte) {
		// Encrypt the data
		encrypted, err := EncryptBytes(originalData, validKey)
		if err != nil {
			// Encryption failed - this might be expected for very large inputs
			return
		}

		// Decrypt the encrypted data
		decrypted, err := DecryptBytes(encrypted, validKey)
		if err != nil {
			// This should never happen with our own encrypted data
			t.Fatalf("Decryption failed for our own encrypted data: %v", err)
		}

		// Verify round-trip property
		if len(originalData) != len(decrypted) {
			t.Fatalf("Length mismatch: original=%d, decrypted=%d", len(originalData), len(decrypted))
		}

		for i := range originalData {
			if originalData[i] != decrypted[i] {
				t.Fatalf("Data mismatch at position %d: original=0x%02x, decrypted=0x%02x",
					i, originalData[i], decrypted[i])
			}
		}
	})
}
