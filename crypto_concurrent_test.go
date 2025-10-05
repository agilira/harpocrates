// crypto_concurrent_test.go: Concurrent test cases for cryptographic utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"sync"
	"testing"

	"github.com/agilira/harpocrates"
)

func TestConcurrentAccess_Concurrency(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			text := "test-" + string(rune(id))
			encrypted, err := crypto.Encrypt(text, key)
			if err != nil {
				t.Errorf("Concurrent encryption %d failed: %v", id, err)
			}
			decrypted, err := crypto.Decrypt(encrypted, key)
			if err != nil {
				t.Errorf("Concurrent decryption %d failed: %v", id, err)
			}
			if decrypted != text {
				t.Errorf("Concurrent round-trip %d mismatch", id)
			}
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestConcurrentKeyGeneration tests concurrent key generation
func TestConcurrentKeyGeneration(t *testing.T) {
	const numGoroutines = 20
	keys := make([][]byte, numGoroutines)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Errorf("Concurrent key generation %d failed: %v", id, err)
				return
			}
			mu.Lock()
			keys[id] = key
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Verify all keys were generated and are different
	for i, key := range keys {
		if key == nil {
			t.Errorf("Key %d was not generated", i)
			continue
		}
		if len(key) != crypto.KeySize {
			t.Errorf("Key %d has wrong size: got %d, want %d", i, len(key), crypto.KeySize)
		}
		// Check for duplicates
		for j := i + 1; j < len(keys); j++ {
			if keys[j] != nil && string(key) == string(keys[j]) {
				t.Errorf("Duplicate keys found at indices %d and %d", i, j)
			}
		}
	}
}

// TestConcurrentNonceGeneration tests concurrent nonce generation
func TestConcurrentNonceGeneration(t *testing.T) {
	const numGoroutines = 20
	const nonceSize = 12
	nonces := make([][]byte, numGoroutines)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			nonce, err := crypto.GenerateNonce(nonceSize)
			if err != nil {
				t.Errorf("Concurrent nonce generation %d failed: %v", id, err)
				return
			}
			mu.Lock()
			nonces[id] = nonce
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Verify all nonces were generated and are different
	for i, nonce := range nonces {
		if nonce == nil {
			t.Errorf("Nonce %d was not generated", i)
			continue
		}
		if len(nonce) != nonceSize {
			t.Errorf("Nonce %d has wrong size: got %d, want %d", i, len(nonce), nonceSize)
		}
		// Check for duplicates
		for j := i + 1; j < len(nonces); j++ {
			if nonces[j] != nil && string(nonce) == string(nonces[j]) {
				t.Errorf("Duplicate nonces found at indices %d and %d", i, j)
			}
		}
	}
}

// TestConcurrentKeyDerivation tests concurrent PBKDF2 key derivation
func TestConcurrentKeyDerivation(t *testing.T) {
	const numGoroutines = 10
	password := []byte("test-password")
	salt := []byte("test-salt")
	keys := make([][]byte, numGoroutines)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key, err := crypto.DeriveKeyPBKDF2(password, salt, 1000, 32)
			if err != nil {
				t.Errorf("Concurrent key derivation %d failed: %v", id, err)
				return
			}
			mu.Lock()
			keys[id] = key
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Verify all keys were derived and are identical (deterministic)
	firstKey := keys[0]
	if firstKey == nil {
		t.Fatal("First key was not derived")
	}

	for i, key := range keys {
		if key == nil {
			t.Errorf("Key %d was not derived", i)
			continue
		}
		if len(key) != 32 {
			t.Errorf("Key %d has wrong size: got %d, want 32", i, len(key))
		}
		if string(key) != string(firstKey) {
			t.Errorf("Key %d differs from first key (non-deterministic)", i)
		}
	}
}

// TestConcurrentEncryptionDecryption tests concurrent encryption/decryption with different keys
func TestConcurrentEncryptionDecryption(t *testing.T) {
	const numGoroutines = 15
	plaintext := "concurrent-test-data"
	results := make([]bool, numGoroutines)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Generate unique key for each goroutine
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Errorf("Key generation %d failed: %v", id, err)
				return
			}

			// Encrypt
			encrypted, err := crypto.Encrypt(plaintext, key)
			if err != nil {
				t.Errorf("Encryption %d failed: %v", id, err)
				return
			}

			// Decrypt
			decrypted, err := crypto.Decrypt(encrypted, key)
			if err != nil {
				t.Errorf("Decryption %d failed: %v", id, err)
				return
			}

			// Verify round-trip
			success := decrypted == plaintext
			mu.Lock()
			results[id] = success
			mu.Unlock()

			if !success {
				t.Errorf("Round-trip %d failed: expected %s, got %s", id, plaintext, decrypted)
			}
		}(i)
	}
	wg.Wait()

	// Verify all operations succeeded
	for i, success := range results {
		if !success {
			t.Errorf("Operation %d did not complete successfully", i)
		}
	}
}

// TestConcurrentKeyValidation tests concurrent key validation
func TestConcurrentKeyValidation(t *testing.T) {
	const numGoroutines = 20
	validKey := make([]byte, crypto.KeySize)
	invalidKey := make([]byte, 16)
	results := make([]error, numGoroutines)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			var err error
			if id%2 == 0 {
				err = crypto.ValidateKey(validKey)
			} else {
				err = crypto.ValidateKey(invalidKey)
			}

			mu.Lock()
			results[id] = err
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Verify results are consistent
	for i, err := range results {
		if i%2 == 0 {
			// Should be valid
			if err != nil {
				t.Errorf("Valid key validation %d failed: %v", i, err)
			}
		} else {
			// Should be invalid
			if err == nil {
				t.Errorf("Invalid key validation %d should have failed", i)
			}
		}
	}
}
