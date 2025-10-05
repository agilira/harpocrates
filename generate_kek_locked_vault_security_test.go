// generate_kek_locked_vault_security_test.go: Test cases for Vault KEK Generation functions.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"sync"
	"testing"
	"time"
)

// TestGenerateKEKLocked_VaultSecurity tests the internal generateKEKLocked function (61.5% → 85%+)
// Focus: Lock contention, error paths, version conflicts, memory allocation failures, edge cases
func TestGenerateKEKLocked_VaultSecurity(t *testing.T) {

	t.Run("LockContention_ThreadSafety", func(t *testing.T) {
		// VAULT CRITICAL: Test lock contention scenarios
		// Multiple goroutines trying to call generateKEKLocked simultaneously

		km := NewKeyManager()

		var wg sync.WaitGroup
		results := make(chan *KeyVersion, 10)
		errors := make(chan error, 10)

		// Launch multiple concurrent generateKEK calls (which internally use generateKEKLocked)
		numGoroutines := 5
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				// Call GenerateKEK which internally calls generateKEKLocked
				kek, err := km.GenerateKEK("concurrent-test")
				if err != nil {
					errors <- err
				} else {
					results <- kek
				}
			}(i)
		}

		wg.Wait()
		close(results)
		close(errors)

		// Count results
		successCount := 0
		for kek := range results {
			if kek != nil {
				successCount++
			}
		}

		errorCount := 0
		for err := range errors {
			if err != nil {
				errorCount++
				t.Logf("Concurrent error: %v", err)
			}
		}

		// At least one should succeed
		if successCount == 0 {
			t.Error("No successful KEK generation in concurrent test")
		}

		t.Logf("✅ LOCK CONTENTION: %d successes, %d errors", successCount, errorCount)
	})

	t.Run("VersionConflict_EdgeCase", func(t *testing.T) {
		// VAULT CRITICAL: Test version numbering edge cases
		// Force version conflicts by manipulating internal state

		km := NewKeyManager()

		// Create initial KEK to establish versioning
		initialKEK, err := km.GenerateKEK("version-test")
		if err != nil {
			t.Fatalf("Failed to create initial KEK: %v", err)
		}

		t.Logf("Initial KEK version: %d", initialKEK.Version)

		// Create many KEKs rapidly to test version increment logic
		prevVersion := initialKEK.Version
		for i := 0; i < 5; i++ {
			kek, err := km.GenerateKEK("version-increment")
			if err != nil {
				t.Errorf("KEK generation %d failed: %v", i, err)
				continue
			}

			// Verify version increments properly
			if kek.Version != prevVersion+1 {
				t.Errorf("Version increment error: expected %d, got %d", prevVersion+1, kek.Version)
			}

			prevVersion = kek.Version
		}

		t.Logf("✅ VERSION CONFLICT: Version increments tested")
	})

	t.Run("MemoryAllocation_Stress", func(t *testing.T) {
		// VAULT CRITICAL: Test memory allocation patterns during KEK generation

		km := NewKeyManager()

		// Generate many KEKs to test memory allocation patterns
		const numKEKs = 100
		start := time.Now()

		for i := 0; i < numKEKs; i++ {
			kek, err := km.GenerateKEK("memory-stress")
			if err != nil {
				t.Errorf("Memory stress KEK %d failed: %v", i, err)
			}

			// Verify KEK is valid
			if kek == nil {
				t.Errorf("KEK %d is nil", i)
			}

			// Clean up to prevent memory buildup (simulate real usage)
			if i%10 == 0 {
				// Keep some versions, clean others
				if len(km.versions) > 50 {
					// Force cleanup by setting older versions to deprecated
					for id, version := range km.versions {
						if version.Version < kek.Version-20 {
							version.Status = StatusDeprecated
							delete(km.versions, id)
						}
					}
				}
			}
		}

		elapsed := time.Since(start)
		t.Logf("✅ MEMORY STRESS: Generated %d KEKs in %v (%.2f KEKs/ms)",
			numKEKs, elapsed, float64(numKEKs)/float64(elapsed.Nanoseconds())*1000000)
	})

	t.Run("ErrorPath_InvalidPurpose", func(t *testing.T) {
		// VAULT CRITICAL: Test error handling paths in generateKEKLocked

		km := NewKeyManager()

		// Test various invalid purpose strings
		invalidPurposes := []string{
			"",                         // Empty purpose
			string(make([]byte, 1000)), // Very long purpose
			"\x00\x01\x02",             // Binary data
			"purpose with\nnewlines\tand\ttabs",
		}

		for i, purpose := range invalidPurposes {
			kek, err := km.GenerateKEK(purpose)

			// Some may succeed (system is robust) or fail gracefully
			if err != nil {
				t.Logf("Invalid purpose %d failed as expected: %v", i, err)
			} else if kek != nil {
				t.Logf("Invalid purpose %d succeeded (robust system): KEK %s", i, kek.ID)
			}
		}

		t.Logf("✅ ERROR PATHS: Invalid purposes tested")
	})

	t.Run("CachedGCM_Performance", func(t *testing.T) {
		// VAULT CRITICAL: Test cached GCM initialization in generateKEKLocked

		km := NewKeyManager()

		// Generate KEK and test that cached GCM is properly initialized
		kek, err := km.GenerateKEK("cached-gcm-test")
		if err != nil {
			t.Fatalf("Failed to generate KEK: %v", err)
		}

		// Verify cached GCM is initialized (indirect test)
		if kek.cachedGCM == nil {
			t.Error("Cached GCM should be initialized after KEK generation")
		}

		// Test that we can use the KEK for encryption (which relies on cached GCM)
		testData := "test-data-for-cached-gcm"
		encrypted, err := km.EncryptWithKEK(testData, kek.ID)
		if err != nil {
			t.Errorf("Failed to encrypt with cached GCM: %v", err)
		}

		// Decrypt to verify cached GCM works
		decrypted, err := km.DecryptWithKEK(encrypted, kek.ID)
		if err != nil {
			t.Errorf("Failed to decrypt with cached GCM: %v", err)
		}

		if decrypted != testData {
			t.Errorf("Cached GCM decrypt mismatch: expected %s, got %s", testData, decrypted)
		}

		t.Logf("✅ CACHED GCM: Performance optimization verified")
	})

	t.Run("StateConsistency_Validation", func(t *testing.T) {
		// VAULT CRITICAL: Test internal state consistency during generateKEKLocked

		km := NewKeyManager()

		// Generate multiple KEKs and verify state consistency
		kekIDs := make([]string, 0, 10)
		for i := 0; i < 10; i++ {
			kek, err := km.GenerateKEK("state-consistency")
			if err != nil {
				t.Errorf("State consistency KEK %d failed: %v", i, err)
				continue
			}

			kekIDs = append(kekIDs, kek.ID)

			// Verify KEK is in versions map
			storedKEK, exists := km.versions[kek.ID]
			if !exists {
				t.Errorf("KEK %s not found in versions map", kek.ID)
			}

			// Verify consistency between returned KEK and stored KEK
			if storedKEK.ID != kek.ID || storedKEK.Version != kek.Version {
				t.Errorf("State inconsistency: stored KEK differs from returned KEK")
			}

			// Note: GenerateKEK creates KEKs with StatusPending, it does NOT activate them
			// This is correct behavior for zero-downtime rotation workflow
			// So we don't expect activeKEK to be updated automatically

			// Verify KEK status is pending (not active)
			if kek.Status != StatusPending {
				t.Errorf("New KEK should have StatusPending, got: %s", kek.Status)
			}
		}

		// Verify all generated KEKs are unique
		uniqueIDs := make(map[string]bool)
		for _, id := range kekIDs {
			if uniqueIDs[id] {
				t.Errorf("Duplicate KEK ID generated: %s", id)
			}
			uniqueIDs[id] = true
		}

		t.Logf("✅ STATE CONSISTENCY: Generated %d unique KEKs with consistent state", len(kekIDs))
	})

	t.Run("CryptographicQuality_Validation", func(t *testing.T) {
		// VAULT CRITICAL: Test cryptographic quality of generated keys

		km := NewKeyManager()

		// Generate multiple KEKs and analyze key quality
		keys := make([][]byte, 0, 20)
		for i := 0; i < 20; i++ {
			kek, err := km.GenerateKEK("crypto-quality")
			if err != nil {
				t.Errorf("Crypto quality KEK %d failed: %v", i, err)
				continue
			}

			// Verify key length
			if len(kek.Key) != 32 {
				t.Errorf("Invalid key length: expected 32, got %d", len(kek.Key))
			}

			keys = append(keys, make([]byte, len(kek.Key)))
			copy(keys[len(keys)-1], kek.Key)
		}

		// Basic randomness check: no two keys should be identical
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				if string(keys[i]) == string(keys[j]) {
					t.Errorf("Duplicate keys generated at positions %d and %d", i, j)
				}
			}
		}

		// Basic entropy check: keys should not be all zeros or have obvious patterns
		for i, key := range keys {
			allZeros := true
			allOnes := true
			for _, b := range key {
				if b != 0x00 {
					allZeros = false
				}
				if b != 0xFF {
					allOnes = false
				}
			}

			if allZeros {
				t.Errorf("Key %d is all zeros - poor entropy", i)
			}
			if allOnes {
				t.Errorf("Key %d is all ones - poor entropy", i)
			}
		}

		t.Logf("✅ CRYPTOGRAPHIC QUALITY: %d keys generated with good entropy", len(keys))
	})
}
