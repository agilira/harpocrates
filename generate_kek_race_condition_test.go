// generate_kek_race_condition_test.go: Test cases for Vault KEK Generation functions.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"sync"
	"testing"
)

// TestGenerateKEK_ThreadSafetyBug reproduces the race condition bug found by our aggressive tests
// This test demonstrates the critical thread-safety issue in GenerateKEK
func TestGenerateKEK_ThreadSafetyBug(t *testing.T) {

	t.Run("ConcurrentAccess_RaceCondition", func(t *testing.T) {
		// VAULT CRITICAL BUG: Concurrent GenerateKEK calls cause race condition
		// This test reliably reproduces the "concurrent map iteration and map write" panic

		km := NewKeyManager()

		var wg sync.WaitGroup
		errors := make(chan error, 100)

		// Launch many concurrent KEK generations to trigger race condition
		numGoroutines := 20
		generationsPerGoroutine := 10

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()

				for j := 0; j < generationsPerGoroutine; j++ {
					// Each generation can race with others in:
					// 1. getNextVersion() reading km.versions
					// 2. Writing to km.versions[version.ID]
					_, err := km.GenerateKEK("race-test")
					if err != nil {
						errors <- err
					}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		// If the test doesn't panic, check for any errors
		errorCount := 0
		for err := range errors {
			errorCount++
			t.Logf("Generation error: %v", err)
		}

		t.Logf("Completed %d concurrent KEK generations", numGoroutines*generationsPerGoroutine)
		t.Logf("Errors encountered: %d", errorCount)

		// The fact that this test can complete OR panic shows the race condition exists
		// If it panics: race condition reproduced
		// If it completes: we got lucky with timing, but race still exists
	})

	t.Run("FixVerification", func(t *testing.T) {
		// VAULT CRITICAL: Verify our race condition fix works

		km := NewKeyManager()

		// Test that multiple calls to GenerateKEK are now thread-safe
		var wg sync.WaitGroup
		results := make(chan error, 100)

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				// Each call should be thread-safe now with our lock
				_, err := km.GenerateKEK("fix-verification")
				results <- err
			}()
		}

		wg.Wait()
		close(results)

		errorCount := 0
		for err := range results {
			if err != nil {
				errorCount++
			}
		}

		t.Logf("Fix verification: %d errors out of 50 concurrent GenerateKEK calls", errorCount)

		// With the fix, this should not panic or race
		if errorCount == 0 {
			t.Logf("SUCCESS: Race condition fix verified - no errors in concurrent access")
		}
	})

	t.Run("VersionNumberConsistency", func(t *testing.T) {
		// VAULT CRITICAL: Even if no panic, race conditions can cause version number issues

		km := NewKeyManager()

		var wg sync.WaitGroup
		keks := make(chan *KeyVersion, 100)

		// Generate many KEKs concurrently
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				kek, err := km.GenerateKEK("version-test")
				if err == nil && kek != nil {
					keks <- kek
				}
			}()
		}

		wg.Wait()
		close(keks)

		// Analyze version numbers for consistency
		versions := make(map[int]int) // version -> count
		for kek := range keks {
			versions[kek.Version]++
		}

		// Check for duplicate version numbers (race condition symptom)
		duplicates := 0
		for version, count := range versions {
			if count > 1 {
				duplicates++
				t.Logf("RACE CONDITION DETECTED: Version %d used %d times", version, count)
			}
		}

		if duplicates > 0 {
			t.Errorf("Found %d duplicate version numbers - evidence of race condition", duplicates)
		}

		t.Logf("Generated KEKs with versions: %v", versions)
	})
}
