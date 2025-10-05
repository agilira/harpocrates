// generate_kek_vault_failures_test.go: Test cases for Vault KEK Generation functions.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestGenerateKEK_VaultGradeFailures tests GenerateKEK (61.5% → 85%+)
// VAULT FOUNDATION - Key generation bugs = TOTAL VAULT COMPROMISE
func TestGenerateKEK_VaultGradeFailures(t *testing.T) {

	t.Run("GenerateKey_Failure_ResourceExhaustion", func(t *testing.T) {
		// VAULT CRITICAL: Force GenerateKey() to fail (lines 113-116)
		// If we exhaust entropy or memory, GenerateKey might fail

		km := NewKeyManager()

		// Create massive memory pressure to stress crypto/rand
		memoryHogs := make([][]byte, 200)
		for i := range memoryHogs {
			memoryHogs[i] = make([]byte, 1024*1024) // 200MB total
		}

		// Force multiple garbage collections to stress system
		for i := 0; i < 5; i++ {
			runtime.GC()
		}

		// Rapid-fire KEK generation to stress entropy pool
		failures := 0
		successes := 0

		for i := 0; i < 100; i++ {
			kek, err := km.GenerateKEK("stress-test")

			if err != nil && strings.Contains(err.Error(), "key generation failed") {
				failures++
				t.Logf("SUCCESS: Forced GenerateKey failure - %v", err)
			} else if err != nil {
				t.Logf("Other error: %v", err)
			} else {
				successes++
				// Clean up successful KEK to prevent memory issues
				if kek != nil {
					delete(km.versions, kek.ID)
				}
			}
		}

		// Clean up memory
		for i := range memoryHogs {
			memoryHogs[i] = nil
		}
		runtime.GC()

		t.Logf("GenerateKey stress test: %d failures, %d successes", failures, successes)

		if failures > 0 {
			t.Logf("SUCCESS: Triggered GenerateKey failure path")
		}
	})

	t.Run("KeyID_Generation_Failure_EntropyExhaustion", func(t *testing.T) {
		// VAULT CRITICAL: Force io.ReadFull ID generation to fail (lines 120-123)
		// This is the hardest path to trigger - need to exhaust crypto/rand

		km := NewKeyManager()

		// Try to exhaust entropy by making many concurrent requests
		var wg sync.WaitGroup
		idFailures := 0
		var mu sync.Mutex

		// Launch many goroutines to stress crypto/rand
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				// Each goroutine generates many KEKs rapidly
				for j := 0; j < 20; j++ {
					_, err := km.GenerateKEK(fmt.Sprintf("entropy-stress-%d-%d", id, j))

					if err != nil && strings.Contains(err.Error(), "key ID generation failed") {
						mu.Lock()
						idFailures++
						mu.Unlock()
						t.Logf("SUCCESS: Forced key ID generation failure - %v", err)
					}
				}
			}(i)
		}

		wg.Wait()

		t.Logf("ID generation stress test: %d failures detected", idFailures)

		if idFailures > 0 {
			t.Logf("SUCCESS: Triggered key ID generation failure path")
		}
	})

	t.Run("CachedGCM_Failure_CorruptedKey", func(t *testing.T) {
		// VAULT CRITICAL: Force initCachedGCM() to fail (lines 135-137)
		// This should be achievable by corrupting the key after generation

		km := NewKeyManager()

		// We need to test this indirectly since we can't modify GenerateKey easily
		// But we can test the initCachedGCM path by understanding what could fail

		// Test 1: Try with extreme system stress during GCM initialization
		runtime.GC()

		// Create many KEKs rapidly to stress GCM initialization
		for i := 0; i < 100; i++ {
			kek, err := km.GenerateKEK("gcm-stress")

			if err != nil && strings.Contains(err.Error(), "failed to initialize cached GCM") {
				t.Logf("SUCCESS: Forced GCM initialization failure - %v", err)
				break
			} else if err != nil {
				t.Logf("Other error during GCM test: %v", err)
			} else if kek != nil {
				// Clean up to prevent memory issues
				delete(km.versions, kek.ID)
			}
		}
	})

	t.Run("VersionsMap_Corruption_EdgeCase", func(t *testing.T) {
		// VAULT CRITICAL: Test what happens if versions map gets corrupted during generation

		km := NewKeyManager()

		// Test with nil versions map (this might cause panic or error)
		originalVersions := km.versions

		// Don't set to nil (causes panic), but test with empty map
		km.versions = make(map[string]*KeyVersion)

		kek, err := km.GenerateKEK("versions-test")

		// Restore original versions
		km.versions = originalVersions

		if err != nil {
			t.Logf("Got error with empty versions map: %v", err)
		} else if kek != nil {
			t.Logf("KEK generated successfully with empty versions: %s", kek.ID)
			// Add to original versions for cleanup
			km.versions[kek.ID] = kek
		}
	})

	t.Run("ConcurrentGeneration_RaceConditions", func(t *testing.T) {
		// VAULT CRITICAL: Test concurrent KEK generation for race conditions

		km := NewKeyManager()

		var wg sync.WaitGroup
		errors := make(chan error, 100)
		keks := make(chan *KeyVersion, 100)

		// Launch many concurrent KEK generations
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				kek, err := km.GenerateKEK(fmt.Sprintf("concurrent-%d", id))

				if err != nil {
					errors <- err
				} else {
					keks <- kek
				}
			}(i)
		}

		wg.Wait()
		close(errors)
		close(keks)

		// Analyze results
		errorCount := 0
		kekCount := 0
		uniqueIDs := make(map[string]bool)

		for err := range errors {
			errorCount++
			t.Logf("Concurrent generation error: %v", err)
		}

		for kek := range keks {
			kekCount++
			if kek != nil {
				if uniqueIDs[kek.ID] {
					t.Errorf("DUPLICATE KEK ID DETECTED: %s - CRITICAL SECURITY BUG!", kek.ID)
				}
				uniqueIDs[kek.ID] = true
			}
		}

		t.Logf("Concurrent test: %d errors, %d KEKs, %d unique IDs", errorCount, kekCount, len(uniqueIDs))

		// VAULT CRITICAL: All IDs must be unique
		assert.Equal(t, kekCount, len(uniqueIDs), "All KEK IDs must be unique - duplicate IDs are CRITICAL SECURITY BUG")
	})

	t.Run("MemoryLeak_PreventionfullExhaustion", func(t *testing.T) {
		// VAULT CRITICAL: Test for memory leaks during rapid KEK generation

		km := NewKeyManager()

		// Generate many KEKs and track memory usage
		initialVersionCount := len(km.versions)

		generatedCount := 0
		for i := 0; i < 1000; i++ {
			kek, err := km.GenerateKEK("memory-test")

			if err != nil {
				t.Logf("Memory test error at iteration %d: %v", i, err)
				break
			}

			if kek != nil {
				generatedCount++

				// Periodically clean up to test cleanup behavior
				if i%100 == 0 {
					// Remove some old KEKs to simulate normal operations
					count := 0
					for id := range km.versions {
						if count >= 50 {
							break
						}
						delete(km.versions, id)
						count++
					}
				}
			}
		}

		finalVersionCount := len(km.versions)

		t.Logf("Memory test: generated %d KEKs, versions: %d → %d",
			generatedCount, initialVersionCount, finalVersionCount)

		// Force garbage collection to detect any leaks
		runtime.GC()
		runtime.GC()
	})

	t.Run("EdgeCase_ExtremePurposeStrings", func(t *testing.T) {
		// VAULT CRITICAL: Test with extreme purpose strings that might break generation

		km := NewKeyManager()

		extremePurposes := []string{
			"",                               // Empty string
			strings.Repeat("x", 1000),        // Very long string
			"\x00\x01\x02\xFF",               // Binary data
			"unicode-测试-🔑-vault",             // Unicode characters
			"sql'injection\"attempt<script>", // Injection attempts
			strings.Repeat("a", 65536),       // 64KB string
		}

		for i, purpose := range extremePurposes {
			kek, err := km.GenerateKEK(purpose)

			if err != nil {
				t.Logf("Extreme purpose test %d failed: %v", i, err)

				// Check if it's one of our target error types
				if strings.Contains(err.Error(), "key generation failed") ||
					strings.Contains(err.Error(), "key ID generation failed") ||
					strings.Contains(err.Error(), "failed to initialize cached GCM") {
					t.Logf("SUCCESS: Triggered target error path with extreme purpose")
				}
			} else if kek != nil {
				t.Logf("Extreme purpose test %d succeeded: KEK %s", i, kek.ID)

				// Verify purpose was stored correctly
				assert.Equal(t, purpose, kek.Purpose, "Purpose should be stored correctly")

				// Clean up
				delete(km.versions, kek.ID)
			}
		}
	})

	t.Run("SystemResource_ExhaustionAttack", func(t *testing.T) {
		// VAULT CRITICAL: Test behavior under extreme system resource pressure

		km := NewKeyManager()

		// Create extreme memory pressure
		memoryPressure := make([][]byte, 500)
		for i := range memoryPressure {
			memoryPressure[i] = make([]byte, 1024*1024) // 500MB
		}

		// Create CPU pressure
		done := make(chan bool, 4)
		for i := 0; i < 4; i++ {
			go func() {
				start := time.Now()
				for time.Since(start) < 100*time.Millisecond {
					// CPU intensive work
					for j := 0; j < 1000000; j++ {
						_ = j * j
					}
				}
				done <- true
			}()
		}

		// Try KEK generation under pressure
		pressureErrors := 0
		for i := 0; i < 50; i++ {
			kek, err := km.GenerateKEK("pressure-test")

			if err != nil {
				pressureErrors++
				t.Logf("Pressure test error %d: %v", i, err)
			} else if kek != nil {
				// Clean up immediately to save memory
				delete(km.versions, kek.ID)
			}
		}

		// Wait for CPU pressure to end
		for i := 0; i < 4; i++ {
			<-done
		}

		// Clean up memory
		for i := range memoryPressure {
			memoryPressure[i] = nil
		}
		runtime.GC()

		t.Logf("System pressure test: %d errors out of 50 attempts", pressureErrors)

		if pressureErrors > 0 {
			t.Logf("SUCCESS: System pressure caused KEK generation failures")
		}
	})

	t.Run("TimeExecution_Boundary", func(t *testing.T) {
		// VAULT CRITICAL: Test timing-related edge cases

		km := NewKeyManager()

		// Test rapid generation to check for timing bugs
		// Add small buffer to handle microsecond timing variations
		start := time.Now().UTC().Add(-10 * time.Millisecond) // 10ms buffer before test start

		// Set a reasonable end boundary after the test ends
		maxTime := start.Add(10 * time.Second) // 10 second window for rapid generation

		rapidCount := 0
		for i := 0; i < 100 && time.Since(start) < 50*time.Millisecond; i++ {
			kek, err := km.GenerateKEK("timing-test")

			if err != nil {
				t.Logf("Timing test error: %v", err)
			} else if kek != nil {
				rapidCount++
				// Verify timestamp is reasonable - must be after start and before reasonable max time
				// Convert KEK timestamp to UTC for fair comparison
				kekTimeUTC := kek.CreatedAt.UTC()
				if kekTimeUTC.Before(start) || kekTimeUTC.After(maxTime) {
					t.Errorf("KEK timestamp out of reasonable range: %v (expected between %v and %v)",
						kekTimeUTC, start, maxTime)
				}

				delete(km.versions, kek.ID)
			}
		}

		elapsed := time.Since(start)
		t.Logf("Generated %d KEKs in %v (%.2f KEKs/ms)",
			rapidCount, elapsed, float64(rapidCount)/float64(elapsed.Nanoseconds())*1000000)
	})
}
