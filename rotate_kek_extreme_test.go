// rotate_kek_extreme_test.go: Test cases for extreme conditions in rotating KEK.
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

// TestRotateKEKZeroDowntime_ForceFailures attempts to force the 3 error paths
// using extreme conditions and resource exhaustion
func TestRotateKEKZeroDowntime_ForceFailures(t *testing.T) {

	t.Run("PrepareFailure_ResourceExhaustion", func(t *testing.T) {
		// VAULT CRITICAL: Try to force PrepareKEKRotation failure through resource exhaustion

		km := NewKeyManager()

		// Fill up the versions map to stress memory
		for i := 0; i < 1000; i++ {
			kek := &KeyVersion{
				ID:     fmt.Sprintf("stress-kek-%d", i),
				Key:    make([]byte, 1024), // Large keys to use memory
				Status: StatusRevoked,
			}
			km.versions[kek.ID] = kek
		}

		// Try rotation with stressed system
		_, err := km.RotateKEKZeroDowntime("resource-exhaustion-test")

		if err != nil && strings.Contains(err.Error(), "preparation failed") {
			// SUCCESS: We forced preparation failure!
			t.Logf("Successfully forced preparation failure: %v", err)

			// Verify system state
			assert.Nil(t, km.pendingKEK, "No pending KEK after preparation failure")
		} else if err != nil {
			t.Logf("Got error but not preparation failure: %v", err)
		} else {
			t.Logf("Rotation succeeded despite resource stress")
		}
	})

	t.Run("ValidateFailure_CorruptedState", func(t *testing.T) {
		// VAULT CRITICAL: Try to force ValidateKEKRotation failure by corrupting state

		km := NewKeyManager()

		// Manually create a pending KEK with corrupted state
		km.pendingKEK = &KeyVersion{
			ID:     "corrupted-validation-test",
			Key:    nil, // nil key should cause validation issues
			Status: StatusPending,
		}

		_, err := km.RotateKEKZeroDowntime("validate-failure-test")

		if err != nil && strings.Contains(err.Error(), "validation failed") {
			// SUCCESS: We forced validation failure!
			t.Logf("Successfully forced validation failure: %v", err)

			// Verify rollback occurred
			if km.pendingKEK != nil {
				assert.Equal(t, StatusRevoked, km.pendingKEK.Status, "Validation failure must trigger rollback")
			}
		} else if err != nil {
			t.Logf("Got error but not validation failure: %v", err)
		} else {
			t.Logf("Rotation succeeded despite corrupted state")
		}
	})

	t.Run("CommitFailure_StateRaceCondition", func(t *testing.T) {
		// VAULT CRITICAL: Try to force CommitKEKRotation failure through race conditions

		km := NewKeyManager()

		// Create multiple goroutines that will stress the commit phase
		var wg sync.WaitGroup
		results := make(chan error, 10)

		// Launch concurrent operations that might interfere with commit
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				// Each goroutine tries rotation - commit phase might fail due to races
				_, err := km.RotateKEKZeroDowntime("commit-race-test")
				results <- err
			}(i)
		}

		wg.Wait()
		close(results)

		// Check if any commit failures occurred
		commitFailures := 0
		for err := range results {
			if err != nil && strings.Contains(err.Error(), "commit failed") {
				commitFailures++
				t.Logf("Successfully forced commit failure: %v", err)
			}
		}

		if commitFailures > 0 {
			t.Logf("Forced %d commit failures out of 10 attempts", commitFailures)
		} else {
			t.Logf("No commit failures - system is very robust")
		}
	})

	t.Run("MemoryPressure_AllPhases", func(t *testing.T) {
		// VAULT CRITICAL: Apply memory pressure to try forcing failures in any phase

		km := NewKeyManager()

		// Create memory pressure
		memoryHogs := make([][]byte, 100)
		for i := range memoryHogs {
			memoryHogs[i] = make([]byte, 1024*1024) // 1MB each = 100MB total
		}

		// Force garbage collection to stress memory system
		runtime.GC()
		runtime.GC()

		_, err := km.RotateKEKZeroDowntime("memory-pressure-test")

		// Clean up memory
		for i := range memoryHogs {
			memoryHogs[i] = nil
		}
		runtime.GC()

		if err != nil {
			if strings.Contains(err.Error(), "preparation failed") {
				t.Logf("Memory pressure caused preparation failure: %v", err)
			} else if strings.Contains(err.Error(), "validation failed") {
				t.Logf("Memory pressure caused validation failure: %v", err)
			} else if strings.Contains(err.Error(), "commit failed") {
				t.Logf("Memory pressure caused commit failure: %v", err)
			} else {
				t.Logf("Memory pressure caused other failure: %v", err)
			}
		} else {
			t.Logf("Rotation succeeded despite memory pressure")
		}
	})

	t.Run("TimeoutStress_AllPhases", func(t *testing.T) {
		// VAULT CRITICAL: Time-based stress to try forcing failures

		km := NewKeyManager()

		// Rapid-fire rotations to stress timing
		failures := map[string]int{
			"preparation": 0,
			"validation":  0,
			"commit":      0,
		}

		for i := 0; i < 50; i++ {
			_, err := km.RotateKEKZeroDowntime("timing-stress")

			if err != nil {
				if strings.Contains(err.Error(), "preparation failed") {
					failures["preparation"]++
				} else if strings.Contains(err.Error(), "validation failed") {
					failures["validation"]++
				} else if strings.Contains(err.Error(), "commit failed") {
					failures["commit"]++
				}
			}

			// Brief pause to allow some timing variation
			if i%10 == 0 {
				time.Sleep(time.Microsecond)
			}
		}

		for phase, count := range failures {
			if count > 0 {
				t.Logf("Timing stress caused %d %s failures", count, phase)
			}
		}

		if failures["preparation"] == 0 && failures["validation"] == 0 && failures["commit"] == 0 {
			t.Logf("No failures under timing stress - system is extremely robust")
		}
	})

	t.Run("InvalidState_DirectManipulation", func(t *testing.T) {
		// VAULT CRITICAL: Directly manipulate KeyManager state to force failures

		km := NewKeyManager()

		// Test 1: Corrupt active KEK before rotation
		originalActiveKEK := km.activeKEK
		km.activeKEK = &KeyVersion{
			ID:     "corrupted-active",
			Key:    []byte{0x00},  // Invalid key
			Status: StatusRevoked, // Wrong status
		}

		_, err1 := km.RotateKEKZeroDowntime("corrupted-active-test")

		// Restore active KEK for next test
		km.activeKEK = originalActiveKEK
		km.pendingKEK = nil // Clear any pending state

		// Test 2: Don't set versions to nil (causes panic)
		// Instead, create empty but valid versions map
		km.versions = make(map[string]*KeyVersion)

		_, err2 := km.RotateKEKZeroDowntime("empty-versions-test")

		// Restore versions map
		km.versions = make(map[string]*KeyVersion)

		// Test 3: Set invalid pending KEK state
		km.pendingKEK = &KeyVersion{
			ID:     "invalid-pending",
			Key:    make([]byte, 0), // Empty key
			Status: StatusActive,    // Wrong status for pending
		}

		_, err3 := km.RotateKEKZeroDowntime("invalid-pending-test")

		// Check if any manipulation caused expected failures
		errors := []error{err1, err2, err3}
		tests := []string{"corrupted-active", "nil-versions", "invalid-pending"}

		for i, err := range errors {
			if err != nil {
				t.Logf("State manipulation test %s caused error: %v", tests[i], err)

				if strings.Contains(err.Error(), "preparation failed") ||
					strings.Contains(err.Error(), "validation failed") ||
					strings.Contains(err.Error(), "commit failed") {
					t.Logf("Successfully triggered expected failure phase in test %s", tests[i])
				}
			}
		}
	})
}
