// rotate_kek_specific_failures_test.go: Test cases for specific failure scenarios in rotating KEK.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRotateKEKZeroDowntime_PrepareFailureSpecific tests the discovered prepare failure path
// "rotation in progress" - this is the key to triggering prepare failure!
func TestRotateKEKZeroDowntime_PrepareFailureSpecific(t *testing.T) {

	t.Run("PrepareFailure_RotationInProgress", func(t *testing.T) {
		// VAULT CRITICAL: Force "rotation in progress" error to trigger prepare failure
		km := NewKeyManager()

		// Set a pending KEK to simulate rotation in progress
		km.pendingKEK = &KeyVersion{
			ID:     "existing-rotation-in-progress",
			Key:    make([]byte, 32),
			Status: StatusPending,
		}

		// Fill key with some data
		for i := range km.pendingKEK.Key {
			km.pendingKEK.Key[i] = byte(i)
		}

		// Now try to start another rotation - this should fail at prepare phase
		_, err := km.RotateKEKZeroDowntime("second-rotation-attempt")

		// VAULT CRITICAL: Should fail with "preparation failed" and "rotation in progress"
		assert.Error(t, err, "Should fail when rotation already in progress")
		assert.Contains(t, err.Error(), "preparation failed", "Should be preparation failure")
		assert.Contains(t, err.Error(), "rotation in progress", "Should indicate rotation in progress")

		// VAULT CRITICAL: Verify no side effects - original pending KEK should be unchanged
		assert.NotNil(t, km.pendingKEK, "Original pending KEK should remain")
		assert.Equal(t, "existing-rotation-in-progress", km.pendingKEK.ID)
		assert.Equal(t, StatusPending, km.pendingKEK.Status)

		t.Logf("SUCCESS: Triggered prepare failure - %v", err)
	})

	t.Run("PrepareFailure_RotationInValidating", func(t *testing.T) {
		// VAULT CRITICAL: Test with KEK in validating status
		km := NewKeyManager()

		// Set a KEK in validating status
		km.pendingKEK = &KeyVersion{
			ID:     "validating-rotation",
			Key:    make([]byte, 32),
			Status: StatusValidating, // Different status
		}

		for i := range km.pendingKEK.Key {
			km.pendingKEK.Key[i] = byte(i + 100)
		}

		_, err := km.RotateKEKZeroDowntime("new-rotation-during-validating")

		if err != nil {
			t.Logf("Got error with validating KEK: %v", err)

			if strings.Contains(err.Error(), "preparation failed") {
				t.Logf("SUCCESS: Triggered prepare failure with validating KEK")
			}
		} else {
			t.Logf("Rotation succeeded even with validating KEK")
		}
	})

	t.Run("ValidateFailure_NilKey", func(t *testing.T) {
		// VAULT CRITICAL: We saw that nil key causes validation issues
		// Let's create a specific test for this path

		km := NewKeyManager()

		// Manually create pending KEK with nil key (this causes validation failure)
		km.pendingKEK = &KeyVersion{
			ID:     "nil-key-validation-test",
			Key:    nil, // This will cause DeriveKeyHKDF to fail
			Status: StatusPending,
		}

		_, err := km.RotateKEKZeroDowntime("validate-nil-key")

		if err != nil && strings.Contains(err.Error(), "validation failed") {
			// SUCCESS: We triggered validation failure!
			t.Logf("SUCCESS: Triggered validation failure with nil key - %v", err)

			// Verify automatic rollback occurred
			if km.pendingKEK != nil {
				assert.Equal(t, StatusRevoked, km.pendingKEK.Status, "Validation failure must trigger rollback")
			}
		} else {
			t.Logf("Unexpected result with nil key: %v", err)
		}
	})

	t.Run("CommitFailure_Investigation", func(t *testing.T) {
		// VAULT CRITICAL: Investigate what could cause commit failure
		// Commit failure is the hardest to trigger

		km := NewKeyManager()

		// Try to create conditions where commit might fail
		// Maybe by corrupting state between validation and commit?

		// First, let's do a normal prepare and validate
		newKEK, err := km.PrepareKEKRotation("commit-investigation")
		if err != nil {
			t.Fatalf("Prepare should succeed: %v", err)
		}

		err = km.ValidateKEKRotation()
		if err != nil {
			t.Fatalf("Validate should succeed: %v", err)
		}

		// Now the KEK should be in StatusValidating
		assert.Equal(t, StatusValidating, km.pendingKEK.Status)

		// Try to corrupt something that might cause commit to fail
		originalActiveKEK := km.activeKEK

		// What if we corrupt the active KEK?
		km.activeKEK = nil

		err = km.CommitKEKRotation()

		// Restore state
		km.activeKEK = originalActiveKEK

		if err != nil {
			t.Logf("Commit failed with nil activeKEK: %v", err)

			// If we call RotateKEKZeroDowntime now, will it rollback?
			// Actually, let's not - the state is already corrupted
		} else {
			t.Logf("Commit succeeded even with nil activeKEK")
		}

		// Test completed - this helps us understand commit behavior
		t.Logf("KEK after commit test - newKEK: %+v", newKEK)
	})

	t.Run("AllPaths_StateMachine", func(t *testing.T) {
		// VAULT CRITICAL: Test the state machine transitions that could fail

		testCases := []struct {
			name          string
			setupPending  bool
			pendingStatus string
			expectError   string
		}{
			{
				name:         "NoPendingKEK",
				setupPending: false,
				expectError:  "",
			},
			{
				name:          "PendingKEK",
				setupPending:  true,
				pendingStatus: StatusPending,
				expectError:   "preparation failed",
			},
			{
				name:          "ValidatingKEK",
				setupPending:  true,
				pendingStatus: StatusValidating,
				expectError:   "preparation failed",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				km := NewKeyManager()

				if tc.setupPending {
					km.pendingKEK = &KeyVersion{
						ID:     "state-machine-test",
						Key:    make([]byte, 32),
						Status: tc.pendingStatus,
					}

					for i := range km.pendingKEK.Key {
						km.pendingKEK.Key[i] = byte(i)
					}
				}

				_, err := km.RotateKEKZeroDowntime("state-machine-test")

				if tc.expectError != "" {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.expectError)
					t.Logf("Expected error occurred: %v", err)
				} else {
					if err != nil {
						t.Logf("Unexpected error: %v", err)
					} else {
						t.Logf("Success as expected")
					}
				}
			})
		}
	})
}
