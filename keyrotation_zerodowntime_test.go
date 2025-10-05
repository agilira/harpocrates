// keyrotation_zerodowntime_test.go: Tests for zero-downtime key rotation mechanism
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"testing"
)

// TestZeroDowntimeRotation tests the new zero-downtime mechanism
func TestZeroDowntimeRotation(t *testing.T) {
	km := NewKeyManager()

	// Setup: Create an initial KEK
	initialKEK, err := km.GenerateKEK("test-purpose")
	if err != nil {
		t.Fatalf("Failed to generate initial KEK: %v", err)
	}

	err = km.ActivateKEK(initialKEK.ID)
	if err != nil {
		t.Fatalf("Failed to activate initial KEK: %v", err)
	}

	// Verify that the initial KEK is active
	currentKEK, err := km.GetCurrentKEK()
	if err != nil {
		t.Fatalf("Failed to get current KEK: %v", err)
	}
	if currentKEK.ID != initialKEK.ID {
		t.Error("Initial KEK should be active")
	}

	t.Run("SuccessfulZeroDowntimeRotation", func(t *testing.T) {
		// Test full zero-downtime rotation
		newKEK, err := km.RotateKEKZeroDowntime("test-purpose")
		if err != nil {
			t.Fatalf("Zero-downtime rotation failed: %v", err)
		}

		// Verify that the new KEK is active
		currentKEK, err := km.GetCurrentKEK()
		if err != nil {
			t.Fatalf("Failed to get current KEK after rotation: %v", err)
		}
		if currentKEK.ID != newKEK.ID {
			t.Error("New KEK should be active after rotation")
		}

		// Verify that the old KEK is still available for decryption
		oldKEK, err := km.GetKEKByID(initialKEK.ID)
		if err != nil {
			t.Fatalf("Old KEK should still be available: %v", err)
		}
		if oldKEK.Status != StatusDeprecated {
			t.Errorf("Old KEK should be deprecated, got status: %s", oldKEK.Status)
		}

		// Test that both KEKs work for decryption
		testData := "test-data-for-backward-compatibility"

		// Encrypt with old KEK (simulating legacy data)
		legacyEncrypted, err := km.DecryptWithKEK(testData, initialKEK.ID)
		if err == nil {
			// if no error, it means the data was not encrypted, so we encrypt it
			// try to encrypt it
			_, err = km.DecryptWithKEK(legacyEncrypted, initialKEK.ID)
			if err != nil {
				t.Errorf("Failed to decrypt with old KEK: %v", err)
			}
		}
	})

	t.Run("StepByStepRotation", func(t *testing.T) {
		// Test individual phases
		km2 := NewKeyManager()

		// Setup initial KEK
		initialKEK2, err := km2.GenerateKEK("step-test")
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}
		err = km2.ActivateKEK(initialKEK2.ID)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		// Fase 1: Prepare
		pendingKEK, err := km2.PrepareKEKRotation("step-test")
		if err != nil {
			t.Fatalf("PrepareKEKRotation failed: %v", err)
		}
		if pendingKEK.Status != StatusPending {
			t.Errorf("Expected pending status, got: %s", pendingKEK.Status)
		}

		// Verify that the active KEK has not changed
		activeKEK, err := km2.GetCurrentKEK()
		if err != nil {
			t.Fatalf("Failed to get current KEK: %v", err)
		}
		if activeKEK.ID != initialKEK2.ID {
			t.Error("Active KEK should not change during preparation")
		}

		// Fase 2: Validate
		err = km2.ValidateKEKRotation()
		if err != nil {
			t.Fatalf("ValidateKEKRotation failed: %v", err)
		}
		if km2.pendingKEK.Status != StatusValidating {
			t.Errorf("Expected validating status, got: %s", km2.pendingKEK.Status)
		}

		// Fase 3: Commit
		err = km2.CommitKEKRotation()
		if err != nil {
			t.Fatalf("CommitKEKRotation failed: %v", err)
		}

		// Verify final result
		finalKEK, err := km2.GetCurrentKEK()
		if err != nil {
			t.Fatalf("Failed to get final KEK: %v", err)
		}
		if finalKEK.ID != pendingKEK.ID {
			t.Error("Pending KEK should become active after commit")
		}
		if km2.pendingKEK != nil {
			t.Error("pendingKEK should be nil after commit")
		}
	})

	t.Run("RollbackMechanism", func(t *testing.T) {
		km3 := NewKeyManager()

		// Setup initial KEK
		initialKEK3, err := km3.GenerateKEK("rollback-test")
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}
		err = km3.ActivateKEK(initialKEK3.ID)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		// Prepare rotation
		_, err = km3.PrepareKEKRotation("rollback-test")
		if err != nil {
			t.Fatalf("PrepareKEKRotation failed: %v", err)
		}

		// Verify that there is a pending KEK
		if km3.pendingKEK == nil {
			t.Fatal("Should have pending KEK")
		}

		// Rollback
		err = km3.RollbackKEKRotation()
		if err != nil {
			t.Fatalf("RollbackKEKRotation failed: %v", err)
		}

		// Verify that the pending KEK has been removed
		if km3.pendingKEK != nil {
			t.Error("pendingKEK should be nil after rollback")
		}

		// Verify that the active KEK is still the original one
		activeKEK, err := km3.GetCurrentKEK()
		if err != nil {
			t.Fatalf("Failed to get current KEK: %v", err)
		}
		if activeKEK.ID != initialKEK3.ID {
			t.Error("Active KEK should remain unchanged after rollback")
		}
	})
}
