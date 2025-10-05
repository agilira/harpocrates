// export_vault_test.go: Test cases for Vault Export functions.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestExportKeyMaterial_VaultSecurity tests ExportKeyMaterial (84.6% → 85%+)
// Key export is critical for vault backup and recovery operations
func TestExportKeyMaterial_VaultSecurity(t *testing.T) {
	t.Run("EmptyKeyManagerExport", func(t *testing.T) {
		km := NewKeyManager()

		// Test export from empty key manager
		exportData, err := km.ExportKeyMaterial()
		if err != nil {
			t.Errorf("ExportKeyMaterial should succeed on empty manager: %v", err)
		}

		if exportData == nil {
			t.Error("ExportKeyMaterial must return non-nil data")
		}

		// Verify the exported data structure
		var exported struct {
			Versions    map[string]interface{} `json:"versions"`
			CurrentKEK  string                 `json:"current_kek,omitempty"`
			PreviousKEK string                 `json:"previous_kek,omitempty"`
			MaxVersions int                    `json:"max_versions"`
		}

		err = json.Unmarshal(exportData, &exported)
		if err != nil {
			t.Errorf("Exported data should be valid JSON: %v", err)
		}

		if exported.Versions == nil {
			t.Error("Exported data must contain versions map")
		}

		if len(exported.Versions) != 0 {
			t.Error("Empty manager should export empty versions map")
		}

		if exported.CurrentKEK != "" {
			t.Error("Empty manager should have no current KEK")
		}

		if exported.PreviousKEK != "" {
			t.Error("Empty manager should have no previous KEK")
		}
	})

	t.Run("SingleKEKExport", func(t *testing.T) {
		km := NewKeyManager()

		// Generate single KEK
		kek, err := km.GenerateKEK("vault-export-single")
		if err != nil {
			t.Fatalf("Failed to generate KEK: %v", err)
		}

		err = km.ActivateKEK(kek.ID)
		if err != nil {
			t.Fatalf("Failed to activate KEK: %v", err)
		}

		// Export with single active KEK
		exportData, err := km.ExportKeyMaterial()
		if err != nil {
			t.Errorf("ExportKeyMaterial with single KEK failed: %v", err)
		}

		var exported struct {
			Versions    map[string]interface{} `json:"versions"`
			CurrentKEK  string                 `json:"current_kek"`
			PreviousKEK string                 `json:"previous_kek,omitempty"`
			MaxVersions int                    `json:"max_versions"`
		}

		err = json.Unmarshal(exportData, &exported)
		if err != nil {
			t.Errorf("Failed to parse exported JSON: %v", err)
		}

		if len(exported.Versions) != 1 {
			t.Errorf("Expected 1 version in export, got %d", len(exported.Versions))
		}

		if exported.CurrentKEK != kek.ID {
			t.Errorf("CurrentKEK mismatch: expected %s, got %s", kek.ID, exported.CurrentKEK)
		}

		if exported.PreviousKEK != "" {
			t.Error("Single KEK export should have no previous KEK")
		}
	})

	t.Run("MultipleKEKExportWithRotation", func(t *testing.T) {
		km := NewKeyManager()

		// Generate initial KEK
		kek1, err := km.GenerateKEK("vault-export-multi-1")
		if err != nil {
			t.Fatalf("Failed to generate KEK 1: %v", err)
		}

		err = km.ActivateKEK(kek1.ID)
		if err != nil {
			t.Fatalf("Failed to activate KEK 1: %v", err)
		}

		// Rotate to create previous KEK
		kek2, err := km.RotateKEK("vault-export-multi-2")
		if err != nil {
			t.Fatalf("Failed to rotate KEK: %v", err)
		}

		// Generate additional KEK
		kek3, err := km.GenerateKEK("vault-export-multi-3")
		if err != nil {
			t.Fatalf("Failed to generate KEK 3: %v", err)
		}

		// Export with multiple KEKs
		exportData, err := km.ExportKeyMaterial()
		if err != nil {
			t.Errorf("ExportKeyMaterial with multiple KEKs failed: %v", err)
		}

		var exported struct {
			Versions    map[string]interface{} `json:"versions"`
			CurrentKEK  string                 `json:"current_kek"`
			PreviousKEK string                 `json:"previous_kek"`
			MaxVersions int                    `json:"max_versions"`
		}

		err = json.Unmarshal(exportData, &exported)
		if err != nil {
			t.Errorf("Failed to parse multi-KEK export JSON: %v", err)
		}

		if len(exported.Versions) < 2 {
			t.Errorf("Expected at least 2 versions in export, got %d", len(exported.Versions))
		}

		if exported.CurrentKEK != kek2.ID {
			t.Errorf("CurrentKEK should be rotated KEK %s, got %s", kek2.ID, exported.CurrentKEK)
		}

		if exported.PreviousKEK != kek1.ID {
			t.Errorf("PreviousKEK should be original KEK %s, got %s", kek1.ID, exported.PreviousKEK)
		}

		// Verify kek3 is in versions but not current/previous
		if _, exists := exported.Versions[kek3.ID]; !exists {
			t.Error("KEK 3 should be in exported versions")
		}
	})

	t.Run("SecurityValidation", func(t *testing.T) {
		km := NewKeyManager()

		// Generate KEK with sensitive data
		kek, err := km.GenerateKEK("vault-security-validation")
		if err != nil {
			t.Fatalf("Failed to generate KEK: %v", err)
		}

		err = km.ActivateKEK(kek.ID)
		if err != nil {
			t.Fatalf("Failed to activate KEK: %v", err)
		}

		// Export and verify no sensitive data is included
		exportData, err := km.ExportKeyMaterial()
		if err != nil {
			t.Errorf("ExportKeyMaterial security test failed: %v", err)
		}

		exportStr := string(exportData)

		// Verify actual key material is NOT exported
		keyStr := string(kek.Key)
		if strings.Contains(exportStr, keyStr) {
			t.Error("Exported data MUST NOT contain actual key material")
		}

		// Verify sensitive fields are not exported
		if strings.Contains(exportStr, "\"key\":") {
			t.Error("Exported data MUST NOT contain key field")
		}

		// Verify safe fields are exported
		if !strings.Contains(exportStr, kek.ID) {
			t.Error("Exported data must contain KEK ID")
		}

		if !strings.Contains(exportStr, kek.Algorithm) {
			t.Error("Exported data must contain algorithm info")
		}

		if !strings.Contains(exportStr, kek.Purpose) {
			t.Error("Exported data must contain purpose info")
		}
	})

	t.Run("ErrorPathCoverage", func(t *testing.T) {
		km := NewKeyManager()

		// Generate KEK with problematic metadata to potentially trigger marshaling issues
		kek, err := km.GenerateKEK("vault-error-path-test")
		if err != nil {
			t.Fatalf("Failed to generate KEK: %v", err)
		}

		// Add potentially problematic metadata
		if kek.Metadata == nil {
			kek.Metadata = make(map[string]interface{})
		}
		kek.Metadata["complex_data"] = map[string]interface{}{
			"nested": map[string]interface{}{
				"level1": "value1",
				"level2": []string{"item1", "item2"},
			},
		}
		kek.Metadata["nil_value"] = nil
		kek.Metadata["empty_string"] = ""

		err = km.ActivateKEK(kek.ID)
		if err != nil {
			t.Fatalf("Failed to activate KEK: %v", err)
		}

		// Test export with complex metadata (should still work with json.Marshal)
		exportData, err := km.ExportKeyMaterial()
		if err != nil {
			t.Errorf("ExportKeyMaterial should handle complex metadata: %v", err)
		}

		if exportData == nil {
			t.Error("ExportKeyMaterial must return data even with complex metadata")
		}

		// Verify the data is valid JSON
		var result map[string]interface{}
		err = json.Unmarshal(exportData, &result)
		if err != nil {
			t.Errorf("Exported data should be valid JSON even with complex metadata: %v", err)
		}
	})
}
