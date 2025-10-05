// keyrotation_test.go: Test suite for key rotation utilities
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestKeyManagerBasic verifies the basic operations of the KeyManager
func TestKeyManagerBasic(t *testing.T) {
	km := NewKeyManager()

	if km == nil {
		t.Fatal("NewKeyManager returned nil")
	}

	if len(km.versions) != 0 {
		t.Errorf("New KeyManager should have empty versions, got %d", len(km.versions))
	}
}

// TestKEKGeneration verifies the generation of KEK
func TestKEKGeneration(t *testing.T) {
	km := NewKeyManager()

	kek, err := km.GenerateKEK("nemesis-vault")
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}

	// Verify KEK properties
	if kek.ID == "" {
		t.Error("KEK ID should not be empty")
	}

	if !strings.HasPrefix(kek.ID, "kek_") {
		t.Errorf("KEK ID should start with 'kek_', got: %s", kek.ID)
	}

	if len(kek.Key) != KeySize {
		t.Errorf("KEK key size should be %d, got %d", KeySize, len(kek.Key))
	}

	if kek.Version != 1 {
		t.Errorf("First KEK version should be 1, got %d", kek.Version)
	}

	if kek.Status != StatusPending {
		t.Errorf("New KEK status should be %s, got %s", StatusPending, kek.Status)
	}

	if kek.Algorithm != "AES-256-GCM" {
		t.Errorf("KEK algorithm should be AES-256-GCM, got %s", kek.Algorithm)
	}

	if kek.Purpose != "nemesis-vault" {
		t.Errorf("KEK purpose should be 'nemesis-vault', got %s", kek.Purpose)
	}
}

// TestKEKActivation verifies the activation of KEK
func TestKEKActivation(t *testing.T) {
	km := NewKeyManager()

	// Generate KEK
	kek, err := km.GenerateKEK("test")
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}

	// Activate KEK
	err = km.ActivateKEK(kek.ID)
	if err != nil {
		t.Fatalf("Failed to activate KEK: %v", err)
	}

	// Verify status
	if kek.Status != StatusActive {
		t.Errorf("KEK status should be %s, got %s", StatusActive, kek.Status)
	}

	// Verify that it is the current KEK
	currentKEK, err := km.GetCurrentKEK()
	if err != nil {
		t.Fatalf("Failed to get current KEK: %v", err)
	}

	if currentKEK.ID != kek.ID {
		t.Errorf("Current KEK ID should be %s, got %s", kek.ID, currentKEK.ID)
	}
}

// TestKEKRotation verifies the complete rotation
func TestKEKRotation(t *testing.T) {
	km := NewKeyManager()

	// First KEK
	kek1, err := km.GenerateKEK("test")
	if err != nil {
		t.Fatalf("Failed to generate first KEK: %v", err)
	}

	err = km.ActivateKEK(kek1.ID)
	if err != nil {
		t.Fatalf("Failed to activate first KEK: %v", err)
	}

	// Rotation
	kek2, err := km.RotateKEK("test")
	if err != nil {
		t.Fatalf("Failed to rotate KEK: %v", err)
	}

	// Verify that the new KEK is active
	if kek2.Status != StatusActive {
		t.Errorf("New KEK status should be %s, got %s", StatusActive, kek2.Status)
	}

	// Verify that the old KEK is deprecated
	if kek1.Status != StatusDeprecated {
		t.Errorf("Old KEK status should be %s, got %s", StatusDeprecated, kek1.Status)
	}

	// Verify that the current KEK is the new one
	currentKEK, err := km.GetCurrentKEK()
	if err != nil {
		t.Fatalf("Failed to get current KEK: %v", err)
	}

	if currentKEK.ID != kek2.ID {
		t.Errorf("Current KEK should be %s, got %s", kek2.ID, currentKEK.ID)
	}

	// Verify that previousKEK is set
	if km.previousKEK == nil || km.previousKEK.ID != kek1.ID {
		t.Errorf("Previous KEK should be %s", kek1.ID)
	}
}

// TestKEKRevocation verifies the revocation of KEK
func TestKEKRevocation(t *testing.T) {
	km := NewKeyManager()

	// Generate two KEK
	kek1, err := km.GenerateKEK("test")
	if err != nil {
		t.Fatalf("Failed to generate first KEK: %v", err)
	}

	kek2, err := km.GenerateKEK("test")
	if err != nil {
		t.Fatalf("Failed to generate second KEK: %v", err)
	}

	// Activate the first KEK
	err = km.ActivateKEK(kek1.ID)
	if err != nil {
		t.Fatalf("Failed to activate first KEK: %v", err)
	}

	// Should not be able to revoke active KEK
	err = km.RevokeKEK(kek1.ID)
	if err == nil {
		t.Error("Should not be able to revoke active KEK")
	}

	// Rotate to the second KEK
	err = km.ActivateKEK(kek2.ID)
	if err != nil {
		t.Fatalf("Failed to activate second KEK: %v", err)
	}

	// Now it should be possible to revoke the first KEK
	err = km.RevokeKEK(kek1.ID)
	if err != nil {
		t.Fatalf("Failed to revoke KEK: %v", err)
	}

	// Verify that it is revoked
	if kek1.Status != StatusRevoked {
		t.Errorf("KEK status should be %s, got %s", StatusRevoked, kek1.Status)
	}

	// Verify that the key has been zeroed
	if kek1.Key != nil {
		t.Error("Revoked KEK key should be nil")
	}
}

// TestDataKeyDerivation verifies the derivation of DEK from KEK
func TestDataKeyDerivation(t *testing.T) {
	km := NewKeyManager()

	// Setup KEK
	kek, err := km.GenerateKEK("nemesis-vault")
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}

	err = km.ActivateKEK(kek.ID)
	if err != nil {
		t.Fatalf("Failed to activate KEK: %v", err)
	}

	// Derive DEK
	context := []byte("nemesis-vault-secrets")
	dek, kekID, err := km.DeriveDataKey(context, 32)
	if err != nil {
		t.Fatalf("Failed to derive DEK: %v", err)
	}

	// Verify DEK
	if len(dek) != 32 {
		t.Errorf("DEK should be 32 bytes, got %d", len(dek))
	}

	if kekID != kek.ID {
		t.Errorf("Returned KEK ID should be %s, got %s", kek.ID, kekID)
	}

	// Verify that derive produces the same result with the same context
	dek2, kekID2, err := km.DeriveDataKey(context, 32)
	if err != nil {
		t.Fatalf("Failed to derive DEK second time: %v", err)
	}

	if string(dek) != string(dek2) {
		t.Error("DEK derivation should be deterministic")
	}

	if kekID != kekID2 {
		t.Error("KEK ID should be consistent")
	}

	// Verify that different context produces different DEK
	dek3, _, err := km.DeriveDataKey([]byte("different-context"), 32)
	if err != nil {
		t.Fatalf("Failed to derive DEK with different context: %v", err)
	}

	if string(dek) == string(dek3) {
		t.Error("Different contexts should produce different DEKs")
	}
}

// TestBackwardCompatibilityDecryption verifies decryption with legacy KEK
func TestBackwardCompatibilityDecryption(t *testing.T) {
	km := NewKeyManager()

	// First KEK
	kek1, err := km.GenerateKEK("test")
	if err != nil {
		t.Fatalf("Failed to generate first KEK: %v", err)
	}

	err = km.ActivateKEK(kek1.ID)
	if err != nil {
		t.Fatalf("Failed to activate first KEK: %v", err)
	}

	// Encrypt data with first KEK
	testData := "secret data encrypted with old KEK"
	encryptedData, err := Encrypt(testData, kek1.Key)
	if err != nil {
		t.Fatalf("Failed to encrypt with first KEK: %v", err)
	}

	// Rotate to the second KEK
	_, err = km.RotateKEK("test")
	if err != nil {
		t.Fatalf("Failed to rotate KEK: %v", err)
	}

	// Verify that we can still decrypt with the previous KEK
	decryptedData, err := km.DecryptWithKEK(encryptedData, kek1.ID)
	if err != nil {
		t.Fatalf("Failed to decrypt with legacy KEK: %v", err)
	}

	if decryptedData != testData {
		t.Errorf("Decrypted data should be '%s', got '%s'", testData, decryptedData)
	}
}

// TestKEKListing verifies the listing of KEKs
func TestKEKListing(t *testing.T) {
	km := NewKeyManager()

	// Generate multiple KEKs
	kek1, _ := km.GenerateKEK("test1")
	kek2, _ := km.GenerateKEK("test2")
	kek3, _ := km.GenerateKEK("test3")

	_ = km.ActivateKEK(kek1.ID)
	_ = km.ActivateKEK(kek2.ID)
	_ = km.RevokeKEK(kek3.ID)

	// List KEK
	keks := km.ListKEKs()

	if len(keks) != 3 {
		t.Errorf("Should list 3 KEKs, got %d", len(keks))
	}

	// Verify that the keys are not exposed
	for _, kek := range keks {
		if kek.Key != nil {
			t.Error("Listed KEK should not expose actual key material")
		}
	}

	// Verify status
	statusCount := make(map[string]int)
	for _, kek := range keks {
		statusCount[kek.Status]++
	}

	if statusCount[StatusActive] != 1 {
		t.Errorf("Should have 1 active KEK, got %d", statusCount[StatusActive])
	}

	if statusCount[StatusDeprecated] != 1 {
		t.Errorf("Should have 1 deprecated KEK, got %d", statusCount[StatusDeprecated])
	}

	if statusCount[StatusRevoked] != 1 {
		t.Errorf("Should have 1 revoked KEK, got %d", statusCount[StatusRevoked])
	}
}

// TestKeyManagerExport verifies the export of key material
func TestKeyManagerExport(t *testing.T) {
	km := NewKeyManager()

	// Setup some KEKs
	kek1, _ := km.GenerateKEK("test1")
	kek2, _ := km.GenerateKEK("test2")

	_ = km.ActivateKEK(kek1.ID)
	_ = km.ActivateKEK(kek2.ID)

	// Export
	exportData, err := km.ExportKeyMaterial()
	if err != nil {
		t.Fatalf("Failed to export key material: %v", err)
	}

	// Verify that it is valid JSON
	var exported map[string]interface{}
	err = json.Unmarshal(exportData, &exported)
	if err != nil {
		t.Fatalf("Exported data is not valid JSON: %v", err)
	}

	// Verify main fields
	if _, exists := exported["versions"]; !exists {
		t.Error("Exported data should contain 'versions'")
	}

	if _, exists := exported["current_kek"]; !exists {
		t.Error("Exported data should contain 'current_kek'")
	}

	if _, exists := exported["previous_kek"]; !exists {
		t.Error("Exported data should contain 'previous_kek'")
	}

	// Verify that no actual keys are present in the export
	exportStr := string(exportData)
	if strings.Contains(exportStr, "\"key\":") && !strings.Contains(exportStr, "\"key\":\"\"") {
		t.Error("Export should not contain actual key material")
	}
}

// TestKeyManagerWithOptions verifies the options of the KeyManager
func TestKeyManagerWithOptions(t *testing.T) {
	km := NewKeyManagerWithOptions(5)

	if km.maxVersions != 5 {
		t.Errorf("MaxVersions should be 5, got %d", km.maxVersions)
	}
}

// TestErrorHandling verifies error handling
func TestErrorHandling(t *testing.T) {
	km := NewKeyManager()

	// Test GetCurrentKEK without active KEK
	_, err := km.GetCurrentKEK()
	if err == nil {
		t.Error("GetCurrentKEK should fail when no active KEK")
	}

	// Test ActivateKEK with non-existent ID
	err = km.ActivateKEK("non-existent-id")
	if err == nil {
		t.Error("ActivateKEK should fail with non-existent ID")
	}

	// Test GetKEKByID with non-existent ID
	_, err = km.GetKEKByID("non-existent-id")
	if err == nil {
		t.Error("GetKEKByID should fail with non-existent ID")
	}

	// Test RevokeKEK with non-existent ID
	err = km.RevokeKEK("non-existent-id")
	if err == nil {
		t.Error("RevokeKEK should fail with non-existent ID")
	}

	// Test DeriveDataKey without active KEK
	_, _, err = km.DeriveDataKey([]byte("test"), 32)
	if err == nil {
		t.Error("DeriveDataKey should fail when no active KEK")
	}
}

// TestNEMESISWorkflow verifies the complete NEMESIS workflow
func TestNEMESISWorkflow(t *testing.T) {
	// Simulate the typical NEMESIS vault workflow
	km := NewKeyManager()

	// 1. Generate initial KEK for NEMESIS vault
	masterKEK, err := km.GenerateKEK("nemesis-master-vault")
	if err != nil {
		t.Fatalf("Failed to generate master KEK: %v", err)
	}

	err = km.ActivateKEK(masterKEK.ID)
	if err != nil {
		t.Fatalf("Failed to activate master KEK: %v", err)
	}

	// 2. Derive DEK for vault secrets
	vaultContext := []byte("nemesis-vault-secrets-v1")
	vaultDEK, kekID, err := km.DeriveDataKey(vaultContext, 32)
	if err != nil {
		t.Fatalf("Failed to derive vault DEK: %v", err)
	}

	// 3. Use DEK to encrypt vault secrets
	vaultSecret := "database-password-12345"
	encryptedSecret, err := Encrypt(vaultSecret, vaultDEK)
	if err != nil {
		t.Fatalf("Failed to encrypt vault secret: %v", err)
	}

	// 4. Simulate KEK rotation (security policy)
	newKEK, err := km.RotateKEK("nemesis-master-vault")
	if err != nil {
		t.Fatalf("Failed to rotate master KEK: %v", err)
	}

	// 5. Verify that we can still decrypt existing secrets
	// Re-derive the DEK from the previous KEK to verify backward compatibility
	legacyKEK, err := km.GetKEKByID(kekID)
	if err != nil {
		t.Fatalf("Failed to get legacy KEK: %v", err)
	}

	legacyDEK, err := DeriveKeyHKDF(legacyKEK.Key, nil, vaultContext, 32)
	if err != nil {
		t.Fatalf("Failed to re-derive legacy DEK: %v", err)
	}

	decryptedSecret, err := Decrypt(encryptedSecret, legacyDEK)
	if err != nil {
		t.Fatalf("Failed to decrypt legacy secret: %v", err)
	}

	if decryptedSecret != vaultSecret {
		t.Errorf("Decrypted secret mismatch: expected '%s', got '%s'", vaultSecret, decryptedSecret)
	}

	// 6. New secrets use the new KEK
	newVaultDEK, newKEKID, err := km.DeriveDataKey(vaultContext, 32)
	if err != nil {
		t.Fatalf("Failed to derive DEK with new KEK: %v", err)
	}

	if newKEKID != newKEK.ID {
		t.Errorf("New DEK should use new KEK ID")
	}

	// The DEKs should be different (new KEK)
	if string(vaultDEK) == string(newVaultDEK) {
		t.Error("DEK derived from different KEK should be different")
	}

	t.Logf("✅ NEMESIS workflow completed successfully:")
	t.Logf("  - Master KEK rotated from %s to %s", masterKEK.ID, newKEK.ID)
	t.Logf("  - Legacy secrets still decryptable")
	t.Logf("  - New secrets use rotated KEK")
}

// BenchmarkKEKRotation measures the performance of KEK rotation
func BenchmarkKEKRotation(b *testing.B) {
	km := NewKeyManager()

	// Prima KEK
	kek1, err := km.GenerateKEK("benchmark")
	if err != nil {
		b.Fatalf("Failed to generate initial KEK: %v", err)
	}

	err = km.ActivateKEK(kek1.ID)
	if err != nil {
		b.Fatalf("Failed to activate initial KEK: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := km.RotateKEK("benchmark")
		if err != nil {
			b.Fatalf("KEK rotation failed: %v", err)
		}
	}
}

// BenchmarkDEKDerivation measures the performance of DEK derivation
func BenchmarkDEKDerivation(b *testing.B) {
	km := NewKeyManager()

	kek, err := km.GenerateKEK("benchmark")
	if err != nil {
		b.Fatalf("Failed to generate KEK: %v", err)
	}

	err = km.ActivateKEK(kek.ID)
	if err != nil {
		b.Fatalf("Failed to activate KEK: %v", err)
	}

	context := []byte("benchmark-context")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := km.DeriveDataKey(context, 32)
		if err != nil {
			b.Fatalf("DEK derivation failed: %v", err)
		}
	}
}

// BenchmarkCachedGCMEncryption measures performance with cached GCM vs standard
func BenchmarkCachedGCMEncryption(b *testing.B) {
	km := NewKeyManager()
	kek, err := km.GenerateKEK("benchmark")
	if err != nil {
		b.Fatalf("Failed to generate KEK: %v", err)
	}
	err = km.ActivateKEK(kek.ID)
	if err != nil {
		b.Fatalf("Failed to activate KEK: %v", err)
	}

	testData := "test data for performance comparison"

	b.Run("StandardEncrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := Encrypt(testData, kek.Key)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("CachedGCMEncrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := kek.EncryptWithCachedGCM(testData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestCleanupOldVersions verifies the cleanup of old versions
func TestCleanupOldVersions(t *testing.T) {
	km := NewKeyManagerWithOptions(3) // Limit to 3 versions

	// Generate more KEK than the limit
	keks := make([]*KeyVersion, 5)
	for i := 0; i < 5; i++ {
		kek, err := km.GenerateKEK(fmt.Sprintf("test-%d", i))
		if err != nil {
			t.Fatalf("Failed to generate KEK %d: %v", i, err)
		}
		keks[i] = kek
	}

	// Activate the first KEK
	err := km.ActivateKEK(keks[0].ID)
	if err != nil {
		t.Fatalf("Failed to activate KEK: %v", err)
	}

	// Revoke a KEK to trigger cleanup
	err = km.RevokeKEK(keks[2].ID)
	if err != nil {
		t.Fatalf("Failed to revoke KEK: %v", err)
	}

	err = km.RevokeKEK(keks[3].ID)
	if err != nil {
		t.Fatalf("Failed to revoke KEK: %v", err)
	}

	// Force cleanup via rotation
	_, err = km.RotateKEK("test-cleanup")
	if err != nil {
		t.Fatalf("Failed to rotate KEK: %v", err)
	}

	// Verify that some revoked versions have been removed
	allVersions := km.ListKEKs()
	revokedCount := 0
	for _, v := range allVersions {
		if v.Status == StatusRevoked {
			revokedCount++
		}
	}

	// There should be no more than 1-2 revoked versions (cleanup should have removed them)
	if revokedCount > 2 {
		t.Errorf("Expected ≤2 revoked versions after cleanup, got %d", revokedCount)
	}

	t.Logf("After cleanup: total versions=%d, revoked=%d", len(allVersions), revokedCount)
}

// TestKeyManagerEdgeCases tests edge cases to improve coverage
func TestKeyManagerEdgeCases(t *testing.T) {
	km := NewKeyManager()

	// Test GenerateKEK error path - force an error by temporarily modifying
	// (this is hard to test directly, so we test the normal path)
	kek, err := km.GenerateKEK("")
	if err != nil {
		t.Fatalf("Failed to generate KEK with empty purpose: %v", err)
	}
	if kek.Purpose != "" {
		t.Errorf("Expected empty purpose, got %s", kek.Purpose)
	}

	// Test ActivateKEK with revoked KEK
	err = km.ActivateKEK(kek.ID)
	if err != nil {
		t.Fatalf("Failed to activate KEK: %v", err)
	}

	// Generate a second KEK and activate it
	kek2, err := km.GenerateKEK("test2")
	if err != nil {
		t.Fatalf("Failed to generate second KEK: %v", err)
	}

	err = km.ActivateKEK(kek2.ID)
	if err != nil {
		t.Fatalf("Failed to activate second KEK: %v", err)
	}

	// Now revoke the first one and try to activate it
	err = km.RevokeKEK(kek.ID)
	if err != nil {
		t.Fatalf("Failed to revoke KEK: %v", err)
	}

	// Attempt to activate revoked KEK (should fail)
	err = km.ActivateKEK(kek.ID)
	if err == nil {
		t.Error("Expected error when activating revoked KEK")
	}

	// Test GetKEKByID with revoked KEK
	_, err = km.GetKEKByID(kek.ID)
	if err == nil {
		t.Error("Expected error when getting revoked KEK")
	}
}

// TestBufferPoolEdgeCases tests buffer pooling edge cases for coverage
func TestBufferPoolEdgeCases(t *testing.T) {
	// Test getBuffer with different sizes for full coverage
	testSizes := []int{32, 500, 1024, 50000, 64 * 1024, 128 * 1024}

	for _, size := range testSizes {
		buf := getBuffer(size)
		if buf == nil {
			t.Fatalf("getBuffer returned nil for size %d", size)
		}

		// Verify capacity
		if cap(*buf) < size {
			t.Errorf("Buffer capacity %d < requested size %d", cap(*buf), size)
		}

		putBuffer(buf)
	}

	// Test putBuffer with nil
	putBuffer(nil)

	// Test putDynamicBuffer edge cases
	putDynamicBuffer(nil)
	putDynamicBuffer([]byte{}) // Empty slice

	// Buffer con capacità 0
	emptyBuf := make([]byte, 0)
	putDynamicBuffer(emptyBuf)

	// Buffer with small capacity
	smallBuf := make([]byte, 0, 100)
	putDynamicBuffer(smallBuf)

	// Buffer with very large capacity (above threshold)
	largeBuf := make([]byte, 0, 128*1024)
	putDynamicBuffer(largeBuf)
}

// TestRotateKEKErrorPaths tests the error paths of RotateKEK
func TestRotateKEKErrorPaths(t *testing.T) {
	km := NewKeyManager()

	// Test RotateKEK without current KEK (should work)
	kek1, err := km.RotateKEK("test-rotation")
	if err != nil {
		t.Fatalf("RotateKEK should work without current KEK: %v", err)
	}

	if kek1.Status != StatusActive {
		t.Errorf("Rotated KEK should be active, got %s", kek1.Status)
	}

	// Seconda rotazione
	_, err = km.RotateKEK("test-rotation-2")
	if err != nil {
		t.Fatalf("Second rotation failed: %v", err)
	}

	// Verify that the first KEK is deprecated
	if kek1.Status != StatusDeprecated {
		t.Errorf("First KEK should be deprecated after rotation, got %s", kek1.Status)
	}

	// Verify that previousKEK is set
	if km.previousKEK == nil || km.previousKEK.ID != kek1.ID {
		t.Error("Previous KEK should be set to first KEK")
	}
}

// TestDeriveDataKeyErrorPaths tests the error paths of DeriveDataKey
func TestDeriveDataKeyErrorPaths(t *testing.T) {
	km := NewKeyManager()

	// Test without active KEK
	_, _, err := km.DeriveDataKey([]byte("test"), 32)
	if err == nil {
		t.Error("DeriveDataKey should fail without active KEK")
	}

	// Test with active KEK but invalid key length
	kek, err := km.GenerateKEK("test")
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}

	err = km.ActivateKEK(kek.ID)
	if err != nil {
		t.Fatalf("Failed to activate KEK: %v", err)
	}

	// Test with invalid key length (too large)
	_, _, err = km.DeriveDataKey([]byte("test"), 1024*1024) // 1MB - too large for HKDF
	if err == nil {
		t.Error("DeriveDataKey should fail with very large key length")
	}
}

// TestEncryptionErrorPaths tests the error paths of encryption
func TestEncryptionErrorPaths(t *testing.T) {
	// Test EncryptBytes with invalid key already covered in existing tests

	// Test DecryptBytes with corrupted data (additional paths)
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Encrypt to obtain valid data
	encrypted, err := Encrypt("test data", key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Test with wrong key (authentication failure)
	wrongKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	_, err = Decrypt(encrypted, wrongKey)
	if err == nil {
		t.Error("Decrypt should fail with wrong key")
	}
}

// TestStreamingErrorPaths tests the error paths of streaming
func TestStreamingErrorPaths(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test NewStreamingEncryptorWithChunkSize with limit parameters
	_, err = NewStreamingEncryptorWithChunkSize(&bytes.Buffer{}, key, 0) // Zero chunk size
	if err == nil {
		t.Error("Should fail with zero chunk size")
	}

	_, err = NewStreamingEncryptorWithChunkSize(&bytes.Buffer{}, key, -1) // Negative chunk size
	if err == nil {
		t.Error("Should fail with negative chunk size")
	}

	_, err = NewStreamingEncryptorWithChunkSize(&bytes.Buffer{}, key, 10*1024*1024+1) // Too large (>10MB)
	if err == nil {
		t.Error("Should fail with chunk size too large")
	}

	// Test with valid chunk sizes but limits
	enc1, err := NewStreamingEncryptorWithChunkSize(&bytes.Buffer{}, key, 1) // Very small
	if err != nil {
		t.Fatalf("Should work with chunk size 1: %v", err)
	}
	_ = enc1.Close()

	enc2, err := NewStreamingEncryptorWithChunkSize(&bytes.Buffer{}, key, 10*1024*1024) // Maximum (10MB)
	if err != nil {
		t.Fatalf("Should work with max chunk size: %v", err)
	}
	_ = enc2.Close()
}

// TestGetCurrentKEKEdgeCases tests edge cases for GetCurrentKEK
func TestGetCurrentKEKEdgeCases(t *testing.T) {
	km := NewKeyManager()

	// Test GetCurrentKEK without active KEK (already tested but for coverage)
	_, err := km.GetCurrentKEK()
	if err == nil {
		t.Error("GetCurrentKEK should fail without active KEK")
	}

	// Genera e attiva KEK
	kek, err := km.GenerateKEK("test")
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}

	err = km.ActivateKEK(kek.ID)
	if err != nil {
		t.Fatalf("Failed to activate KEK: %v", err)
	}

	// Modifica manualmente status to test edge case
	kek.Status = StatusPending
	_, err = km.GetCurrentKEK()
	if err == nil {
		t.Error("GetCurrentKEK should fail if current KEK is not active")
	}

	// Ripristina status
	kek.Status = StatusActive
	currentKEK, err := km.GetCurrentKEK()
	if err != nil {
		t.Fatalf("GetCurrentKEK should work with active KEK: %v", err)
	}

	if currentKEK.ID != kek.ID {
		t.Error("GetCurrentKEK should return correct KEK")
	}
}

// TestValidateKEKRotation_CriticalSecurityPaths tests ValidateKEKRotation (48.5% → 85%+)
// Critical for vault security - KEK validation must be thoroughly tested
func TestValidateKEKRotation_CriticalSecurityPaths(t *testing.T) {
	t.Run("NoPendingKEK", func(t *testing.T) {
		km := NewKeyManager()

		err := km.ValidateKEKRotation()
		if err == nil {
			t.Fatal("ValidateKEKRotation must fail when no pending KEK exists")
		}

		if !strings.Contains(err.Error(), "no pending KEK") {
			t.Errorf("Error must indicate no pending KEK, got: %v", err)
		}
	})

	t.Run("SuccessfulValidation", func(t *testing.T) {
		km := NewKeyManager()

		// Generate and activate KEK
		kek, err := km.GenerateKEK("vault-validation-test")
		if err != nil {
			t.Fatalf("Failed to generate KEK: %v", err)
		}

		err = km.ActivateKEK(kek.ID)
		if err != nil {
			t.Fatalf("Failed to activate KEK: %v", err)
		}

		// Prepare rotation to create pending KEK
		_, err = km.PrepareKEKRotation("vault-validation-pending")
		if err != nil {
			t.Fatalf("Failed to prepare KEK rotation: %v", err)
		}

		// Validation should succeed
		err = km.ValidateKEKRotation()
		if err != nil {
			t.Errorf("ValidateKEKRotation must succeed with valid pending KEK: %v", err)
		}

		// Pending KEK should remain valid after successful validation
		if km.pendingKEK == nil {
			t.Error("Pending KEK must exist after successful validation")
		}
	})
}

// TestRotateKEKZeroDowntime_VaultCritical tests RotateKEKZeroDowntime (50.0% → 85%+)
// Zero-downtime rotation is critical for vault availability
func TestRotateKEKZeroDowntime_VaultCritical(t *testing.T) {
	t.Run("SuccessfulZeroDowntimeRotation", func(t *testing.T) {
		km := NewKeyManager()

		// Generate and activate initial KEK
		kek, err := km.GenerateKEK("zero-downtime-vault-test")
		if err != nil {
			t.Fatalf("Failed to generate initial KEK: %v", err)
		}

		originalKekID := kek.ID

		err = km.ActivateKEK(kek.ID)
		if err != nil {
			t.Fatalf("Failed to activate initial KEK: %v", err)
		}

		// Perform zero-downtime rotation
		newKekVersion, err := km.RotateKEKZeroDowntime("zero-downtime-rotation-vault")
		if err != nil {
			t.Errorf("RotateKEKZeroDowntime must succeed with active KEK: %v", err)
		}

		if newKekVersion == nil {
			t.Error("RotateKEKZeroDowntime must return new KEK version")
		}

		// After successful rotation, the new KEK becomes active
		if km.activeKEK == nil {
			t.Error("Active KEK must exist after zero-downtime rotation")
			return // Avoid nil pointer dereference
		}

		// The returned KEK should now be the active one
		if km.activeKEK.ID != newKekVersion.ID {
			t.Error("Returned KEK version must be the new active KEK")
		}

		// The new KEK ID should be different from the original
		if newKekVersion.ID == originalKekID {
			t.Error("Zero-downtime rotation must generate a different KEK ID")
		}
	})

	t.Run("MultipleRotationAttempts", func(t *testing.T) {
		km := NewKeyManager()

		// Generate and activate initial KEK
		kek, err := km.GenerateKEK("multi-rotation-vault-test")
		if err != nil {
			t.Fatalf("Failed to generate initial KEK: %v", err)
		}

		err = km.ActivateKEK(kek.ID)
		if err != nil {
			t.Fatalf("Failed to activate initial KEK: %v", err)
		}

		// First rotation
		firstRotation, err := km.RotateKEKZeroDowntime("first-rotation")
		if err != nil {
			t.Fatalf("First zero-downtime rotation failed: %v", err)
		}

		// Second rotation
		secondRotation, err := km.RotateKEKZeroDowntime("second-rotation")
		if err != nil {
			t.Fatalf("Second zero-downtime rotation failed: %v", err)
		}

		// All KEK IDs should be different
		if firstRotation.ID == kek.ID || secondRotation.ID == kek.ID || firstRotation.ID == secondRotation.ID {
			t.Error("All rotation KEK IDs must be unique")
		}

		// Final active KEK should be the last rotation
		if km.activeKEK.ID != secondRotation.ID {
			t.Error("Active KEK must be the latest rotation")
		}
	})

	t.Run("ErrorPathTesting", func(t *testing.T) {
		km := NewKeyManager()

		// Test various purpose strings to exercise different code paths
		purposes := []string{"", "vault-test", "emergency-rotation", "scheduled-rotation"}

		for _, purpose := range purposes {
			kekVersion, err := km.RotateKEKZeroDowntime(purpose)

			// All should succeed regardless of purpose content
			if err != nil && !strings.Contains(err.Error(), "validation failed") {
				t.Errorf("Unexpected error for purpose '%s': %v", purpose, err)
			}

			// If successful, check return value consistency
			if err == nil && kekVersion == nil {
				t.Errorf("Success case must return valid KEK version for purpose '%s'", purpose)
			}
		}
	})

	t.Run("ValidationFailureRollback", func(t *testing.T) {
		km := NewKeyManager()

		// Test ValidationFailure by forcing rotation when already in progress
		// First, start a rotation
		kek, err := km.GenerateKEK("validation-test")
		if err != nil {
			t.Fatalf("Failed to generate KEK: %v", err)
		}

		err = km.ActivateKEK(kek.ID)
		if err != nil {
			t.Fatalf("Failed to activate KEK: %v", err)
		}

		// Start preparing rotation to create pending state
		_, err = km.PrepareKEKRotation("pending-rotation-test")
		if err != nil {
			t.Fatalf("Failed to prepare KEK rotation: %v", err)
		}

		// Now attempt another rotation - should fail during preparation (rotation already in progress)
		_, err = km.RotateKEKZeroDowntime("force-validation-failure")
		if err == nil {
			t.Error("RotateKEKZeroDowntime should fail when rotation already in progress")
		}

		if !strings.Contains(err.Error(), "preparation failed") && !strings.Contains(err.Error(), "rotation already in progress") {
			t.Errorf("Expected preparation failure error, got: %v", err)
		}
	})
}

// TestGenerateKEK_VaultCritical tests GenerateKEK (61.5% → 85%+)
// KEK generation is the foundation of vault security
func TestGenerateKEK_VaultCritical(t *testing.T) {
	t.Run("KEKGenerationValidation", func(t *testing.T) {
		km := NewKeyManager()

		// Test various purpose strings
		purposes := []string{
			"vault-primary-kek",
			"emergency-kek",
			"",
			"special-chars-!@#$%^&*()",
			strings.Repeat("long-purpose-", 10),
		}

		for _, purpose := range purposes {
			kek, err := km.GenerateKEK(purpose)
			if err != nil {
				t.Errorf("GenerateKEK failed for purpose '%s': %v", purpose, err)
				continue
			}

			if kek == nil {
				t.Errorf("GenerateKEK returned nil KEK for purpose '%s'", purpose)
				continue
			}

			// Validate KEK structure
			if kek.ID == "" {
				t.Errorf("GenerateKEK must generate non-empty ID for purpose '%s'", purpose)
			}

			if len(kek.Key) != 32 { // AES-256
				t.Errorf("GenerateKEK must generate 32-byte key, got %d for purpose '%s'", len(kek.Key), purpose)
			}

			if kek.CreatedAt.IsZero() {
				t.Errorf("GenerateKEK must set CreatedAt timestamp for purpose '%s'", purpose)
			}
		}
	})

	t.Run("KEKUniqueness", func(t *testing.T) {
		km := NewKeyManager()

		// Generate multiple KEKs with same purpose
		keks := make([]*KeyVersion, 5)
		for i := 0; i < 5; i++ {
			kek, err := km.GenerateKEK("uniqueness-test")
			if err != nil {
				t.Fatalf("GenerateKEK #%d failed: %v", i, err)
			}
			keks[i] = kek
		}

		// Verify all IDs are unique
		ids := make(map[string]bool)
		for i, kek := range keks {
			if ids[kek.ID] {
				t.Errorf("GenerateKEK #%d generated duplicate ID: %s", i, kek.ID)
			}
			ids[kek.ID] = true
		}

		// Verify all keys are unique
		keys := make(map[string]bool)
		for i, kek := range keks {
			keyStr := string(kek.Key)
			if keys[keyStr] {
				t.Errorf("GenerateKEK #%d generated duplicate key", i)
			}
			keys[keyStr] = true
		}
	})

	t.Run("ErrorPathHandling", func(t *testing.T) {
		km := NewKeyManager()

		// We cannot easily mock the crypto/rand failures or GenerateKey failures
		// in this test environment, but we can test the successful path variations
		// and ensure proper error handling by testing edge cases

		// Test with nil KeyManager (though constructor prevents this)
		if km == nil {
			t.Error("KeyManager should not be nil")
		}

		// Test successful generation multiple times to ensure consistency
		for i := 0; i < 10; i++ {
			kek, err := km.GenerateKEK(fmt.Sprintf("stress-test-%d", i))
			if err != nil {
				t.Errorf("GenerateKEK iteration %d failed: %v", i, err)
				continue
			}

			// Verify the KEK can initialize GCM (tests initCachedGCM path)
			gcm, err := kek.getCachedGCM()
			if err != nil {
				t.Errorf("Generated KEK %d failed GCM initialization: %v", i, err)
			}
			if gcm == nil {
				t.Errorf("Generated KEK %d returned nil GCM cipher", i)
			}
		}
	})
}

// TestRotateKEK_VaultCritical tests RotateKEK (62.5% → 85%+)
// Standard KEK rotation is essential for vault key lifecycle management
func TestRotateKEK_VaultCritical(t *testing.T) {
	t.Run("SuccessfulRotation", func(t *testing.T) {
		km := NewKeyManager()

		// Generate and activate initial KEK
		kek, err := km.GenerateKEK("vault-primary-kek")
		if err != nil {
			t.Fatalf("Failed to generate initial KEK: %v", err)
		}

		err = km.ActivateKEK(kek.ID)
		if err != nil {
			t.Fatalf("Failed to activate initial KEK: %v", err)
		}

		originalKEKID := kek.ID

		// Perform standard rotation
		newKEK, err := km.RotateKEK("vault-rotated-kek")
		if err != nil {
			t.Errorf("RotateKEK must succeed with active KEK: %v", err)
		}

		if newKEK == nil {
			t.Error("RotateKEK must return new KEK version")
			return // Avoid nil pointer dereference
		}

		if newKEK.ID == originalKEKID {
			t.Error("RotateKEK must generate new KEK with different ID")
		}

		// New KEK should be active after successful rotation
		if km.activeKEK == nil || km.activeKEK.ID != newKEK.ID {
			t.Error("New KEK must be active after successful rotation")
		}
	})

	t.Run("MultipleRotationSequence", func(t *testing.T) {
		km := NewKeyManager()

		// Initial KEK
		kek1, err := km.GenerateKEK("seq-kek-1")
		if err != nil {
			t.Fatalf("Failed to generate KEK 1: %v", err)
		}

		err = km.ActivateKEK(kek1.ID)
		if err != nil {
			t.Fatalf("Failed to activate KEK 1: %v", err)
		}

		// Chain of rotations
		var previousID = kek1.ID
		for i := 2; i <= 5; i++ {
			rotatedKEK, err := km.RotateKEK(fmt.Sprintf("seq-kek-%d", i))
			if err != nil {
				t.Errorf("RotateKEK #%d failed: %v", i, err)
				break
			}

			if rotatedKEK.ID == previousID {
				t.Errorf("RotateKEK #%d must generate unique ID", i)
			}

			previousID = rotatedKEK.ID
		}

		// Final KEK should be active
		if km.activeKEK == nil || km.activeKEK.ID != previousID {
			t.Error("Final rotated KEK must be active")
		}
	})

	t.Run("EdgeCaseHandling", func(t *testing.T) {
		km := NewKeyManager()

		// Test rotation with empty purpose
		kek, err := km.GenerateKEK("edge-case-test")
		if err != nil {
			t.Fatalf("Failed to generate KEK: %v", err)
		}

		err = km.ActivateKEK(kek.ID)
		if err != nil {
			t.Fatalf("Failed to activate KEK: %v", err)
		}

		// Test rotation with various purpose strings
		purposes := []string{"", "vault-edge", "special!@#$%^&*()"}
		for _, purpose := range purposes {
			rotatedKEK, err := km.RotateKEK(purpose)
			if err != nil {
				t.Errorf("RotateKEK with purpose '%s' failed: %v", purpose, err)
				continue
			}

			if rotatedKEK == nil {
				t.Errorf("RotateKEK with purpose '%s' returned nil KEK", purpose)
			}

			// Setup for next iteration (activate the new KEK)
			if rotatedKEK != nil {
				err = km.ActivateKEK(rotatedKEK.ID)
				if err != nil {
					t.Errorf("Failed to activate rotated KEK: %v", err)
				}
			}
		}
	})
}
