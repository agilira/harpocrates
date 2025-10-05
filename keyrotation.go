// keyrotation.go: Key rotation utilities for NEMESIS vault key management
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	goerrors "github.com/agilira/go-errors"
	"github.com/agilira/go-timecache"
)

// KeyVersion represents a specific version of a cryptographic key
type KeyVersion struct {
	ID        string                 `json:"id"`                 // Unique identifier for the key version
	Key       []byte                 `json:"-"`                  // The cryptographic key (not serialized in JSON for security)
	KeyB64    string                 `json:"key,omitempty"`      // Key in base64 for export/import when needed
	Version   int                    `json:"version"`            // Incremental version number
	CreatedAt time.Time              `json:"created_at"`         // Creation timestamp
	Status    string                 `json:"status"`             // "active", "pending", "deprecated", "revoked"
	Algorithm string                 `json:"algorithm"`          // Cryptographic algorithm used
	Purpose   string                 `json:"purpose"`            // Purpose of the key (e.g. "KEK", "DEK", "signature")
	Metadata  map[string]interface{} `json:"metadata,omitempty"` // Additional metadata

	// Performance optimization: cached cipher to eliminate overhead aes.NewCipher + cipher.NewGCM
	cachedGCM cipher.AEAD `json:"-"` // Cache of the GCM for performance - not serialized
}

// initCachedGCM initializes the cached GCM cipher for optimal performance
func (kv *KeyVersion) initCachedGCM() error {
	block, err := aes.NewCipher(kv.Key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	kv.cachedGCM = gcm
	return nil
}

// getCachedGCM returns the cached GCM or initializes it if necessary
func (kv *KeyVersion) getCachedGCM() (cipher.AEAD, error) {
	if kv.cachedGCM == nil {
		if err := kv.initCachedGCM(); err != nil {
			return nil, err
		}
	}
	return kv.cachedGCM, nil
}

// KeyManager manages key rotations for the NEMESIS vault
type KeyManager struct {
	mu          sync.RWMutex           // Mutex for thread safety
	activeKEK   *KeyVersion            // Active KEK for encryption
	pendingKEK  *KeyVersion            // Pending KEK for preparation/validation
	previousKEK *KeyVersion            // Previous KEK (for decrypt legacy)
	versions    map[string]*KeyVersion // Store all versions
	maxVersions int                    // Maximum number of versions to keep
}

// Error codes for key rotation
const (
	ErrCodeKeyNotFound      = "KEY_NOT_FOUND"
	ErrCodeKeyInactive      = "KEY_INACTIVE"
	ErrCodeKeyGeneration    = "KEY_GENERATION"
	ErrCodeKeyRotation      = "KEY_ROTATION"
	ErrCodeKeyValidation    = "KEY_VALIDATION"
	ErrCodeKeySerialization = "KEY_SERIALIZATION"
)

// Key status constants
const (
	StatusActive     = "active"     // Active key for encryption/decryption
	StatusPending    = "pending"    // Key in preparation for activation
	StatusValidating = "validating" // Key in validation phase
	StatusDeprecated = "deprecated" // Deprecated key (for decryption only)
	StatusRevoked    = "revoked"    // Revoked key (not usable)
)

// NewKeyManager creates a new key manager
func NewKeyManager() *KeyManager {
	return &KeyManager{
		versions:    make(map[string]*KeyVersion),
		maxVersions: 10, // Default: keep 10 versions maximum
	}
}

// NewKeyManagerWithOptions creates a key manager with custom options
func NewKeyManagerWithOptions(maxVersions int) *KeyManager {
	km := NewKeyManager()
	km.maxVersions = maxVersions
	return km
}

// GenerateKEK generates a new KEK (Key Encryption Key) for NEMESIS
func (km *KeyManager) GenerateKEK(purpose string) (*KeyVersion, error) {
	// THREAD SAFETY: Lock for the entire operation
	km.mu.Lock()
	defer km.mu.Unlock()

	return km.generateKEKLocked(purpose)
}

// generateKEKLocked is the internal implementation that assumes the mutex is already held
func (km *KeyManager) generateKEKLocked(purpose string) (*KeyVersion, error) {
	key, err := GenerateKey()
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeKeyGeneration, "failed to generate KEK")
		return nil, fmt.Errorf("key generation failed: %w", richErr)
	}

	// Genera ID unico per la versione
	idBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		richErr := goerrors.Wrap(err, ErrCodeKeyGeneration, "failed to generate key ID")
		return nil, fmt.Errorf("key ID generation failed: %w", richErr)
	}

	version := &KeyVersion{
		ID:        fmt.Sprintf("kek_%x", idBytes),
		Key:       key,
		Version:   km.getNextVersion(),
		CreatedAt: timecache.CachedTime().UTC(),
		Status:    StatusPending,
		Algorithm: "AES-256-GCM",
		Purpose:   purpose,
		Metadata: map[string]interface{}{
			"generator": "go-crypto",
			"type":      "KEK",
		},
	}

	// Performance optimization: pre-compute GCM cipher for this KeyVersion
	if err := version.initCachedGCM(); err != nil {
		return nil, fmt.Errorf("failed to initialize cached GCM: %w", err)
	}

	km.versions[version.ID] = version
	return version, nil
}

// ActivateKEK activates a KEK as the current key
func (km *KeyManager) ActivateKEK(keyID string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	version, exists := km.versions[keyID]
	if !exists {
		richErr := goerrors.New(ErrCodeKeyNotFound, fmt.Sprintf("key ID %s not found", keyID))
		return fmt.Errorf("key not found: %w", richErr)
	}

	if version.Status == StatusRevoked {
		richErr := goerrors.New(ErrCodeKeyInactive, fmt.Sprintf("cannot activate revoked key %s", keyID))
		return fmt.Errorf("key revoked: %w", richErr)
	}

	// Validate the key
	if err := ValidateKey(version.Key); err != nil {
		richErr := goerrors.Wrap(err, ErrCodeKeyValidation, "key validation failed")
		return fmt.Errorf("invalid key: %w", richErr)
	}

	// Deprecate the current key if it exists
	if km.activeKEK != nil {
		km.previousKEK = km.activeKEK
		km.activeKEK.Status = StatusDeprecated
	}

	// Activate the new key
	version.Status = StatusActive
	km.activeKEK = version

	return nil
}

// RotateKEK performs a full KEK rotation by generating and activating a new key
func (km *KeyManager) RotateKEK(purpose string) (*KeyVersion, error) {
	// Generate new KEK
	newKEK, err := km.GenerateKEK(purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new KEK: %w", err)
	}

	// Activate immediately
	if err := km.ActivateKEK(newKEK.ID); err != nil {
		richErr := goerrors.Wrap(err, ErrCodeKeyRotation, "failed to activate new KEK")
		return nil, fmt.Errorf("KEK rotation failed: %w", richErr)
	}

	// Cleanup old versions if necessary
	km.cleanupOldVersions()

	return newKEK, nil
}

// PrepareKEKRotation prepares a new KEK for zero-downtime rotation
// Phase 1: Generate the new KEK in pending state without impacting the active one
func (km *KeyManager) PrepareKEKRotation(purpose string) (*KeyVersion, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Check if a rotation is already in progress
	if km.pendingKEK != nil {
		richErr := goerrors.New(ErrCodeKeyRotation, "rotation already in progress")
		return nil, fmt.Errorf("rotation in progress: %w", richErr)
	}

	// Generate new KEK in pending state (using locked version since we already hold the mutex)
	newKEK, err := km.generateKEKLocked(purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new KEK: %w", err)
	}

	// Set as pending instead of active
	newKEK.Status = StatusPending
	km.pendingKEK = newKEK

	return newKEK, nil
}

// ValidateKEKRotation validates that the new KEK works correctly
// Phase 2: Test encrypt/decrypt with the new KEK before activating it
func (km *KeyManager) ValidateKEKRotation() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.pendingKEK == nil {
		richErr := goerrors.New(ErrCodeKeyRotation, "no pending KEK to validate")
		return fmt.Errorf("no pending KEK: %w", richErr)
	}

	// Validation test: generate test data and try encrypt/decrypt
	testContext := []byte("validation-test-context")
	testData := []byte("zero-downtime-validation-test-data")

	// Derive a test key using the pending KEK
	testDEK, err := DeriveKeyHKDF(km.pendingKEK.Key, nil, testContext, 32)
	if err != nil {
		km.pendingKEK.Status = StatusRevoked
		richErr := goerrors.Wrap(err, ErrCodeKeyValidation, "failed to derive test key")
		return fmt.Errorf("KEK validation failed: %w", richErr)
	}

	// Test encrypt/decrypt with the derived key
	encrypted, err := EncryptBytes(testData, testDEK)
	if err != nil {
		km.pendingKEK.Status = StatusRevoked
		Zeroize(testDEK)
		richErr := goerrors.Wrap(err, ErrCodeKeyValidation, "failed to encrypt test data")
		return fmt.Errorf("KEK validation failed: %w", richErr)
	}

	decrypted, err := DecryptBytes(encrypted, testDEK)
	if err != nil {
		km.pendingKEK.Status = StatusRevoked
		Zeroize(testDEK)
		richErr := goerrors.Wrap(err, ErrCodeKeyValidation, "failed to decrypt test data")
		return fmt.Errorf("KEK validation failed: %w", richErr)
	}

	// Verify that the decrypted data matches the original
	if string(decrypted) != string(testData) {
		km.pendingKEK.Status = StatusRevoked
		Zeroize(testDEK)
		richErr := goerrors.New(ErrCodeKeyValidation, "decrypted data does not match original")
		return fmt.Errorf("KEK validation failed: %w", richErr)
	}

	// Cleanup test data
	Zeroize(testDEK)
	Zeroize(decrypted)

	// Promote the KEK to validating status
	km.pendingKEK.Status = StatusValidating

	return nil
}

// CommitKEKRotation completes the rotation by activating the new KEK
// Phase 3: Activate the new KEK while keeping the old one available for decrypt
func (km *KeyManager) CommitKEKRotation() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.pendingKEK == nil || km.pendingKEK.Status != StatusValidating {
		richErr := goerrors.New(ErrCodeKeyRotation, "no validated pending KEK to commit")
		return fmt.Errorf("no validated KEK to commit: %w", richErr)
	}

	// Move the current KEK to previous if it exists
	if km.activeKEK != nil {
		km.previousKEK = km.activeKEK
		km.activeKEK.Status = StatusDeprecated
	}

	// Activate the new KEK
	km.pendingKEK.Status = StatusActive
	km.activeKEK = km.pendingKEK
	km.pendingKEK = nil

	// Cleanup old versions if necessary
	km.cleanupOldVersions()

	return nil
}

// RollbackKEKRotation undoes an ongoing rotation
func (km *KeyManager) RollbackKEKRotation() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.pendingKEK == nil {
		// SECURITY FIX: Fail if no rotation in progress to prevent race condition success
		richErr := goerrors.New(ErrCodeKeyRotation, "no rotation in progress to rollback")
		return fmt.Errorf("no rotation to rollback: %w", richErr)
	}

	// Revoke the pending KEK
	km.pendingKEK.Status = StatusRevoked
	if km.pendingKEK.Key != nil {
		Zeroize(km.pendingKEK.Key)
	}

	km.pendingKEK = nil

	return nil
}

// RotateKEKZeroDowntime runs the full zero-downtime KEK rotation process
// Complete orchestration: prepare -> validate -> commit with automatic rollback on error
func (km *KeyManager) RotateKEKZeroDowntime(purpose string) (*KeyVersion, error) {
	// Phase 1: Prepare the new KEK
	newKEK, err := km.PrepareKEKRotation(purpose)
	if err != nil {
		return nil, fmt.Errorf("preparation failed: %w", err)
	}

	// Phase 2: Validate the new KEK
	if err := km.ValidateKEKRotation(); err != nil {
		// Automatic rollback on validation failure
		_ = km.RollbackKEKRotation()
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Phase 3: Commit the rotation
	if err := km.CommitKEKRotation(); err != nil {
		// Automatic rollback on commit failure
		_ = km.RollbackKEKRotation()
		return nil, fmt.Errorf("commit failed: %w", err)
	}

	return newKEK, nil
}

// GetCurrentKEK returns the current active KEK
func (km *KeyManager) GetCurrentKEK() (*KeyVersion, error) {
	if km.activeKEK == nil {
		richErr := goerrors.New(ErrCodeKeyNotFound, "no active KEK found")
		return nil, fmt.Errorf("no active KEK: %w", richErr)
	}

	if km.activeKEK.Status != StatusActive {
		richErr := goerrors.New(ErrCodeKeyInactive, "current KEK is not active")
		return nil, fmt.Errorf("KEK inactive: %w", richErr)
	}

	return km.activeKEK, nil
}

// GetKEKByID returns a specific KEK by ID (for legacy data decryption)
func (km *KeyManager) GetKEKByID(keyID string) (*KeyVersion, error) {
	version, exists := km.versions[keyID]
	if !exists {
		richErr := goerrors.New(ErrCodeKeyNotFound, fmt.Sprintf("key ID %s not found", keyID))
		return nil, fmt.Errorf("key not found: %w", richErr)
	}

	if version.Status == StatusRevoked {
		richErr := goerrors.New(ErrCodeKeyInactive, fmt.Sprintf("key %s is revoked", keyID))
		return nil, fmt.Errorf("key revoked: %w", richErr)
	}

	return version, nil
}

// ListKEKs returns all KEKs with their status
func (km *KeyManager) ListKEKs() []*KeyVersion {
	versions := make([]*KeyVersion, 0, len(km.versions))
	for _, version := range km.versions {
		// Create a copy for safety without the actual key
		safeCopy := &KeyVersion{
			ID:        version.ID,
			Version:   version.Version,
			CreatedAt: version.CreatedAt,
			Status:    version.Status,
			Algorithm: version.Algorithm,
			Purpose:   version.Purpose,
			Metadata:  version.Metadata,
		}
		versions = append(versions, safeCopy)
	}
	return versions
}

// RevokeKEK revokes a specific KEK
func (km *KeyManager) RevokeKEK(keyID string) error {
	version, exists := km.versions[keyID]
	if !exists {
		richErr := goerrors.New(ErrCodeKeyNotFound, fmt.Sprintf("key ID %s not found", keyID))
		return fmt.Errorf("key not found: %w", richErr)
	}

	// Cannot revoke the current active KEK without rotating first
	if km.activeKEK != nil && km.activeKEK.ID == keyID {
		richErr := goerrors.New(ErrCodeKeyRotation, "cannot revoke current active KEK - rotate first")
		return fmt.Errorf("cannot revoke active KEK: %w", richErr)
	}

	version.Status = StatusRevoked

	// Zero out the key for safety
	Zeroize(version.Key)
	version.Key = nil

	return nil
}

// DeriveDataKey derives a DEK (Data Encryption Key) from the current KEK using HKDF
func (km *KeyManager) DeriveDataKey(context []byte, keyLength int) ([]byte, string, error) {
	currentKEK, err := km.GetCurrentKEK()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get current KEK: %w", err)
	}

	// Use HKDF to derive the DEK
	dek, err := DeriveKeyHKDF(currentKEK.Key, nil, context, keyLength)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeKeyGeneration, "DEK derivation failed")
		return nil, "", fmt.Errorf("DEK derivation failed: %w", richErr)
	}

	return dek, currentKEK.ID, nil
}

// DecryptWithKEK decrypts data using a specific KEK (for backward compatibility)
func (km *KeyManager) DecryptWithKEK(encryptedData string, kekID string) (string, error) {
	kek, err := km.GetKEKByID(kekID)
	if err != nil {
		return "", fmt.Errorf("failed to get KEK %s: %w", kekID, err)
	}

	return Decrypt(encryptedData, kek.Key)
}

// ExportKeyMaterial exports the keys in a secure format (without the actual keys)
func (km *KeyManager) ExportKeyMaterial() ([]byte, error) {
	exportData := struct {
		Versions    map[string]*KeyVersion `json:"versions"`
		CurrentKEK  string                 `json:"current_kek,omitempty"`
		PreviousKEK string                 `json:"previous_kek,omitempty"`
		MaxVersions int                    `json:"max_versions"`
	}{
		Versions:    make(map[string]*KeyVersion),
		MaxVersions: km.maxVersions,
	}

	// Copy versions without the actual keys
	for id, version := range km.versions {
		safeCopy := &KeyVersion{
			ID:        version.ID,
			Version:   version.Version,
			CreatedAt: version.CreatedAt,
			Status:    version.Status,
			Algorithm: version.Algorithm,
			Purpose:   version.Purpose,
			Metadata:  version.Metadata,
		}
		exportData.Versions[id] = safeCopy
	}

	if km.activeKEK != nil {
		exportData.CurrentKEK = km.activeKEK.ID
	}
	if km.previousKEK != nil {
		exportData.PreviousKEK = km.previousKEK.ID
	}

	data, err := json.Marshal(exportData)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeKeySerialization, "failed to marshal key material")
		return nil, fmt.Errorf("export failed: %w", richErr)
	}

	return data, nil
}

// Helper functions

// getNextVersion calculates the next version number
func (km *KeyManager) getNextVersion() int {
	maxVersion := 0
	for _, version := range km.versions {
		if version.Version > maxVersion {
			maxVersion = version.Version
		}
	}
	return maxVersion + 1
}

// cleanupOldVersions removes old versions beyond the limit
func (km *KeyManager) cleanupOldVersions() {
	if len(km.versions) <= km.maxVersions {
		return
	}

	// Collect revoked or very old versions
	toDelete := make([]string, 0)
	for id, version := range km.versions {
		if version.Status == StatusRevoked {
			toDelete = append(toDelete, id)
		}
	}

	// Removes the identified versions
	for _, id := range toDelete {
		if km.activeKEK != nil && km.activeKEK.ID == id {
			continue // Do not remove the current key
		}
		if km.previousKEK != nil && km.previousKEK.ID == id {
			continue // Do not remove the previous key (for decrypt)
		}

		// Zero out the key before removal
		if version := km.versions[id]; version != nil && version.Key != nil {
			Zeroize(version.Key)
		}
		delete(km.versions, id)
	}
}

// EncryptWithKEK encrypts using a specific KEK with cached cipher for optimal performance
func (km *KeyManager) EncryptWithKEK(plaintext string, kekID string) (string, error) {
	km.mu.RLock()
	kek, exists := km.versions[kekID]
	km.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("KEK %s not found", kekID)
	}

	return kek.EncryptWithCachedGCM(plaintext)
}

// EncryptWithCachedGCM encrypts using the cached GCM for optimal performance - eliminates overhead of aes.NewCipher + cipher.NewGCM
func (kv *KeyVersion) EncryptWithCachedGCM(plaintext string) (string, error) {
	plaintextBytes := []byte(plaintext)
	return kv.EncryptBytesWithCachedGCM(plaintextBytes)
}

// EncryptBytesWithCachedGCM encrypts bytes using the cached GCM - core optimization for 500k ops/sec target
func (kv *KeyVersion) EncryptBytesWithCachedGCM(plaintext []byte) (string, error) {
	gcm, err := kv.getCachedGCM()
	if err != nil {
		return "", fmt.Errorf("failed to get cached GCM: %w", err)
	}

	// Use buffer pooling for the nonce
	nonceBuffer := getBuffer(gcm.NonceSize())
	defer putBuffer(nonceBuffer)
	nonce := (*nonceBuffer)[:gcm.NonceSize()]

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Optimization: use buffer pooling for ciphertext
	expectedSize := len(nonce) + len(plaintext) + gcm.Overhead()
	ciphertextBuf := getDynamicBuffer()
	defer putDynamicBuffer(ciphertextBuf)

	if cap(ciphertextBuf) < expectedSize {
		ciphertextBuf = make([]byte, 0, expectedSize)
	} else {
		ciphertextBuf = ciphertextBuf[:0]
	}

	// Append nonce, then seal
	ciphertextBuf = append(ciphertextBuf, nonce...)
	ciphertext := gcm.Seal(ciphertextBuf, nonce, plaintext, nil) // #nosec G407 -- nonce is generated from crypto/rand

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
