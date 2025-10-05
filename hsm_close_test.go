// hsm_close_test.go: Quick test for HSMManager.Close() to reach >90% coverage
//
// This focused test covers the HSM Manager Close function (currently 77.8%)
// to push us over the >90% coverage threshold for vault production deployment.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHSMProviderForClose is a simple mock for testing Close functionality
type mockHSMProviderForClose struct {
	name        string
	initialized bool
	shouldFail  bool
	closeCalled bool
}

func (m *mockHSMProviderForClose) Name() string    { return m.name }
func (m *mockHSMProviderForClose) Version() string { return "1.0.0" }
func (m *mockHSMProviderForClose) Capabilities() []HSMCapability {
	return []HSMCapability{CapabilityEncrypt}
}
func (m *mockHSMProviderForClose) IsHealthy() bool { return m.initialized }
func (m *mockHSMProviderForClose) Initialize(ctx context.Context, config map[string]interface{}) error {
	m.initialized = true
	return nil
}

func (m *mockHSMProviderForClose) Close() error {
	m.closeCalled = true
	m.initialized = false
	if m.shouldFail {
		return errors.New("mock close failure")
	}
	return nil
}

// Implement remaining interface methods as no-ops for this test
func (m *mockHSMProviderForClose) GenerateKey(ctx HSMOperationContext, keyType KeyType, usage []KeyUsage, params map[string]interface{}) (*HSMKeyInfo, error) {
	return nil, nil
}
func (m *mockHSMProviderForClose) ImportKey(ctx HSMOperationContext, keyMaterial []byte, keyType KeyType, usage []KeyUsage, params map[string]interface{}) (*HSMKeyInfo, error) {
	return nil, nil
}
func (m *mockHSMProviderForClose) DeleteKey(ctx HSMOperationContext) error { return nil }
func (m *mockHSMProviderForClose) ListKeys(ctx context.Context, filter map[string]interface{}) ([]*HSMKeyInfo, error) {
	return nil, nil
}
func (m *mockHSMProviderForClose) GetKeyInfo(ctx HSMOperationContext) (*HSMKeyInfo, error) {
	return nil, nil
}
func (m *mockHSMProviderForClose) Encrypt(ctx HSMOperationContext, plaintext []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockHSMProviderForClose) Decrypt(ctx HSMOperationContext, ciphertext []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockHSMProviderForClose) Sign(ctx HSMOperationContext, data []byte, hashAlgorithm crypto.Hash) ([]byte, error) {
	return nil, nil
}
func (m *mockHSMProviderForClose) Verify(ctx HSMOperationContext, data []byte, signature []byte, hashAlgorithm crypto.Hash) error {
	return nil
}
func (m *mockHSMProviderForClose) DeriveKey(ctx HSMOperationContext, derivationData []byte, outputKeyType KeyType, params map[string]interface{}) (*HSMKeyInfo, error) {
	return nil, nil
}
func (m *mockHSMProviderForClose) WrapKey(ctx HSMOperationContext, targetKeyID string, wrappingParams map[string]interface{}) ([]byte, error) {
	return nil, nil
}
func (m *mockHSMProviderForClose) UnwrapKey(ctx HSMOperationContext, wrappedKey []byte, keyType KeyType, usage []KeyUsage, params map[string]interface{}) (*HSMKeyInfo, error) {
	return nil, nil
}
func (m *mockHSMProviderForClose) GenerateRandom(ctx context.Context, length int) ([]byte, error) {
	return nil, nil
}

// TestHSMManager_CloseOperation validates HSM Manager close functionality
func TestHSMManager_CloseOperation(t *testing.T) {
	t.Run("Close_SucceedsWithMultipleProviders", func(t *testing.T) {
		manager, err := NewHSMManager(nil, nil)
		require.NoError(t, err, "HSM Manager creation must succeed")

		// Register multiple providers
		provider1 := &mockHSMProviderForClose{name: "provider1"}
		provider2 := &mockHSMProviderForClose{name: "provider2"}
		provider3 := &mockHSMProviderForClose{name: "provider3"}

		require.NoError(t, manager.RegisterProvider("provider1", provider1))
		require.NoError(t, manager.RegisterProvider("provider2", provider2))
		require.NoError(t, manager.RegisterProvider("provider3", provider3))

		// Close manager should close all providers
		err = manager.Close()
		assert.NoError(t, err, "Close must succeed when all providers close successfully")

		// Verify all providers were closed
		assert.True(t, provider1.closeCalled, "Provider1 Close() must be called")
		assert.True(t, provider2.closeCalled, "Provider2 Close() must be called")
		assert.True(t, provider3.closeCalled, "Provider3 Close() must be called")

		assert.False(t, provider1.initialized, "Provider1 must be uninitialized after close")
		assert.False(t, provider2.initialized, "Provider2 must be uninitialized after close")
		assert.False(t, provider3.initialized, "Provider3 must be uninitialized after close")
	})

	t.Run("Close_HandlesProviderFailures", func(t *testing.T) {
		manager, err := NewHSMManager(nil, nil)
		require.NoError(t, err, "HSM Manager creation must succeed")

		// Register providers where some will fail to close
		providerSuccess := &mockHSMProviderForClose{name: "success", shouldFail: false}
		providerFail1 := &mockHSMProviderForClose{name: "fail1", shouldFail: true}
		providerFail2 := &mockHSMProviderForClose{name: "fail2", shouldFail: true}

		require.NoError(t, manager.RegisterProvider("success", providerSuccess))
		require.NoError(t, manager.RegisterProvider("fail1", providerFail1))
		require.NoError(t, manager.RegisterProvider("fail2", providerFail2))

		// Close should collect all failures but still attempt to close all providers
		err = manager.Close()
		assert.Error(t, err, "Close must return error when some providers fail to close")

		// Verify all providers had Close() called despite failures
		assert.True(t, providerSuccess.closeCalled, "Successful provider Close() must be called")
		assert.True(t, providerFail1.closeCalled, "Failing provider1 Close() must be called")
		assert.True(t, providerFail2.closeCalled, "Failing provider2 Close() must be called")

		// Verify error message contains information about failed providers
		errorMsg := err.Error()
		assert.Contains(t, errorMsg, "fail1", "Error must mention failing provider fail1")
		assert.Contains(t, errorMsg, "fail2", "Error must mention failing provider fail2")
	})

	t.Run("Close_EmptyManager", func(t *testing.T) {
		manager, err := NewHSMManager(nil, nil)
		require.NoError(t, err, "HSM Manager creation must succeed")

		// Close empty manager should succeed
		err = manager.Close()
		assert.NoError(t, err, "Close must succeed on empty HSM manager")
	})

	t.Run("Close_SingleProviderFailure", func(t *testing.T) {
		manager, err := NewHSMManager(nil, nil)
		require.NoError(t, err, "HSM Manager creation must succeed")

		// Register single failing provider
		failingProvider := &mockHSMProviderForClose{name: "single-failure", shouldFail: true}
		require.NoError(t, manager.RegisterProvider("single-failure", failingProvider))

		// Close should return error for single provider failure
		err = manager.Close()
		assert.Error(t, err, "Close must return error when single provider fails to close")
		assert.Contains(t, err.Error(), "single-failure", "Error must identify the failing provider")
		assert.True(t, failingProvider.closeCalled, "Failing provider Close() must be called")
	})
}
