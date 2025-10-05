// hsm_test.go: Comprehensive tests for HSM module in Harpocrates
//
// This test suite covers all HSM functionality including:
// - HSM Manager initialization and lifecycle
// - Provider registration and management
// - Error handling and edge cases
// - Security validations
// - Performance requirements
//
// Target: >90% coverage for production vault deployment
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"context"
	"crypto"
	"testing"
	"time"

	goplugins "github.com/agilira/go-plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHSMProvider implements HSMProvider for testing
type mockHSMProvider struct {
	name         string
	version      string
	capabilities []HSMCapability
	initialized  bool
	healthy      bool
	keys         map[string]*HSMKeyInfo
	shouldFail   bool
}

func newMockHSMProvider(name, version string) *mockHSMProvider {
	return &mockHSMProvider{
		name:         name,
		version:      version,
		capabilities: []HSMCapability{CapabilityGenerateSymmetric, CapabilityEncrypt, CapabilityDecrypt},
		healthy:      true,
		keys:         make(map[string]*HSMKeyInfo),
	}
}

func (m *mockHSMProvider) Name() string {
	return m.name
}

func (m *mockHSMProvider) Version() string {
	return m.version
}

func (m *mockHSMProvider) Capabilities() []HSMCapability {
	return m.capabilities
}

func (m *mockHSMProvider) Initialize(ctx context.Context, config map[string]interface{}) error {
	if m.shouldFail {
		return ErrHSMNotInitialized
	}
	m.initialized = true
	return nil
}

func (m *mockHSMProvider) Close() error {
	m.initialized = false
	return nil
}

func (m *mockHSMProvider) IsHealthy() bool {
	return m.healthy && m.initialized
}

func (m *mockHSMProvider) GenerateKey(ctx HSMOperationContext, keyType KeyType, usage []KeyUsage, params map[string]interface{}) (*HSMKeyInfo, error) {
	if !m.initialized {
		return nil, ErrHSMNotInitialized
	}

	keyInfo := &HSMKeyInfo{
		ID:          "mock-key-" + string(keyType),
		Label:       "Mock Generated Key",
		Type:        keyType,
		Usage:       usage,
		Size:        256,
		Algorithm:   "AES-256-GCM",
		CreatedAt:   time.Now(),
		Extractable: true,
		Metadata:    make(map[string]string),
	}

	m.keys[keyInfo.ID] = keyInfo
	return keyInfo, nil
}

func (m *mockHSMProvider) ImportKey(ctx HSMOperationContext, keyMaterial []byte, keyType KeyType, usage []KeyUsage, params map[string]interface{}) (*HSMKeyInfo, error) {
	return nil, ErrHSMOperationFailed
}

func (m *mockHSMProvider) DeleteKey(ctx HSMOperationContext) error {
	if !m.initialized {
		return ErrHSMNotInitialized
	}
	delete(m.keys, ctx.KeyID)
	return nil
}

func (m *mockHSMProvider) ListKeys(ctx context.Context, filter map[string]interface{}) ([]*HSMKeyInfo, error) {
	if !m.initialized {
		return nil, ErrHSMNotInitialized
	}

	var keys []*HSMKeyInfo
	for _, key := range m.keys {
		keyInfo := *key // Copy
		keys = append(keys, &keyInfo)
	}
	return keys, nil
}

func (m *mockHSMProvider) GetKeyInfo(ctx HSMOperationContext) (*HSMKeyInfo, error) {
	if !m.initialized {
		return nil, ErrHSMNotInitialized
	}

	key, exists := m.keys[ctx.KeyID]
	if !exists {
		return nil, ErrHSMKeyNotFound
	}

	keyInfo := *key // Copy
	return &keyInfo, nil
}

func (m *mockHSMProvider) Encrypt(ctx HSMOperationContext, plaintext []byte) ([]byte, error) {
	if !m.initialized {
		return nil, ErrHSMNotInitialized
	}

	if _, exists := m.keys[ctx.KeyID]; !exists {
		return nil, ErrHSMKeyNotFound
	}

	// Mock encryption - just return modified plaintext
	prefix := []byte("encrypted:")
	result := make([]byte, len(prefix)+len(plaintext))
	copy(result, prefix)
	copy(result[len(prefix):], plaintext)
	return result, nil
}

func (m *mockHSMProvider) Decrypt(ctx HSMOperationContext, ciphertext []byte) ([]byte, error) {
	if !m.initialized {
		return nil, ErrHSMNotInitialized
	}

	if _, exists := m.keys[ctx.KeyID]; !exists {
		return nil, ErrHSMKeyNotFound
	}

	// Mock decryption - remove "encrypted:" prefix
	prefix := []byte("encrypted:")
	if len(ciphertext) >= len(prefix) && string(ciphertext[:len(prefix)]) == "encrypted:" {
		return ciphertext[len(prefix):], nil
	}

	return nil, ErrHSMOperationFailed
}

func (m *mockHSMProvider) Sign(ctx HSMOperationContext, data []byte, hashAlgorithm crypto.Hash) ([]byte, error) {
	return nil, ErrHSMOperationFailed
}

func (m *mockHSMProvider) Verify(ctx HSMOperationContext, data []byte, signature []byte, hashAlgorithm crypto.Hash) error {
	return ErrHSMOperationFailed
}

func (m *mockHSMProvider) DeriveKey(ctx HSMOperationContext, derivationData []byte, outputKeyType KeyType, params map[string]interface{}) (*HSMKeyInfo, error) {
	return nil, ErrHSMOperationFailed
}

func (m *mockHSMProvider) WrapKey(ctx HSMOperationContext, targetKeyID string, wrappingParams map[string]interface{}) ([]byte, error) {
	return nil, ErrHSMOperationFailed
}

func (m *mockHSMProvider) UnwrapKey(ctx HSMOperationContext, wrappedKey []byte, keyType KeyType, usage []KeyUsage, params map[string]interface{}) (*HSMKeyInfo, error) {
	return nil, ErrHSMOperationFailed
}

func (m *mockHSMProvider) GenerateRandom(ctx context.Context, length int) ([]byte, error) {
	if !m.initialized {
		return nil, ErrHSMNotInitialized
	}

	if length <= 0 {
		return nil, ErrHSMInvalidParameters
	}

	// Mock random generation
	result := make([]byte, length)
	for i := range result {
		result[i] = byte(i % 256)
	}
	return result, nil
}

// Test HSM Manager Creation and Configuration

func TestNewHSMManager(t *testing.T) {
	tests := []struct {
		name           string
		config         *HSMManagerConfig
		pluginManager  *goplugins.Manager[HSMRequest, HSMResponse]
		expectError    bool
		expectedConfig *HSMManagerConfig
	}{
		{
			name:          "with nil config",
			config:        nil,
			pluginManager: nil,
			expectError:   false,
			expectedConfig: &HSMManagerConfig{
				FailoverEnabled:     false,
				HealthCheckInterval: 30 * time.Second,
				OperationTimeout:    10 * time.Second,
			},
		},
		{
			name: "with custom config",
			config: &HSMManagerConfig{
				DefaultProvider:     "test-provider",
				FailoverEnabled:     true,
				HealthCheckInterval: 60 * time.Second,
				OperationTimeout:    5 * time.Second,
			},
			pluginManager:  nil,
			expectError:    false,
			expectedConfig: nil, // Will use provided config
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewHSMManager(tt.config, tt.pluginManager)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)

				if tt.expectedConfig != nil {
					assert.Equal(t, tt.expectedConfig.FailoverEnabled, manager.config.FailoverEnabled)
					assert.Equal(t, tt.expectedConfig.HealthCheckInterval, manager.config.HealthCheckInterval)
					assert.Equal(t, tt.expectedConfig.OperationTimeout, manager.config.OperationTimeout)
				}
			}
		})
	}
}

// Test Provider Registration and Management

func TestHSMManager_RegisterProvider(t *testing.T) {
	manager, err := NewHSMManager(nil, nil)
	require.NoError(t, err)

	tests := []struct {
		name         string
		providerName string
		provider     HSMProvider
		expectError  bool
	}{
		{
			name:         "register valid provider",
			providerName: "test-provider",
			provider:     newMockHSMProvider("test-provider", "1.0.0"),
			expectError:  false,
		},
		{
			name:         "register nil provider",
			providerName: "nil-provider",
			provider:     nil,
			expectError:  true,
		},
		{
			name:         "register failing provider",
			providerName: "failing-provider",
			provider: func() HSMProvider {
				p := newMockHSMProvider("failing-provider", "1.0.0")
				p.shouldFail = true
				return p
			}(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.RegisterProvider(tt.providerName, tt.provider)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify provider is registered
				provider, err := manager.GetProvider(tt.providerName)
				assert.NoError(t, err)
				assert.NotNil(t, provider)
				assert.Equal(t, tt.providerName, provider.Name())
			}
		})
	}
}

func TestHSMManager_GetProvider(t *testing.T) {
	manager, err := NewHSMManager(&HSMManagerConfig{
		DefaultProvider: "default-provider",
	}, nil)
	require.NoError(t, err)

	// Register test providers
	defaultProvider := newMockHSMProvider("default-provider", "1.0.0")
	otherProvider := newMockHSMProvider("other-provider", "1.0.0")
	unhealthyProvider := newMockHSMProvider("unhealthy-provider", "1.0.0")
	unhealthyProvider.healthy = false

	require.NoError(t, manager.RegisterProvider("default-provider", defaultProvider))
	require.NoError(t, manager.RegisterProvider("other-provider", otherProvider))
	require.NoError(t, manager.RegisterProvider("unhealthy-provider", unhealthyProvider))

	tests := []struct {
		name         string
		providerName string
		expectError  bool
		errorType    error
	}{
		{
			name:         "get default provider with empty name",
			providerName: "",
			expectError:  false,
		},
		{
			name:         "get specific provider",
			providerName: "other-provider",
			expectError:  false,
		},
		{
			name:         "get non-existent provider",
			providerName: "non-existent",
			expectError:  true,
			errorType:    ErrHSMProviderNotFound,
		},
		{
			name:         "get unhealthy provider",
			providerName: "unhealthy-provider",
			expectError:  true,
			errorType:    ErrHSMHealthCheckFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := manager.GetProvider(tt.providerName)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, provider)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

// Test HSM Manager Lifecycle

func TestHSMManager_Close(t *testing.T) {
	manager, err := NewHSMManager(nil, nil)
	require.NoError(t, err)

	// Register multiple providers
	provider1 := newMockHSMProvider("provider1", "1.0.0")
	provider2 := newMockHSMProvider("provider2", "1.0.0")

	require.NoError(t, manager.RegisterProvider("provider1", provider1))
	require.NoError(t, manager.RegisterProvider("provider2", provider2))

	// Close manager
	err = manager.Close()
	assert.NoError(t, err)

	// Verify providers are closed
	assert.False(t, provider1.initialized)
	assert.False(t, provider2.initialized)
}

// Test HSM Key Operations

func TestHSMProvider_KeyOperations(t *testing.T) {
	provider := newMockHSMProvider("test", "1.0.0")

	// Initialize provider
	ctx := context.Background()
	err := provider.Initialize(ctx, nil)
	require.NoError(t, err)

	// Test key generation
	opCtx := HSMOperationContext{
		Context:  ctx,
		KeyID:    "",
		Metadata: make(map[string]string),
	}

	keyInfo, err := provider.GenerateKey(opCtx, KeyTypeAES256, []KeyUsage{KeyUsageEncrypt, KeyUsageDecrypt}, nil)
	require.NoError(t, err)
	require.NotNil(t, keyInfo)
	assert.Equal(t, KeyTypeAES256, keyInfo.Type)
	assert.Equal(t, 256, keyInfo.Size)

	// Test encryption/decryption
	opCtx.KeyID = keyInfo.ID
	plaintext := []byte("test message")

	ciphertext, err := provider.Encrypt(opCtx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := provider.Decrypt(opCtx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Test key deletion
	err = provider.DeleteKey(opCtx)
	assert.NoError(t, err)

	// Verify key is gone
	_, err = provider.GetKeyInfo(opCtx)
	assert.ErrorIs(t, err, ErrHSMKeyNotFound)
}

// Test Error Handling

func TestHSMProvider_ErrorHandling(t *testing.T) {
	provider := newMockHSMProvider("test", "1.0.0")

	// Test operations before initialization
	ctx := HSMOperationContext{
		Context: context.Background(),
		KeyID:   "non-existent",
	}

	_, err := provider.GenerateKey(ctx, KeyTypeAES256, []KeyUsage{KeyUsageEncrypt}, nil)
	assert.ErrorIs(t, err, ErrHSMNotInitialized)

	_, err = provider.Encrypt(ctx, []byte("test"))
	assert.ErrorIs(t, err, ErrHSMNotInitialized)

	_, err = provider.Decrypt(ctx, []byte("test"))
	assert.ErrorIs(t, err, ErrHSMNotInitialized)

	// Initialize provider
	err = provider.Initialize(context.Background(), nil)
	require.NoError(t, err)

	// Test operations with non-existent key
	_, err = provider.Encrypt(ctx, []byte("test"))
	assert.ErrorIs(t, err, ErrHSMKeyNotFound)

	_, err = provider.Decrypt(ctx, []byte("test"))
	assert.ErrorIs(t, err, ErrHSMKeyNotFound)

	_, err = provider.GetKeyInfo(ctx)
	assert.ErrorIs(t, err, ErrHSMKeyNotFound)
}

// Test Random Generation

func TestHSMProvider_GenerateRandom(t *testing.T) {
	provider := newMockHSMProvider("test", "1.0.0")
	ctx := context.Background()

	// Test before initialization
	_, err := provider.GenerateRandom(ctx, 32)
	assert.ErrorIs(t, err, ErrHSMNotInitialized)

	// Initialize provider
	err = provider.Initialize(ctx, nil)
	require.NoError(t, err)

	// Test valid random generation
	random, err := provider.GenerateRandom(ctx, 32)
	assert.NoError(t, err)
	assert.Len(t, random, 32)

	// Test invalid length
	_, err = provider.GenerateRandom(ctx, 0)
	assert.ErrorIs(t, err, ErrHSMInvalidParameters)

	_, err = provider.GenerateRandom(ctx, -1)
	assert.ErrorIs(t, err, ErrHSMInvalidParameters)
}

// Test HSM Constants and Types

func TestHSMCapabilities(t *testing.T) {
	// Test that all capabilities are defined
	capabilities := []HSMCapability{
		CapabilityGenerateSymmetric,
		CapabilityGenerateAsymmetric,
		CapabilityGenerateEphemeral,
		CapabilityEncrypt,
		CapabilityDecrypt,
		CapabilitySign,
		CapabilityVerify,
		CapabilityKeyDerivation,
		CapabilityKeyWrapping,
		CapabilityKeyUnwrapping,
		CapabilityRandomGeneration,
		CapabilityKeyRotation,
		CapabilityKeyBackup,
		CapabilityTamperEvidence,
		CapabilitySecureKeyStorage,
		CapabilityAccessControl,
	}

	for _, cap := range capabilities {
		assert.NotEmpty(t, string(cap), "Capability should not be empty")
	}
}

func TestKeyTypes(t *testing.T) {
	keyTypes := []KeyType{
		KeyTypeAES256,
		KeyTypeAES128,
		KeyTypeChaCha20,
		KeyTypeRSA2048,
		KeyTypeRSA4096,
		KeyTypeECDSAP256,
		KeyTypeECDSAP384,
		KeyTypeEd25519,
		KeyTypeGeneric,
	}

	for _, keyType := range keyTypes {
		assert.NotEmpty(t, string(keyType), "Key type should not be empty")
	}
}

func TestKeyUsage(t *testing.T) {
	usages := []KeyUsage{
		KeyUsageEncrypt,
		KeyUsageDecrypt,
		KeyUsageSign,
		KeyUsageVerify,
		KeyUsageWrap,
		KeyUsageUnwrap,
		KeyUsageDerive,
		KeyUsageGeneral,
	}

	for _, usage := range usages {
		assert.NotEmpty(t, string(usage), "Key usage should not be empty")
	}
}

// Test Error Types and Messages

func TestHSMErrors(t *testing.T) {
	errors := []error{
		ErrHSMNotInitialized,
		ErrHSMKeyNotFound,
		ErrHSMOperationFailed,
		ErrHSMInvalidKeyType,
		ErrHSMInvalidUsage,
		ErrHSMProviderNotFound,
		ErrHSMHealthCheckFailed,
		ErrHSMOperationTimeout,
		ErrHSMInvalidParameters,
		ErrHSMAccessDenied,
	}

	for _, err := range errors {
		assert.NotNil(t, err, "Error should not be nil")
		assert.NotEmpty(t, err.Error(), "Error message should not be empty")
	}
}

// Benchmark Tests

func BenchmarkHSMProvider_GenerateKey(b *testing.B) {
	provider := newMockHSMProvider("benchmark", "1.0.0")
	ctx := HSMOperationContext{Context: context.Background()}

	err := provider.Initialize(context.Background(), nil)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.GenerateKey(ctx, KeyTypeAES256, []KeyUsage{KeyUsageEncrypt}, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHSMProvider_Encrypt(b *testing.B) {
	provider := newMockHSMProvider("benchmark", "1.0.0")
	ctx := HSMOperationContext{Context: context.Background()}

	err := provider.Initialize(context.Background(), nil)
	require.NoError(b, err)

	// Generate a key first
	keyInfo, err := provider.GenerateKey(ctx, KeyTypeAES256, []KeyUsage{KeyUsageEncrypt}, nil)
	require.NoError(b, err)

	ctx.KeyID = keyInfo.ID
	plaintext := []byte("benchmark test data for encryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.Encrypt(ctx, plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}
}
