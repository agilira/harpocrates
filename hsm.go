// hsm.go: Hardware Security Module (HSM) plugin interface for go-crypto
//
// This module provides a plugin-based architecture powered by github.com/agilira/go-plugins
// for integrating various HSM providers including PKCS#11 devices, cloud HSMs
// (AWS CloudHSM, Azure Key Vault), and software fallbacks. The interface is designed
// for high-performance vault operations with comprehensive error handling and
// security best practices.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"context"
	"crypto"
	"fmt"
	"sync"
	"time"

	goerrors "github.com/agilira/go-errors"
	goplugins "github.com/agilira/go-plugins"
)

// HSMCapability represents specific HSM capabilities and features
type HSMCapability string

const (
	// Key Generation Capabilities
	CapabilityGenerateSymmetric  HSMCapability = "generate_symmetric"  // AES, ChaCha20, etc.
	CapabilityGenerateAsymmetric HSMCapability = "generate_asymmetric" // RSA, ECDSA, EdDSA
	CapabilityGenerateEphemeral  HSMCapability = "generate_ephemeral"  // Session keys, temporary keys

	// Cryptographic Operations
	CapabilityEncrypt       HSMCapability = "encrypt"        // Symmetric/Asymmetric encryption
	CapabilityDecrypt       HSMCapability = "decrypt"        // Symmetric/Asymmetric decryption
	CapabilitySign          HSMCapability = "sign"           // Digital signatures
	CapabilityVerify        HSMCapability = "verify"         // Signature verification
	CapabilityKeyDerivation HSMCapability = "key_derivation" // PBKDF2, HKDF, scrypt

	// Advanced Features
	CapabilityKeyWrapping      HSMCapability = "key_wrapping"      // Key encryption keys (KEK)
	CapabilityKeyUnwrapping    HSMCapability = "key_unwrapping"    // KEK decryption
	CapabilityRandomGeneration HSMCapability = "random_generation" // Hardware RNG
	CapabilityKeyRotation      HSMCapability = "key_rotation"      // Automated key rotation
	CapabilityKeyBackup        HSMCapability = "key_backup"        // Key backup/recovery

	// Security Features
	CapabilityTamperEvidence   HSMCapability = "tamper_evidence"    // Tamper detection
	CapabilitySecureKeyStorage HSMCapability = "secure_key_storage" // Hardware-backed storage
	CapabilityAccessControl    HSMCapability = "access_control"     // Role-based access
)

// KeyType represents different types of cryptographic keys
type KeyType string

const (
	KeyTypeAES256    KeyType = "aes-256"    // 256-bit AES symmetric key
	KeyTypeAES128    KeyType = "aes-128"    // 128-bit AES symmetric key
	KeyTypeChaCha20  KeyType = "chacha20"   // ChaCha20 symmetric key
	KeyTypeRSA2048   KeyType = "rsa-2048"   // 2048-bit RSA key pair
	KeyTypeRSA4096   KeyType = "rsa-4096"   // 4096-bit RSA key pair
	KeyTypeECDSAP256 KeyType = "ecdsa-p256" // ECDSA P-256 key pair
	KeyTypeECDSAP384 KeyType = "ecdsa-p384" // ECDSA P-384 key pair
	KeyTypeEd25519   KeyType = "ed25519"    // Ed25519 key pair
	KeyTypeGeneric   KeyType = "generic"    // Generic key material
)

// KeyUsage defines how a key can be used
type KeyUsage string

const (
	KeyUsageEncrypt KeyUsage = "encrypt" // Encryption operations
	KeyUsageDecrypt KeyUsage = "decrypt" // Decryption operations
	KeyUsageSign    KeyUsage = "sign"    // Digital signature creation
	KeyUsageVerify  KeyUsage = "verify"  // Signature verification
	KeyUsageWrap    KeyUsage = "wrap"    // Key wrapping (KEK)
	KeyUsageUnwrap  KeyUsage = "unwrap"  // Key unwrapping
	KeyUsageDerive  KeyUsage = "derive"  // Key derivation
	KeyUsageGeneral KeyUsage = "general" // General purpose usage
)

// HSMKeyInfo represents metadata about keys stored in HSM
type HSMKeyInfo struct {
	ID          string            `json:"id"`          // Unique key identifier in HSM
	Label       string            `json:"label"`       // Human-readable label
	Type        KeyType           `json:"type"`        // Type of cryptographic key
	Usage       []KeyUsage        `json:"usage"`       // Allowed key usage operations
	Size        int               `json:"size"`        // Key size in bits
	Algorithm   string            `json:"algorithm"`   // Cryptographic algorithm
	CreatedAt   time.Time         `json:"created_at"`  // Creation timestamp
	ExpiresAt   *time.Time        `json:"expires_at"`  // Expiration time (if any)
	Extractable bool              `json:"extractable"` // Whether key can be exported
	Metadata    map[string]string `json:"metadata"`    // Additional HSM-specific metadata
}

// HSMOperationContext provides context for HSM operations
type HSMOperationContext struct {
	Context     context.Context        `json:"-"`            // Go context for cancellation/timeout
	KeyID       string                 `json:"key_id"`       // Key identifier for operation
	Algorithm   string                 `json:"algorithm"`    // Specific algorithm variant
	Parameters  map[string]interface{} `json:"parameters"`   // Algorithm-specific parameters
	Metadata    map[string]string      `json:"metadata"`     // Operation metadata
	UserContext map[string]string      `json:"user_context"` // User/session context
}

// HSMProvider defines the interface that all HSM plugins must implement
//
// This interface provides a comprehensive set of cryptographic operations that can be
// performed by Hardware Security Modules. Implementations should handle errors gracefully
// and provide detailed error information for security auditing.
type HSMProvider interface {
	// Provider Information
	Name() string                  // Provider name (e.g., "pkcs11", "aws-cloudhsm")
	Version() string               // Provider version
	Capabilities() []HSMCapability // Supported capabilities

	// Lifecycle Management
	Initialize(ctx context.Context, config map[string]interface{}) error // Initialize HSM connection
	Close() error                                                        // Clean shutdown and resource cleanup
	IsHealthy() bool                                                     // Health check status

	// Key Management Operations
	GenerateKey(ctx HSMOperationContext, keyType KeyType, usage []KeyUsage, params map[string]interface{}) (*HSMKeyInfo, error)
	ImportKey(ctx HSMOperationContext, keyMaterial []byte, keyType KeyType, usage []KeyUsage, params map[string]interface{}) (*HSMKeyInfo, error)
	DeleteKey(ctx HSMOperationContext) error
	ListKeys(ctx context.Context, filter map[string]interface{}) ([]*HSMKeyInfo, error)
	GetKeyInfo(ctx HSMOperationContext) (*HSMKeyInfo, error)

	// Cryptographic Operations
	Encrypt(ctx HSMOperationContext, plaintext []byte) ([]byte, error)
	Decrypt(ctx HSMOperationContext, ciphertext []byte) ([]byte, error)
	Sign(ctx HSMOperationContext, data []byte, hashAlgorithm crypto.Hash) ([]byte, error)
	Verify(ctx HSMOperationContext, data []byte, signature []byte, hashAlgorithm crypto.Hash) error

	// Key Derivation and Wrapping
	DeriveKey(ctx HSMOperationContext, derivationData []byte, outputKeyType KeyType, params map[string]interface{}) (*HSMKeyInfo, error)
	WrapKey(ctx HSMOperationContext, targetKeyID string, wrappingParams map[string]interface{}) ([]byte, error)
	UnwrapKey(ctx HSMOperationContext, wrappedKey []byte, keyType KeyType, usage []KeyUsage, params map[string]interface{}) (*HSMKeyInfo, error)

	// Random Number Generation
	GenerateRandom(ctx context.Context, length int) ([]byte, error)
}

// HSMManager manages multiple HSM providers using the go-plugins framework
type HSMManager struct {
	mu              sync.RWMutex
	pluginManager   *goplugins.Manager[HSMRequest, HSMResponse] // Plugin manager for HSM providers
	activeProviders map[string]HSMProvider                      // Active HSM provider instances
	defaultProvider string                                      // Default provider name
	config          *HSMManagerConfig                           // Manager configuration
}

// HSMManagerConfig provides configuration for the HSM manager
type HSMManagerConfig struct {
	DefaultProvider     string                            `json:"default_provider"`      // Default HSM provider to use
	ProviderConfigs     map[string]map[string]interface{} `json:"provider_configs"`      // Per-provider configurations
	FailoverEnabled     bool                              `json:"failover_enabled"`      // Enable automatic failover
	FailoverProviders   []string                          `json:"failover_providers"`    // Failover provider priority order
	HealthCheckInterval time.Duration                     `json:"health_check_interval"` // Health check frequency
	OperationTimeout    time.Duration                     `json:"operation_timeout"`     // Default operation timeout
}

// HSMRequest represents a request to an HSM provider plugin
type HSMRequest struct {
	Operation  string                 `json:"operation"`  // Operation type (encrypt, decrypt, sign, etc.)
	Context    HSMOperationContext    `json:"context"`    // Operation context
	Data       []byte                 `json:"data"`       // Operation data
	Parameters map[string]interface{} `json:"parameters"` // Operation parameters
}

// HSMResponse represents a response from an HSM provider plugin
type HSMResponse struct {
	Success  bool                   `json:"success"`  // Operation success status
	Data     []byte                 `json:"data"`     // Response data
	KeyInfo  *HSMKeyInfo            `json:"key_info"` // Key information (for key operations)
	Error    string                 `json:"error"`    // Error message (if any)
	Metadata map[string]interface{} `json:"metadata"` // Response metadata
}

// Common HSM errors with proper error codes for auditing
var (
	ErrHSMNotInitialized    = goerrors.New("HSM_001", "HSM provider not initialized")
	ErrHSMKeyNotFound       = goerrors.New("HSM_002", "Key not found in HSM")
	ErrHSMOperationFailed   = goerrors.New("HSM_003", "HSM operation failed")
	ErrHSMInvalidKeyType    = goerrors.New("HSM_004", "Invalid or unsupported key type")
	ErrHSMInvalidUsage      = goerrors.New("HSM_005", "Invalid key usage for operation")
	ErrHSMProviderNotFound  = goerrors.New("HSM_006", "HSM provider not found")
	ErrHSMHealthCheckFailed = goerrors.New("HSM_007", "HSM health check failed")
	ErrHSMOperationTimeout  = goerrors.New("HSM_008", "HSM operation timed out")
	ErrHSMInvalidParameters = goerrors.New("HSM_009", "Invalid operation parameters")
	ErrHSMAccessDenied      = goerrors.New("HSM_010", "Access denied by HSM")
)

// NewHSMManager creates a new HSM manager with plugin support
func NewHSMManager(config *HSMManagerConfig, pluginManager *goplugins.Manager[HSMRequest, HSMResponse]) (*HSMManager, error) {
	if config == nil {
		config = &HSMManagerConfig{
			FailoverEnabled:     false,
			HealthCheckInterval: 30 * time.Second,
			OperationTimeout:    10 * time.Second,
		}
	}

	manager := &HSMManager{
		pluginManager:   pluginManager,
		activeProviders: make(map[string]HSMProvider),
		config:          config,
	}

	return manager, nil
}

// RegisterProvider registers an HSM provider with the manager
func (h *HSMManager) RegisterProvider(name string, provider HSMProvider) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	// Initialize the provider with its configuration
	ctx := context.Background()
	if timeout := h.config.OperationTimeout; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	providerConfig := h.config.ProviderConfigs[name]
	if err := provider.Initialize(ctx, providerConfig); err != nil {
		return fmt.Errorf("failed to initialize HSM provider %s: %w", name, err)
	}

	h.activeProviders[name] = provider

	// Set as default if it's the first provider or explicitly configured
	if h.defaultProvider == "" || h.config.DefaultProvider == name {
		h.defaultProvider = name
	}

	return nil
}

// GetProvider returns an HSM provider by name
func (h *HSMManager) GetProvider(name string) (HSMProvider, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if name == "" {
		name = h.defaultProvider
	}

	provider, exists := h.activeProviders[name]
	if !exists {
		return nil, fmt.Errorf("%w: provider %s", ErrHSMProviderNotFound, name)
	}

	// Health check before returning provider
	if !provider.IsHealthy() {
		return nil, fmt.Errorf("%w: provider %s", ErrHSMHealthCheckFailed, name)
	}

	return provider, nil
}

// Close shuts down all HSM providers
func (h *HSMManager) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var errors []error

	for name, provider := range h.activeProviders {
		if err := provider.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close HSM provider %s: %w", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to close some HSM providers: %v", errors)
	}

	return nil
}
