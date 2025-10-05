// Package crypto provides high-performance secure cryptographic utilities for Go applications.
//
// This package offers a comprehensive set of cryptographic primitives including:
//   - AES-256-GCM authenticated encryption and decryption with cipher caching
//   - Argon2id key derivation for secure password-based key generation
//   - HKDF-SHA256 for high-entropy key derivation (DEK generation)
//   - PBKDF2-SHA256 legacy support for backward compatibility
//   - Cryptographically secure random number generation
//   - Advanced key rotation and management for enterprise vaults (NEMESIS-ready)
//   - Hardware Security Module (HSM) integration with plugin architecture
//   - Secure memory zeroization and buffer pooling for sensitive data
//   - Streaming encryption for large datasets
//
// The package is designed for high-performance production systems, with optimizations
// including cipher caching, buffer pooling, and micro-optimizations achieving
// 1.31M+ operations per second on modern hardware.
//
// # Quick Start
//
// Basic encryption and decryption:
//
//	// Generate a new encryption key
//	key, err := crypto.GenerateKey()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Encrypt some data
//	ciphertext, err := crypto.Encrypt("sensitive data", key)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Decrypt the data
//	plaintext, err := crypto.Decrypt(ciphertext, key)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Println(plaintext) // Output: sensitive data
//
// # Key Derivation
//
// For deriving keys from passwords:
//
//	password := []byte("my-secure-password")
//	salt := []byte("random-salt-123")
//
//	// Derive a key using Argon2id with secure defaults
//	derivedKey, err := crypto.DeriveKeyDefault(password, salt, 32)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Use custom parameters for higher security
//	params := &crypto.KDFParams{
//		Time:    4,    // 4 iterations
//		Memory:  128,  // 128 MB memory
//		Threads: 2,    // 2 threads
//	}
//	key, err := crypto.DeriveKey(password, salt, 32, params)
//
// # Key Management
//
// Key utilities for import/export and validation:
//
//	// Generate and export a key
//	key, _ := crypto.GenerateKey()
//	base64Key := crypto.KeyToBase64(key)
//	hexKey := crypto.KeyToHex(key)
//
//	// Import and validate a key
//	importedKey, err := crypto.KeyFromBase64(base64Key)
//	if err != nil {
//		log.Fatal(err)
//	}
//	err = crypto.ValidateKey(importedKey)
//	if err != nil {
//		log.Fatal("Invalid key:", err)
//	}
//
//	// Generate a fingerprint for identification
//	fingerprint := crypto.GetKeyFingerprint(key)
//	fmt.Println("Key fingerprint:", fingerprint)
//
//	// Securely wipe sensitive data
//	crypto.Zeroize(key)
//
// # Error Handling
//
// All functions return standard Go errors for maximum compatibility.
// For advanced error handling with rich error details, the library integrates
// with github.com/agilira/go-errors.
//
// Example error handling:
//
//	ciphertext, err := crypto.Encrypt("data", key)
//	if err != nil {
//		if errors.Is(err, crypto.ErrInvalidKeySize) {
//			// Handle invalid key size
//		} else if errors.Is(err, crypto.ErrEmptyPlaintext) {
//			// Handle empty plaintext
//		}
//		// Handle other errors
//	}
//
// # Security Considerations
//
// This library uses industry-standard cryptographic algorithms with enterprise security:
//   - AES-256-GCM for authenticated encryption with nonce uniqueness guarantees
//   - Argon2id for key derivation (resistant to ASIC/FPGA attacks and side-channel attacks)
//   - HKDF-SHA256 for high-entropy key derivation (suitable for DEK generation)
//   - Cryptographically secure random number generation (crypto/rand)
//   - Secure memory zeroization with cache-line aligned clearing
//   - Thread-safe key rotation with mutex protection against race conditions
//   - Cipher caching with key fingerprinting to prevent key confusion attacks
//   - Buffer pooling with security-first design (automatic zeroing on return)
//
// Security testing includes advanced attack simulation following Argus security patterns.
// For detailed security information, see the Security documentation.
//
// # Performance
//
// The library is highly optimized for production workloads with:
//   - Cipher caching: Eliminates aes.NewCipher + cipher.NewGCM overhead (49% performance boost)
//   - Buffer pooling: Reduces memory allocations by 79% with intelligent reuse
//   - Cache-line optimization: Loop unrolling and memory access patterns tuned for modern CPUs
//   - Ring buffer techniques: Applied micro-optimizations for consistent low latency
//
// Benchmark results on AMD Ryzen 5 7520U:
//   - Single operation: ~764ns (1.31M ops/sec)
//   - Encrypt+Decrypt cycle: ~1528ns (655k ops/sec)
//   - Memory efficiency: 632B per operation vs 3050B (standard implementation)
//   - Thread-safe: Linear scaling with worker pools for multi-core systems
//
// Target performance for NEMESIS vault: 500k+ ops/sec (2.6x margin achieved)
//
// # Key Rotation for Enterprise Vaults (NEMESIS)
//
// Advanced key management with zero-downtime rotation:
//
//	// Create a key manager for enterprise vault
//	km := crypto.NewKeyManager()
//
//	// Generate and activate initial KEK
//	kek, err := km.GenerateKEK("vault-master")
//	if err != nil {
//		log.Fatal(err)
//	}
//	err = km.ActivateKEK(kek.ID)
//
//	// Derive data encryption keys
//	context := []byte("tenant:vault-app,path:/secrets/db")
//	dek, kekID, err := km.DeriveDataKey(context, 32)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Perform zero-downtime rotation
//	newKEK, err := km.PrepareKEKRotation("vault-master-v2")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Validate new KEK before commit
//	if err := km.ValidateKEKRotation(newKEK.ID); err != nil {
//		km.RollbackKEKRotation() // Safe rollback
//		log.Fatal(err)
//	}
//
//	// Commit rotation atomically
//	if err := km.CommitKEKRotation(); err != nil {
//		log.Fatal(err)
//	}
//
// # Hardware Security Module (HSM) Support
//
// Enterprise-grade HSM integration using the go-plugins architecture for secure
// key management and cryptographic operations in hardware-protected environments:
//
//	// Initialize HSM with plugin
//	hsm, err := crypto.NewHSM("pkcs11", map[string]interface{}{
//		"library_path": "/usr/lib/pkcs11/libpkcs11.so",
//		"slot_id":      0,
//		"pin":          "1234",
//	})
//	if err != nil {
//		log.Fatal("HSM initialization failed:", err)
//	}
//	defer hsm.Close()
//
//	// Generate key in HSM
//	keyHandle, err := hsm.GenerateKey("vault-master-kek", 32)
//	if err != nil {
//		log.Fatal("HSM key generation failed:", err)
//	}
//
//	// Use HSM for encryption
//	plaintext := []byte("sensitive vault data")
//	ciphertext, err := hsm.Encrypt(keyHandle, plaintext)
//	if err != nil {
//		log.Fatal("HSM encryption failed:", err)
//	}
//
//	// Decrypt using HSM
//	decrypted, err := hsm.Decrypt(keyHandle, ciphertext)
//	if err != nil {
//		log.Fatal("HSM decryption failed:", err)
//	}
//
// HSM Features:
//   - PKCS#11 standard compliance for broad hardware support
//   - Plugin architecture using github.com/agilira/go-plugins
//   - Secure key generation within hardware boundaries
//   - Hardware-protected encryption/decryption operations
//   - Key lifecycle management (generation, rotation, destruction)
//   - Tamper-resistant security with hardware attestation
//   - Multi-vendor HSM support (SafeNet, Thales, AWS CloudHSM, etc.)
//
// The HSM integration provides FIPS 140-2 Level 3/4 security compliance for
// enterprise vault deployments requiring hardware-based key protection.
//
// # Streaming Encryption for Large Datasets
//
// Efficient streaming encryption for large files and data streams:
//
//	// Create streaming encryptor
//	key, _ := crypto.GenerateKey()
//	encryptor, err := crypto.NewStreamingEncryptorWithChunkSize(output, key, 64*1024)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer encryptor.Close()
//
//	// Stream large amounts of data
//	for _, chunk := range dataChunks {
//		if _, err := encryptor.Write(chunk); err != nil {
//			log.Fatal(err)
//		}
//	}
//
// Copyright (c) 2025 AGILira
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0
package crypto
