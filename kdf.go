// kdf.go: Key derivation utilities for secure ke	//	// Use secure defaults (pass nil)
//	key, err := crypto.DeriveKey(password, salt, 32, nil)
//
// Pre-defined configurations are available via helper functions:
//	params := crypto.NemesisKDFParams()    // NEMESIS vault optimized
//	params := crypto.HighSecurityKDFParams() // Maximum securitymanagement uses Argon2id.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	goerrors "github.com/agilira/go-errors"
	"golang.org/x/crypto/argon2"
	pbkdf2 "golang.org/x/crypto/pbkdf2"
)

// Default Argon2 parameters for key derivation.
// These values provide a good balance between security and performance.
const (
	// DefaultTime is the default number of iterations for Argon2id.
	// Higher values increase security but also computation time.
	DefaultTime = 3

	// DefaultMemory is the default memory usage in MB for Argon2id.
	// Higher values increase security against memory-based attacks.
	DefaultMemory = 64

	// DefaultThreads is the default number of threads for Argon2id.
	// Should not exceed the number of CPU cores.
	DefaultThreads = 4
)

// KDFParams defines custom parameters for Argon2id key derivation.
//
// If a field is zero, the library's secure default will be used.
// This allows for flexible configuration while maintaining security.
//
// Example:
//
//	// Use custom parameters
//	params := &crypto.KDFParams{
//		Time:    4,    // 4 iterations
//		Memory:  128,  // 128 MB memory
//		Threads: 2,    // 2 threads
//	}
//	key, err := crypto.DeriveKey(password, salt, 32, params)
//
//	// Use secure defaults (pass nil)
//	key, err := crypto.DeriveKey(password, salt, 32, nil)
type KDFParams struct {
	// Time is the number of iterations for Argon2id.
	// Higher values increase security but also computation time.
	// If zero, DefaultTime is used.
	Time uint32 `json:"time,omitempty"`

	// Memory is the memory usage in MB for Argon2id.
	// Higher values increase security against memory-based attacks.
	// If zero, DefaultMemory is used.
	Memory uint32 `json:"memory,omitempty"`

	// Threads is the number of threads for Argon2id.
	// Should not exceed the number of CPU cores.
	// If zero, DefaultThreads is used.
	Threads uint8 `json:"threads,omitempty"`
}

// NemesisKDFParams returns Argon2id parameters optimized for NEMESIS vault workloads.
//
// These parameters balance security with performance for high-throughput vault operations
// while maintaining strong resistance against attacks. Suitable for production NEMESIS
// deployments with moderate security requirements.
//
// Parameters: Time=2, Memory=64MB, Threads=4
func NemesisKDFParams() *KDFParams {
	return &KDFParams{
		Time:    2,  // Slightly faster for high-throughput
		Memory:  64, // Balanced memory usage
		Threads: 4,  // Standard parallel processing
	}
}

// HighSecurityKDFParams returns Argon2id parameters for maximum security scenarios.
//
// These parameters prioritize security over performance and should be used when
// protecting highly sensitive data or when computational resources are abundant.
// Recommended for master key derivation or high-value secret encryption.
//
// Parameters: Time=5, Memory=128MB, Threads=4
func HighSecurityKDFParams() *KDFParams {
	return &KDFParams{
		Time:    5,   // Higher iteration count
		Memory:  128, // Double memory usage
		Threads: 4,   // Standard parallel processing
	}
}

// FastKDFParams returns Argon2id parameters optimized for speed.
//
// These parameters prioritize performance while maintaining acceptable security.
// Suitable for development, testing, or scenarios where KDF performance is critical
// and the threat model allows for slightly reduced security margins.
//
// Parameters: Time=1, Memory=32MB, Threads=2
func FastKDFParams() *KDFParams {
	return &KDFParams{
		Time:    1,  // Minimal iterations for speed
		Memory:  32, // Reduced memory footprint
		Threads: 2,  // Fewer threads for lower resource usage
	}
}

// DeriveKey derives a key from a password and salt using Argon2id (the recommended variant).
//
// Argon2id is the recommended variant of Argon2, providing resistance against both
// side-channel attacks and time-memory trade-off attacks. It uses secure default
// parameters that provide strong protection against both CPU and memory-based attacks.
//
// Parameters:
//   - password: The password to derive the key from (cannot be empty)
//   - salt: The salt to use for key derivation (cannot be empty, should be random)
//   - keyLen: The desired length of the derived key in bytes (must be positive)
//   - params: Custom Argon2id parameters (nil to use secure defaults)
//
// Returns:
//   - The derived key as a byte slice
//   - An error if key derivation fails
//
// Example:
//
//	password := []byte("my-secure-password")
//	salt := []byte("random-salt-123")
//
//	// Use secure defaults
//	key, err := crypto.DeriveKey(password, salt, 32, nil)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Use custom parameters
//	params := &crypto.KDFParams{
//		Time:    4,
//		Memory:  128,
//		Threads: 2,
//	}
//	key, err := crypto.DeriveKey(password, salt, 32, params)
//
// If params is nil, secure defaults are used (Time: 3, Memory: 64MB, Threads: 4).
func DeriveKey(password, salt []byte, keyLen int, params *KDFParams) ([]byte, error) {
	if len(password) == 0 {
		return nil, goerrors.New("EMPTY_PASSWORD", "password cannot be empty")
	}
	if len(salt) == 0 {
		return nil, goerrors.New("EMPTY_SALT", "salt cannot be empty")
	}
	if keyLen <= 0 {
		return nil, goerrors.New("INVALID_KEYLEN", "key length must be positive")
	}

	// Set parameters with defaults
	time := uint32(DefaultTime)
	memory := uint32(DefaultMemory * 1024)
	threads := uint8(DefaultThreads)

	// Override with custom parameters if provided
	if params != nil {
		if params.Time > 0 {
			time = params.Time
		}
		if params.Memory > 0 {
			memory = params.Memory * 1024
		}
		if params.Threads > 0 {
			threads = params.Threads
		}
	}

	// Use Argon2id with determined parameters
	// Note: Type conversions are safe due to parameter validation above
	// gosec G115 is excluded for these conversions as they are necessary for Argon2 API
	key := argon2.IDKey(password, salt, time, memory, threads, uint32(keyLen)) // #nosec G115
	return key, nil
}

// DeriveKeyDefault derives a key using Argon2id with secure default parameters.
//
// This is a convenience function for when you don't need custom parameters.
// It's equivalent to calling DeriveKey with params set to nil.
//
// Parameters:
//   - password: The password to derive the key from (cannot be empty)
//   - salt: The salt to use for key derivation (cannot be empty, should be random)
//   - keyLen: The desired length of the derived key in bytes (must be positive)
//
// Returns:
//   - The derived key as a byte slice
//   - An error if key derivation fails
//
// Example:
//
//	password := []byte("my-secure-password")
//	salt := []byte("random-salt-123")
//	key, err := crypto.DeriveKeyDefault(password, salt, 32)
//	if err != nil {
//		log.Fatal(err)
//	}
func DeriveKeyDefault(password, salt []byte, keyLen int) ([]byte, error) {
	return DeriveKey(password, salt, keyLen, nil)
}

// DeriveKeyWithParams derives a key from a password and salt using Argon2id with custom parameters.
//
// This is a legacy function that provides direct parameter control. For new code,
// consider using DeriveKey with a KDFParams struct for better readability and maintainability.
//
// Parameters:
//   - password: The password to derive the key from (cannot be empty)
//   - salt: The salt to use for key derivation (cannot be empty, should be random)
//   - time: The number of iterations (must be positive)
//   - memoryMB: The memory usage in MB (must be positive)
//   - threads: The number of threads (must be positive)
//   - keyLen: The desired length of the derived key in bytes (must be positive)
//
// Returns:
//   - The derived key as a byte slice
//   - An error if key derivation fails
//
// Example:
//
//	password := []byte("my-secure-password")
//	salt := []byte("random-salt-123")
//	key, err := crypto.DeriveKeyWithParams(password, salt, 4, 128, 2, 32)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Use this function only if you need to customize the parameters for specific requirements.
func DeriveKeyWithParams(password, salt []byte, time, memoryMB, threads, keyLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, goerrors.New("EMPTY_PASSWORD", "password cannot be empty")
	}
	if len(salt) == 0 {
		return nil, goerrors.New("EMPTY_SALT", "salt cannot be empty")
	}
	if time <= 0 {
		return nil, goerrors.New("INVALID_TIME", "time parameter must be positive")
	}
	if memoryMB <= 0 {
		return nil, goerrors.New("INVALID_MEMORY", "memory parameter must be positive")
	}
	if threads <= 0 {
		return nil, goerrors.New("INVALID_THREADS", "threads parameter must be positive")
	}
	if keyLen <= 0 {
		return nil, goerrors.New("INVALID_KEYLEN", "key length must be positive")
	}

	// Type conversions are safe due to parameter validation above
	// gosec G115 is excluded for these conversions as they are necessary for Argon2 API
	key := argon2.IDKey(password, salt, uint32(time), uint32(memoryMB*1024), uint8(threads), uint32(keyLen)) // #nosec G115
	return key, nil
}

// DeriveKeyPBKDF2 derives a key using PBKDF2-SHA256 (deprecated).
//
// This function is deprecated and kept only for backward compatibility.
// Use DeriveKey with Argon2id instead for better security against modern attacks.
// This function will be removed in a future version.
//
// Parameters:
//   - password: The password to derive the key from (cannot be empty)
//   - salt: The salt to use for key derivation (cannot be empty, should be random)
//   - iterations: The number of iterations (must be positive, recommend at least 100,000)
//   - keyLen: The desired length of the derived key in bytes (must be positive)
//
// Returns:
//   - The derived key as a byte slice
//   - An error if key derivation fails
//
// Example:
//
//	password := []byte("my-secure-password")
//	salt := []byte("random-salt-123")
//	key, err := crypto.DeriveKeyPBKDF2(password, salt, 100000, 32)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Deprecated: Use DeriveKey instead for better security.
func DeriveKeyPBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, goerrors.New("EMPTY_PASSWORD", "password cannot be empty")
	}
	if len(salt) == 0 {
		return nil, goerrors.New("EMPTY_SALT", "salt cannot be empty")
	}
	if iterations <= 0 {
		return nil, goerrors.New("INVALID_ITERATIONS", "iterations must be positive")
	}
	if keyLen <= 0 {
		return nil, goerrors.New("INVALID_KEYLEN", "key length must be positive")
	}

	key := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
	return key, nil
}

// DeriveKeyHKDF derives a key using HKDF-SHA256 (RFC 5869).
// This is ideal for envelope encryption where you need to derive multiple
// keys from a single master key (e.g., KEK → DEK derivation in NEMESIS).
//
// Parameters:
//   - masterKey: The input keying material (IKM), typically 32 bytes
//   - salt: Optional salt value (can be nil), used for key strengthening
//   - info: Optional context/application info (can be nil), prevents key reuse across contexts
//   - keyLen: Length of output key in bytes (typically 32 for AES-256)
//
// Example:
//
//	masterKey := []byte("my-32-byte-master-key-for-nemesis")
//	dek, err := crypto.DeriveKeyHKDF(masterKey, nil, []byte("nemesis-dek-v1"), 32)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Security: HKDF is designed for high-entropy inputs (like randomly generated keys).
// For password-based key derivation, use DeriveKey() with Argon2id instead.
func DeriveKeyHKDF(masterKey, salt, info []byte, keyLen int) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, goerrors.New("INVALID_MASTER_KEY", "master key cannot be empty")
	}
	if keyLen <= 0 {
		return nil, goerrors.New("INVALID_KEYLEN", "key length must be positive")
	}
	if keyLen > 255*32 {
		return nil, goerrors.New("INVALID_KEYLEN", "key length too large for HKDF-SHA256")
	}

	// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
	h := sha256.New
	if salt == nil {
		// Usa buffer pool per zero salt invece di allocazione diretta
		saltBuf := getBuffer(h().Size())
		defer putBuffer(saltBuf)
		salt = (*saltBuf)[:h().Size()]
		// Buffer è già zero-inizializzato dalla pool
	}

	// Extract phase
	prk := hkdfExtract(h, salt, masterKey)

	// Expand phase
	okm := hkdfExpand(h, prk, info, keyLen)

	return okm, nil
}

// DeriveKeyHKDFDefault derives a key using HKDF-SHA256 with sensible defaults.
// Uses empty salt and info, suitable for simple key derivation scenarios.
//
// Parameters:
//   - masterKey: The input keying material (32+ bytes recommended)
//   - keyLen: Length of output key in bytes (typically 32)
//
// Example:
//
//	dek, err := crypto.DeriveKeyHKDFDefault(kek, 32)
func DeriveKeyHKDFDefault(masterKey []byte, keyLen int) ([]byte, error) {
	return DeriveKeyHKDF(masterKey, nil, nil, keyLen)
}

// hkdfExtract implements the HKDF-Extract step: PRK = HMAC(salt, IKM) - ottimizzato per buffer pooling
func hkdfExtract(hash func() hash.Hash, salt, ikm []byte) []byte {
	mac := hmac.New(hash, salt)
	mac.Write(ikm)

	// Usa buffer pool per ridurre allocazioni
	prkBuf := getDynamicBuffer()
	defer putDynamicBuffer(prkBuf)

	result := mac.Sum(prkBuf[:0])
	// Return a copy since we're putting the buffer back
	prk := make([]byte, len(result))
	copy(prk, result)
	return prk
}

// hkdfExpand implements the HKDF-Expand step to generate the output key material - ottimizzato per cache locality
func hkdfExpand(hash func() hash.Hash, prk, info []byte, length int) []byte {
	hashSize := hash().Size()
	n := (length + hashSize - 1) / hashSize // Ceiling division

	// Usa buffer pooling per ridurre allocazioni nelle DEK operations
	okmBuf := getDynamicBuffer()
	defer putDynamicBuffer(okmBuf)

	tBuf := getDynamicBuffer()
	defer putDynamicBuffer(tBuf)

	// Pre-allocate con capacità esatta per evitare resize
	if cap(okmBuf) < length {
		okmBuf = make([]byte, 0, length)
	} else {
		okmBuf = okmBuf[:0]
	}

	tCapNeeded := hashSize + len(info) + 1
	if cap(tBuf) < tCapNeeded {
		tBuf = make([]byte, 0, tCapNeeded)
	} else {
		tBuf = tBuf[:0]
	}

	// Stack allocate single-byte buffer per iteration counter
	counterBuf := [1]byte{}

	for i := 1; i <= n; i++ {
		mac := hmac.New(hash, prk)
		mac.Write(tBuf)
		mac.Write(info)
		counterBuf[0] = byte(i)
		mac.Write(counterBuf[:])
		tBuf = mac.Sum(tBuf[:0])

		if i == n {
			okmBuf = append(okmBuf, tBuf[:length-len(okmBuf)]...)
		} else {
			okmBuf = append(okmBuf, tBuf...)
		}
	}

	// Return a copy since we're putting buffers back to pool
	result := make([]byte, len(okmBuf))
	copy(result, okmBuf)
	return result
}
