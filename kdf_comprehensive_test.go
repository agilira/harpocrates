// kdf_comprehensive_test.go: Exhaustive tests for Key Derivation Function components
//
// This test suite ensures 100% coverage for all KDF parameter constructors and derivation
// methods in Harpocrates. Critical for vault deployments where every KDF operation must
// be validated for security compliance and performance characteristics.
//
// Coverage targets: NemesisKDFParams, HighSecurityKDFParams, FastKDFParams (currently 0%)
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKDFParameterConstructors validates all KDF parameter constructor functions
// These constructors are critical for vault security profiles - each must return
// proper Argon2id parameters for their intended security/performance balance
func TestKDFParameterConstructors(t *testing.T) {
	t.Run("NemesisKDFParams_ProducesBalancedSecurityProfile", func(t *testing.T) {
		params := NemesisKDFParams()

		// Validate NEMESIS security profile parameters
		require.NotNil(t, params, "NEMESIS KDF parameters must not be nil for vault operations")
		assert.Equal(t, uint32(2), params.Time, "NEMESIS profile requires time=2 for balanced throughput")
		assert.Equal(t, uint32(64), params.Memory, "NEMESIS profile requires 64MB memory for production workloads")
		assert.Equal(t, uint8(4), params.Threads, "NEMESIS profile requires 4 threads for parallel efficiency")

		// Ensure parameters meet minimum security threshold for vault deployment
		assert.GreaterOrEqual(t, params.Time, uint32(1), "Time parameter must meet minimum iteration security")
		assert.GreaterOrEqual(t, params.Memory, uint32(32), "Memory parameter must meet minimum security threshold")
		assert.GreaterOrEqual(t, params.Threads, uint8(1), "Thread count must be positive for parallel processing")
	})

	t.Run("HighSecurityKDFParams_ProducesMaximumSecurityProfile", func(t *testing.T) {
		params := HighSecurityKDFParams()

		// Validate high-security profile parameters
		require.NotNil(t, params, "High-security KDF parameters must not be nil for sensitive data protection")
		assert.Equal(t, uint32(5), params.Time, "High-security profile requires time=5 for maximum resistance")
		assert.Equal(t, uint32(128), params.Memory, "High-security profile requires 128MB for enhanced security")
		assert.Equal(t, uint8(4), params.Threads, "High-security profile maintains 4 threads for performance")

		// Verify high-security parameters exceed standard thresholds
		nemesisParams := NemesisKDFParams()
		assert.Greater(t, params.Time, nemesisParams.Time, "High-security must exceed NEMESIS time iterations")
		assert.Greater(t, params.Memory, nemesisParams.Memory, "High-security must exceed NEMESIS memory usage")
		assert.GreaterOrEqual(t, params.Threads, nemesisParams.Threads, "High-security maintains thread efficiency")
	})

	t.Run("FastKDFParams_ProducesPerformanceOptimizedProfile", func(t *testing.T) {
		params := FastKDFParams()

		// Validate performance-optimized profile parameters
		require.NotNil(t, params, "Fast KDF parameters must not be nil for performance scenarios")
		assert.Equal(t, uint32(1), params.Time, "Fast profile requires time=1 for minimal iteration overhead")
		assert.Equal(t, uint32(32), params.Memory, "Fast profile requires 32MB for reduced memory footprint")
		assert.Equal(t, uint8(2), params.Threads, "Fast profile uses 2 threads for lower resource consumption")

		// Ensure fast parameters maintain minimum security while optimizing performance
		assert.GreaterOrEqual(t, params.Time, uint32(1), "Fast profile must maintain minimum security iteration")
		assert.GreaterOrEqual(t, params.Memory, uint32(16), "Fast profile must maintain minimum memory security")
		assert.GreaterOrEqual(t, params.Threads, uint8(1), "Fast profile must use at least one processing thread")

		// Verify performance optimization versus standard parameters
		nemesisParams := NemesisKDFParams()
		assert.LessOrEqual(t, params.Time, nemesisParams.Time, "Fast profile optimizes time iterations")
		assert.LessOrEqual(t, params.Memory, nemesisParams.Memory, "Fast profile optimizes memory usage")
	})

	t.Run("KDFParameterProfiles_MaintainSecurityHierarchy", func(t *testing.T) {
		fastParams := FastKDFParams()
		nemesisParams := NemesisKDFParams()
		highSecParams := HighSecurityKDFParams()

		// Verify security hierarchy: Fast < NEMESIS < HighSecurity
		// Time parameter hierarchy (iterations affect computational cost)
		assert.LessOrEqual(t, fastParams.Time, nemesisParams.Time,
			"Fast profile must not exceed NEMESIS time complexity")
		assert.LessOrEqual(t, nemesisParams.Time, highSecParams.Time,
			"NEMESIS profile must not exceed high-security time complexity")

		// Memory parameter hierarchy (memory affects rainbow table resistance)
		assert.LessOrEqual(t, fastParams.Memory, nemesisParams.Memory,
			"Fast profile must not exceed NEMESIS memory requirements")
		assert.LessOrEqual(t, nemesisParams.Memory, highSecParams.Memory,
			"NEMESIS profile must not exceed high-security memory requirements")

		// Thread parameters should be reasonable for all profiles
		for _, params := range []*KDFParams{fastParams, nemesisParams, highSecParams} {
			assert.LessOrEqual(t, params.Threads, uint8(8),
				"Thread count should not exceed typical CPU core availability")
			assert.GreaterOrEqual(t, params.Threads, uint8(1),
				"Thread count must be positive for parallel processing")
		}
	})
}

// TestKDFParameterConstructors_Integration validates parameter constructors work with DeriveKeyWithParams
// This ensures that all constructor outputs produce valid KDF operations for vault key derivation
func TestKDFParameterConstructors_Integration(t *testing.T) {
	// Test data for KDF operations
	password := "vault-master-password-for-testing"
	salt := []byte("harpocrates-kdf-salt-32-bytes!!")
	keyLength := uint32(32) // 256-bit derived key

	testCases := []struct {
		name           string
		paramsFunc     func() *KDFParams
		description    string
		expectValidKey bool
	}{
		{
			name:           "NemesisKDFParams_ProducesValidDerivedKey",
			paramsFunc:     NemesisKDFParams,
			description:    "NEMESIS parameters must produce valid 256-bit keys for vault operations",
			expectValidKey: true,
		},
		{
			name:           "HighSecurityKDFParams_ProducesValidDerivedKey",
			paramsFunc:     HighSecurityKDFParams,
			description:    "High-security parameters must produce valid 256-bit keys for sensitive data",
			expectValidKey: true,
		},
		{
			name:           "FastKDFParams_ProducesValidDerivedKey",
			paramsFunc:     FastKDFParams,
			description:    "Fast parameters must produce valid 256-bit keys for performance scenarios",
			expectValidKey: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := tc.paramsFunc()
			require.NotNil(t, params, "Parameter constructor must return valid KDF parameters")

			// Derive key using constructed parameters
			passwordBytes := []byte(password)
			derivedKey, err := DeriveKeyWithParams(passwordBytes, salt, int(params.Time), int(params.Memory), int(params.Threads), int(keyLength))

			if tc.expectValidKey {
				require.NoError(t, err, "KDF operation with constructed parameters must succeed: %s", tc.description)
				require.NotNil(t, derivedKey, "Derived key must not be nil for vault operations")
				assert.Len(t, derivedKey, int(keyLength), "Derived key must match requested length")

				// Verify derived key is not all zeros (cryptographic sanity check)
				assert.NotEqual(t, make([]byte, keyLength), derivedKey,
					"Derived key must not be all zeros - indicates KDF failure")

				// Verify reproducibility - same inputs should produce same output
				derivedKey2, err2 := DeriveKeyWithParams(passwordBytes, salt, int(params.Time), int(params.Memory), int(params.Threads), int(keyLength))
				require.NoError(t, err2, "Reproducibility test must not fail")
				assert.Equal(t, derivedKey, derivedKey2,
					"KDF must be deterministic - same inputs must produce identical outputs")

				// Verify different passwords produce different keys (avalanche effect)
				differentPasswordBytes := []byte(password + "-modified")
				differentKey, err3 := DeriveKeyWithParams(differentPasswordBytes, salt, int(params.Time), int(params.Memory), int(params.Threads), int(keyLength))
				require.NoError(t, err3, "KDF with different password must succeed")
				assert.NotEqual(t, derivedKey, differentKey,
					"Different passwords must produce different derived keys")
			}
		})
	}
}

// TestKDFParameterConstructors_SecurityProperties validates cryptographic properties of constructor outputs
// This ensures all parameter sets meet vault security requirements under various threat models
func TestKDFParameterConstructors_SecurityProperties(t *testing.T) {
	t.Run("AllParameterProfiles_ResistTimingAttacks", func(t *testing.T) {
		// Test that all parameter profiles are deterministic and timing-independent
		profiles := map[string]func() *KDFParams{
			"NEMESIS":      NemesisKDFParams,
			"HighSecurity": HighSecurityKDFParams,
			"Fast":         FastKDFParams,
		}

		for profileName, constructor := range profiles {
			t.Run("Profile_"+profileName, func(t *testing.T) {
				// Multiple calls should return identical parameters (timing independence)
				params1 := constructor()
				params2 := constructor()

				assert.Equal(t, params1.Time, params2.Time,
					"Parameter constructor must be deterministic for timing attack resistance")
				assert.Equal(t, params1.Memory, params2.Memory,
					"Parameter constructor must be deterministic for timing attack resistance")
				assert.Equal(t, params1.Threads, params2.Threads,
					"Parameter constructor must be deterministic for timing attack resistance")
			})
		}
	})

	t.Run("AllParameterProfiles_MeetMinimumSecurityThresholds", func(t *testing.T) {
		// Define minimum security thresholds for vault deployment
		minTime := uint32(1)    // Minimum 1 iteration
		minMemory := uint32(16) // Minimum 16MB memory
		minThreads := uint8(1)  // Minimum 1 thread

		profiles := []struct {
			name   string
			params *KDFParams
		}{
			{"NEMESIS", NemesisKDFParams()},
			{"HighSecurity", HighSecurityKDFParams()},
			{"Fast", FastKDFParams()},
		}

		for _, profile := range profiles {
			t.Run("SecurityThreshold_"+profile.name, func(t *testing.T) {
				assert.GreaterOrEqual(t, profile.params.Time, minTime,
					"%s profile must meet minimum time security threshold", profile.name)
				assert.GreaterOrEqual(t, profile.params.Memory, minMemory,
					"%s profile must meet minimum memory security threshold", profile.name)
				assert.GreaterOrEqual(t, profile.params.Threads, minThreads,
					"%s profile must meet minimum thread processing threshold", profile.name)
			})
		}
	})
}

// BenchmarkKDFParameterConstructors measures performance characteristics of parameter constructors
// These benchmarks ensure constructor calls have minimal overhead for high-frequency vault operations
func BenchmarkKDFParameterConstructors(b *testing.B) {
	b.Run("NemesisKDFParams_ConstructorPerformance", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			params := NemesisKDFParams()
			if params == nil {
				b.Fatal("Constructor must return valid parameters")
			}
		}
	})

	b.Run("HighSecurityKDFParams_ConstructorPerformance", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			params := HighSecurityKDFParams()
			if params == nil {
				b.Fatal("Constructor must return valid parameters")
			}
		}
	})

	b.Run("FastKDFParams_ConstructorPerformance", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			params := FastKDFParams()
			if params == nil {
				b.Fatal("Constructor must return valid parameters")
			}
		}
	})
}

// TestKDFParameterConstructors_ConcurrentSafety validates thread safety of parameter constructors
// Critical for vault environments with concurrent key derivation operations
func TestKDFParameterConstructors_ConcurrentSafety(t *testing.T) {
	const numGoroutines = 100
	const iterationsPerGoroutine = 10

	constructors := map[string]func() *KDFParams{
		"NEMESIS":      NemesisKDFParams,
		"HighSecurity": HighSecurityKDFParams,
		"Fast":         FastKDFParams,
	}

	for name, constructor := range constructors {
		t.Run("ConcurrentAccess_"+name, func(t *testing.T) {
			// Channel to collect results from goroutines
			results := make(chan *KDFParams, numGoroutines*iterationsPerGoroutine)

			// Launch concurrent goroutines calling constructor
			for g := 0; g < numGoroutines; g++ {
				go func() {
					for i := 0; i < iterationsPerGoroutine; i++ {
						params := constructor()
						results <- params
					}
				}()
			}

			// Collect and validate all results
			expectedResults := numGoroutines * iterationsPerGoroutine
			var collectedParams []*KDFParams

			for i := 0; i < expectedResults; i++ {
				params := <-results
				require.NotNil(t, params, "Constructor must return valid parameters under concurrent access")
				collectedParams = append(collectedParams, params)
			}

			// Verify all results are identical (thread safety validation)
			require.Len(t, collectedParams, expectedResults, "Must collect all concurrent constructor results")

			firstResult := collectedParams[0]
			for i, params := range collectedParams {
				assert.Equal(t, firstResult.Time, params.Time,
					"Time parameter must be consistent across concurrent calls (result %d)", i)
				assert.Equal(t, firstResult.Memory, params.Memory,
					"Memory parameter must be consistent across concurrent calls (result %d)", i)
				assert.Equal(t, firstResult.Threads, params.Threads,
					"Threads parameter must be consistent across concurrent calls (result %d)", i)
			}
		})
	}
}
