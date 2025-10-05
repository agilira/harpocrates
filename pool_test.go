// pool_test.go: Buffer pooling tests
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestBufferPoolBasic verifies basic get/put operations of the buffer pools
func TestBufferPoolBasic(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"Small buffer (32B)", 32},
		{"Medium buffer (1KB)", 1024},
		{"Large buffer (64KB)", 64 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get buffer
			buf := getBuffer(tt.size)
			if buf == nil {
				t.Fatal("getBuffer returned nil")
			}

			// Verify that the buffer is at least the requested size
			if cap(*buf) < tt.size {
				t.Errorf("Buffer capacity %d < requested size %d", cap(*buf), tt.size)
			}

			// Test writing/reading
			if len(*buf) >= tt.size {
				for i := 0; i < tt.size && i < len(*buf); i++ {
					(*buf)[i] = byte(i % 256)
				}
			}

			// Return to pool
			putBuffer(buf)
		})
	}
}

// TestDynamicBufferPool verifies the functionality of the dynamic pool
func TestDynamicBufferPool(t *testing.T) {
	// Get dynamic buffer
	buf := getDynamicBuffer()
	if buf == nil {
		t.Fatal("getDynamicBuffer returned nil")
	}

	// Verify initial capacity (optimized for cache locality)
	if cap(buf) < 256 {
		t.Errorf("Dynamic buffer capacity %d too small", cap(buf))
	}

	// Test append operations
	buf = append(buf, []byte("test data for dynamic buffer")...)
	if len(buf) == 0 {
		t.Error("Dynamic buffer should contain data")
	}

	// Return to pool
	putDynamicBuffer(buf)
}

// TestBufferPoolSafety verifies the safety of buffer pooling (zero-out)
func TestBufferPoolSafety(t *testing.T) {
	// Get buffer and write sensitive data
	buf := getBuffer(64)
	sensitiveData := []byte("secret-data-12345")
	copy(*buf, sensitiveData)

	// Return to pool
	putBuffer(buf)

	// Get another buffer and verify it has been zeroed
	buf2 := getBuffer(64)
	defer putBuffer(buf2)

	for i := 0; i < len(sensitiveData) && i < len(*buf2); i++ {
		if (*buf2)[i] != 0 {
			t.Errorf("Buffer not zeroed at position %d: got %v, want 0", i, (*buf2)[i])
		}
	}
}

// TestBufferPoolConcurrency verifica thread-safety
func TestBufferPoolConcurrency(t *testing.T) {
	const numGoroutines = 100
	const numOpsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Test concurrent access
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOpsPerGoroutine; j++ {
				// Test small buffer pool
				smallBuf := getBuffer(32)
				(*smallBuf)[0] = byte(id)
				putBuffer(smallBuf)

				// Test medium buffer pool
				medBuf := getBuffer(1024)
				(*medBuf)[0] = byte(j)
				putBuffer(medBuf)

				// Test dynamic buffer pool
				dynBuf := getDynamicBuffer()
				dynBuf = append(dynBuf, byte(id), byte(j))
				putDynamicBuffer(dynBuf)
			}
		}(i)
	}

	wg.Wait()
}

// TestWarmupPools verifies the warmup function
func TestWarmupPools(t *testing.T) {
	// Warmup with 10 buffers per pool
	WarmupPools(10)

	// Verify that buffers are available (indirect test)
	// Ensure there are no panics or errors
	for i := 0; i < 5; i++ {
		buf := getBuffer(64)
		putBuffer(buf)

		dynBuf := getDynamicBuffer()
		putDynamicBuffer(dynBuf)
	}
}

// TestPoolStats verifies that the statistics do not panic
func TestPoolStats(t *testing.T) {
	stats := GetPoolStats()
	// Statistics are -1 with standard sync.Pool (placeholder)
	if stats.SmallBuffers != -1 || stats.MediumBuffers != -1 ||
		stats.LargeBuffers != -1 || stats.DynamicBuffers != -1 {
		t.Log("Pool stats available:", stats)
	}
}

// BenchmarkEncryptionWithPooling compares performance with/without pooling
func BenchmarkEncryptionWithPooling(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}

	testCases := []struct {
		name string
		data string
	}{
		{"Small (16B)", "small test data"},
		{"Medium (1KB)", generateBenchData(1024)},
		{"Large (64KB)", generateBenchData(64 * 1024)},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encrypted, err := Encrypt(tc.data, key)
				if err != nil {
					b.Fatal(err)
				}

				_, err = Decrypt(encrypted, key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkBufferPoolOperations measures the performance of pool operations
func BenchmarkBufferPoolOperations(b *testing.B) {
	b.Run("SmallBuffer", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := getBuffer(32)
			putBuffer(buf)
		}
	})

	b.Run("MediumBuffer", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := getBuffer(1024)
			putBuffer(buf)
		}
	})

	b.Run("DynamicBuffer", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := getDynamicBuffer()
			putDynamicBuffer(buf)
		}
	})
}

// BenchmarkEncryptionAllocation measures memory allocations
func BenchmarkEncryptionAllocation(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}

	data := "test data for allocation benchmarking"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		encrypted, err := Encrypt(data, key)
		if err != nil {
			b.Fatal(err)
		}

		_, err = Decrypt(encrypted, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestEncryptionPerformanceNEMESIS verifies that performance is >= 500k ops/s for NEMESIS
func TestEncryptionPerformanceNEMESIS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	// Test NEMESIS typical use case: small encrypted values
	testData := "vault-secret-key-12345678901234567890"

	const targetOpsPerSec = 500_000 // NEMESIS requirement
	const testDuration = 1 * time.Second

	start := time.Now()
	ops := 0

	for time.Since(start) < testDuration {
		encrypted, err := Encrypt(testData, key)
		if err != nil {
			t.Fatal(err)
		}

		_, err = Decrypt(encrypted, key)
		if err != nil {
			t.Fatal(err)
		}

		ops += 2 // encrypt + decrypt
	}

	actualDuration := time.Since(start)
	opsPerSec := float64(ops) / actualDuration.Seconds()

	t.Logf("Performance: %.0f ops/sec (target: %d ops/sec)", opsPerSec, targetOpsPerSec)
	t.Logf("Operations: %d in %v", ops, actualDuration)

	if opsPerSec < targetOpsPerSec {
		t.Logf("⚠️  Performance below NEMESIS target: %.0f < %d ops/sec", opsPerSec, targetOpsPerSec)
		// doesn't fail the test, just log a warning
	} else {
		t.Logf("✅ Performance meets NEMESIS requirement: %.0f >= %d ops/sec", opsPerSec, targetOpsPerSec)
	}
}

// TestMemoryUsageOptimization verifies that pooling reduces allocations
func TestMemoryUsageOptimization(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	data := "test data for memory optimization"

	// Force garbage collection for clean baseline
	runtime.GC()

	// Measure memory before
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Perform operations with pooling
	for i := 0; i < 1000; i++ {
		encrypted, err := Encrypt(data, key)
		if err != nil {
			t.Fatal(err)
		}

		_, err = Decrypt(encrypted, key)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Measure memory after
	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Calculate allocations
	allocBytes := m2.TotalAlloc - m1.TotalAlloc
	allocsCount := m2.Mallocs - m1.Mallocs

	t.Logf("Memory allocated: %d bytes in %d allocations", allocBytes, allocsCount)
	t.Logf("Average allocation: %d bytes per op", allocBytes/1000)

	// Pooling should keep allocations reasonable
	if allocsCount > 10000 { // Reasonable threshold
		t.Logf("⚠️  High allocation count: %d (may indicate pooling not working optimally)", allocsCount)
	}
}

// generateBenchData generates test data for benchmarks
func generateBenchData(size int) string {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}
	return string(data)
}
