// pool.go: Buffer pooling optimized for cryptographic operations
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"sync"
)

var (
	// Buffer pools optimized for different sizes to reduce GC pressure
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32) // Buffer optimized for AES-GCM nonces (12 bytes) and keys (32 bytes)
			return &buf
		},
	}

	mediumBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 512) // Buffer optimized for medium-sized data
			return &buf
		},
	}

	largeBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 4*1024) // Buffer optimized for large data, reduced for better cache locality
			return &buf
		},
	}

	// Pool for dynamic byte slices optimized for common ciphertexts - uses pointers to avoid allocations
	dynamicBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 256)
			return &buf // Return pointer to avoid allocations (SA6002)
		},
	}
)

// init function for automatic warm-up of pools to eliminate cold start latency - ring buffer experience
func init() {
	// Pre-warm pools to reduce first-access latency in production
	// Use conservative count to avoid impacting startup time
	WarmupPools(4)
}

// getBuffer retrieves a buffer from the appropriate pool based on size
func getBuffer(size int) *[]byte {
	switch {
	case size <= 32:
		buf := smallBufferPool.Get().(*[]byte)
		*buf = (*buf)[:size] // Slice to requested size to avoid clear overhead
		return buf
	case size <= 512:
		buf := mediumBufferPool.Get().(*[]byte)
		*buf = (*buf)[:size] // Slice to requested size to avoid clear overhead
		return buf
	case size <= 4*1024:
		buf := largeBufferPool.Get().(*[]byte)
		*buf = (*buf)[:size] // Slice to requested size to avoid clear overhead
		return buf
	default:
		// For very large sizes, allocate directly
		buf := make([]byte, size)
		return &buf
	}
}

// clearBuffer optimizes zeroing for cache locality - inspired by high-performance ring buffer
func clearBuffer(buf []byte) {
	// For small buffers use range loop which is more cache friendly
	if len(buf) <= 64 {
		for i := range buf {
			buf[i] = 0
		}
		return
	}

	// For large buffers use unrolled loop for better throughput on cache line (64 bytes)
	i := 0
	for i < len(buf)-7 {
		// Unroll 8 operations for cache line optimization
		buf[i] = 0
		buf[i+1] = 0
		buf[i+2] = 0
		buf[i+3] = 0
		buf[i+4] = 0
		buf[i+5] = 0
		buf[i+6] = 0
		buf[i+7] = 0
		i += 8
	}
	// Handle remainder
	for i < len(buf) {
		buf[i] = 0
		i++
	}
}

// putBuffer returns a buffer to the appropriate pool - optimized for skip clear on unused buffers
func putBuffer(buf *[]byte) {
	if buf == nil {
		return
	}

	// Micro optimization: skip clear for buffer with capacity but zero length (unused)
	if len(*buf) > 0 {
		clearBuffer(*buf)
	}

	size := cap(*buf)
	switch {
	case size == 32:
		smallBufferPool.Put(buf)
	case size == 512:
		mediumBufferPool.Put(buf)
	case size == 4*1024:
		largeBufferPool.Put(buf)
		// Dynamic buffers or non-standard sizes are not returned to the pool
	}
}

// getDynamicBuffer retrieves a dynamic buffer that can grow - optimized for zero allocations
func getDynamicBuffer() []byte {
	buf := dynamicBufferPool.Get().(*[]byte)
	return (*buf)[:0] // Reset length but keep capacity - eliminates type assertion overhead
}

// putDynamicBuffer returns a dynamic buffer to the pool - optimized for zero allocations
func putDynamicBuffer(buf []byte) {
	bufCap := cap(buf)
	if bufCap == 0 {
		return // Avoid panic on empty buffer
	}

	// For small dynamic buffers we skip clear for performance
	// Only for large buffers where security is more critical
	if bufCap > 1024 {
		fullBuf := buf[:bufCap]
		clearBuffer(fullBuf)
	}

	// Only buffers with optimal capacity are returned to the pool
	if bufCap <= 4*1024 && bufCap >= 128 {
		dynamicBufferPool.Put(&buf) // Pass pointer to avoid allocations (SA6002)
	}
}

// PoolStats provides statistics on the pools for performance monitoring
type PoolStats struct {
	SmallBuffers   int
	MediumBuffers  int
	LargeBuffers   int
	DynamicBuffers int
}

// GetPoolStats returns the current statistics of the pools (for debugging/monitoring)
func GetPoolStats() PoolStats {
	// Note: sync.Pool does not expose direct statistics,
	// this is a placeholder for future implementations with custom pools
	return PoolStats{
		SmallBuffers:   -1, // Not available with standard sync.Pool
		MediumBuffers:  -1,
		LargeBuffers:   -1,
		DynamicBuffers: -1,
	}
}

// WarmupPools pre allocates buffers in the pools to reduce cold latency
func WarmupPools(count int) {
	// Pre-allocates buffers in all pools using helper functions
	smallBufs := make([]*[]byte, count)
	mediumBufs := make([]*[]byte, count)
	largeBufs := make([]*[]byte, count)
	dynamicBufs := make([][]byte, count)

	// Allocates using the wrapper functions that handle type assertions
	for i := 0; i < count; i++ {
		smallBufs[i] = getBuffer(32)
		mediumBufs[i] = getBuffer(1024)
		largeBufs[i] = getBuffer(64 * 1024)
		dynamicBufs[i] = getDynamicBuffer()
	}

	// Returns the buffers to the pools using the helper functions
	for i := 0; i < count; i++ {
		putBuffer(smallBufs[i])
		putBuffer(mediumBufs[i])
		putBuffer(largeBufs[i])
		putDynamicBuffer(dynamicBufs[i])
	}
}
