// flush_vault_test.go: Test cases for Vault Flushing functions.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// errorWriter simulates write failures for testing error paths - reserved for future I/O failure tests
var _ io.Writer = (*errorWriter)(nil) // Ensure interface compliance

type errorWriter struct {
	writeCount int
	failAt     int
}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	w.writeCount++
	if w.writeCount == w.failAt {
		return 0, errors.New("simulated write failure")
	}
	return len(p), nil
}

// TestFlushChunk_VaultSecurity tests flushChunk (83.3% → 85%+)
// Chunk flushing is critical for vault streaming security
func TestFlushChunk_VaultSecurity(t *testing.T) {
	t.Run("EmptyBufferFlush", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}

		var output bytes.Buffer
		encryptor, err := NewStreamingEncryptor(&output, key)
		if err != nil {
			t.Fatalf("Failed to create streaming encryptor: %v", err)
		}

		// Close immediately without writing data (tests empty buffer flush)
		err = encryptor.Close()
		if err != nil {
			t.Errorf("Closing with empty buffer should succeed: %v", err)
		}

		// Output should contain only header, no chunk data
		if output.Len() == 0 {
			t.Error("Output should contain at least the header")
		}
	})

	t.Run("ChunkCounterOverflowHandling", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 42)
		}

		var output bytes.Buffer
		encryptor, err := NewStreamingEncryptorWithChunkSize(&output, key, 1024)
		if err != nil {
			t.Fatalf("Failed to create streaming encryptor: %v", err)
		}

		// Access the internal encryptor to simulate overflow condition
		if se, ok := encryptor.(*streamingEncryptor); ok {
			// Simulate being very close to chunk counter overflow
			se.bytesWritten = int64(0xFFFFFFFF) * 1024 // Near max uint32 chunks

			// Write small data to trigger flush
			data := []byte("overflow-test-data")
			_, err = encryptor.Write(data)
			// This might fail due to chunk counter overflow, which is expected behavior
			if err != nil && !contains(err.Error(), "CHUNK_OVERFLOW") {
				t.Errorf("Expected chunk overflow error or success, got: %v", err)
			}
		}
	})

	t.Run("MultipleSmallWrites", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 84)
		}

		var output bytes.Buffer
		encryptor, err := NewStreamingEncryptor(&output, key)
		if err != nil {
			t.Fatalf("Failed to create streaming encryptor: %v", err)
		}

		// Write multiple small chunks to test buffering and flushing
		for i := 0; i < 10; i++ {
			data := make([]byte, 100)
			for j := range data {
				data[j] = byte((i*100 + j) % 256)
			}

			_, err = encryptor.Write(data)
			if err != nil {
				t.Errorf("Small write %d should succeed: %v", i, err)
			}
		}

		// Close to flush remaining data
		err = encryptor.Close()
		if err != nil {
			t.Errorf("Closing after multiple small writes should succeed: %v", err)
		}

		if output.Len() == 0 {
			t.Error("Multiple small writes should produce output")
		}
	})

	t.Run("ExactChunkSizeBoundary", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 128)
		}

		var output bytes.Buffer
		chunkSize := 1024
		encryptor, err := NewStreamingEncryptorWithChunkSize(&output, key, chunkSize)
		if err != nil {
			t.Fatalf("Failed to create streaming encryptor: %v", err)
		}

		// Write exactly chunk size to test boundary condition
		data := make([]byte, chunkSize)
		for i := range data {
			data[i] = byte((i * 3) % 256)
		}

		_, err = encryptor.Write(data)
		if err != nil {
			t.Errorf("Exact chunk size write should succeed: %v", err)
		}

		// Write one more byte to trigger flush of previous chunk
		_, err = encryptor.Write([]byte{0xFF})
		if err != nil {
			t.Errorf("Additional byte write should succeed: %v", err)
		}

		err = encryptor.Close()
		if err != nil {
			t.Errorf("Closing after boundary test should succeed: %v", err)
		}

		if output.Len() == 0 {
			t.Error("Boundary test should produce output")
		}
	})

	t.Run("LargeEncryptedChunkHandling", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 200)
		}

		var output bytes.Buffer
		// Use large but valid chunk size
		encryptor, err := NewStreamingEncryptorWithChunkSize(&output, key, 8*1024*1024) // 8MB chunks
		if err != nil {
			t.Fatalf("Failed to create streaming encryptor: %v", err)
		}

		// Write large amount of data
		largeData := make([]byte, 1024*1024) // 1MB of data
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		_, err = encryptor.Write(largeData)
		if err != nil {
			t.Errorf("Large data write should succeed: %v", err)
		}

		err = encryptor.Close()
		if err != nil {
			t.Errorf("Closing with large data should succeed: %v", err)
		}

		if output.Len() == 0 {
			t.Error("Large data flush should produce output")
		}
	})
}

// Helper function to check if string contains substring
func contains(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || (len(str) > len(substr) &&
		(str[:len(substr)] == substr || str[len(str)-len(substr):] == substr ||
			findSubstring(str, substr))))
}

func findSubstring(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
