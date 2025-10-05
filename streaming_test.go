// streaming_test.go: Test cases for streaming encryption/decryption.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/agilira/harpocrates"
)

// TestStreamingEncryptionBasic tests basic streaming encryption functionality
func TestStreamingEncryptionBasic(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	testData := "Hello, World! This is a test of streaming encryption."

	// Encrypt
	var encrypted bytes.Buffer
	encryptor, err := crypto.NewStreamingEncryptor(&encrypted, key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	n, err := encryptor.Write([]byte(testData))
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), n)
	}

	if err := encryptor.Close(); err != nil {
		t.Fatalf("Failed to close encryptor: %v", err)
	}

	// Decrypt
	decryptor, err := crypto.NewStreamingDecryptor(&encrypted, key)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	defer func() { _ = decryptor.Close() }()

	var decrypted bytes.Buffer
	if _, err := io.Copy(&decrypted, decryptor); err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if decrypted.String() != testData {
		t.Errorf("Decrypted data doesn't match original.\nExpected: %q\nGot: %q", testData, decrypted.String())
	}
}

// TestStreamingEncryptionLargeData tests streaming with large datasets
func TestStreamingEncryptionLargeData(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create 1MB of test data
	testData := make([]byte, 1024*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Encrypt
	var encrypted bytes.Buffer
	encryptor, err := crypto.NewStreamingEncryptor(&encrypted, key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	written, err := encryptor.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}
	if written != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), written)
	}

	if err := encryptor.Close(); err != nil {
		t.Fatalf("Failed to close encryptor: %v", err)
	}

	// Decrypt
	decryptor, err := crypto.NewStreamingDecryptor(&encrypted, key)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	defer func() { _ = decryptor.Close() }()

	var decrypted bytes.Buffer
	if _, err := io.Copy(&decrypted, decryptor); err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if !bytes.Equal(decrypted.Bytes(), testData) {
		t.Error("Decrypted data doesn't match original")
	}
}

// TestStreamingEncryptionMultipleWrites tests multiple write operations
func TestStreamingEncryptionMultipleWrites(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test data in chunks
	chunks := []string{
		"First chunk of data",
		"Second chunk of data",
		"Third chunk of data",
		"Final chunk of data",
	}
	expectedData := strings.Join(chunks, "")

	// Encrypt
	var encrypted bytes.Buffer
	encryptor, err := crypto.NewStreamingEncryptor(&encrypted, key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	totalWritten := 0
	for i, chunk := range chunks {
		n, err := encryptor.Write([]byte(chunk))
		if err != nil {
			t.Fatalf("Failed to write chunk %d: %v", i, err)
		}
		totalWritten += n
	}

	if err := encryptor.Close(); err != nil {
		t.Fatalf("Failed to close encryptor: %v", err)
	}

	if totalWritten != len(expectedData) {
		t.Errorf("Expected to write %d bytes total, wrote %d", len(expectedData), totalWritten)
	}

	// Decrypt
	decryptor, err := crypto.NewStreamingDecryptor(&encrypted, key)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	defer func() { _ = decryptor.Close() }()

	var decrypted bytes.Buffer
	if _, err := io.Copy(&decrypted, decryptor); err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if decrypted.String() != expectedData {
		t.Errorf("Decrypted data doesn't match original.\nExpected: %q\nGot: %q", expectedData, decrypted.String())
	}
}

// TestStreamingEncryptionCustomChunkSize tests custom chunk sizes
func TestStreamingEncryptionCustomChunkSize(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	testData := strings.Repeat("A", 1000) // 1KB of data

	chunkSizes := []int{100, 512, 2048}

	for _, chunkSize := range chunkSizes {
		t.Run(fmt.Sprintf("chunkSize_%d", chunkSize), func(t *testing.T) {
			// Encrypt
			var encrypted bytes.Buffer
			encryptor, err := crypto.NewStreamingEncryptorWithChunkSize(&encrypted, key, chunkSize)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			if _, err := encryptor.Write([]byte(testData)); err != nil {
				t.Fatalf("Failed to write data: %v", err)
			}

			if err := encryptor.Close(); err != nil {
				t.Fatalf("Failed to close encryptor: %v", err)
			}

			// Decrypt
			decryptor, err := crypto.NewStreamingDecryptor(&encrypted, key)
			if err != nil {
				t.Fatalf("Failed to create decryptor: %v", err)
			}
			defer func() { _ = decryptor.Close() }()

			var decrypted bytes.Buffer
			if _, err := io.Copy(&decrypted, decryptor); err != nil {
				t.Fatalf("Failed to decrypt data: %v", err)
			}

			if decrypted.String() != testData {
				t.Error("Decrypted data doesn't match original")
			}
		})
	}
}

// TestStreamingEncryptionInvalidParams tests error handling for invalid parameters
func TestStreamingEncryptionInvalidParams(t *testing.T) {
	var buf bytes.Buffer

	tests := []struct {
		name      string
		key       []byte
		chunkSize int
		wantError string
	}{
		{
			name:      "invalid key size",
			key:       []byte("short"),
			chunkSize: 1024,
			wantError: "INVALID_KEY_SIZE",
		},
		{
			name:      "zero chunk size",
			key:       make([]byte, 32),
			chunkSize: 0,
			wantError: "INVALID_CHUNK_SIZE",
		},
		{
			name:      "negative chunk size",
			key:       make([]byte, 32),
			chunkSize: -1,
			wantError: "INVALID_CHUNK_SIZE",
		},
		{
			name:      "chunk size too large",
			key:       make([]byte, 32),
			chunkSize: 11 * 1024 * 1024, // 11MB
			wantError: "INVALID_CHUNK_SIZE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.NewStreamingEncryptorWithChunkSize(&buf, tt.key, tt.chunkSize)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("Expected error containing %q, got %q", tt.wantError, err.Error())
			}
		})
	}
}

// TestStreamingDecryptionInvalidParams tests decryption error handling
func TestStreamingDecryptionInvalidParams(t *testing.T) {
	var buf bytes.Buffer

	// Test invalid key size
	_, err := crypto.NewStreamingDecryptor(&buf, []byte("short"))
	if err == nil {
		t.Fatal("Expected error for short key, got nil")
	}
	if !strings.Contains(err.Error(), "INVALID_KEY_SIZE") {
		t.Errorf("Expected INVALID_KEY_SIZE error, got %q", err.Error())
	}
}

// TestStreamingEncryptionWrongKey tests decryption with wrong key
func TestStreamingEncryptionWrongKey(t *testing.T) {
	key1, _ := crypto.GenerateKey()
	key2, _ := crypto.GenerateKey()

	testData := "Secret data that should fail to decrypt"

	// Encrypt with key1
	var encrypted bytes.Buffer
	encryptor, err := crypto.NewStreamingEncryptor(&encrypted, key1)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	if _, err := encryptor.Write([]byte(testData)); err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	if err := encryptor.Close(); err != nil {
		t.Fatalf("Failed to close encryptor: %v", err)
	}

	// Try to decrypt with key2
	decryptor, err := crypto.NewStreamingDecryptor(&encrypted, key2)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	defer func() { _ = decryptor.Close() }()

	var decrypted bytes.Buffer
	_, err = io.Copy(&decrypted, decryptor)
	if err == nil {
		t.Fatal("Expected decryption error with wrong key, got nil")
	}
	if !strings.Contains(err.Error(), "CHUNK_DECRYPTION_FAILED") {
		t.Errorf("Expected CHUNK_DECRYPTION_FAILED error, got %q", err.Error())
	}
}

// TestStreamingEncryptionCorruptedData tests behavior with corrupted data
func TestStreamingEncryptionCorruptedData(t *testing.T) {
	key, _ := crypto.GenerateKey()
	testData := "This data will be corrupted"

	// Encrypt normally
	var encrypted bytes.Buffer
	encryptor, err := crypto.NewStreamingEncryptor(&encrypted, key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	if _, err := encryptor.Write([]byte(testData)); err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	if err := encryptor.Close(); err != nil {
		t.Fatalf("Failed to close encryptor: %v", err)
	}

	// Corrupt the data by flipping a bit in the middle
	encryptedData := encrypted.Bytes()
	if len(encryptedData) > 30 {
		encryptedData[30] ^= 0x01 // Flip one bit
	}

	// Try to decrypt corrupted data
	corruptedReader := bytes.NewReader(encryptedData)
	decryptor, err := crypto.NewStreamingDecryptor(corruptedReader, key)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	defer func() { _ = decryptor.Close() }()

	var decrypted bytes.Buffer
	_, err = io.Copy(&decrypted, decryptor)
	if err == nil {
		t.Fatal("Expected decryption error with corrupted data, got nil")
	}
}

// TestStreamingEncryptionEmptyData tests streaming with empty data
func TestStreamingEncryptionEmptyData(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Encrypt empty data
	var encrypted bytes.Buffer
	encryptor, err := crypto.NewStreamingEncryptor(&encrypted, key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	if err := encryptor.Close(); err != nil {
		t.Fatalf("Failed to close encryptor: %v", err)
	}

	// Decrypt
	decryptor, err := crypto.NewStreamingDecryptor(&encrypted, key)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	defer func() { _ = decryptor.Close() }()

	var decrypted bytes.Buffer
	if _, err := io.Copy(&decrypted, decryptor); err != nil {
		t.Fatalf("Failed to decrypt empty data: %v", err)
	}

	if decrypted.Len() != 0 {
		t.Errorf("Expected empty decrypted data, got %d bytes", decrypted.Len())
	}
}

// TestStreamingEncryptionClosedOperations tests operations on closed encryptor/decryptor
func TestStreamingEncryptionClosedOperations(t *testing.T) {
	key, _ := crypto.GenerateKey()

	// Test writing to closed encryptor
	var buf bytes.Buffer
	encryptor, _ := crypto.NewStreamingEncryptor(&buf, key)
	_ = encryptor.Close()

	_, err := encryptor.Write([]byte("test"))
	if err == nil {
		t.Fatal("Expected error writing to closed encryptor, got nil")
	}
	if !strings.Contains(err.Error(), "ENCRYPTOR_CLOSED") {
		t.Errorf("Expected ENCRYPTOR_CLOSED error, got %q", err.Error())
	}

	// Test reading from closed decryptor
	// First create valid encrypted data
	buf.Reset()
	encryptor2, _ := crypto.NewStreamingEncryptor(&buf, key)
	_, _ = encryptor2.Write([]byte("test"))
	_ = encryptor2.Close()

	decryptor, _ := crypto.NewStreamingDecryptor(&buf, key)
	_ = decryptor.Close()

	data := make([]byte, 10)
	_, err = decryptor.Read(data)
	if err == nil {
		t.Fatal("Expected error reading from closed decryptor, got nil")
	}
	if !strings.Contains(err.Error(), "DECRYPTOR_CLOSED") {
		t.Errorf("Expected DECRYPTOR_CLOSED error, got %q", err.Error())
	}
}

// TestStreamingEncryptionNEMESISPattern tests NEMESIS DR snapshot pattern
func TestStreamingEncryptionNEMESISPattern(t *testing.T) {
	// Simulate NEMESIS pattern: KEK -> DEK for streaming
	kek, _ := crypto.GenerateKey()

	// Derive DEK for this snapshot using HKDF
	dek, err := crypto.DeriveKeyHKDF(kek, nil, []byte("nemesis-snapshot-v1"), 32)
	if err != nil {
		t.Fatalf("Failed to derive DEK: %v", err)
	}

	// Simulate large snapshot data (10MB)
	snapshotSize := 10 * 1024 * 1024
	snapshotData := make([]byte, snapshotSize)
	_, _ = rand.Read(snapshotData)

	// Encrypt snapshot with streaming
	var encrypted bytes.Buffer
	encryptor, err := crypto.NewStreamingEncryptor(&encrypted, dek)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Write in chunks to simulate real streaming
	chunkSize := 1024 * 1024 // 1MB chunks
	for i := 0; i < len(snapshotData); i += chunkSize {
		end := i + chunkSize
		if end > len(snapshotData) {
			end = len(snapshotData)
		}

		if _, err := encryptor.Write(snapshotData[i:end]); err != nil {
			t.Fatalf("Failed to write chunk at offset %d: %v", i, err)
		}
	}

	if err := encryptor.Close(); err != nil {
		t.Fatalf("Failed to close encryptor: %v", err)
	}

	// Verify encrypted size includes overhead but is reasonable
	encryptedSize := encrypted.Len()
	overhead := float64(encryptedSize-snapshotSize) / float64(snapshotSize) * 100
	if overhead > 5.0 { // Should be less than 5% overhead
		t.Errorf("Encryption overhead too high: %.2f%% (encrypted: %d, original: %d)",
			overhead, encryptedSize, snapshotSize)
	}

	// Decrypt snapshot
	decryptor, err := crypto.NewStreamingDecryptor(&encrypted, dek)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	defer func() { _ = decryptor.Close() }()

	var decrypted bytes.Buffer
	if _, err := io.Copy(&decrypted, decryptor); err != nil {
		t.Fatalf("Failed to decrypt snapshot: %v", err)
	}

	// Verify integrity
	if !bytes.Equal(decrypted.Bytes(), snapshotData) {
		t.Error("Decrypted snapshot doesn't match original")
	}

	t.Logf("✅ NEMESIS pattern test: %d MB snapshot, %.2f%% overhead",
		snapshotSize/(1024*1024), overhead)
}

// TestStreamingEncryptionConcurrency tests concurrent streaming operations
func TestStreamingEncryptionConcurrency(t *testing.T) {
	key, _ := crypto.GenerateKey()
	testData := strings.Repeat("Concurrent test data ", 1000)

	// Test multiple concurrent encrypt/decrypt operations
	numGoroutines := 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Each goroutine gets unique data
			data := fmt.Sprintf("%s [goroutine-%d]", testData, id)

			// Encrypt
			var encrypted bytes.Buffer
			encryptor, err := crypto.NewStreamingEncryptor(&encrypted, key)
			if err != nil {
				t.Errorf("Goroutine %d: Failed to create encryptor: %v", id, err)
				return
			}

			if _, err := encryptor.Write([]byte(data)); err != nil {
				t.Errorf("Goroutine %d: Failed to write data: %v", id, err)
				return
			}

			if err := encryptor.Close(); err != nil {
				t.Errorf("Goroutine %d: Failed to close encryptor: %v", id, err)
				return
			}

			// Decrypt
			decryptor, err := crypto.NewStreamingDecryptor(&encrypted, key)
			if err != nil {
				t.Errorf("Goroutine %d: Failed to create decryptor: %v", id, err)
				return
			}
			defer func() { _ = decryptor.Close() }()

			var decrypted bytes.Buffer
			if _, err := io.Copy(&decrypted, decryptor); err != nil {
				t.Errorf("Goroutine %d: Failed to decrypt data: %v", id, err)
				return
			}

			if decrypted.String() != data {
				t.Errorf("Goroutine %d: Decrypted data mismatch", id)
				return
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestStreamingEncryptionInvalidHeader tests invalid stream headers during decryption
func TestStreamingEncryptionInvalidHeader(t *testing.T) {
	key, _ := crypto.GenerateKey()

	tests := []struct {
		name      string
		header    []byte
		wantError string
	}{
		{
			name:      "invalid magic",
			header:    []byte("BADM\x01\x00\x00\x00abcdefghijkl\x00\x04\x00\x00"),
			wantError: "INVALID_STREAM_FORMAT",
		},
		{
			name:      "unsupported version",
			header:    []byte("AGCM\x02\x00\x00\x00abcdefghijkl\x00\x04\x00\x00"),
			wantError: "UNSUPPORTED_STREAM_VERSION",
		},
		{
			name:      "invalid chunk size",
			header:    []byte("AGCM\x01\x00\x00\x00abcdefghijkl\x00\x00\x00\x80"), // 2GB chunk size
			wantError: "INVALID_CHUNK_SIZE",
		},
		{
			name:      "truncated header",
			header:    []byte("AGCM\x01\x00"),
			wantError: "HEADER_READ_FAILED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.header)
			decryptor, err := crypto.NewStreamingDecryptor(reader, key)
			if err != nil {
				// Some errors occur during construction
				if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("Expected error containing %q, got %q", tt.wantError, err.Error())
				}
				return
			}

			// Others occur during first read
			buf := make([]byte, 100)
			_, err = decryptor.Read(buf)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("Expected error containing %q, got %q", tt.wantError, err.Error())
			}
		})
	}
}

// TestStreamingEncryptionMultipleClose tests multiple close operations
func TestStreamingEncryptionMultipleClose(t *testing.T) {
	key, _ := crypto.GenerateKey()

	// Test multiple closes on encryptor
	var buf bytes.Buffer
	encryptor, err := crypto.NewStreamingEncryptor(&buf, key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// First close should succeed
	if err := encryptor.Close(); err != nil {
		t.Errorf("First close failed: %v", err)
	}

	// Second close should be no-op
	if err := encryptor.Close(); err != nil {
		t.Errorf("Second close failed: %v", err)
	}

	// Test multiple closes on decryptor
	decryptor, err := crypto.NewStreamingDecryptor(&buf, key)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}

	// First close should succeed
	if err := decryptor.Close(); err != nil {
		t.Errorf("First close failed: %v", err)
	}

	// Second close should be no-op
	if err := decryptor.Close(); err != nil {
		t.Errorf("Second close failed: %v", err)
	}
}
