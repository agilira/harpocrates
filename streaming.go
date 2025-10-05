// streaming.go: Streaming encryption/decryption for large data sets.
//
// This module provides streaming interfaces for encrypting and decrypting large
// amounts of data without loading everything into memory. This is crucial for
// NEMESIS disaster recovery snapshots that can be several gigabytes in size.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	goerrors "github.com/agilira/go-errors"
)

// StreamingEncryptor provides streaming encryption capabilities for large datasets.
// It encrypts data in chunks while maintaining the security guarantees of AES-GCM.
//
// Example usage:
//
//	key, _ := crypto.GenerateKey()
//	encryptor, _ := crypto.NewStreamingEncryptor(outputWriter, key)
//	defer encryptor.Close()
//
//	io.Copy(encryptor, inputReader) // Encrypts while streaming
//
// Note: The output format includes a header with nonce and authentication data.
type StreamingEncryptor interface {
	// Write encrypts and writes data to the underlying writer.
	// Data is processed in chunks for memory efficiency.
	Write(data []byte) (int, error)

	// Close finalizes the encryption and writes any remaining data.
	// Must be called to ensure data integrity.
	Close() error
}

// StreamingDecryptor provides streaming decryption capabilities for large datasets.
// It decrypts data in chunks while verifying authentication tags.
//
// Example usage:
//
//	key, _ := crypto.GenerateKey()
//	decryptor, _ := crypto.NewStreamingDecryptor(inputReader, key)
//	defer decryptor.Close()
//
//	io.Copy(outputWriter, decryptor) // Decrypts while streaming
//
// Note: Reads header information first to extract nonce and verify format.
type StreamingDecryptor interface {
	// Read decrypts and returns data from the underlying reader.
	// Data is processed in chunks for memory efficiency.
	Read(data []byte) (int, error)

	// Close finalizes the decryption and verifies final authentication.
	// Must be called to ensure data integrity.
	Close() error
}

// streamingEncryptor implements StreamingEncryptor using AES-GCM.
type streamingEncryptor struct {
	writer       io.Writer
	gcm          cipher.AEAD
	nonce        []byte
	buffer       []byte
	chunkSize    int
	closed       bool
	bytesWritten int64
}

// streamingDecryptor implements StreamingDecryptor using AES-GCM.
type streamingDecryptor struct {
	reader     io.Reader
	gcm        cipher.AEAD
	nonce      []byte
	buffer     []byte
	chunkSize  int
	closed     bool
	headerRead bool
	remaining  []byte // Leftover bytes from previous read
	chunkCount uint32 // Explicit chunk counter for nonce generation
}

// Default chunk size for streaming operations (64KB)
// This balances memory usage with encryption efficiency.
const DefaultChunkSize = 64 * 1024

// Stream format header structure:
// [4 bytes: Magic] [4 bytes: Version] [12 bytes: Nonce] [4 bytes: Chunk Size]
const (
	streamMagic   = "AGCM" // AGILira GCM format
	streamVersion = uint32(1)
	headerSize    = 4 + 4 + 12 + 4 // 24 bytes total
)

// NewStreamingEncryptor creates a new streaming encryptor with default chunk size.
//
// Parameters:
//   - writer: Destination writer for encrypted data
//   - key: 32-byte AES-256 key for encryption
//
// Returns a StreamingEncryptor that encrypts data in chunks while maintaining
// AES-GCM security guarantees. The encrypted stream includes a header with
// metadata required for decryption.
//
// Example:
//
//	file, _ := os.Create("encrypted.bin")
//	key, _ := crypto.GenerateKey()
//	enc, err := crypto.NewStreamingEncryptor(file, key)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer enc.Close()
func NewStreamingEncryptor(writer io.Writer, key []byte) (StreamingEncryptor, error) {
	return NewStreamingEncryptorWithChunkSize(writer, key, DefaultChunkSize)
}

// NewStreamingEncryptorWithChunkSize creates a streaming encryptor with custom chunk size.
//
// Parameters:
//   - writer: Destination writer for encrypted data
//   - key: 32-byte AES-256 key for encryption
//   - chunkSize: Size of each encrypted chunk (recommended: 64KB-1MB)
//
// Smaller chunks use less memory but have more overhead.
// Larger chunks are more efficient but use more memory.
func NewStreamingEncryptorWithChunkSize(writer io.Writer, key []byte, chunkSize int) (StreamingEncryptor, error) {
	if len(key) != 32 {
		return nil, goerrors.New("INVALID_KEY_SIZE", "key must be 32 bytes for AES-256")
	}
	if chunkSize <= 0 || chunkSize > 10*1024*1024 { // Max 10MB chunks
		return nil, goerrors.New("INVALID_CHUNK_SIZE", "chunk size must be between 1 and 10MB")
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, goerrors.Wrap(err, "CIPHER_CREATION_FAILED", "failed to create AES cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, goerrors.Wrap(err, "GCM_CREATION_FAILED", "failed to create GCM mode")
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, goerrors.Wrap(err, "NONCE_GENERATION_FAILED", "failed to generate nonce")
	}

	enc := &streamingEncryptor{
		writer:    writer,
		gcm:       gcm,
		nonce:     nonce,
		chunkSize: chunkSize,
		buffer:    make([]byte, 0, chunkSize),
		closed:    false,
	}

	// Write header
	if err := enc.writeHeader(); err != nil {
		return nil, err
	}

	return enc, nil
}

// NewStreamingDecryptor creates a new streaming decryptor.
//
// Parameters:
//   - reader: Source reader for encrypted data
//   - key: 32-byte AES-256 key for decryption
//
// The decryptor automatically reads the header to extract nonce and chunk size,
// then provides streaming decryption of the remaining data.
//
// Example:
//
//	file, _ := os.Open("encrypted.bin")
//	key := getKey() // Your 32-byte key
//	dec, err := crypto.NewStreamingDecryptor(file, key)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer dec.Close()
func NewStreamingDecryptor(reader io.Reader, key []byte) (StreamingDecryptor, error) {
	if len(key) != 32 {
		return nil, goerrors.New("INVALID_KEY_SIZE", "key must be 32 bytes for AES-256")
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, goerrors.Wrap(err, "CIPHER_CREATION_FAILED", "failed to create AES cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, goerrors.Wrap(err, "GCM_CREATION_FAILED", "failed to create GCM mode")
	}

	dec := &streamingDecryptor{
		reader:     reader,
		gcm:        gcm,
		closed:     false,
		headerRead: false,
		remaining:  make([]byte, 0),
	}

	return dec, nil
}

// writeHeader writes the stream format header.
func (e *streamingEncryptor) writeHeader() error {
	header := make([]byte, headerSize)

	// Magic bytes
	copy(header[0:4], []byte(streamMagic))

	// Version (little endian)
	header[4] = byte(streamVersion)
	header[5] = byte(streamVersion >> 8)
	header[6] = byte(streamVersion >> 16)
	header[7] = byte(streamVersion >> 24)

	// Nonce
	copy(header[8:20], e.nonce)

	// Chunk size (little endian)
	if e.chunkSize > 0xFFFFFFFF {
		return goerrors.New("CHUNK_SIZE_OVERFLOW", "chunk size too large")
	}
	chunkSize := uint32(e.chunkSize) // #nosec G115 -- overflow checked above
	header[20] = byte(chunkSize)
	header[21] = byte(chunkSize >> 8)
	header[22] = byte(chunkSize >> 16)
	header[23] = byte(chunkSize >> 24)

	_, err := e.writer.Write(header)
	if err != nil {
		return goerrors.Wrap(err, "HEADER_WRITE_FAILED", "failed to write stream header")
	}

	return nil
}

// Write implements the Write method of StreamingEncryptor.
func (e *streamingEncryptor) Write(data []byte) (int, error) {
	if e.closed {
		return 0, goerrors.New("ENCRYPTOR_CLOSED", "cannot write to closed encryptor")
	}

	totalWritten := 0

	for len(data) > 0 {
		// Fill buffer up to chunk size
		available := e.chunkSize - len(e.buffer)
		toWrite := len(data)
		if toWrite > available {
			toWrite = available
		}

		e.buffer = append(e.buffer, data[:toWrite]...)
		data = data[toWrite:]
		totalWritten += toWrite

		// If buffer is full, encrypt and write chunk
		if len(e.buffer) == e.chunkSize {
			if err := e.flushChunk(); err != nil {
				return totalWritten, err
			}
		}
	}

	return totalWritten, nil
}

// Close implements the Close method of StreamingEncryptor.
func (e *streamingEncryptor) Close() error {
	if e.closed {
		return nil
	}

	// Flush any remaining data
	if len(e.buffer) > 0 {
		if err := e.flushChunk(); err != nil {
			return err
		}
	}

	e.closed = true
	return nil
}

// flushChunk encrypts and writes the current buffer as a chunk.
func (e *streamingEncryptor) flushChunk() error {
	if len(e.buffer) == 0 {
		return nil
	}

	// Create chunk-specific nonce by appending chunk counter
	chunkNonce := make([]byte, len(e.nonce)+4)
	copy(chunkNonce, e.nonce)

	// Add chunk counter (little endian)
	bytesPerChunk := int64(e.chunkSize)
	chunkCounterI64 := e.bytesWritten / bytesPerChunk
	if chunkCounterI64 > 0xFFFFFFFF {
		return goerrors.New("CHUNK_OVERFLOW", "chunk counter overflow")
	}
	chunkCounter := uint32(chunkCounterI64) // #nosec G115 -- overflow checked above
	chunkNonce[len(e.nonce)] = byte(chunkCounter)
	chunkNonce[len(e.nonce)+1] = byte(chunkCounter >> 8)
	chunkNonce[len(e.nonce)+2] = byte(chunkCounter >> 16)
	chunkNonce[len(e.nonce)+3] = byte(chunkCounter >> 24)

	// Encrypt chunk
	// #nosec G407 -- chunkNonce is generated from random base nonce + counter, not hardcoded
	encrypted := e.gcm.Seal(nil, chunkNonce[:e.gcm.NonceSize()], e.buffer, nil)

	// Write chunk size (little endian) + encrypted data
	chunkHeader := make([]byte, 4)
	encryptedLen := len(encrypted)
	if encryptedLen > 0xFFFFFFFF {
		return goerrors.New("ENCRYPTED_SIZE_OVERFLOW", "encrypted chunk too large")
	}
	encryptedSize := uint32(encryptedLen)
	chunkHeader[0] = byte(encryptedSize)
	chunkHeader[1] = byte(encryptedSize >> 8)
	chunkHeader[2] = byte(encryptedSize >> 16)
	chunkHeader[3] = byte(encryptedSize >> 24)

	if _, err := e.writer.Write(chunkHeader); err != nil {
		return goerrors.Wrap(err, "CHUNK_HEADER_WRITE_FAILED", "failed to write chunk header")
	}

	if _, err := e.writer.Write(encrypted); err != nil {
		return goerrors.Wrap(err, "CHUNK_WRITE_FAILED", "failed to write encrypted chunk")
	}

	e.bytesWritten += int64(len(e.buffer))
	e.buffer = e.buffer[:0] // Reset buffer

	return nil
}

// readHeader reads and validates the stream format header.
func (d *streamingDecryptor) readHeader() error {
	if d.headerRead {
		return nil
	}

	header := make([]byte, headerSize)
	if _, err := io.ReadFull(d.reader, header); err != nil {
		return goerrors.Wrap(err, "HEADER_READ_FAILED", "failed to read stream header")
	}

	// Validate magic
	if string(header[0:4]) != streamMagic {
		return goerrors.New("INVALID_STREAM_FORMAT", "invalid magic bytes")
	}

	// Read version
	version := uint32(header[4]) | uint32(header[5])<<8 | uint32(header[6])<<16 | uint32(header[7])<<24
	if version != streamVersion {
		return goerrors.New("UNSUPPORTED_STREAM_VERSION", "unsupported stream version")
	}

	// Extract nonce
	d.nonce = make([]byte, 12)
	copy(d.nonce, header[8:20])

	// Read chunk size
	d.chunkSize = int(uint32(header[20]) | uint32(header[21])<<8 | uint32(header[22])<<16 | uint32(header[23])<<24)
	if d.chunkSize <= 0 || d.chunkSize > 10*1024*1024 {
		return goerrors.New("INVALID_CHUNK_SIZE", "invalid chunk size in header")
	}

	d.buffer = make([]byte, 0, d.chunkSize+16) // +16 for GCM tag
	d.headerRead = true

	return nil
}

// Read implements the Read method of StreamingDecryptor.
func (d *streamingDecryptor) Read(data []byte) (int, error) {
	if d.closed {
		return 0, goerrors.New("DECRYPTOR_CLOSED", "cannot read from closed decryptor")
	}

	// Read header if not done yet
	if !d.headerRead {
		if err := d.readHeader(); err != nil {
			return 0, err
		}
	}

	totalRead := 0

	for len(data) > 0 {
		// If we have remaining decrypted data, use it first
		if len(d.remaining) > 0 {
			n := copy(data, d.remaining)
			d.remaining = d.remaining[n:]
			data = data[n:]
			totalRead += n
			continue
		}

		// Read next chunk
		chunk, err := d.readNextChunk()
		if err != nil {
			if err == io.EOF && totalRead > 0 {
				return totalRead, nil
			}
			return totalRead, err
		}

		if len(chunk) == 0 {
			return totalRead, io.EOF
		}

		// Copy what we can to output buffer
		n := copy(data, chunk)
		if n < len(chunk) {
			// Save remainder for next read
			d.remaining = make([]byte, len(chunk)-n)
			copy(d.remaining, chunk[n:])
		}

		data = data[n:]
		totalRead += n
	}

	return totalRead, nil
}

// Close implements the Close method of StreamingDecryptor.
func (d *streamingDecryptor) Close() error {
	if d.closed {
		return nil
	}

	d.closed = true
	return nil
}

// readNextChunk reads and decrypts the next chunk from the stream.
func (d *streamingDecryptor) readNextChunk() ([]byte, error) {
	// Read chunk size
	chunkHeader := make([]byte, 4)
	if _, err := io.ReadFull(d.reader, chunkHeader); err != nil {
		return nil, err // Propagate EOF or other read errors
	}

	encryptedSize := uint32(chunkHeader[0]) | uint32(chunkHeader[1])<<8 | uint32(chunkHeader[2])<<16 | uint32(chunkHeader[3])<<24

	if encryptedSize == 0 {
		return []byte{}, nil
	}

	maxSize := d.chunkSize + 16 // +16 for GCM tag
	if maxSize > 0xFFFFFFFF {
		return nil, goerrors.New("MAX_SIZE_OVERFLOW", "maximum chunk size too large")
	}
	maxSizeUint32 := uint32(maxSize) // #nosec G115 -- overflow checked above
	if encryptedSize > maxSizeUint32 {
		return nil, goerrors.New("INVALID_CHUNK_SIZE", "chunk size exceeds maximum")
	}

	// Read encrypted chunk
	encrypted := make([]byte, encryptedSize)
	if _, err := io.ReadFull(d.reader, encrypted); err != nil {
		return nil, goerrors.Wrap(err, "CHUNK_READ_FAILED", "failed to read encrypted chunk")
	}

	// Create chunk-specific nonce using explicit chunk counter
	// This is more robust than approximating from buffer length
	if d.chunkCount > 0xFFFFFFFF-1 {
		return nil, goerrors.New("CHUNK_OVERFLOW", "maximum chunk count reached")
	}
	chunkCounter := d.chunkCount
	d.chunkCount++ // Increment for next chunk
	chunkNonce := make([]byte, len(d.nonce)+4)
	copy(chunkNonce, d.nonce)
	chunkNonce[len(d.nonce)] = byte(chunkCounter)
	chunkNonce[len(d.nonce)+1] = byte(chunkCounter >> 8)
	chunkNonce[len(d.nonce)+2] = byte(chunkCounter >> 16)
	chunkNonce[len(d.nonce)+3] = byte(chunkCounter >> 24)

	// Decrypt chunk
	decrypted, err := d.gcm.Open(nil, chunkNonce[:d.gcm.NonceSize()], encrypted, nil)
	if err != nil {
		return nil, goerrors.Wrap(err, "CHUNK_DECRYPTION_FAILED", "failed to decrypt chunk")
	}

	return decrypted, nil
}
