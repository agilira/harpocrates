# Streaming Operations

This document describes the streaming encryption and decryption capabilities for processing large datasets efficiently with constant memory usage.

## Overview

The streaming operations allow you to encrypt and decrypt large amounts of data (GB-scale) without loading everything into memory. This is essential for NEMESIS disaster recovery snapshots and large file processing.

## Key Features

- **Constant memory usage** regardless of data size
- **Chunked processing** with configurable chunk sizes
- **AES-GCM security** maintained for streaming operations
- **Format compatibility** with standard encryption functions
- **Error recovery** with proper resource cleanup

## Architecture

### Stream Format

The streaming format includes a header followed by encrypted chunks:

```
┌─────────────────────────────────────────────────────────┐
│                    Stream Header (24 bytes)             │
├─────────────┬─────────────┬─────────────┬─────────────────┤
│ Magic (4B)  │Version (4B) │ Nonce (12B) │ChunkSize (4B) │
├─────────────┴─────────────┴─────────────┴─────────────────┤
│                  Encrypted Chunk 1                     │
├─────────────────────────────────────────────────────────┤
│                  Encrypted Chunk 2                     │
├─────────────────────────────────────────────────────────┤
│                        ...                              │
├─────────────────────────────────────────────────────────┤
│                 Final Authentication                    │
└─────────────────────────────────────────────────────────┘
```

- **Magic**: `"AGCM"` (AGILira GCM format identifier)
- **Version**: `1` (format version)
- **Nonce**: 12-byte random nonce for GCM
- **ChunkSize**: Chunk size in bytes (default: 64KB)

## API Reference

### Interfaces

```go
// StreamingEncryptor encrypts data in chunks
type StreamingEncryptor interface {
    Write(data []byte) (int, error)
    Close() error
}

// StreamingDecryptor decrypts data in chunks  
type StreamingDecryptor interface {
    Read(data []byte) (int, error)
    Close() error
}
```

### Constructor Functions

```go
// Create streaming encryptor
func NewStreamingEncryptor(writer io.Writer, key []byte) (StreamingEncryptor, error)
func NewStreamingEncryptorWithChunkSize(writer io.Writer, key []byte, chunkSize int) (StreamingEncryptor, error)

// Create streaming decryptor
func NewStreamingDecryptor(reader io.Reader, key []byte) (StreamingDecryptor, error)
```

### Constants

```go
const DefaultChunkSize = 64 * 1024  // 64KB default chunk size
```

## Usage Examples

### Basic Streaming Encryption

```go
package main

import (
    "os"
    "io"
    "log"
    "github.com/agilira/harpocrates"
)

func encryptLargeFile(inputPath, outputPath string, key []byte) error {
    // Open input file
    inputFile, err := os.Open(inputPath)
    if err != nil {
        return err
    }
    defer inputFile.Close()
    
    // Create output file
    outputFile, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer outputFile.Close()
    
    // Create streaming encryptor
    encryptor, err := crypto.NewStreamingEncryptor(outputFile, key)
    if err != nil {
        return err
    }
    defer encryptor.Close()
    
    // Stream encryption
    _, err = io.Copy(encryptor, inputFile)
    return err
}
```

### Basic Streaming Decryption

```go
func decryptLargeFile(inputPath, outputPath string, key []byte) error {
    // Open encrypted file
    inputFile, err := os.Open(inputPath)
    if err != nil {
        return err
    }
    defer inputFile.Close()
    
    // Create output file
    outputFile, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer outputFile.Close()
    
    // Create streaming decryptor
    decryptor, err := crypto.NewStreamingDecryptor(inputFile, key)
    if err != nil {
        return err
    }
    defer decryptor.Close()
    
    // Stream decryption
    _, err = io.Copy(outputFile, decryptor)
    return err
}
```

### Custom Chunk Size

```go
func encryptWithCustomChunk(writer io.Writer, reader io.Reader, key []byte) error {
    // Use 1MB chunks for very large files
    chunkSize := 1024 * 1024
    
    encryptor, err := crypto.NewStreamingEncryptorWithChunkSize(
        writer, key, chunkSize)
    if err != nil {
        return err
    }
    defer encryptor.Close()
    
    _, err = io.Copy(encryptor, reader)
    return err
}
```

### Progress Tracking

```go
type ProgressWriter struct {
    writer      io.Writer
    written     int64
    total       int64
    lastPercent int
}

func (pw *ProgressWriter) Write(data []byte) (int, error) {
    n, err := pw.writer.Write(data)
    pw.written += int64(n)
    
    percent := int(pw.written * 100 / pw.total)
    if percent > pw.lastPercent {
        fmt.Printf("Progress: %d%%\n", percent)
        pw.lastPercent = percent
    }
    
    return n, err
}

func encryptWithProgress(inputPath, outputPath string, key []byte) error {
    // Get file size
    stat, err := os.Stat(inputPath)
    if err != nil {
        return err
    }
    
    inputFile, err := os.Open(inputPath)
    if err != nil {
        return err
    }
    defer inputFile.Close()
    
    outputFile, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer outputFile.Close()
    
    // Wrap output with progress tracking
    progressWriter := &ProgressWriter{
        writer: outputFile,
        total:  stat.Size(),
    }
    
    encryptor, err := crypto.NewStreamingEncryptor(progressWriter, key)
    if err != nil {
        return err
    }
    defer encryptor.Close()
    
    _, err = io.Copy(encryptor, inputFile)
    return err
}
```

### Error Handling and Recovery

```go
func robustStreamingOperation(inputPath, outputPath string, key []byte) error {
    inputFile, err := os.Open(inputPath)
    if err != nil {
        return fmt.Errorf("failed to open input: %w", err)
    }
    defer inputFile.Close()
    
    outputFile, err := os.Create(outputPath)
    if err != nil {
        return fmt.Errorf("failed to create output: %w", err)
    }
    defer func() {
        outputFile.Close()
        if err != nil {
            // Clean up partial file on error
            os.Remove(outputPath)
        }
    }()
    
    encryptor, err := crypto.NewStreamingEncryptor(outputFile, key)
    if err != nil {
        return fmt.Errorf("failed to create encryptor: %w", err)
    }
    
    // Ensure proper cleanup
    defer func() {
        if closeErr := encryptor.Close(); closeErr != nil && err == nil {
            err = fmt.Errorf("failed to close encryptor: %w", closeErr)
        }
    }()
    
    _, err = io.Copy(encryptor, inputFile)
    if err != nil {
        return fmt.Errorf("encryption failed: %w", err)
    }
    
    return nil
}
```

### Memory-Efficient Processing

```go
func processLargeDataStream(input io.Reader, output io.Writer, key []byte) error {
    // Process data in small chunks to minimize memory usage
    chunkSize := 32 * 1024  // 32KB chunks
    
    encryptor, err := crypto.NewStreamingEncryptorWithChunkSize(
        output, key, chunkSize)
    if err != nil {
        return err
    }
    defer encryptor.Close()
    
    // Use smaller buffer for copy operation
    buffer := make([]byte, 8192)  // 8KB buffer
    
    for {
        n, err := input.Read(buffer)
        if n > 0 {
            _, writeErr := encryptor.Write(buffer[:n])
            if writeErr != nil {
                return writeErr
            }
        }
        
        if err == io.EOF {
            break
        }
        if err != nil {
            return err
        }
    }
    
    return nil
}
```

## Performance Considerations

### Chunk Size Selection

- **Small chunks (8-32KB)**: Lower memory usage, higher overhead
- **Medium chunks (64KB)**: Balanced performance (default)  
- **Large chunks (1-4MB)**: Higher throughput, more memory usage

### Buffer Management

The streaming implementation uses buffer pooling to minimize allocations:

```go
// Internally managed buffer pools
var (
    smallBufferPool = sync.Pool{New: func() interface{} { 
        return make([]byte, 32*1024) 
    }}
    largeBufferPool = sync.Pool{New: func() interface{} { 
        return make([]byte, 1024*1024) 
    }}
)
```

### Performance Benchmarks

Typical performance characteristics:

- **Throughput**: 200-800 MB/s (depending on hardware)
- **Memory usage**: Constant ~2x chunk size regardless of data size
- **CPU overhead**: ~10-15% compared to non-streaming operations
- **I/O efficiency**: Near-optimal with proper chunk sizing

## NEMESIS Integration

### Snapshot Encryption

```go
func encryptNEMESISSnapshot(snapshotPath, encryptedPath string) error {
    key, err := crypto.GenerateKey()
    if err != nil {
        return err
    }
    
    // Store key securely (implementation specific)
    err = storeKeySecurely("nemesis-snapshot", key)
    if err != nil {
        crypto.Zeroize(key)
        return err
    }
    
    // Encrypt large snapshot file
    err = encryptLargeFile(snapshotPath, encryptedPath, key)
    crypto.Zeroize(key)
    
    return err
}
```

### Disaster Recovery

```go
func restoreNEMESISSnapshot(encryptedPath, restoredPath, keyID string) error {
    key, err := retrieveKeySecurely(keyID)
    if err != nil {
        return err
    }
    defer crypto.Zeroize(key)
    
    return decryptLargeFile(encryptedPath, restoredPath, key)
}
```

## Best Practices

### Resource Management

1. **Always call `Close()`** on encryptors and decryptors
2. **Use `defer` statements** for reliable cleanup
3. **Handle `Close()` errors** explicitly
4. **Clean up partial files** on operation failure

### Chunk Size Selection

1. **Use default (64KB)** for most applications
2. **Use smaller chunks** when memory is constrained
3. **Use larger chunks** for high-throughput scenarios
4. **Test performance** with your specific data patterns

### Error Handling

1. **Check all errors** during streaming operations
2. **Implement proper cleanup** on failure
3. **Validate data integrity** after operations
4. **Log errors** with sufficient context

### Security

1. **Secure key management** throughout the process
2. **Zeroize keys** after use
3. **Validate stream headers** for format correctness
4. **Use authenticated encryption** (built-in with GCM)

---

Harpocrates • an AGILira library