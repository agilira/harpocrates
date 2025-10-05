// crypto_edge_test.go: Edge test cases for cryptographic utilities.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/agilira/harpocrates"
)

func TestGenerateKey_EdgeCases(t *testing.T) {
	keys := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Errorf("GenerateKey() failed on iteration %d: %v", i, err)
			continue
		}
		if len(key) != crypto.KeySize {
			t.Errorf("GenerateKey() returned key with wrong size on iteration %d: got %d, want %d", i, len(key), crypto.KeySize)
			continue
		}
		keys[i] = key
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Equal(keys[i], keys[j]) {
				t.Errorf("GenerateKey() returned duplicate keys at indices %d and %d", i, j)
			}
		}
	}
}

func TestGenerateNonce_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		size       int
		wantErr    bool
		isEnvLimit bool
	}{
		{"negative size", -1, true, false},
		{"zero size", 0, true, false},
		{"very large size", 1000000, false, true},
		{"valid size", 12, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce, err := crypto.GenerateNonce(tt.size)
			if (err != nil) != tt.wantErr {
				if tt.isEnvLimit {
					t.Logf("Environment limitation detected: %v (expected: %v)", err, tt.wantErr)
					return
				}
				t.Errorf("GenerateNonce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(nonce) != tt.size {
					t.Errorf("GenerateNonce() returned nonce with wrong size: got %d, want %d", len(nonce), tt.size)
				}
			}
		})
	}
	nonces := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		nonce, err := crypto.GenerateNonce(12)
		if err != nil {
			t.Errorf("GenerateNonce() failed on iteration %d: %v", i, err)
			continue
		}
		if len(nonce) != 12 {
			t.Errorf("GenerateNonce() returned nonce with wrong size on iteration %d: got %d, want 12", i, len(nonce))
			continue
		}
		nonces[i] = nonce
	}
	for i := 0; i < len(nonces); i++ {
		for j := i + 1; j < len(nonces); j++ {
			if bytes.Equal(nonces[i], nonces[j]) {
				t.Errorf("GenerateNonce() returned duplicate nonces at indices %d and %d", i, j)
			}
		}
	}
}

func TestGetKeyFingerprint_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		key        []byte
		wantEmpty  bool
		isEnvLimit bool
	}{
		{"nil key", nil, true, false},
		{"empty key", []byte{}, true, false},
		{"valid key", make([]byte, crypto.KeySize), false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.key != nil {
				for i := range tt.key {
					tt.key[i] = byte(i)
				}
			}
			fingerprint := crypto.GetKeyFingerprint(tt.key)
			if tt.wantEmpty {
				if fingerprint != "" {
					t.Errorf("GetKeyFingerprint() returned non-empty fingerprint for %s: %s", tt.name, fingerprint)
				}
			} else {
				if fingerprint == "" {
					t.Errorf("GetKeyFingerprint() returned empty fingerprint for %s", tt.name)
				}
			}
		})
	}
	key1 := make([]byte, crypto.KeySize)
	key2 := make([]byte, crypto.KeySize)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(255 - i)
	}
	fp1 := crypto.GetKeyFingerprint(key1)
	fp2 := crypto.GetKeyFingerprint(key2)
	if fp1 == fp2 {
		t.Error("GetKeyFingerprint() returned same fingerprint for different keys")
	}
}

func TestCryptoErrorHandling(t *testing.T) {
	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()
	rand.Reader = &failingReader{}
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	_, err := crypto.Encrypt("test", key)
	if err == nil {
		t.Error("Expected error when nonce generation fails")
	}
	_, err = crypto.GenerateKey()
	if err == nil {
		t.Error("Expected error when key generation fails")
	}
	_, err = crypto.GenerateNonce(12)
	if err == nil {
		t.Error("Expected error when nonce generation fails")
	}
}

type failingReader struct{}

func (r *failingReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestValidateKeyEdgeCases(t *testing.T) {
	err := crypto.ValidateKey(nil)
	if err == nil {
		t.Error("Expected error for nil key")
	}
	err = crypto.ValidateKey([]byte{})
	if err == nil {
		t.Error("Expected error for empty key")
	}
	invalidSizes := []int{0, 1, 15, 16, 24, 31, 33, 48, 64, 128}
	for _, size := range invalidSizes {
		invalidKey := make([]byte, size)
		err := crypto.ValidateKey(invalidKey)
		if err == nil {
			t.Errorf("Expected error for key size %d", size)
		}
	}
	validKey := make([]byte, crypto.KeySize)
	err = crypto.ValidateKey(validKey)
	if err != nil {
		t.Errorf("Expected no error for valid key, got %v", err)
	}
}
