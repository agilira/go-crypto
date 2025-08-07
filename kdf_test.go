// kdf_test.go: Test cases for key derivation utilities.
//
// Copyright (c) 2025 AGILira
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/agilira/go-crypto"
)

// TestDeriveKey_Valid tests the new Argon2-based DeriveKey function
func TestDeriveKey_Valid(t *testing.T) {
	pw := []byte("my-secure-password")
	salt := []byte("random-salt-123")

	key, err := crypto.DeriveKey(pw, salt, 32, nil)
	if err != nil {
		t.Fatalf("DeriveKey() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Test that key is not all zeros
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Generated key should not be all zeros")
	}
}

// TestDeriveKey_InvalidParams tests DeriveKey with invalid parameters
func TestDeriveKey_InvalidParams(t *testing.T) {
	_, err := crypto.DeriveKey(nil, []byte("salt"), 32, nil)
	if err == nil {
		t.Error("Expected error for nil password")
	}

	_, err = crypto.DeriveKey([]byte("pw"), nil, 32, nil)
	if err == nil {
		t.Error("Expected error for nil salt")
	}

	_, err = crypto.DeriveKey([]byte("pw"), []byte("salt"), 0, nil)
	if err == nil {
		t.Error("Expected error for zero key length")
	}

	_, err = crypto.DeriveKey([]byte("pw"), []byte("salt"), -1, nil)
	if err == nil {
		t.Error("Expected error for negative key length")
	}
}

// TestDeriveKey_DifferentSalts tests that different salts produce different keys
func TestDeriveKey_DifferentSalts(t *testing.T) {
	pw := []byte("my-password")
	salt1 := []byte("salt-1")
	salt2 := []byte("salt-2")

	key1, _ := crypto.DeriveKey(pw, salt1, 32, nil)
	key2, _ := crypto.DeriveKey(pw, salt2, 32, nil)

	if bytes.Equal(key1, key2) {
		t.Error("Keys should be different for different salts")
	}
}

// TestDeriveKey_Consistency tests that same parameters produce same key
func TestDeriveKey_Consistency(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")
	keyLen := 32

	key1, err := crypto.DeriveKey(pw, salt, keyLen, nil)
	if err != nil {
		t.Fatalf("First DeriveKey() error: %v", err)
	}

	key2, err := crypto.DeriveKey(pw, salt, keyLen, nil)
	if err != nil {
		t.Fatalf("Second DeriveKey() error: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("Same parameters should produce same key")
	}
}

// TestDeriveKeyDefault tests the convenience function for default parameters
func TestDeriveKeyDefault(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")

	key, err := crypto.DeriveKeyDefault(pw, salt, 32)
	if err != nil {
		t.Fatalf("DeriveKeyDefault() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}
}

// TestDeriveKeyWithParams tests the custom parameters function
func TestDeriveKeyWithParams(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")

	key, err := crypto.DeriveKeyWithParams(pw, salt, 1, 16, 1, 32)
	if err != nil {
		t.Fatalf("DeriveKeyWithParams() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}
}

// TestDeriveKeyWithParams_InvalidParams tests DeriveKeyWithParams with invalid parameters
func TestDeriveKeyWithParams_InvalidParams(t *testing.T) {
	pw := []byte("password")
	salt := []byte("salt")

	testCases := []struct {
		name                          string
		time, memory, threads, keyLen int
	}{
		{"zero time", 0, 16, 1, 32},
		{"negative time", -1, 16, 1, 32},
		{"zero memory", 1, 0, 1, 32},
		{"negative memory", 1, -1, 1, 32},
		{"zero threads", 1, 16, 0, 32},
		{"negative threads", 1, 16, -1, 32},
		{"zero key length", 1, 16, 1, 0},
		{"negative key length", 1, 16, 1, -1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := crypto.DeriveKeyWithParams(pw, salt, tc.time, tc.memory, tc.threads, tc.keyLen)
			if err == nil {
				t.Error("Expected error for invalid parameters")
			}
		})
	}
}

// TestDeriveKeyPBKDF2_Valid tests PBKDF2 key derivation (backward compatibility)
func TestDeriveKeyPBKDF2_Valid(t *testing.T) {
	pw := []byte("my-secure-password")
	salt := []byte("random-salt-123")

	key, err := crypto.DeriveKeyPBKDF2(pw, salt, 100_000, 32)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}
}

// TestDeriveKeyPBKDF2_InvalidParams tests PBKDF2 with invalid parameters
func TestDeriveKeyPBKDF2_InvalidParams(t *testing.T) {
	_, err := crypto.DeriveKeyPBKDF2(nil, []byte("salt"), 100_000, 32)
	if err == nil {
		t.Error("Expected error for nil password")
	}

	_, err = crypto.DeriveKeyPBKDF2([]byte("pw"), nil, 100_000, 32)
	if err == nil {
		t.Error("Expected error for nil salt")
	}

	_, err = crypto.DeriveKeyPBKDF2([]byte("pw"), []byte("salt"), 0, 32)
	if err == nil {
		t.Error("Expected error for zero iterations")
	}

	_, err = crypto.DeriveKeyPBKDF2([]byte("pw"), []byte("salt"), 100_000, 0)
	if err == nil {
		t.Error("Expected error for zero key length")
	}
}

// TestDeriveKeyPBKDF2_DifferentSalts tests that different salts produce different keys with PBKDF2
func TestDeriveKeyPBKDF2_DifferentSalts(t *testing.T) {
	pw := []byte("my-password")
	salt1 := []byte("salt-1")
	salt2 := []byte("salt-2")

	key1, _ := crypto.DeriveKeyPBKDF2(pw, salt1, 100_000, 32)
	key2, _ := crypto.DeriveKeyPBKDF2(pw, salt2, 100_000, 32)

	if bytes.Equal(key1, key2) {
		t.Error("Keys should be different for different salts")
	}
}

// TestDeriveKeyPBKDF2_VariousIterationCounts tests PBKDF2 with different iteration counts
func TestDeriveKeyPBKDF2_VariousIterationCounts(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")
	iterationsList := []int{1, 100, 1000, 10000, 100000}

	for _, iterations := range iterationsList {
		t.Run(fmt.Sprintf("iterations_%d", iterations), func(t *testing.T) {
			key, err := crypto.DeriveKeyPBKDF2(pw, salt, iterations, 32)
			if err != nil {
				t.Fatalf("DeriveKeyPBKDF2() error: %v", err)
			}

			if len(key) != 32 {
				t.Errorf("Expected key length 32, got %d", len(key))
			}
		})
	}
}

// TestDeriveKeyPBKDF2_VariousKeyLengths tests PBKDF2 with different key lengths
func TestDeriveKeyPBKDF2_VariousKeyLengths(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")
	keyLengths := []int{16, 24, 32, 48, 64}

	for _, keyLen := range keyLengths {
		t.Run(fmt.Sprintf("keylen_%d", keyLen), func(t *testing.T) {
			key, err := crypto.DeriveKeyPBKDF2(pw, salt, 1000, keyLen)
			if err != nil {
				t.Fatalf("DeriveKeyPBKDF2() error: %v", err)
			}

			if len(key) != keyLen {
				t.Errorf("Expected key length %d, got %d", keyLen, len(key))
			}
		})
	}
}

// TestDeriveKeyPBKDF2_NegativeParameters tests PBKDF2 with negative parameters
func TestDeriveKeyPBKDF2_NegativeParameters(t *testing.T) {
	pw := []byte("password")
	salt := []byte("salt")

	_, err := crypto.DeriveKeyPBKDF2(pw, salt, -1, 32)
	if err == nil {
		t.Error("Expected error for negative iterations")
	}

	_, err = crypto.DeriveKeyPBKDF2(pw, salt, 1000, -1)
	if err == nil {
		t.Error("Expected error for negative key length")
	}
}

// TestDeriveKeyPBKDF2_VeryLargeParameters tests PBKDF2 with very large parameters
func TestDeriveKeyPBKDF2_VeryLargeParameters(t *testing.T) {
	pw := []byte("password")
	salt := []byte("salt")

	// Test with very large iteration count
	key, err := crypto.DeriveKeyPBKDF2(pw, salt, 1000000, 32)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2() error: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Test with very large key length
	key, err = crypto.DeriveKeyPBKDF2(pw, salt, 1000, 1024)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2() error: %v", err)
	}

	if len(key) != 1024 {
		t.Errorf("Expected key length 1024, got %d", len(key))
	}
}

// TestDeriveKeyPBKDF2_Consistency tests that same parameters produce same key with PBKDF2
func TestDeriveKeyPBKDF2_Consistency(t *testing.T) {
	pw := []byte("my-password")
	salt := []byte("my-salt")
	iterations := 1000
	keyLen := 32

	key1, err := crypto.DeriveKeyPBKDF2(pw, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("First DeriveKeyPBKDF2() error: %v", err)
	}

	key2, err := crypto.DeriveKeyPBKDF2(pw, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("Second DeriveKeyPBKDF2() error: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("Same parameters should produce same key")
	}
}

// TestDeriveKeyWithCustomParams tests DeriveKey with custom parameters
func TestDeriveKeyWithCustomParams(t *testing.T) {
	password := []byte("test-password")
	salt := []byte("test-salt")

	// Test with custom parameters
	params := &crypto.KDFParams{
		Time:    2,
		Memory:  64,
		Threads: 2,
	}

	key, err := crypto.DeriveKey(password, salt, 32, params)
	if err != nil {
		t.Fatalf("DeriveKey() error: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Test with partial custom parameters (some fields zero)
	paramsPartial := &crypto.KDFParams{
		Time:    3,
		Memory:  0, // Will use default
		Threads: 0, // Will use default
	}

	key2, err := crypto.DeriveKey(password, salt, 32, paramsPartial)
	if err != nil {
		t.Fatalf("DeriveKey() with partial params error: %v", err)
	}
	if len(key2) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key2))
	}

	// Keys should be different due to different parameters
	if bytes.Equal(key, key2) {
		t.Error("Expected different keys for different parameters")
	}
}
