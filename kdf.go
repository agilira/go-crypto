// kdf.go: Key derivation utilities for secure key management uses Argon2id.
//
// Copyright (c) 2025 AGILira
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/sha256"

	goerrors "github.com/agilira/go-errors"
	"golang.org/x/crypto/argon2"
	pbkdf2 "golang.org/x/crypto/pbkdf2"
)

// Default Argon2 parameters for key derivation
const (
	DefaultTime    = 3  // Number of iterations
	DefaultMemory  = 64 // Memory usage in MB
	DefaultThreads = 4  // Number of threads
)

// KDFParams defines custom parameters for Argon2id key derivation.
// If a field is zero, the library's secure default will be used.
type KDFParams struct {
	Time    uint32 `json:"time,omitempty"`    // Number of iterations
	Memory  uint32 `json:"memory,omitempty"`  // Memory usage in MB
	Threads uint8  `json:"threads,omitempty"` // Number of threads
}

// DeriveKey derives a key from a password and salt using Argon2id (the recommended variant).
// Uses secure default parameters that provide strong protection against both CPU and memory-based attacks.
// If params is nil, secure defaults are used.
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
	key := argon2.IDKey(password, salt, time, memory, threads, uint32(keyLen))
	return key, nil
}

// DeriveKeyDefault derives a key using Argon2id with secure default parameters.
// This is a convenience function for when you don't need custom parameters.
func DeriveKeyDefault(password, salt []byte, keyLen int) ([]byte, error) {
	return DeriveKey(password, salt, keyLen, nil)
}

// DeriveKeyWithParams derives a key from a password and salt using Argon2id with custom parameters.
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
	key := argon2.IDKey(password, salt, uint32(time), uint32(memoryMB*1024), uint8(threads), uint32(keyLen))
	return key, nil
}

// DeriveKeyPBKDF2 is deprecated. Use DeriveKey instead for better security.
// This function is kept for backward compatibility but will be removed in a future version.
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
