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

// Default Argon2 parameters for key derivation.
// These values provide a good balance between security and performance.
const (
	// DefaultTime is the default number of iterations for Argon2id.
	// Higher values increase security but also computation time.
	DefaultTime = 3

	// DefaultMemory is the default memory usage in MB for Argon2id.
	// Higher values increase security against memory-based attacks.
	DefaultMemory = 64

	// DefaultThreads is the default number of threads for Argon2id.
	// Should not exceed the number of CPU cores.
	DefaultThreads = 4
)

// KDFParams defines custom parameters for Argon2id key derivation.
//
// If a field is zero, the library's secure default will be used.
// This allows for flexible configuration while maintaining security.
//
// Example:
//
//	// Use custom parameters
//	params := &crypto.KDFParams{
//		Time:    4,    // 4 iterations
//		Memory:  128,  // 128 MB memory
//		Threads: 2,    // 2 threads
//	}
//	key, err := crypto.DeriveKey(password, salt, 32, params)
//
//	// Use secure defaults (pass nil)
//	key, err := crypto.DeriveKey(password, salt, 32, nil)
type KDFParams struct {
	// Time is the number of iterations for Argon2id.
	// Higher values increase security but also computation time.
	// If zero, DefaultTime is used.
	Time uint32 `json:"time,omitempty"`

	// Memory is the memory usage in MB for Argon2id.
	// Higher values increase security against memory-based attacks.
	// If zero, DefaultMemory is used.
	Memory uint32 `json:"memory,omitempty"`

	// Threads is the number of threads for Argon2id.
	// Should not exceed the number of CPU cores.
	// If zero, DefaultThreads is used.
	Threads uint8 `json:"threads,omitempty"`
}

// DeriveKey derives a key from a password and salt using Argon2id (the recommended variant).
//
// Argon2id is the recommended variant of Argon2, providing resistance against both
// side-channel attacks and time-memory trade-off attacks. It uses secure default
// parameters that provide strong protection against both CPU and memory-based attacks.
//
// Parameters:
//   - password: The password to derive the key from (cannot be empty)
//   - salt: The salt to use for key derivation (cannot be empty, should be random)
//   - keyLen: The desired length of the derived key in bytes (must be positive)
//   - params: Custom Argon2id parameters (nil to use secure defaults)
//
// Returns:
//   - The derived key as a byte slice
//   - An error if key derivation fails
//
// Example:
//
//	password := []byte("my-secure-password")
//	salt := []byte("random-salt-123")
//
//	// Use secure defaults
//	key, err := crypto.DeriveKey(password, salt, 32, nil)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Use custom parameters
//	params := &crypto.KDFParams{
//		Time:    4,
//		Memory:  128,
//		Threads: 2,
//	}
//	key, err := crypto.DeriveKey(password, salt, 32, params)
//
// If params is nil, secure defaults are used (Time: 3, Memory: 64MB, Threads: 4).
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
//
// This is a convenience function for when you don't need custom parameters.
// It's equivalent to calling DeriveKey with params set to nil.
//
// Parameters:
//   - password: The password to derive the key from (cannot be empty)
//   - salt: The salt to use for key derivation (cannot be empty, should be random)
//   - keyLen: The desired length of the derived key in bytes (must be positive)
//
// Returns:
//   - The derived key as a byte slice
//   - An error if key derivation fails
//
// Example:
//
//	password := []byte("my-secure-password")
//	salt := []byte("random-salt-123")
//	key, err := crypto.DeriveKeyDefault(password, salt, 32)
//	if err != nil {
//		log.Fatal(err)
//	}
func DeriveKeyDefault(password, salt []byte, keyLen int) ([]byte, error) {
	return DeriveKey(password, salt, keyLen, nil)
}

// DeriveKeyWithParams derives a key from a password and salt using Argon2id with custom parameters.
//
// This is a legacy function that provides direct parameter control. For new code,
// consider using DeriveKey with a KDFParams struct for better readability and maintainability.
//
// Parameters:
//   - password: The password to derive the key from (cannot be empty)
//   - salt: The salt to use for key derivation (cannot be empty, should be random)
//   - time: The number of iterations (must be positive)
//   - memoryMB: The memory usage in MB (must be positive)
//   - threads: The number of threads (must be positive)
//   - keyLen: The desired length of the derived key in bytes (must be positive)
//
// Returns:
//   - The derived key as a byte slice
//   - An error if key derivation fails
//
// Example:
//
//	password := []byte("my-secure-password")
//	salt := []byte("random-salt-123")
//	key, err := crypto.DeriveKeyWithParams(password, salt, 4, 128, 2, 32)
//	if err != nil {
//		log.Fatal(err)
//	}
//
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

// DeriveKeyPBKDF2 derives a key using PBKDF2-SHA256 (deprecated).
//
// This function is deprecated and kept only for backward compatibility.
// Use DeriveKey with Argon2id instead for better security against modern attacks.
// This function will be removed in a future version.
//
// Parameters:
//   - password: The password to derive the key from (cannot be empty)
//   - salt: The salt to use for key derivation (cannot be empty, should be random)
//   - iterations: The number of iterations (must be positive, recommend at least 100,000)
//   - keyLen: The desired length of the derived key in bytes (must be positive)
//
// Returns:
//   - The derived key as a byte slice
//   - An error if key derivation fails
//
// Example:
//
//	password := []byte("my-secure-password")
//	salt := []byte("random-salt-123")
//	key, err := crypto.DeriveKeyPBKDF2(password, salt, 100000, 32)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Deprecated: Use DeriveKey instead for better security.
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
