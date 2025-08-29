// Package crypto provides secure cryptographic utilities for Go applications.
//
// This package offers a comprehensive set of cryptographic primitives including:
//   - AES-256-GCM authenticated encryption and decryption
//   - Argon2id key derivation for secure password-based key generation
//   - PBKDF2-SHA256 legacy support for backward compatibility
//   - Cryptographically secure random number generation
//   - Key management utilities (import/export, validation, fingerprinting)
//   - Secure memory zeroization for sensitive data
//
// The package is designed for clarity, reliability, and high code quality,
// following Go best practices and security standards.
//
// # Quick Start
//
// Basic encryption and decryption:
//
//	// Generate a new encryption key
//	key, err := crypto.GenerateKey()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Encrypt some data
//	ciphertext, err := crypto.Encrypt("sensitive data", key)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Decrypt the data
//	plaintext, err := crypto.Decrypt(ciphertext, key)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Println(plaintext) // Output: sensitive data
//
// # Key Derivation
//
// For deriving keys from passwords:
//
//	password := []byte("my-secure-password")
//	salt := []byte("random-salt-123")
//
//	// Derive a key using Argon2id with secure defaults
//	derivedKey, err := crypto.DeriveKeyDefault(password, salt, 32)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Use custom parameters for higher security
//	params := &crypto.KDFParams{
//		Time:    4,    // 4 iterations
//		Memory:  128,  // 128 MB memory
//		Threads: 2,    // 2 threads
//	}
//	key, err := crypto.DeriveKey(password, salt, 32, params)
//
// # Key Management
//
// Key utilities for import/export and validation:
//
//	// Generate and export a key
//	key, _ := crypto.GenerateKey()
//	base64Key := crypto.KeyToBase64(key)
//	hexKey := crypto.KeyToHex(key)
//
//	// Import and validate a key
//	importedKey, err := crypto.KeyFromBase64(base64Key)
//	if err != nil {
//		log.Fatal(err)
//	}
//	err = crypto.ValidateKey(importedKey)
//	if err != nil {
//		log.Fatal("Invalid key:", err)
//	}
//
//	// Generate a fingerprint for identification
//	fingerprint := crypto.GetKeyFingerprint(key)
//	fmt.Println("Key fingerprint:", fingerprint)
//
//	// Securely wipe sensitive data
//	crypto.Zeroize(key)
//
// # Error Handling
//
// All functions return standard Go errors for maximum compatibility.
// For advanced error handling with rich error details, the library integrates
// with github.com/agilira/go-errors.
//
// Example error handling:
//
//	ciphertext, err := crypto.Encrypt("data", key)
//	if err != nil {
//		if errors.Is(err, crypto.ErrInvalidKeySize) {
//			// Handle invalid key size
//		} else if errors.Is(err, crypto.ErrEmptyPlaintext) {
//			// Handle empty plaintext
//		}
//		// Handle other errors
//	}
//
// # Security Considerations
//
// This library uses industry-standard cryptographic algorithms:
//   - AES-256-GCM for authenticated encryption
//   - Argon2id for key derivation (resistant to ASIC/FPGA attacks)
//   - Cryptographically secure random number generation
//   - Secure memory zeroization
//
// For detailed security information, see the Security documentation.
//
// # Performance
//
// The library is optimized for typical use cases with:
//   - Minimal memory allocations
//   - Efficient base64 encoding/decoding
//   - Fast key fingerprinting algorithm
//   - Configurable Argon2id parameters for security/performance balance
//
// Copyright (c) 2025 AGILira
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0
package crypto
