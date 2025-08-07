// keyutils.go: Key utilities for import/export, zeroization, and fingerprinting.
//
// Copyright (c) 2025 AGILira
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	goerrors "github.com/agilira/go-errors"
)

// KeyToBase64 encodes a key as a base64 string.
func KeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// KeyFromBase64 decodes a base64 string to a key.
func KeyFromBase64(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, goerrors.Wrap(err, "BASE64_DECODE_ERROR", "failed to decode base64 key")
	}
	return key, nil
}

// KeyToHex encodes a key as a hexadecimal string.
func KeyToHex(key []byte) string {
	return hex.EncodeToString(key)
}

// KeyFromHex decodes a hexadecimal string to a key.
func KeyFromHex(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, goerrors.Wrap(err, "HEX_DECODE_ERROR", "failed to decode hex key")
	}
	return key, nil
}

// Zeroize securely wipes a byte slice from memory.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GetKeyFingerprint generates a fingerprint for a key (non-cryptographic).
// Uses the first 8 bytes of SHA-256 for better collision resistance while maintaining speed.
func GetKeyFingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	hash := sha256.Sum256(key)
	return fmt.Sprintf("%016x", hash[:8])
}

// GenerateKey generates a cryptographically secure random key of KeySize bytes.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, goerrors.Wrap(err, "KEY_GEN_ERROR", "failed to generate key")
	}
	return key, nil
}

// GenerateNonce generates a cryptographically secure random nonce of the given size.
func GenerateNonce(size int) ([]byte, error) {
	if size <= 0 {
		return nil, goerrors.New("INVALID_NONCE_SIZE", "nonce size must be positive")
	}
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, goerrors.Wrap(err, "NONCE_GEN_ERROR", "failed to generate nonce")
	}
	return nonce, nil
}

// ValidateKey checks that a key has the correct size for AES-256.
func ValidateKey(key []byte) error {
	if len(key) != KeySize {
		return goerrors.New("INVALID_KEY_SIZE", fmt.Sprintf("key size must be %d bytes for AES-256, got %d", KeySize, len(key)))
	}
	return nil
}
