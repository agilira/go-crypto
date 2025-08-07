// encryption.go: Encryption and decryption utilities using AES-256-GCM and other secure algorithms.
//
// Copyright (c) 2025 AGILira
// Series: an AGLIra fragment
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	goerrors "github.com/agilira/go-errors"
)

// KeySize is the required key size for AES-256 encryption in bytes.
const KeySize = 32

// Public standard errors for drop-in compatibility
var (
	ErrInvalidKeySize  = errors.New("crypto: invalid key size")
	ErrEmptyPlaintext  = errors.New("crypto: plaintext cannot be empty")
	ErrCipherInit      = errors.New("crypto: cipher initialization error")
	ErrGCMInit         = errors.New("crypto: GCM initialization error")
	ErrNonceGen        = errors.New("crypto: nonce generation error")
	ErrBase64Decode    = errors.New("crypto: base64 decode error")
	ErrCiphertextShort = errors.New("crypto: ciphertext too short")
	ErrDecrypt         = errors.New("crypto: decryption error")
)

// Error codes for rich error handling
const (
	ErrCodeInvalidKey   = "CRYPTO_INVALID_KEY"
	ErrCodeEmptyPlain   = "CRYPTO_EMPTY_PLAINTEXT"
	ErrCodeCipherInit   = "CRYPTO_CIPHER_INIT"
	ErrCodeGCMInit      = "CRYPTO_GCM_INIT"
	ErrCodeNonceGen     = "CRYPTO_NONCE_GEN"
	ErrCodeBase64Decode = "CRYPTO_BASE64_DECODE"
	ErrCodeCipherShort  = "CRYPTO_CIPHERTEXT_SHORT"
	ErrCodeDecrypt      = "CRYPTO_DECRYPT"
)

// Encrypt encrypts a plaintext string using AES-256-GCM.
// Returns a base64 encoded string containing the nonce and ciphertext.
// Empty plaintext is supported and will result in a valid ciphertext containing only the nonce and authentication tag.
func Encrypt(plaintext string, key []byte) (string, error) {
	if len(key) != KeySize {
		richErr := goerrors.New(ErrCodeInvalidKey, fmt.Sprintf("invalid key size: must be 32 bytes for AES-256 (got %d)", len(key)))
		return "", fmt.Errorf("%w: %w", ErrInvalidKeySize, richErr)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeCipherInit, "failed to create cipher")
		return "", fmt.Errorf("%w: %w", ErrCipherInit, richErr)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeGCMInit, "failed to create GCM")
		return "", fmt.Errorf("%w: %w", ErrGCMInit, richErr)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		richErr := goerrors.Wrap(err, ErrCodeNonceGen, "failed to generate nonce")
		return "", fmt.Errorf("%w: %w", ErrNonceGen, richErr)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64 encoded ciphertext string using AES-256-GCM.
func Decrypt(encryptedText string, key []byte) (string, error) {
	if len(key) != KeySize {
		richErr := goerrors.New(ErrCodeInvalidKey, fmt.Sprintf("invalid key size: must be 32 bytes for AES-256 (got %d)", len(key)))
		return "", fmt.Errorf("%w: %w", ErrInvalidKeySize, richErr)
	}
	if encryptedText == "" {
		richErr := goerrors.New(ErrCodeEmptyPlain, "encrypted text cannot be empty")
		return "", fmt.Errorf("%w: %w", ErrEmptyPlaintext, richErr)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeBase64Decode, "failed to decode base64")
		return "", fmt.Errorf("%w: %w", ErrBase64Decode, richErr)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeCipherInit, "failed to create cipher")
		return "", fmt.Errorf("%w: %w", ErrCipherInit, richErr)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeGCMInit, "failed to create GCM")
		return "", fmt.Errorf("%w: %w", ErrGCMInit, richErr)
	}
	if len(ciphertext) < gcm.NonceSize() {
		richErr := goerrors.New(ErrCodeCipherShort, "ciphertext too short")
		return "", fmt.Errorf("%w: %w", ErrCiphertextShort, richErr)
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		richErr := goerrors.Wrap(err, ErrCodeDecrypt, "failed to decrypt")
		return "", fmt.Errorf("%w: %w", ErrDecrypt, richErr)
	}
	return string(plaintext), nil
}

// (EncryptWithAAD, DecryptWithAAD and helpers will be added next)
