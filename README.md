# go-crypto

Robust, reusable AES-256-GCM cryptography utilities for Go.

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://www.mozilla.org/en-US/MPL/2.0/)
[![Coverage](https://img.shields.io/badge/coverage-86.3%25-brightgreen)]()

## Overview
**go-crypto** provides secure, well-tested primitives for encryption, decryption, key and nonce management, and key fingerprinting using AES-256-GCM. Designed for reliability, clarity, and maximum code quality.

## Installation
```sh
go get github.com/agilira/go-crypto
```

## Quick Examples

### Basic Encryption/Decryption
```go
import crypto "github.com/agilira/go-crypto"

key, err := crypto.GenerateKey()
if err != nil {
    // handle error
}

ciphertext, err := crypto.Encrypt("secret data", key)
if err != nil {
    // handle error
}

plaintext, err := crypto.Decrypt(ciphertext, key)
if err != nil {
    // handle error
}

// Empty plaintext is also supported
emptyCiphertext, err := crypto.Encrypt("", key)
if err != nil {
    // handle error
}
```

### Key Derivation with Argon2
```go
password := []byte("my-secure-password")
salt := []byte("random-salt-123")

// Use secure defaults
key, err := crypto.DeriveKeyDefault(password, salt, 32)
if err != nil {
    // handle error
}

// Or use custom parameters
params := &crypto.KDFParams{
    Time:    4,    // 4 iterations
    Memory:  128,  // 128 MB
    Threads: 2,    // 2 threads
}
key, err = crypto.DeriveKey(password, salt, 32, params)
if err != nil {
    // handle error
}
```

### Key Import/Export
```go
key, _ := crypto.GenerateKey()

// Export as base64
base64Key := crypto.KeyToBase64(key)

// Import from base64
restoredKey, err := crypto.KeyFromBase64(base64Key)
if err != nil {
    // handle error
}

// Securely wipe sensitive data
crypto.Zeroize(key)
```

## API Reference

### Core Functions
- `Encrypt(plaintext string, key []byte) (string, error)` - Encrypt data with AES-256-GCM
- `Decrypt(encryptedText string, key []byte) (string, error)` - Decrypt data with AES-256-GCM

### Key Management
- `GenerateKey() ([]byte, error)` - Generate cryptographically secure 32-byte key
- `GenerateNonce(size int) ([]byte, error)` - Generate cryptographically secure nonce
- `ValidateKey(key []byte) error` - Validate key size for AES-256
- `GetKeyFingerprint(key []byte) string` - Generate non-cryptographic key fingerprint (first 8 bytes of SHA-256)

### Key Derivation
- `DeriveKey(password, salt []byte, keyLen int, params *KDFParams) ([]byte, error)` - Derive key using Argon2id with optional custom parameters
- `DeriveKeyDefault(password, salt []byte, keyLen int) ([]byte, error)` - Derive key using Argon2id with secure defaults
- `DeriveKeyWithParams(password, salt []byte, time, memoryMB, threads, keyLen int) ([]byte, error)` - Derive key with custom Argon2id parameters (legacy)
- `DeriveKeyPBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error)` - Derive key using PBKDF2-SHA256 (deprecated)

### Configuration
- `KDFParams` - Struct for custom Argon2id parameters (Time, Memory, Threads)

### Key Import/Export
- `KeyToBase64(key []byte) string` - Encode key as base64
- `KeyFromBase64(s string) ([]byte, error)` - Decode key from base64
- `KeyToHex(key []byte) string` - Encode key as hex
- `KeyFromHex(s string) ([]byte, error)` - Decode key from hex

### Security Utilities
- `Zeroize(b []byte)` - Securely wipe sensitive data from memory

## Testing
The library includes comprehensive test coverage (90.3%) with:
- Unit tests for all functions
- Integration tests for complete workflows
- Boundary condition testing
- Error path testing
- Concurrent access testing
- Stress testing with large datasets
- Corrupted data handling tests

Run tests with:
```sh
go test
```

## Security Considerations
- Uses AES-256-GCM for authenticated encryption
- Uses Argon2id for key derivation (resistant to ASIC/FPGA attacks)
- Cryptographically secure random number generation
- Secure memory zeroization for sensitive data
- Input validation and error handling
- No known vulnerabilities

For detailed security information, see [Security Documentation](docs/security.md).

## Performance
- Optimized for typical use cases
- Minimal memory allocations
- Efficient base64 encoding/decoding
- Fast key fingerprinting algorithm

## Error Handling
All functions return standard Go errors for maximum compatibility. For advanced error handling with rich error details, the library integrates with `github.com/agilira/go-errors`.

### Standard Errors
- `ErrInvalidKeySize` - Key size is not 32 bytes for AES-256
- `ErrEmptyPlaintext` - Encrypted text is empty (plaintext can be empty)
- `ErrCipherInit` - AES cipher initialization failed
- `ErrGCMInit` - GCM mode initialization failed
- `ErrNonceGen` - Nonce generation failed
- `ErrBase64Decode` - Base64 decoding failed
- `ErrCiphertextShort` - Ciphertext is too short
- `ErrDecrypt` - Decryption failed (authentication or corruption)

### Error Handling Example
```go
ciphertext, err := crypto.Encrypt("data", key)
if err != nil {
    if errors.Is(err, crypto.ErrInvalidKeySize) {
        // Handle invalid key size
    } else if errors.Is(err, crypto.ErrEmptyPlaintext) {
        // Handle empty plaintext
    }
    // Handle other errors
}
```

## Advanced Configuration Example

The library follows Go best practices by exposing configuration structs that applications can populate from any source:

```go
// Load configuration from JSON file
type AppConfig struct {
    KDFParams crypto.KDFParams `json:"kdf_params"`
}

// config.json:
// {
//   "kdf_params": {
//     "time": 4,
//     "memory": 128,
//     "threads": 2
//   }
// }

var config AppConfig
json.NewDecoder(file).Decode(&config)

// Use custom parameters
key, err := crypto.DeriveKey(password, salt, 32, &config.KDFParams)

// Or use secure defaults
key, err := crypto.DeriveKeyDefault(password, salt, 32)
```

## Documentation

- [Encryption & Decryption](docs/encryption.md) - Core encryption functions
- [Key Utilities](docs/keyutils.md) - Key generation, import/export, and utilities
- [Key Derivation Functions](docs/kdf.md) - Argon2id and PBKDF2 support
- [Security Considerations](docs/security.md) - Security features and best practices
- [Development Roadmap](ROADMAP.md) - Future development plans and features

## License
MPL 2.0 — Copyright (c) AGILira
