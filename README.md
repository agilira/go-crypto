# go-crypto: Reusable AES-256-GCM cryptography library for Go.
### an AGILira library

Originally developed for Nemesis, go-crypto provides secure and well-tested primitives for encryption, decryption, key and nonce management, and key fingerprinting using AES-256-GCM.
Designed for clarity, reliability, and high code quality.

[![CI](https://github.com/agilira/go-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/agilira/go-crypto/actions/workflows/ci.yml)
[![Security](https://img.shields.io/badge/Security-gosec-brightgreen)](https://github.com/agilira/go-crypto/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/agilira/go-crypto)](https://goreportcard.com/report/github.com/agilira/go-crypto)
[![Coverage](https://img.shields.io/badge/coverage-91.5%25-brightgreen)](https://github.com/agilira/go-crypto/actions/workflows/ci.yml)

## Features

- AES-256-GCM authenticated encryption
- Argon2id key derivation (resistant to ASIC/FPGA attacks)
- PBKDF2-SHA256 legacy support
- Cryptographically secure random number generation
- Secure memory zeroization for sensitive data
- Cross-platform support (Windows, Linux, macOS)

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

## Testing
```sh
go test
```

The library includes comprehensive test coverage with unit tests, integration tests, boundary condition testing, error path testing, concurrent access testing, and stress testing.

## Documentation

- [API Reference](docs/api.md) - Complete API documentation and examples
- [Security Considerations](docs/security.md) - Security features and best practices
- [Encryption & Decryption](docs/encryption.md) - Core encryption functions
- [Key Utilities](docs/keyutils.md) - Key generation, import/export, and utilities
- [Key Derivation Functions](docs/kdf.md) - Argon2id and PBKDF2 support

## Security

This library uses industry-standard cryptographic algorithms and follows security best practices. For detailed security information, see [Security Documentation](docs/security.md).

### Security Tool Exclusions
Some static analysis rules are excluded with documented justification. See [Security Documentation](docs/security.md) for details.

## Performance

- Optimized for typical use cases
- Minimal memory allocations
- Efficient base64 encoding/decoding
- Fast key fingerprinting algorithm

## Error Handling

All functions return standard Go errors for maximum compatibility. For advanced error handling with rich error details, the library integrates with `github.com/agilira/go-errors`.

---

go-crypto • an AGILira library
