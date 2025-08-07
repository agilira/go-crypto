# API Reference

## Core Functions

### Encryption/Decryption
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

---

go-crypto • an AGILira library
