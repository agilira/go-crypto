# API Reference

## Constants

### Key Size
- `KeySize = 32` - Required key size for AES-256 encryption in bytes

### Default Argon2 Parameters
- `DefaultTime = 3` - Default number of iterations for Argon2id
- `DefaultMemory = 64` - Default memory usage in MB for Argon2id  
- `DefaultThreads = 4` - Default number of threads for Argon2id

### Error Codes
- `ErrCodeInvalidKey = "CRYPTO_INVALID_KEY"`
- `ErrCodeEmptyPlain = "CRYPTO_EMPTY_PLAINTEXT"`
- `ErrCodeCipherInit = "CRYPTO_CIPHER_INIT"`
- `ErrCodeGCMInit = "CRYPTO_GCM_INIT"`
- `ErrCodeNonceGen = "CRYPTO_NONCE_GEN"`
- `ErrCodeBase64Decode = "CRYPTO_BASE64_DECODE"`
- `ErrCodeCipherShort = "CRYPTO_CIPHERTEXT_SHORT"`
- `ErrCodeDecrypt = "CRYPTO_DECRYPT"`

## Core Functions

### Encryption/Decryption
- `Encrypt(plaintext string, key []byte) (string, error)` - Encrypt string data with AES-256-GCM authenticated encryption (convenience wrapper)
- `Decrypt(encryptedText string, key []byte) (string, error)` - Decrypt string data with AES-256-GCM authenticated decryption (convenience wrapper)
- `EncryptBytes(plaintext []byte, key []byte) (string, error)` - Encrypt binary data with AES-256-GCM authenticated encryption (core function)
- `DecryptBytes(encryptedText string, key []byte) ([]byte, error)` - Decrypt binary data with AES-256-GCM authenticated decryption (core function)

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

### Key Import/Export
- `KeyToBase64(key []byte) string` - Encode key as base64
- `KeyFromBase64(s string) ([]byte, error)` - Decode key from base64
- `KeyToHex(key []byte) string` - Encode key as hex
- `KeyFromHex(s string) ([]byte, error)` - Decode key from hex

### Security Utilities
- `Zeroize(b []byte)` - Securely wipe sensitive data from memory

## Types

### KDFParams
Struct for custom Argon2id parameters:
```go
type KDFParams struct {
    Time    uint32 `json:"time,omitempty"`    // Number of iterations
    Memory  uint32 `json:"memory,omitempty"`  // Memory usage in MB
    Threads uint8  `json:"threads,omitempty"` // Number of threads
}
```

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
