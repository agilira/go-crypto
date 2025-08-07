# Key Utilities

This document describes the key utility features of the `go-crypto` library, including key generation, import/export, zeroization, and fingerprinting.

## Key Generation
### func GenerateKey() ([]byte, error)
Generates a cryptographically secure random key of 32 bytes (AES-256).

**Returns:**
- `[]byte`: A 32-byte cryptographically secure random key
- `error`: Error if random generation fails

**Error Codes:**
- `"KEY_GEN_ERROR"` - When random generation fails

**Security Notes:**
- Uses `crypto/rand` for cryptographically secure random generation
- Key is suitable for AES-256 encryption
- Always check for errors in production code

### func GenerateNonce(size int) ([]byte, error)
Generates a cryptographically secure random nonce of the specified size.

**Parameters:**
- `size`: The size of the nonce in bytes (must be > 0)

**Returns:**
- `[]byte`: A cryptographically secure random nonce
- `error`: Error if size is invalid or random generation fails

**Error Codes:**
- `"INVALID_NONCE_SIZE"` - When size is not positive
- `"NONCE_GEN_ERROR"` - When random generation fails

**Security Notes:**
- Uses `crypto/rand` for cryptographically secure random generation
- Size should be appropriate for the encryption mode (12 bytes for GCM)
- Never reuse nonces with the same key

### func ValidateKey(key []byte) error
Checks that a key has the correct size for AES-256 (32 bytes).

**Parameters:**
- `key`: The key to validate

**Returns:**
- `error`: Error if key size is not 32 bytes, nil if valid

**Error Codes:**
- `"INVALID_KEY_SIZE"` - When key size is not 32 bytes

**Usage:**
```go
err := crypto.ValidateKey(key)
if err != nil {
    // Key is invalid
}
```

## Key Import/Export
### func KeyToBase64(key []byte) string
Encodes a key as a base64 string.

### func KeyFromBase64(s string) ([]byte, error)
Decodes a base64 string to a key.

**Error Codes:**
- `"BASE64_DECODE_ERROR"` - When base64 decoding fails

### func KeyToHex(key []byte) string
Encodes a key as a hexadecimal string.

### func KeyFromHex(s string) ([]byte, error)
Decodes a hexadecimal string to a key.

**Error Codes:**
- `"HEX_DECODE_ERROR"` - When hex decoding fails

## Zeroization
### func Zeroize(b []byte)
Securely wipes a byte slice from memory.

## Fingerprinting
### func GetKeyFingerprint(key []byte) string
Generates a non-cryptographic fingerprint for a key.

## Usage Example
```go
import "github.com/agilira/go-crypto"

key, err := crypto.GenerateKey()
if err != nil {
    // handle error
}

base64Key := crypto.KeyToBase64(key)
restoredKey, err := crypto.KeyFromBase64(base64Key)
if err != nil {
    // handle error
}

crypto.Zeroize(key)
``` 

---

go-crypto • an AGILira library