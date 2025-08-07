# Encryption & Decryption

This document describes the encryption and decryption features of the `go-crypto` library, including error handling, usage, and API reference.

## Overview
The library provides secure encryption and decryption using AES-256-GCM. All functions are designed for drop-in compatibility and professional error handling.

## Error Handling
- All functions return standard Go errors for maximum compatibility.
- Internally, errors are enriched using `go-errors` and wrapped with standard errors.
- You can use `errors.Is` for standard error matching, and `errors.As` to extract rich error details if you use `go-errors` in your project.

## Public Errors
- `ErrInvalidKeySize`
- `ErrEmptyPlaintext`
- `ErrCipherInit`
- `ErrGCMInit`
- `ErrNonceGen`
- `ErrBase64Decode`
- `ErrCiphertextShort`
- `ErrDecrypt`

## API Reference

### func Encrypt(plaintext string, key []byte) (string, error)
Encrypts a plaintext string using AES-256-GCM. Returns a base64 encoded string containing the nonce and ciphertext.

### func Decrypt(encryptedText string, key []byte) (string, error)
Decrypts a base64 encoded ciphertext string using AES-256-GCM. Returns the decrypted plaintext string.

## Usage Example
```go
import "github.com/agilira/go-crypto"

key, err := crypto.GenerateKey()
if err != nil {
    // handle error
}

ciphertext, err := crypto.Encrypt("my secret", key)
if err != nil {
    if errors.Is(err, crypto.ErrInvalidKeySize) {
        // handle invalid key size
    }
    // handle other errors
}

plaintext, err := crypto.Decrypt(ciphertext, key)
if err != nil {
    // handle error
}
```

## Advanced Error Extraction
If you use `go-errors`, you can extract rich error details:
```go
import (
    "errors"
    goerrors "github.com/agilira/go-errors"
)

_, err := crypto.Encrypt("data", key)
if err != nil {
    var richErr *goerrors.Error
    if errors.As(err, &richErr) {
        fmt.Println(richErr.Code) // error code
        fmt.Println(richErr.Error())
    }
}
``` 