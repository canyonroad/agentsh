// Package audit provides tamper-proof audit logging with HMAC-based integrity chains.
package audit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// Encryptor provides AES-256-GCM encryption for audit data.
type Encryptor struct {
	gcm cipher.AEAD
}

// NewEncryptor creates an encryptor with the given 32-byte key.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &Encryptor{gcm: gcm}, nil
}

// LoadEncryptionKey loads the encryption key from config.
// If keyEnv is non-empty, it reads the key from that environment variable.
// Otherwise if keyFile is non-empty, it reads the key from that file.
// Returns an error if neither source provides a key or if the key is too short.
func LoadEncryptionKey(keyFile, keyEnv string) ([]byte, error) {
	if keyEnv != "" {
		if key := os.Getenv(keyEnv); key != "" {
			return []byte(key), nil
		}
	}
	if keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		// Ensure 32 bytes
		if len(key) < 32 {
			return nil, fmt.Errorf("key too short: need 32 bytes, got %d", len(key))
		}
		return key[:32], nil
	}
	return nil, fmt.Errorf("no encryption key configured")
}

// Encrypt encrypts plaintext and returns nonce+ciphertext.
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := e.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts nonce+ciphertext and returns plaintext.
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < e.gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:e.gcm.NonceSize()]
	ciphertext = ciphertext[e.gcm.NonceSize():]

	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
