package kms

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"sync"

	kmsv1 "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// GCPKMSProvider uses Google Cloud KMS for envelope encryption.
type GCPKMSProvider struct {
	keyName          string
	encryptedDEKFile string

	client    *kmsv1.KeyManagementClient
	cachedKey []byte
	mu        sync.RWMutex
}

// NewGCPKMSProvider creates a provider that uses GCP Cloud KMS.
// keyName is the full resource name (projects/.../locations/.../keyRings/.../cryptoKeys/...).
// encryptedDEKFile is an optional path to cache the encrypted data key.
func NewGCPKMSProvider(keyName, encryptedDEKFile string) (*GCPKMSProvider, error) {
	if keyName == "" {
		return nil, fmt.Errorf("gcp_kms: key_name is required")
	}

	return &GCPKMSProvider{
		keyName:          keyName,
		encryptedDEKFile: encryptedDEKFile,
	}, nil
}

// Name returns the provider identifier.
func (p *GCPKMSProvider) Name() string {
	return "gcp_kms:" + p.keyName
}

// GetKey retrieves or generates a data encryption key using GCP Cloud KMS.
// If an encrypted DEK file exists, it decrypts it.
// Otherwise, it generates a new DEK and optionally caches the encrypted version.
func (p *GCPKMSProvider) GetKey(ctx context.Context) ([]byte, error) {
	p.mu.RLock()
	if p.cachedKey != nil {
		key := p.cachedKey
		p.mu.RUnlock()
		return key, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.cachedKey != nil {
		return p.cachedKey, nil
	}

	// Initialize client if needed
	if p.client == nil {
		if err := p.initClient(ctx); err != nil {
			return nil, err
		}
	}

	// Try to load and decrypt existing DEK
	if p.encryptedDEKFile != "" {
		if encDEK, err := os.ReadFile(p.encryptedDEKFile); err == nil && len(encDEK) > 0 {
			key, err := p.decryptDEK(ctx, encDEK)
			if err == nil {
				p.cachedKey = key
				return key, nil
			}
			// Fall through to generate new DEK if decryption fails
		}
	}

	// Generate new DEK locally and encrypt with KMS
	key, encryptedKey, err := p.generateDEK(ctx)
	if err != nil {
		return nil, err
	}

	// Cache encrypted DEK to file
	if p.encryptedDEKFile != "" && len(encryptedKey) > 0 {
		if err := os.WriteFile(p.encryptedDEKFile, encryptedKey, 0600); err != nil {
			// Log warning but don't fail
		}
	}

	p.cachedKey = key
	return key, nil
}

// initClient initializes the GCP KMS client.
func (p *GCPKMSProvider) initClient(ctx context.Context) error {
	client, err := kmsv1.NewKeyManagementClient(ctx)
	if err != nil {
		return fmt.Errorf("%w: failed to create GCP KMS client: %v", ErrAuthFailed, err)
	}
	p.client = client
	return nil
}

// decryptDEK decrypts an encrypted data encryption key.
func (p *GCPKMSProvider) decryptDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error) {
	resp, err := p.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       p.keyName,
		Ciphertext: encryptedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt DEK: %v", ErrProviderUnavailable, err)
	}

	return resp.Plaintext, nil
}

// generateDEK generates a new 256-bit key locally and encrypts it with KMS.
// Returns the plaintext key and the encrypted (wrapped) key.
func (p *GCPKMSProvider) generateDEK(ctx context.Context) (plaintext, ciphertext []byte, err error) {
	// Generate 256-bit key locally
	plaintext = make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random key: %v", err)
	}

	// Encrypt with KMS
	resp, err := p.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      p.keyName,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failed to encrypt DEK: %v", ErrProviderUnavailable, err)
	}

	return plaintext, resp.Ciphertext, nil
}

// Close releases resources.
func (p *GCPKMSProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cachedKey = nil
	if p.client != nil {
		p.client.Close()
		p.client = nil
	}
	return nil
}
