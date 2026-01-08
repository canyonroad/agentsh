package kms

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMSProvider uses AWS KMS for envelope encryption of data keys.
type AWSKMSProvider struct {
	keyID            string
	region           string
	encryptedDEKFile string

	client    *kms.Client
	cachedKey []byte
	mu        sync.RWMutex
}

// NewAWSKMSProvider creates a provider that uses AWS KMS for key management.
// keyID is the ARN or alias of the KMS key.
// region is the AWS region (uses default credential chain).
// encryptedDEKFile is an optional path to cache the encrypted data key.
func NewAWSKMSProvider(keyID, region, encryptedDEKFile string) (*AWSKMSProvider, error) {
	if keyID == "" {
		return nil, fmt.Errorf("aws_kms: key_id is required")
	}

	return &AWSKMSProvider{
		keyID:            keyID,
		region:           region,
		encryptedDEKFile: encryptedDEKFile,
	}, nil
}

// Name returns the provider identifier.
func (p *AWSKMSProvider) Name() string {
	return "aws_kms:" + p.keyID
}

// GetKey retrieves or generates a data encryption key using AWS KMS.
// If an encrypted DEK file exists, it decrypts it.
// Otherwise, it generates a new DEK and optionally caches the encrypted version.
func (p *AWSKMSProvider) GetKey(ctx context.Context) ([]byte, error) {
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

	// Generate new DEK
	key, encryptedKey, err := p.generateDEK(ctx)
	if err != nil {
		return nil, err
	}

	// Cache encrypted DEK to file
	if p.encryptedDEKFile != "" && len(encryptedKey) > 0 {
		if err := os.WriteFile(p.encryptedDEKFile, encryptedKey, 0600); err != nil {
			// Log warning but don't fail - we still have the key in memory
			// In production, this should be logged
		}
	}

	p.cachedKey = key
	return key, nil
}

// initClient initializes the AWS KMS client.
func (p *AWSKMSProvider) initClient(ctx context.Context) error {
	opts := []func(*config.LoadOptions) error{}
	if p.region != "" {
		opts = append(opts, config.WithRegion(p.region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("%w: failed to load AWS config: %v", ErrAuthFailed, err)
	}

	p.client = kms.NewFromConfig(cfg)
	return nil
}

// decryptDEK decrypts an encrypted data encryption key.
func (p *AWSKMSProvider) decryptDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error) {
	resp, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(p.keyID),
		CiphertextBlob: encryptedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt DEK: %v", ErrProviderUnavailable, err)
	}

	return resp.Plaintext, nil
}

// generateDEK generates a new data encryption key using AWS KMS.
// Returns the plaintext key and the encrypted (wrapped) key.
func (p *AWSKMSProvider) generateDEK(ctx context.Context) (plaintext, ciphertext []byte, err error) {
	resp, err := p.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(p.keyID),
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failed to generate DEK: %v", ErrProviderUnavailable, err)
	}

	return resp.Plaintext, resp.CiphertextBlob, nil
}

// Close releases resources.
func (p *AWSKMSProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cachedKey = nil
	p.client = nil
	return nil
}
