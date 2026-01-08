package kms

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// AzureKeyVaultProvider uses Azure Key Vault for secret storage.
type AzureKeyVaultProvider struct {
	vaultURL   string
	keyName    string
	keyVersion string

	client    *azsecrets.Client
	cachedKey []byte
	mu        sync.RWMutex
}

// NewAzureKeyVaultProvider creates a provider that uses Azure Key Vault.
// vaultURL is the vault URL (e.g., https://myvault.vault.azure.net).
// keyName is the name of the secret in the vault.
// keyVersion is optional; empty means latest version.
func NewAzureKeyVaultProvider(vaultURL, keyName, keyVersion string) (*AzureKeyVaultProvider, error) {
	if vaultURL == "" {
		return nil, fmt.Errorf("azure_keyvault: vault_url is required")
	}
	if keyName == "" {
		return nil, fmt.Errorf("azure_keyvault: key_name is required")
	}

	return &AzureKeyVaultProvider{
		vaultURL:   vaultURL,
		keyName:    keyName,
		keyVersion: keyVersion,
	}, nil
}

// Name returns the provider identifier.
func (p *AzureKeyVaultProvider) Name() string {
	return "azure_keyvault:" + p.keyName
}

// GetKey retrieves the secret from Azure Key Vault.
func (p *AzureKeyVaultProvider) GetKey(ctx context.Context) ([]byte, error) {
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
		if err := p.initClient(); err != nil {
			return nil, err
		}
	}

	// Get the secret
	resp, err := p.client.GetSecret(ctx, p.keyName, p.keyVersion, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get secret: %v", ErrProviderUnavailable, err)
	}

	if resp.Value == nil || *resp.Value == "" {
		return nil, fmt.Errorf("%w: secret %q is empty", ErrKeyNotFound, p.keyName)
	}

	// Try to decode as base64 first, fall back to raw string
	key, err := base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		// Not base64 encoded, use raw value
		key = []byte(*resp.Value)
	}

	p.cachedKey = key
	return key, nil
}

// initClient initializes the Azure Key Vault client using DefaultAzureCredential.
func (p *AzureKeyVaultProvider) initClient() error {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("%w: failed to create Azure credential: %v", ErrAuthFailed, err)
	}

	client, err := azsecrets.NewClient(p.vaultURL, cred, nil)
	if err != nil {
		return fmt.Errorf("%w: failed to create Key Vault client: %v", ErrAuthFailed, err)
	}

	p.client = client
	return nil
}

// Close releases resources.
func (p *AzureKeyVaultProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cachedKey = nil
	p.client = nil
	return nil
}
