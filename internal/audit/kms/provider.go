// Package kms provides key management system integrations for audit integrity keys.
package kms

import (
	"context"
	"errors"
	"fmt"
)

// Provider abstracts key retrieval from various KMS backends.
type Provider interface {
	// Name returns the provider identifier (for logging).
	Name() string

	// GetKey retrieves or derives the HMAC key.
	// For envelope encryption providers, this decrypts the DEK.
	GetKey(ctx context.Context) ([]byte, error)

	// Close releases any resources (connections, caches).
	Close() error
}

// Config holds provider-specific configuration.
type Config struct {
	// Source specifies the key source: file, env, aws_kms, azure_keyvault, hashicorp_vault, gcp_kms
	Source string

	// File/Env source
	KeyFile string
	KeyEnv  string

	// AWS KMS
	AWSKeyID            string
	AWSRegion           string
	AWSEncryptedDEKFile string

	// Azure Key Vault
	AzureVaultURL   string
	AzureKeyName    string
	AzureKeyVersion string

	// HashiCorp Vault
	VaultAddress    string
	VaultAuthMethod string // token, kubernetes, approle
	VaultTokenFile  string
	VaultK8sRole    string
	VaultAppRoleID  string
	VaultSecretID   string
	VaultSecretPath string
	VaultKeyField   string

	// GCP Cloud KMS
	GCPKeyName          string
	GCPEncryptedDEKFile string
}

// ErrKeyNotFound indicates the key was not found in the KMS.
var ErrKeyNotFound = errors.New("key not found")

// ErrAuthFailed indicates authentication to the KMS failed.
var ErrAuthFailed = errors.New("authentication failed")

// ErrProviderUnavailable indicates the KMS provider is unavailable.
var ErrProviderUnavailable = errors.New("provider unavailable")

// NewProvider creates a provider based on configuration.
func NewProvider(cfg Config) (Provider, error) {
	switch cfg.Source {
	case "file", "env", "":
		return NewFileProvider(cfg.KeyFile, cfg.KeyEnv)
	case "aws_kms":
		return NewAWSKMSProvider(cfg.AWSKeyID, cfg.AWSRegion, cfg.AWSEncryptedDEKFile)
	case "azure_keyvault":
		return NewAzureKeyVaultProvider(cfg.AzureVaultURL, cfg.AzureKeyName, cfg.AzureKeyVersion)
	case "hashicorp_vault":
		return NewVaultProvider(VaultConfig{
			Address:    cfg.VaultAddress,
			AuthMethod: cfg.VaultAuthMethod,
			TokenFile:  cfg.VaultTokenFile,
			K8sRole:    cfg.VaultK8sRole,
			AppRoleID:  cfg.VaultAppRoleID,
			SecretID:   cfg.VaultSecretID,
			SecretPath: cfg.VaultSecretPath,
			KeyField:   cfg.VaultKeyField,
		})
	case "gcp_kms":
		return NewGCPKMSProvider(cfg.GCPKeyName, cfg.GCPEncryptedDEKFile)
	default:
		return nil, fmt.Errorf("unknown key source: %s", cfg.Source)
	}
}
