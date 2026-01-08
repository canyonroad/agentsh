package kms

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
)

// VaultConfig holds configuration for HashiCorp Vault.
type VaultConfig struct {
	Address    string
	AuthMethod string // token, kubernetes, approle
	TokenFile  string
	K8sRole    string
	AppRoleID  string
	SecretID   string
	SecretPath string
	KeyField   string
}

// VaultProvider uses HashiCorp Vault for secret storage.
type VaultProvider struct {
	config    VaultConfig
	client    *vault.Client
	cachedKey []byte
	mu        sync.RWMutex
}

// NewVaultProvider creates a provider that uses HashiCorp Vault.
func NewVaultProvider(cfg VaultConfig) (*VaultProvider, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("hashicorp_vault: address is required")
	}
	if cfg.SecretPath == "" {
		return nil, fmt.Errorf("hashicorp_vault: secret_path is required")
	}
	if cfg.KeyField == "" {
		cfg.KeyField = "key" // default field name
	}
	if cfg.AuthMethod == "" {
		cfg.AuthMethod = "token"
	}

	return &VaultProvider{
		config: cfg,
	}, nil
}

// Name returns the provider identifier.
func (p *VaultProvider) Name() string {
	return "hashicorp_vault:" + p.config.SecretPath
}

// GetKey retrieves the secret from HashiCorp Vault.
func (p *VaultProvider) GetKey(ctx context.Context) ([]byte, error) {
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

	// Initialize and authenticate client if needed
	if p.client == nil {
		if err := p.initClient(ctx); err != nil {
			return nil, err
		}
	}

	// Read the secret
	secret, err := p.client.KVv2("secret").Get(ctx, p.secretPathWithoutPrefix())
	if err != nil {
		// Try KV v1 as fallback
		secret, err = p.readKVv1(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read secret: %v", ErrProviderUnavailable, err)
		}
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: secret %q not found", ErrKeyNotFound, p.config.SecretPath)
	}

	// Extract the key field
	value, ok := secret.Data[p.config.KeyField]
	if !ok {
		return nil, fmt.Errorf("%w: field %q not found in secret", ErrKeyNotFound, p.config.KeyField)
	}

	keyStr, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("key field %q is not a string", p.config.KeyField)
	}

	if keyStr == "" {
		return nil, fmt.Errorf("%w: key field %q is empty", ErrKeyNotFound, p.config.KeyField)
	}

	// Try to decode as base64 first, fall back to raw string
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		key = []byte(keyStr)
	}

	p.cachedKey = key
	return key, nil
}

// secretPathWithoutPrefix removes the "secret/data/" prefix if present.
func (p *VaultProvider) secretPathWithoutPrefix() string {
	path := p.config.SecretPath
	path = strings.TrimPrefix(path, "secret/data/")
	path = strings.TrimPrefix(path, "secret/")
	return path
}

// readKVv1 reads a secret using KV v1 API.
func (p *VaultProvider) readKVv1(ctx context.Context) (*vault.KVSecret, error) {
	secret, err := p.client.Logical().ReadWithContext(ctx, p.config.SecretPath)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, nil
	}
	return &vault.KVSecret{Data: secret.Data}, nil
}

// initClient initializes and authenticates the Vault client.
func (p *VaultProvider) initClient(ctx context.Context) error {
	config := vault.DefaultConfig()
	config.Address = p.config.Address

	client, err := vault.NewClient(config)
	if err != nil {
		return fmt.Errorf("%w: failed to create Vault client: %v", ErrAuthFailed, err)
	}

	// Authenticate based on method
	switch p.config.AuthMethod {
	case "token":
		if err := p.authToken(client); err != nil {
			return err
		}
	case "kubernetes":
		if err := p.authKubernetes(ctx, client); err != nil {
			return err
		}
	case "approle":
		if err := p.authAppRole(ctx, client); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unsupported auth method %q", ErrAuthFailed, p.config.AuthMethod)
	}

	p.client = client
	return nil
}

// authToken authenticates using a token file or VAULT_TOKEN env var.
func (p *VaultProvider) authToken(client *vault.Client) error {
	var token string

	if p.config.TokenFile != "" {
		data, err := os.ReadFile(p.config.TokenFile)
		if err != nil {
			return fmt.Errorf("%w: failed to read token file: %v", ErrAuthFailed, err)
		}
		token = strings.TrimSpace(string(data))
	} else {
		token = os.Getenv("VAULT_TOKEN")
	}

	if token == "" {
		return fmt.Errorf("%w: no token provided", ErrAuthFailed)
	}

	client.SetToken(token)
	return nil
}

// authKubernetes authenticates using Kubernetes service account.
func (p *VaultProvider) authKubernetes(ctx context.Context, client *vault.Client) error {
	if p.config.K8sRole == "" {
		return fmt.Errorf("%w: kubernetes_role is required for kubernetes auth", ErrAuthFailed)
	}

	k8sAuth, err := auth.NewKubernetesAuth(p.config.K8sRole)
	if err != nil {
		return fmt.Errorf("%w: failed to create kubernetes auth: %v", ErrAuthFailed, err)
	}

	authInfo, err := client.Auth().Login(ctx, k8sAuth)
	if err != nil {
		return fmt.Errorf("%w: kubernetes login failed: %v", ErrAuthFailed, err)
	}

	if authInfo == nil {
		return fmt.Errorf("%w: kubernetes login returned no auth info", ErrAuthFailed)
	}

	return nil
}

// authAppRole authenticates using AppRole.
func (p *VaultProvider) authAppRole(ctx context.Context, client *vault.Client) error {
	if p.config.AppRoleID == "" {
		return fmt.Errorf("%w: approle_id is required for approle auth", ErrAuthFailed)
	}

	secretID := p.config.SecretID
	if secretID == "" {
		secretID = os.Getenv("VAULT_SECRET_ID")
	}

	data := map[string]interface{}{
		"role_id": p.config.AppRoleID,
	}
	if secretID != "" {
		data["secret_id"] = secretID
	}

	resp, err := client.Logical().WriteWithContext(ctx, "auth/approle/login", data)
	if err != nil {
		return fmt.Errorf("%w: approle login failed: %v", ErrAuthFailed, err)
	}

	if resp == nil || resp.Auth == nil {
		return fmt.Errorf("%w: approle login returned no auth info", ErrAuthFailed)
	}

	client.SetToken(resp.Auth.ClientToken)
	return nil
}

// Close releases resources.
func (p *VaultProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cachedKey = nil
	if p.client != nil {
		p.client.ClearToken()
	}
	p.client = nil
	return nil
}
