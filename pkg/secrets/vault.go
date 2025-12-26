package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VaultProvider provides secrets from HashiCorp Vault.
type VaultProvider struct {
	config     VaultConfig
	httpClient *http.Client
	token      string
	tokenMu    sync.RWMutex
}

// NewVaultProvider creates a new Vault provider.
func NewVaultProvider(config VaultConfig) (*VaultProvider, error) {
	if config.Address == "" {
		return nil, fmt.Errorf("vault address required")
	}

	p := &VaultProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Set initial token if provided
	if config.Token != "" {
		p.token = config.Token
	}

	return p, nil
}

// Name returns the provider name.
func (p *VaultProvider) Name() string {
	return "vault"
}

// Get retrieves a secret from Vault.
func (p *VaultProvider) Get(ctx context.Context, path string) (*Secret, error) {
	// Ensure we have a valid token
	if err := p.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("%s/v1/%s", strings.TrimSuffix(p.config.Address, "/"), path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	p.tokenMu.RLock()
	req.Header.Set("X-Vault-Token", p.token)
	p.tokenMu.RUnlock()

	if p.config.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.config.Namespace)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrSecretNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(body))
	}

	var vaultResp vaultSecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return p.parseSecret(path, &vaultResp)
}

// List lists secrets at a path prefix.
func (p *VaultProvider) List(ctx context.Context, prefix string) ([]string, error) {
	if err := p.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	// Build URL for LIST operation
	url := fmt.Sprintf("%s/v1/%s", strings.TrimSuffix(p.config.Address, "/"), prefix)

	req, err := http.NewRequestWithContext(ctx, "LIST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	p.tokenMu.RLock()
	req.Header.Set("X-Vault-Token", p.token)
	p.tokenMu.RUnlock()

	if p.config.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.config.Namespace)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(body))
	}

	var listResp vaultListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return listResp.Data.Keys, nil
}

// IsHealthy checks if Vault is healthy.
func (p *VaultProvider) IsHealthy(ctx context.Context) bool {
	url := fmt.Sprintf("%s/v1/sys/health", strings.TrimSuffix(p.config.Address, "/"))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Vault returns 200 for initialized, unsealed, and active
	// 429 for unsealed and standby
	// 472 for disaster recovery mode replication secondary and active
	// 473 for performance standby
	// 501 for not initialized
	// 503 for sealed
	return resp.StatusCode == http.StatusOK ||
		resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == 472 ||
		resp.StatusCode == 473
}

// ensureAuthenticated ensures we have a valid token.
func (p *VaultProvider) ensureAuthenticated(ctx context.Context) error {
	p.tokenMu.RLock()
	hasToken := p.token != ""
	p.tokenMu.RUnlock()

	if hasToken {
		return nil
	}

	switch p.config.AuthMethod {
	case "token":
		if p.config.Token == "" {
			return fmt.Errorf("token auth requires token")
		}
		p.tokenMu.Lock()
		p.token = p.config.Token
		p.tokenMu.Unlock()
		return nil

	case "approle":
		return p.authenticateAppRole(ctx)

	case "kubernetes":
		return p.authenticateKubernetes(ctx)

	default:
		return fmt.Errorf("unsupported auth method: %s", p.config.AuthMethod)
	}
}

// authenticateAppRole authenticates using AppRole.
func (p *VaultProvider) authenticateAppRole(ctx context.Context) error {
	if p.config.RoleID == "" || p.config.SecretID == "" {
		return fmt.Errorf("approle auth requires role_id and secret_id")
	}

	url := fmt.Sprintf("%s/v1/auth/approle/login", strings.TrimSuffix(p.config.Address, "/"))

	payload := fmt.Sprintf(`{"role_id":"%s","secret_id":"%s"}`, p.config.RoleID, p.config.SecretID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("approle auth failed (status %d): %s", resp.StatusCode, string(body))
	}

	var authResp vaultAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	p.tokenMu.Lock()
	p.token = authResp.Auth.ClientToken
	p.tokenMu.Unlock()

	return nil
}

// authenticateKubernetes authenticates using Kubernetes service account.
func (p *VaultProvider) authenticateKubernetes(ctx context.Context) error {
	if p.config.KubeRole == "" {
		return fmt.Errorf("kubernetes auth requires kube_role")
	}

	// Read service account token
	jwt, err := p.readServiceAccountToken()
	if err != nil {
		return fmt.Errorf("reading service account token: %w", err)
	}

	url := fmt.Sprintf("%s/v1/auth/kubernetes/login", strings.TrimSuffix(p.config.Address, "/"))

	payload := fmt.Sprintf(`{"role":"%s","jwt":"%s"}`, p.config.KubeRole, jwt)

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("kubernetes auth failed (status %d): %s", resp.StatusCode, string(body))
	}

	var authResp vaultAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	p.tokenMu.Lock()
	p.token = authResp.Auth.ClientToken
	p.tokenMu.Unlock()

	return nil
}

// readServiceAccountToken reads the Kubernetes service account token.
func (p *VaultProvider) readServiceAccountToken() (string, error) {
	// Default path for Kubernetes service account token
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"

	data, err := readFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("reading token file: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}

// parseSecret parses a Vault response into a Secret.
func (p *VaultProvider) parseSecret(path string, resp *vaultSecretResponse) (*Secret, error) {
	secret := &Secret{
		Path:     path,
		Metadata: make(map[string]string),
	}

	// Handle KV v2 secrets
	if resp.Data.Data != nil {
		secret.Data = resp.Data.Data
		if resp.Data.Metadata != nil {
			if v, ok := resp.Data.Metadata["version"].(float64); ok {
				secret.Version = fmt.Sprintf("%d", int(v))
			}
			if t, ok := resp.Data.Metadata["created_time"].(string); ok {
				if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
					secret.CreatedAt = parsed
				}
			}
		}
	} else {
		// KV v1 or other secret engines
		secret.Data = make(map[string]string)
		for k, v := range resp.Data.Raw {
			if s, ok := v.(string); ok {
				secret.Data[k] = s
			}
		}
	}

	return secret, nil
}

// RevokeToken revokes the current token.
func (p *VaultProvider) RevokeToken(ctx context.Context) error {
	p.tokenMu.RLock()
	if p.token == "" {
		p.tokenMu.RUnlock()
		return nil
	}
	p.tokenMu.RUnlock()

	url := fmt.Sprintf("%s/v1/auth/token/revoke-self", strings.TrimSuffix(p.config.Address, "/"))

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	p.tokenMu.RLock()
	req.Header.Set("X-Vault-Token", p.token)
	p.tokenMu.RUnlock()

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	p.tokenMu.Lock()
	p.token = ""
	p.tokenMu.Unlock()

	return nil
}

// Vault API response types
type vaultSecretResponse struct {
	Data struct {
		Data     map[string]string      `json:"data"`
		Metadata map[string]any         `json:"metadata"`
		Raw      map[string]any         `json:"-"`
	} `json:"data"`
}

func (v *vaultSecretResponse) UnmarshalJSON(data []byte) error {
	type alias vaultSecretResponse
	aux := &struct {
		Data json.RawMessage `json:"data"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// Try to parse as KV v2
	type kvV2Data struct {
		Data     map[string]string `json:"data"`
		Metadata map[string]any    `json:"metadata"`
	}
	var kv2 kvV2Data
	if err := json.Unmarshal(aux.Data, &kv2); err == nil && kv2.Data != nil {
		v.Data.Data = kv2.Data
		v.Data.Metadata = kv2.Metadata
		return nil
	}

	// Parse as raw data (KV v1 or other)
	var raw map[string]any
	if err := json.Unmarshal(aux.Data, &raw); err != nil {
		return err
	}
	v.Data.Raw = raw

	return nil
}

type vaultListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

type vaultAuthResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// readFile is a variable to allow mocking in tests.
var readFile = os.ReadFile
