package secrets

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Provider defines the interface for secret management backends.
type Provider interface {
	// Name returns the provider name.
	Name() string

	// Get retrieves a secret by path.
	Get(ctx context.Context, path string) (*Secret, error)

	// List lists secrets at a path prefix.
	List(ctx context.Context, prefix string) ([]string, error)

	// IsHealthy checks if the provider is healthy.
	IsHealthy(ctx context.Context) bool
}

// Secret represents a retrieved secret.
type Secret struct {
	// Path is the secret path.
	Path string `json:"path"`

	// Data contains the secret data.
	Data map[string]string `json:"-"`

	// Version is the secret version.
	Version string `json:"version,omitempty"`

	// CreatedAt is when the secret was created.
	CreatedAt time.Time `json:"created_at,omitempty"`

	// ExpiresAt is when the secret expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Metadata contains additional metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// IsExpired returns whether the secret has expired.
func (s *Secret) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

// GetValue returns a specific key from the secret data.
func (s *Secret) GetValue(key string) (string, bool) {
	if s.Data == nil {
		return "", false
	}
	v, ok := s.Data[key]
	return v, ok
}

// ManagerConfig configures the secret manager.
type ManagerConfig struct {
	// Providers configures individual secret providers.
	Providers ProvidersConfig `yaml:"providers" json:"providers"`

	// AllowedPaths restricts which secret paths can be accessed.
	AllowedPaths []string `yaml:"allowed_paths" json:"allowed_paths"`

	// Inject configures automatic secret injection.
	Inject []InjectConfig `yaml:"inject" json:"inject"`

	// RequireApproval requires approval for secret access.
	RequireApproval bool `yaml:"require_approval" json:"require_approval"`

	// CacheTTL is how long to cache secrets.
	CacheTTL time.Duration `yaml:"cache_ttl" json:"cache_ttl"`

	// AuditLog enables audit logging.
	AuditLog bool `yaml:"audit_log" json:"audit_log"`
}

// ProvidersConfig configures secret providers.
type ProvidersConfig struct {
	Vault *VaultConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
	AWS   *AWSConfig   `yaml:"aws,omitempty" json:"aws,omitempty"`
	Azure *AzureConfig `yaml:"azure,omitempty" json:"azure,omitempty"`
}

// VaultConfig configures HashiCorp Vault.
type VaultConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	Address      string   `yaml:"address" json:"address"`
	AuthMethod   string   `yaml:"auth_method" json:"auth_method"`
	Token        string   `yaml:"token,omitempty" json:"token,omitempty"`
	RoleID       string   `yaml:"role_id,omitempty" json:"role_id,omitempty"`
	SecretID     string   `yaml:"secret_id,omitempty" json:"secret_id,omitempty"`
	KubeRole     string   `yaml:"kube_role,omitempty" json:"kube_role,omitempty"`
	Namespace    string   `yaml:"namespace,omitempty" json:"namespace,omitempty"`
	AllowedPaths []string `yaml:"allowed_paths" json:"allowed_paths"`
}

// AWSConfig configures AWS Secrets Manager.
type AWSConfig struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	Region         string   `yaml:"region" json:"region"`
	AllowedSecrets []string `yaml:"allowed_secrets" json:"allowed_secrets"`
	RoleARN        string   `yaml:"role_arn,omitempty" json:"role_arn,omitempty"`
}

// AzureConfig configures Azure Key Vault.
type AzureConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	VaultURL      string   `yaml:"vault_url" json:"vault_url"`
	TenantID      string   `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	ClientID      string   `yaml:"client_id,omitempty" json:"client_id,omitempty"`
	AllowedKeys   []string `yaml:"allowed_keys" json:"allowed_keys"`
}

// InjectConfig configures automatic secret injection.
type InjectConfig struct {
	// Provider is the secret provider name.
	Provider string `yaml:"provider" json:"provider"`

	// Path is the secret path in the provider.
	Path string `yaml:"path" json:"path"`

	// Key is the specific key within the secret.
	Key string `yaml:"key,omitempty" json:"key,omitempty"`

	// EnvVar is the environment variable name to inject.
	EnvVar string `yaml:"env_var" json:"env_var"`

	// File is the file path to write the secret to.
	File string `yaml:"file,omitempty" json:"file,omitempty"`
}

// DefaultManagerConfig returns default manager configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		CacheTTL: 5 * time.Minute,
		AuditLog: true,
	}
}

// Manager coordinates secret access across providers.
type Manager struct {
	config    ManagerConfig
	providers map[string]Provider
	cache     *secretCache
	approvals ApprovalService
	auditLog  AuditLogger
	mu        sync.RWMutex
}

// ApprovalService handles secret access approvals.
type ApprovalService interface {
	// Request requests approval for secret access.
	Request(ctx context.Context, req *ApprovalRequest) ApprovalDecision

	// GetPending returns pending approval requests.
	GetPending(ctx context.Context) ([]*ApprovalRequest, error)

	// Approve approves a request.
	Approve(ctx context.Context, requestID, approver string) error

	// Deny denies a request.
	Deny(ctx context.Context, requestID, approver, reason string) error
}

// ApprovalRequest represents a secret access approval request.
type ApprovalRequest struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	Resource      string    `json:"resource"`
	Requester     string    `json:"requester"`
	Justification string    `json:"justification"`
	TTL           time.Duration `json:"ttl"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// ApprovalDecision represents an approval decision.
type ApprovalDecision string

const (
	ApprovalPending  ApprovalDecision = "pending"
	ApprovalApproved ApprovalDecision = "approved"
	ApprovalDenied   ApprovalDecision = "denied"
	ApprovalExpired  ApprovalDecision = "expired"
)

// AuditLogger logs secret access events.
type AuditLogger interface {
	// SecretAccessed logs a secret access event.
	SecretAccessed(agentID, path, provider string, granted bool)

	// SecretInjected logs a secret injection event.
	SecretInjected(agentID, path, envVar string)

	// ApprovalRequested logs an approval request.
	ApprovalRequested(req *ApprovalRequest)

	// ApprovalDecided logs an approval decision.
	ApprovalDecided(requestID string, decision ApprovalDecision, approver string)
}

// NewManager creates a new secret manager.
func NewManager(config ManagerConfig, approvals ApprovalService, auditLog AuditLogger) *Manager {
	m := &Manager{
		config:    config,
		providers: make(map[string]Provider),
		approvals: approvals,
		auditLog:  auditLog,
	}

	if config.CacheTTL > 0 {
		m.cache = newSecretCache(config.CacheTTL)
	}

	return m
}

// RegisterProvider registers a secret provider.
func (m *Manager) RegisterProvider(provider Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[provider.Name()] = provider
}

// GetProvider returns a provider by name.
func (m *Manager) GetProvider(name string) (Provider, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.providers[name]
	return p, ok
}

// ListProviders returns all registered provider names.
func (m *Manager) ListProviders() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	return names
}

// SecretRequest represents a request to access a secret.
type SecretRequest struct {
	Provider      string        `json:"provider"`
	Path          string        `json:"path"`
	AgentID       string        `json:"agent_id"`
	Reason        string        `json:"reason"`
	TTL           time.Duration `json:"ttl"`
	BypassCache   bool          `json:"bypass_cache"`
}

// Get retrieves a secret.
func (m *Manager) Get(ctx context.Context, req SecretRequest) (*Secret, error) {
	// Check if path is allowed
	if !m.isPathAllowed(req.Provider, req.Path) {
		if m.auditLog != nil {
			m.auditLog.SecretAccessed(req.AgentID, req.Path, req.Provider, false)
		}
		return nil, ErrSecretPathNotAllowed
	}

	// Check cache first
	if m.cache != nil && !req.BypassCache {
		if cached := m.cache.get(req.Provider, req.Path); cached != nil {
			return cached, nil
		}
	}

	// Check if approval is required
	if m.config.RequireApproval && m.approvals != nil {
		decision := m.requestApproval(ctx, req)
		if decision != ApprovalApproved {
			if m.auditLog != nil {
				m.auditLog.SecretAccessed(req.AgentID, req.Path, req.Provider, false)
			}
			return nil, ErrSecretAccessDenied
		}
	}

	// Get provider
	provider, ok := m.GetProvider(req.Provider)
	if !ok {
		return nil, fmt.Errorf("provider not found: %s", req.Provider)
	}

	// Fetch secret
	secret, err := provider.Get(ctx, req.Path)
	if err != nil {
		return nil, err
	}

	// Set expiry if TTL specified
	if req.TTL > 0 {
		expiry := time.Now().Add(req.TTL)
		secret.ExpiresAt = &expiry
	}

	// Cache the secret
	if m.cache != nil {
		m.cache.set(req.Provider, req.Path, secret)
	}

	// Audit log
	if m.auditLog != nil {
		m.auditLog.SecretAccessed(req.AgentID, req.Path, req.Provider, true)
	}

	return secret, nil
}

// GetInjections returns secret values for configured injections.
func (m *Manager) GetInjections(ctx context.Context, agentID string) (map[string]string, error) {
	result := make(map[string]string)

	for _, inject := range m.config.Inject {
		secret, err := m.Get(ctx, SecretRequest{
			Provider: inject.Provider,
			Path:     inject.Path,
			AgentID:  agentID,
		})
		if err != nil {
			return nil, fmt.Errorf("getting secret %s/%s: %w", inject.Provider, inject.Path, err)
		}

		var value string
		if inject.Key != "" {
			v, ok := secret.GetValue(inject.Key)
			if !ok {
				return nil, fmt.Errorf("key %s not found in secret %s", inject.Key, inject.Path)
			}
			value = v
		} else {
			// Use first value if no key specified
			for _, v := range secret.Data {
				value = v
				break
			}
		}

		result[inject.EnvVar] = value

		if m.auditLog != nil {
			m.auditLog.SecretInjected(agentID, inject.Path, inject.EnvVar)
		}
	}

	return result, nil
}

// isPathAllowed checks if a path is allowed for a provider.
func (m *Manager) isPathAllowed(provider, path string) bool {
	// Check global allowed paths
	for _, pattern := range m.config.AllowedPaths {
		if matchPath(pattern, path) {
			return true
		}
	}

	// Check provider-specific allowed paths
	switch provider {
	case "vault":
		if m.config.Providers.Vault != nil {
			for _, pattern := range m.config.Providers.Vault.AllowedPaths {
				if matchPath(pattern, path) {
					return true
				}
			}
		}
	case "aws":
		if m.config.Providers.AWS != nil {
			for _, pattern := range m.config.Providers.AWS.AllowedSecrets {
				if matchPath(pattern, path) {
					return true
				}
			}
		}
	case "azure":
		if m.config.Providers.Azure != nil {
			for _, pattern := range m.config.Providers.Azure.AllowedKeys {
				if matchPath(pattern, path) {
					return true
				}
			}
		}
	}

	// If no allowed paths configured, deny by default
	return len(m.config.AllowedPaths) == 0 &&
		m.config.Providers.Vault == nil &&
		m.config.Providers.AWS == nil &&
		m.config.Providers.Azure == nil
}

// requestApproval requests approval for secret access.
func (m *Manager) requestApproval(ctx context.Context, req SecretRequest) ApprovalDecision {
	approvalReq := &ApprovalRequest{
		ID:            fmt.Sprintf("secret-%s-%d", req.Path, time.Now().UnixNano()),
		Type:          "secret_access",
		Resource:      fmt.Sprintf("%s/%s", req.Provider, req.Path),
		Requester:     req.AgentID,
		Justification: req.Reason,
		TTL:           req.TTL,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}

	if m.auditLog != nil {
		m.auditLog.ApprovalRequested(approvalReq)
	}

	return m.approvals.Request(ctx, approvalReq)
}

// Health returns health status of all providers.
func (m *Manager) Health(ctx context.Context) map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	health := make(map[string]bool)
	for name, provider := range m.providers {
		health[name] = provider.IsHealthy(ctx)
	}
	return health
}

// ClearCache clears the secret cache.
func (m *Manager) ClearCache() {
	if m.cache != nil {
		m.cache.clear()
	}
}

// matchPath matches a path against a pattern with wildcard support.
func matchPath(pattern, path string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	// Prefix matching with wildcard
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}

	return pattern == path
}

// Errors
var (
	ErrSecretPathNotAllowed = fmt.Errorf("secret path not allowed")
	ErrSecretAccessDenied   = fmt.Errorf("secret access denied")
	ErrSecretNotFound       = fmt.Errorf("secret not found")
	ErrProviderNotFound     = fmt.Errorf("provider not found")
)
