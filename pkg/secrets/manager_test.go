package secrets

import (
	"context"
	"testing"
	"time"
)

type mockProvider struct {
	name    string
	secrets map[string]*Secret
	healthy bool
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Get(ctx context.Context, path string) (*Secret, error) {
	if s, ok := m.secrets[path]; ok {
		return s, nil
	}
	return nil, ErrSecretNotFound
}

func (m *mockProvider) List(ctx context.Context, prefix string) ([]string, error) {
	var paths []string
	for p := range m.secrets {
		if matchPath(prefix+"*", p) {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

func (m *mockProvider) IsHealthy(ctx context.Context) bool {
	return m.healthy
}

type mockApprovalService struct {
	decision ApprovalDecision
}

func (m *mockApprovalService) Request(ctx context.Context, req *ApprovalRequest) ApprovalDecision {
	return m.decision
}

func (m *mockApprovalService) GetPending(ctx context.Context) ([]*ApprovalRequest, error) {
	return nil, nil
}

func (m *mockApprovalService) Approve(ctx context.Context, requestID, approver string) error {
	return nil
}

func (m *mockApprovalService) Deny(ctx context.Context, requestID, approver, reason string) error {
	return nil
}

type mockAuditLogger struct {
	accessedCalls  int
	injectedCalls  int
	requestedCalls int
	decidedCalls   int
}

func (m *mockAuditLogger) SecretAccessed(agentID, path, provider string, granted bool) {
	m.accessedCalls++
}

func (m *mockAuditLogger) SecretInjected(agentID, path, envVar string) {
	m.injectedCalls++
}

func (m *mockAuditLogger) ApprovalRequested(req *ApprovalRequest) {
	m.requestedCalls++
}

func (m *mockAuditLogger) ApprovalDecided(requestID string, decision ApprovalDecision, approver string) {
	m.decidedCalls++
}

func TestDefaultManagerConfig(t *testing.T) {
	config := DefaultManagerConfig()

	if config.CacheTTL != 5*time.Minute {
		t.Errorf("CacheTTL = %v, want 5m", config.CacheTTL)
	}

	if !config.AuditLog {
		t.Error("AuditLog should be true by default")
	}
}

func TestNewManager(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil)

	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestManager_RegisterProvider(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil)

	provider := &mockProvider{name: "test", healthy: true}
	m.RegisterProvider(provider)

	p, ok := m.GetProvider("test")
	if !ok {
		t.Fatal("provider should be found")
	}

	if p.Name() != "test" {
		t.Errorf("Name() = %q, want test", p.Name())
	}
}

func TestManager_ListProviders(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil)

	m.RegisterProvider(&mockProvider{name: "test1", healthy: true})
	m.RegisterProvider(&mockProvider{name: "test2", healthy: true})

	providers := m.ListProviders()
	if len(providers) != 2 {
		t.Errorf("provider count = %d, want 2", len(providers))
	}
}

func TestManager_Get(t *testing.T) {
	config := DefaultManagerConfig()
	config.CacheTTL = 0 // Disable cache for this test

	m := NewManager(config, nil, nil)

	provider := &mockProvider{
		name:    "test",
		healthy: true,
		secrets: map[string]*Secret{
			"secret/path": {
				Path: "secret/path",
				Data: map[string]string{"key": "value"},
			},
		},
	}
	m.RegisterProvider(provider)

	ctx := context.Background()
	secret, err := m.Get(ctx, SecretRequest{
		Provider: "test",
		Path:     "secret/path",
		AgentID:  "agent-1",
	})

	if err != nil {
		t.Fatalf("Get error: %v", err)
	}

	if secret.Path != "secret/path" {
		t.Errorf("Path = %q, want secret/path", secret.Path)
	}

	v, ok := secret.GetValue("key")
	if !ok || v != "value" {
		t.Errorf("GetValue(key) = %q, want value", v)
	}
}

func TestManager_Get_NotFound(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil)

	provider := &mockProvider{
		name:    "test",
		healthy: true,
		secrets: map[string]*Secret{},
	}
	m.RegisterProvider(provider)

	ctx := context.Background()
	_, err := m.Get(ctx, SecretRequest{
		Provider: "test",
		Path:     "nonexistent",
		AgentID:  "agent-1",
	})

	if err != ErrSecretNotFound {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestManager_Get_ProviderNotFound(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil)

	ctx := context.Background()
	_, err := m.Get(ctx, SecretRequest{
		Provider: "nonexistent",
		Path:     "secret/path",
		AgentID:  "agent-1",
	})

	if err == nil {
		t.Error("should error for nonexistent provider")
	}
}

func TestManager_Get_WithAllowedPaths(t *testing.T) {
	config := DefaultManagerConfig()
	config.AllowedPaths = []string{"allowed/*"}

	auditLog := &mockAuditLogger{}
	m := NewManager(config, nil, auditLog)

	provider := &mockProvider{
		name:    "test",
		healthy: true,
		secrets: map[string]*Secret{
			"allowed/secret": {Path: "allowed/secret", Data: map[string]string{"key": "value"}},
			"denied/secret":  {Path: "denied/secret", Data: map[string]string{"key": "value"}},
		},
	}
	m.RegisterProvider(provider)

	ctx := context.Background()

	// Allowed path should work
	_, err := m.Get(ctx, SecretRequest{
		Provider: "test",
		Path:     "allowed/secret",
		AgentID:  "agent-1",
	})
	if err != nil {
		t.Errorf("allowed path should work: %v", err)
	}

	// Denied path should fail
	_, err = m.Get(ctx, SecretRequest{
		Provider: "test",
		Path:     "denied/secret",
		AgentID:  "agent-1",
	})
	if err != ErrSecretPathNotAllowed {
		t.Errorf("expected ErrSecretPathNotAllowed, got %v", err)
	}
}

func TestManager_Get_WithApproval(t *testing.T) {
	config := DefaultManagerConfig()
	config.RequireApproval = true
	config.CacheTTL = 0 // Disable cache for this test

	approvals := &mockApprovalService{decision: ApprovalApproved}
	m := NewManager(config, approvals, nil)

	provider := &mockProvider{
		name:    "test",
		healthy: true,
		secrets: map[string]*Secret{
			"secret/path":  {Path: "secret/path", Data: map[string]string{"key": "value"}},
			"secret/path2": {Path: "secret/path2", Data: map[string]string{"key": "value2"}},
		},
	}
	m.RegisterProvider(provider)

	ctx := context.Background()

	// Approved
	_, err := m.Get(ctx, SecretRequest{
		Provider: "test",
		Path:     "secret/path",
		AgentID:  "agent-1",
		Reason:   "testing",
	})
	if err != nil {
		t.Errorf("approved request should work: %v", err)
	}

	// Denied - use different path to avoid any caching
	approvals.decision = ApprovalDenied
	_, err = m.Get(ctx, SecretRequest{
		Provider: "test",
		Path:     "secret/path2",
		AgentID:  "agent-1",
	})
	if err != ErrSecretAccessDenied {
		t.Errorf("expected ErrSecretAccessDenied, got %v", err)
	}
}

func TestManager_Get_WithCache(t *testing.T) {
	config := DefaultManagerConfig()
	config.CacheTTL = time.Minute

	m := NewManager(config, nil, nil)

	provider := &mockProvider{
		name:    "test",
		healthy: true,
		secrets: map[string]*Secret{
			"secret/path": {Path: "secret/path", Data: map[string]string{"key": "value"}},
		},
	}
	m.RegisterProvider(provider)

	ctx := context.Background()

	// First call
	_, err := m.Get(ctx, SecretRequest{Provider: "test", Path: "secret/path", AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("first Get error: %v", err)
	}

	// Second call - should hit cache (we can verify by checking cache size)
	initialSize := m.cache.size()
	_, err = m.Get(ctx, SecretRequest{Provider: "test", Path: "secret/path", AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("second Get error: %v", err)
	}

	// Cache size should remain the same
	if m.cache.size() != initialSize {
		t.Errorf("cache size changed unexpectedly")
	}

	// With BypassCache - should still work
	_, err = m.Get(ctx, SecretRequest{Provider: "test", Path: "secret/path", AgentID: "agent-1", BypassCache: true})
	if err != nil {
		t.Fatalf("bypass Get error: %v", err)
	}
}

func TestManager_Get_WithTTL(t *testing.T) {
	config := DefaultManagerConfig()
	config.CacheTTL = 0

	m := NewManager(config, nil, nil)

	provider := &mockProvider{
		name:    "test",
		healthy: true,
		secrets: map[string]*Secret{
			"secret/path": {Path: "secret/path", Data: map[string]string{"key": "value"}},
		},
	}
	m.RegisterProvider(provider)

	ctx := context.Background()
	secret, err := m.Get(ctx, SecretRequest{
		Provider: "test",
		Path:     "secret/path",
		AgentID:  "agent-1",
		TTL:      30 * time.Minute,
	})

	if err != nil {
		t.Fatalf("Get error: %v", err)
	}

	if secret.ExpiresAt == nil {
		t.Error("ExpiresAt should be set when TTL specified")
	}
}

func TestManager_GetInjections(t *testing.T) {
	config := DefaultManagerConfig()
	config.CacheTTL = 0
	config.Inject = []InjectConfig{
		{
			Provider: "test",
			Path:     "secret/api-key",
			Key:      "api_key",
			EnvVar:   "API_KEY",
		},
		{
			Provider: "test",
			Path:     "secret/db-password",
			Key:      "password",
			EnvVar:   "DB_PASSWORD",
		},
	}

	auditLog := &mockAuditLogger{}
	m := NewManager(config, nil, auditLog)

	provider := &mockProvider{
		name:    "test",
		healthy: true,
		secrets: map[string]*Secret{
			"secret/api-key":     {Path: "secret/api-key", Data: map[string]string{"api_key": "sk-123"}},
			"secret/db-password": {Path: "secret/db-password", Data: map[string]string{"password": "secret123"}},
		},
	}
	m.RegisterProvider(provider)

	ctx := context.Background()
	injections, err := m.GetInjections(ctx, "agent-1")
	if err != nil {
		t.Fatalf("GetInjections error: %v", err)
	}

	if len(injections) != 2 {
		t.Errorf("injection count = %d, want 2", len(injections))
	}

	if injections["API_KEY"] != "sk-123" {
		t.Errorf("API_KEY = %q, want sk-123", injections["API_KEY"])
	}

	if injections["DB_PASSWORD"] != "secret123" {
		t.Errorf("DB_PASSWORD = %q, want secret123", injections["DB_PASSWORD"])
	}

	if auditLog.injectedCalls != 2 {
		t.Errorf("injectedCalls = %d, want 2", auditLog.injectedCalls)
	}
}

func TestManager_Health(t *testing.T) {
	config := DefaultManagerConfig()
	m := NewManager(config, nil, nil)

	m.RegisterProvider(&mockProvider{name: "healthy", healthy: true})
	m.RegisterProvider(&mockProvider{name: "unhealthy", healthy: false})

	ctx := context.Background()
	health := m.Health(ctx)

	if len(health) != 2 {
		t.Errorf("health count = %d, want 2", len(health))
	}

	if !health["healthy"] {
		t.Error("healthy provider should be healthy")
	}

	if health["unhealthy"] {
		t.Error("unhealthy provider should be unhealthy")
	}
}

func TestManager_ClearCache(t *testing.T) {
	config := DefaultManagerConfig()
	config.CacheTTL = time.Minute

	m := NewManager(config, nil, nil)

	provider := &mockProvider{
		name:    "test",
		healthy: true,
		secrets: map[string]*Secret{
			"secret/path": {Path: "secret/path", Data: map[string]string{"key": "value"}},
		},
	}
	m.RegisterProvider(provider)

	ctx := context.Background()

	// Populate cache
	m.Get(ctx, SecretRequest{Provider: "test", Path: "secret/path", AgentID: "agent-1"})

	// Clear cache
	m.ClearCache()

	// Cache should be empty now
	if m.cache.size() != 0 {
		t.Errorf("cache size = %d, want 0", m.cache.size())
	}
}

func TestSecret_IsExpired(t *testing.T) {
	// Not expired
	future := time.Now().Add(time.Hour)
	secret := &Secret{ExpiresAt: &future}
	if secret.IsExpired() {
		t.Error("should not be expired")
	}

	// Expired
	past := time.Now().Add(-time.Hour)
	secret.ExpiresAt = &past
	if !secret.IsExpired() {
		t.Error("should be expired")
	}

	// No expiry
	secret.ExpiresAt = nil
	if secret.IsExpired() {
		t.Error("should not be expired when no expiry set")
	}
}

func TestSecret_GetValue(t *testing.T) {
	secret := &Secret{
		Data: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	v, ok := secret.GetValue("key1")
	if !ok || v != "value1" {
		t.Errorf("GetValue(key1) = %q, want value1", v)
	}

	_, ok = secret.GetValue("nonexistent")
	if ok {
		t.Error("GetValue(nonexistent) should return false")
	}

	// Nil data
	secret.Data = nil
	_, ok = secret.GetValue("key1")
	if ok {
		t.Error("GetValue on nil data should return false")
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"*", "anything", true},
		{"secret/*", "secret/path", true},
		{"secret/*", "secret/nested/path", true},
		{"secret/*", "other/path", false},
		{"exact/path", "exact/path", true},
		{"exact/path", "other/path", false},
		{"prefix/", "prefix/something", false}, // No wildcard
	}

	for _, tt := range tests {
		got := matchPath(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestApprovalDecision(t *testing.T) {
	decisions := []ApprovalDecision{
		ApprovalPending,
		ApprovalApproved,
		ApprovalDenied,
		ApprovalExpired,
	}

	for _, d := range decisions {
		if string(d) == "" {
			t.Error("decision should not be empty string")
		}
	}
}

func TestManagerConfig_ProviderSpecificPaths(t *testing.T) {
	config := DefaultManagerConfig()
	config.Providers.Vault = &VaultConfig{
		AllowedPaths: []string{"vault/*"},
	}
	config.Providers.AWS = &AWSConfig{
		AllowedSecrets: []string{"aws/*"},
	}
	config.Providers.Azure = &AzureConfig{
		AllowedKeys: []string{"azure/*"},
	}

	m := NewManager(config, nil, nil)

	// Test Vault path check
	if !m.isPathAllowed("vault", "vault/secret") {
		t.Error("vault/secret should be allowed for vault provider")
	}

	// Test AWS path check
	if !m.isPathAllowed("aws", "aws/secret") {
		t.Error("aws/secret should be allowed for aws provider")
	}

	// Test Azure path check
	if !m.isPathAllowed("azure", "azure/key") {
		t.Error("azure/key should be allowed for azure provider")
	}
}

func TestErrors(t *testing.T) {
	errors := []error{
		ErrSecretPathNotAllowed,
		ErrSecretAccessDenied,
		ErrSecretNotFound,
		ErrProviderNotFound,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Error("error should have message")
		}
	}
}
