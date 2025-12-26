package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewVaultProvider(t *testing.T) {
	config := VaultConfig{
		Address:    "https://vault.example.com",
		AuthMethod: "token",
		Token:      "test-token",
	}

	p, err := NewVaultProvider(config)
	if err != nil {
		t.Fatalf("NewVaultProvider error: %v", err)
	}

	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewVaultProvider_NoAddress(t *testing.T) {
	config := VaultConfig{}

	_, err := NewVaultProvider(config)
	if err == nil {
		t.Error("should error without address")
	}
}

func TestVaultProvider_Name(t *testing.T) {
	config := VaultConfig{
		Address:    "https://vault.example.com",
		AuthMethod: "token",
		Token:      "test-token",
	}

	p, _ := NewVaultProvider(config)

	if p.Name() != "vault" {
		t.Errorf("Name() = %q, want vault", p.Name())
	}
}

func TestVaultProvider_Get(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// KV v2 response
		resp := map[string]any{
			"data": map[string]any{
				"data": map[string]string{
					"api_key": "sk-123",
				},
				"metadata": map[string]any{
					"version":      float64(1),
					"created_time": "2024-01-01T00:00:00Z",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := VaultConfig{
		Address:    server.URL,
		AuthMethod: "token",
		Token:      "test-token",
	}

	p, err := NewVaultProvider(config)
	if err != nil {
		t.Fatalf("NewVaultProvider error: %v", err)
	}

	ctx := context.Background()
	secret, err := p.Get(ctx, "secret/data/test")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}

	if secret.Path != "secret/data/test" {
		t.Errorf("Path = %q, want secret/data/test", secret.Path)
	}

	v, ok := secret.GetValue("api_key")
	if !ok || v != "sk-123" {
		t.Errorf("api_key = %q, want sk-123", v)
	}

	if secret.Version != "1" {
		t.Errorf("Version = %q, want 1", secret.Version)
	}
}

func TestVaultProvider_Get_KVv1(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// KV v1 response (flat data)
		resp := map[string]any{
			"data": map[string]string{
				"username": "admin",
				"password": "secret",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := VaultConfig{
		Address:    server.URL,
		AuthMethod: "token",
		Token:      "test-token",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	secret, err := p.Get(ctx, "secret/test")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}

	if len(secret.Data) != 2 {
		t.Errorf("data count = %d, want 2", len(secret.Data))
	}
}

func TestVaultProvider_Get_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := VaultConfig{
		Address:    server.URL,
		AuthMethod: "token",
		Token:      "test-token",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	_, err := p.Get(ctx, "secret/nonexistent")
	if err != ErrSecretNotFound {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestVaultProvider_List(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "LIST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		resp := map[string]any{
			"data": map[string]any{
				"keys": []string{"secret1", "secret2", "secret3"},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := VaultConfig{
		Address:    server.URL,
		AuthMethod: "token",
		Token:      "test-token",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	keys, err := p.List(ctx, "secret/")
	if err != nil {
		t.Fatalf("List error: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("key count = %d, want 3", len(keys))
	}
}

func TestVaultProvider_IsHealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := VaultConfig{
		Address:    server.URL,
		AuthMethod: "token",
		Token:      "test-token",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	if !p.IsHealthy(ctx) {
		t.Error("should be healthy")
	}
}

func TestVaultProvider_IsHealthy_Unhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := VaultConfig{
		Address:    server.URL,
		AuthMethod: "token",
		Token:      "test-token",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	if p.IsHealthy(ctx) {
		t.Error("should be unhealthy")
	}
}

func TestVaultProvider_AuthenticateAppRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			resp := map[string]any{
				"auth": map[string]any{
					"client_token":   "returned-token",
					"lease_duration": 3600,
					"renewable":      true,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		if r.Header.Get("X-Vault-Token") != "returned-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		resp := map[string]any{
			"data": map[string]string{"key": "value"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := VaultConfig{
		Address:    server.URL,
		AuthMethod: "approle",
		RoleID:     "role-123",
		SecretID:   "secret-456",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	_, err := p.Get(ctx, "secret/test")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
}

func TestVaultProvider_AuthenticateAppRole_Missing(t *testing.T) {
	config := VaultConfig{
		Address:    "https://vault.example.com",
		AuthMethod: "approle",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	_, err := p.Get(ctx, "secret/test")
	if err == nil {
		t.Error("should error without role_id and secret_id")
	}
}

func TestVaultProvider_AuthenticateKubernetes(t *testing.T) {
	// Mock the readFile function
	originalReadFile := readFile
	defer func() { readFile = originalReadFile }()

	readFile = func(path string) ([]byte, error) {
		return []byte("kubernetes-jwt-token"), nil
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" {
			resp := map[string]any{
				"auth": map[string]any{
					"client_token":   "returned-token",
					"lease_duration": 3600,
					"renewable":      true,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		if r.Header.Get("X-Vault-Token") != "returned-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		resp := map[string]any{
			"data": map[string]string{"key": "value"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := VaultConfig{
		Address:    server.URL,
		AuthMethod: "kubernetes",
		KubeRole:   "my-role",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	_, err := p.Get(ctx, "secret/test")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
}

func TestVaultProvider_UnsupportedAuthMethod(t *testing.T) {
	config := VaultConfig{
		Address:    "https://vault.example.com",
		AuthMethod: "unsupported",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	_, err := p.Get(ctx, "secret/test")
	if err == nil {
		t.Error("should error with unsupported auth method")
	}
}

func TestVaultProvider_WithNamespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Namespace") != "my-namespace" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		resp := map[string]any{
			"data": map[string]string{"key": "value"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := VaultConfig{
		Address:    server.URL,
		AuthMethod: "token",
		Token:      "test-token",
		Namespace:  "my-namespace",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	_, err := p.Get(ctx, "secret/test")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
}

func TestVaultProvider_RevokeToken(t *testing.T) {
	revoked := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/revoke-self" {
			revoked = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}))
	defer server.Close()

	config := VaultConfig{
		Address:    server.URL,
		AuthMethod: "token",
		Token:      "test-token",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	err := p.RevokeToken(ctx)
	if err != nil {
		t.Fatalf("RevokeToken error: %v", err)
	}

	if !revoked {
		t.Error("token should be revoked")
	}
}

func TestVaultProvider_RevokeToken_NoToken(t *testing.T) {
	config := VaultConfig{
		Address:    "https://vault.example.com",
		AuthMethod: "token",
	}

	p, _ := NewVaultProvider(config)

	ctx := context.Background()
	err := p.RevokeToken(ctx)
	if err != nil {
		t.Fatalf("RevokeToken error: %v", err)
	}
}

func TestVaultSecretResponse_UnmarshalJSON(t *testing.T) {
	// Test KV v2 format
	kvV2 := `{"data":{"data":{"key":"value"},"metadata":{"version":1}}}`
	var resp1 vaultSecretResponse
	if err := json.Unmarshal([]byte(kvV2), &resp1); err != nil {
		t.Fatalf("unmarshal KV v2 error: %v", err)
	}
	if resp1.Data.Data["key"] != "value" {
		t.Errorf("KV v2 data = %v, want key:value", resp1.Data.Data)
	}

	// Test KV v1 format
	kvV1 := `{"data":{"username":"admin","password":"secret"}}`
	var resp2 vaultSecretResponse
	if err := json.Unmarshal([]byte(kvV1), &resp2); err != nil {
		t.Fatalf("unmarshal KV v1 error: %v", err)
	}
	if resp2.Data.Raw["username"] != "admin" {
		t.Errorf("KV v1 data = %v, want username:admin", resp2.Data.Raw)
	}
}
