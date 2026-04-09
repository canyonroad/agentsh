package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

func TestConfig_TypeName(t *testing.T) {
	c := Config{}
	if got := c.TypeName(); got != "vault" {
		t.Errorf("TypeName() = %q, want 'vault'", got)
	}
}

func TestConfig_Dependencies_TokenLiteral(t *testing.T) {
	c := Config{Auth: AuthConfig{Method: "token", Token: "literal"}}
	if deps := c.Dependencies(); len(deps) != 0 {
		t.Errorf("Dependencies() = %v, want empty", deps)
	}
}

func TestConfig_Dependencies_TokenRef(t *testing.T) {
	tokenRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-token"}
	c := Config{Auth: AuthConfig{Method: "token", TokenRef: &tokenRef}}
	deps := c.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("Dependencies() length = %d, want 1", len(deps))
	}
	if deps[0].Scheme != tokenRef.Scheme || deps[0].Host != tokenRef.Host || deps[0].Path != tokenRef.Path {
		t.Errorf("Dependencies()[0] = {%s, %s, %s}, want {%s, %s, %s}",
			deps[0].Scheme, deps[0].Host, deps[0].Path,
			tokenRef.Scheme, tokenRef.Host, tokenRef.Path)
	}
}

func TestConfig_Dependencies_AppRole(t *testing.T) {
	roleRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-role"}
	secretRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-secret"}

	c := Config{
		Auth: AuthConfig{
			Method:      "approle",
			RoleIDRef:   &roleRef,
			SecretIDRef: &secretRef,
		},
	}
	deps := c.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("Dependencies() length = %d, want 2", len(deps))
	}
}

func TestConfig_Dependencies_AppRoleIgnoresTokenRef(t *testing.T) {
	// TokenRef should be ignored for approle method.
	tokenRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-token"}
	roleRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-role"}

	c := Config{
		Auth: AuthConfig{
			Method:    "approle",
			RoleIDRef: &roleRef,
			TokenRef:  &tokenRef, // irrelevant for approle
		},
	}
	deps := c.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("Dependencies() length = %d, want 1 (only RoleIDRef)", len(deps))
	}
}

func TestConfig_Dependencies_Kubernetes(t *testing.T) {
	// Kubernetes uses a service account token file, no chained refs.
	c := Config{Auth: AuthConfig{Method: "kubernetes", KubeRole: "my-role"}}
	if deps := c.Dependencies(); len(deps) != 0 {
		t.Errorf("Dependencies() = %v, want empty", deps)
	}
}

func TestConfig_Dependencies_LiteralOverridesRef(t *testing.T) {
	// When both literal and ref are set, the ref is not declared as a
	// dependency. The constructor will reject the config later.
	tokenRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-token"}
	c := Config{
		Auth: AuthConfig{
			Method:   "token",
			Token:    "literal-value",
			TokenRef: &tokenRef,
		},
	}
	if deps := c.Dependencies(); len(deps) != 0 {
		t.Errorf("Dependencies() = %v, want empty when literal is set", deps)
	}
}

// ---------------------------------------------------------------------------
// Mock Vault server
// ---------------------------------------------------------------------------

// mockVaultServer returns an httptest.Server that simulates a minimal
// Vault HTTP API sufficient for the Provider tests.
func mockVaultServer(t *testing.T, expectedToken string, kvData map[string]map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify token on all KV/lookup calls.
		gotToken := r.Header.Get("X-Vault-Token")

		switch {
		// Token lookup-self
		case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/token/lookup-self":
			if gotToken != expectedToken {
				writeVaultError(w, http.StatusForbidden, "permission denied")
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{
					"id":       expectedToken,
					"policies": []string{"default"},
				},
			})

		// Token revoke-self
		case r.Method == http.MethodPut && r.URL.Path == "/v1/auth/token/revoke-self":
			w.WriteHeader(http.StatusNoContent)

		// AppRole login
		case r.Method == http.MethodPut && r.URL.Path == "/v1/auth/approle/login":
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": expectedToken,
					"policies":     []string{"default"},
				},
			})

		// Kubernetes login
		case r.Method == http.MethodPut && r.URL.Path == "/v1/auth/kubernetes/login":
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": expectedToken,
					"policies":     []string{"default"},
				},
			})

		// KV v2 read: /v1/{mount}/data/{path}
		default:
			if gotToken != expectedToken {
				writeVaultError(w, http.StatusForbidden, "permission denied")
				return
			}
			// Parse mount and path from the URL.
			// URL pattern: /v1/{mount}/data/{path...}
			parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/v1/"), "/data/", 2)
			if len(parts) != 2 {
				writeVaultError(w, http.StatusNotFound, "no handler for route")
				return
			}
			secretPath := parts[1]
			secretData, ok := kvData[secretPath]
			if !ok {
				writeVaultError(w, http.StatusNotFound, "secret not found")
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"data": map[string]interface{}{
					"data": secretData,
					"metadata": map[string]interface{}{
						"version": 3,
					},
				},
				"lease_duration": 0,
				"lease_id":       "",
			})
		}
	}))
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeVaultError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"errors": []string{msg},
	})
}

// noopResolver is a RefResolver that always returns an error.
// Used for configs with no chained refs.
func noopResolver(_ context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	return secrets.SecretValue{}, fmt.Errorf("noopResolver: unexpected resolve call for %s://%s/%s#%s",
		ref.Scheme, ref.Host, ref.Path, ref.Field)
}

// ---------------------------------------------------------------------------
// Provider constructor tests
// ---------------------------------------------------------------------------

func TestNew_TokenAuth_HappyPath(t *testing.T) {
	srv := mockVaultServer(t, "test-token", nil)
	defer srv.Close()

	cfg := Config{
		Address: srv.URL,
		Auth: AuthConfig{
			Method: "token",
			Token:  "test-token",
		},
	}

	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer p.Close()

	if p.Name() != "vault" {
		t.Errorf("Name() = %q, want 'vault'", p.Name())
	}
	if p.ownedToken {
		t.Error("ownedToken should be false for token auth")
	}
}

// ---------------------------------------------------------------------------
// Fetch tests
// ---------------------------------------------------------------------------

func TestFetch_KVv2_WithField(t *testing.T) {
	kvData := map[string]map[string]interface{}{
		"github": {"token": "ghp_secret123", "user": "bot"},
	}
	srv := mockVaultServer(t, "test-token", kvData)
	defer srv.Close()

	p := newTestProvider(t, srv.URL, "test-token")
	defer p.Close()

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "github", Field: "token"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	defer sv.Zero()

	if got := string(sv.Value); got != "ghp_secret123" {
		t.Errorf("Fetch() value = %q, want 'ghp_secret123'", got)
	}
	if sv.Version != "3" {
		t.Errorf("Fetch() version = %q, want '3'", sv.Version)
	}
	if sv.FetchedAt.IsZero() {
		t.Error("Fetch() FetchedAt is zero")
	}
}

func TestFetch_KVv2_SingleFieldAutoResolve(t *testing.T) {
	kvData := map[string]map[string]interface{}{
		"api-key": {"value": "sk-secret"},
	}
	srv := mockVaultServer(t, "test-token", kvData)
	defer srv.Close()

	p := newTestProvider(t, srv.URL, "test-token")
	defer p.Close()

	// No field specified; single field should auto-resolve.
	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "api-key"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	defer sv.Zero()

	if got := string(sv.Value); got != "sk-secret" {
		t.Errorf("Fetch() value = %q, want 'sk-secret'", got)
	}
}

func TestFetch_KVv2_MultiFieldNoFragment_Error(t *testing.T) {
	kvData := map[string]map[string]interface{}{
		"multi": {"a": "1", "b": "2"},
	}
	srv := mockVaultServer(t, "test-token", kvData)
	defer srv.Close()

	p := newTestProvider(t, srv.URL, "test-token")
	defer p.Close()

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "multi"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch() expected error for multi-field without #field")
	}
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch() error = %v, want ErrInvalidURI", err)
	}
}

func TestFetch_KVv2_MissingField(t *testing.T) {
	kvData := map[string]map[string]interface{}{
		"github": {"token": "ghp_secret123"},
	}
	srv := mockVaultServer(t, "test-token", kvData)
	defer srv.Close()

	p := newTestProvider(t, srv.URL, "test-token")
	defer p.Close()

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "github", Field: "nonexistent"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch() expected error for missing field")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch() error = %v, want ErrNotFound", err)
	}
}

func TestFetch_SecretNotFound(t *testing.T) {
	// No data in the server for this path.
	srv := mockVaultServer(t, "test-token", nil)
	defer srv.Close()

	p := newTestProvider(t, srv.URL, "test-token")
	defer p.Close()

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "does-not-exist", Field: "key"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch() expected error for missing secret")
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch() error = %v, want ErrNotFound", err)
	}
}

func TestFetch_DataPrefixStripped(t *testing.T) {
	kvData := map[string]map[string]interface{}{
		"github": {"token": "ghp_secret123"},
	}
	srv := mockVaultServer(t, "test-token", kvData)
	defer srv.Close()

	p := newTestProvider(t, srv.URL, "test-token")
	defer p.Close()

	// Path "data/github" should be stripped to "github" for the KV v2 call.
	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "data/github", Field: "token"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch() with data/ prefix error = %v", err)
	}
	if got := string(sv.Value); got != "ghp_secret123" {
		t.Errorf("Fetch() value = %q, want 'ghp_secret123'", got)
	}
}

func TestFetch_WrongScheme(t *testing.T) {
	p := &Provider{} // zero-value, no client needed
	ref := secrets.SecretRef{Scheme: "keyring", Host: "svc", Path: "acct"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch() expected error for wrong scheme")
	}
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch() error = %v, want ErrInvalidURI", err)
	}
}

func TestFetch_MissingHost(t *testing.T) {
	p := &Provider{} // zero-value, no client needed
	ref := secrets.SecretRef{Scheme: "vault", Host: "", Path: "secret"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch() expected error for missing host")
	}
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch() error = %v, want ErrInvalidURI", err)
	}
}

func TestFetch_MissingPath(t *testing.T) {
	p := &Provider{} // zero-value, no client needed
	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: ""}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch() expected error for missing path")
	}
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch() error = %v, want ErrInvalidURI", err)
	}
}

func TestFetch_ContextCanceled(t *testing.T) {
	p := &Provider{} // zero-value; ctx check happens before client access
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "secret"}
	_, err := p.Fetch(ctx, ref)
	if err == nil {
		t.Fatal("Fetch() expected error for canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Fetch() error = %v, want context.Canceled", err)
	}
}

func TestFetch_AfterClose(t *testing.T) {
	srv := mockVaultServer(t, "test-token", nil)
	defer srv.Close()

	p := newTestProvider(t, srv.URL, "test-token")
	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "secret", Field: "key"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch() expected error after Close")
	}
}

func TestClose_Idempotent(t *testing.T) {
	srv := mockVaultServer(t, "test-token", nil)
	defer srv.Close()

	p := newTestProvider(t, srv.URL, "test-token")

	if err := p.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// Auth error mapping tests (HTTP 400 → ErrUnauthorized)
// ---------------------------------------------------------------------------

func TestNew_TokenAuth_LookupSelf_400(t *testing.T) {
	// Server returns 400 on lookup-self to simulate an invalid token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			writeVaultError(w, http.StatusBadRequest, "missing client token")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := Config{
		Address: srv.URL,
		Auth:    AuthConfig{Method: "token", Token: "bad-token"},
	}
	_, err := New(context.Background(), cfg, noopResolver)
	if err == nil {
		t.Fatal("expected error for 400 lookup-self")
	}
	if !errors.Is(err, secrets.ErrUnauthorized) {
		t.Errorf("error = %v, want ErrUnauthorized", err)
	}
}

func TestNew_AppRoleAuth_400(t *testing.T) {
	// Server returns 400 on approle login (bad role_id/secret_id).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			writeVaultError(w, http.StatusBadRequest, "invalid role or secret ID")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := Config{
		Address: srv.URL,
		Auth: AuthConfig{
			Method:   "approle",
			RoleID:   "bad-role",
			SecretID: "bad-secret",
		},
	}
	_, err := New(context.Background(), cfg, noopResolver)
	if err == nil {
		t.Fatal("expected error for 400 approle login")
	}
	if !errors.Is(err, secrets.ErrUnauthorized) {
		t.Errorf("error = %v, want ErrUnauthorized", err)
	}
}

func TestNew_KubernetesAuth_400(t *testing.T) {
	// Server returns 400 on kubernetes login (bad JWT).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" {
			writeVaultError(w, http.StatusBadRequest, "invalid JWT")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Create a temp file for the service account token.
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("fake-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Address: srv.URL,
		Auth: AuthConfig{
			Method:        "kubernetes",
			KubeRole:      "my-role",
			KubeTokenPath: tokenFile,
		},
	}
	_, err := New(context.Background(), cfg, noopResolver)
	if err == nil {
		t.Fatal("expected error for 400 kubernetes login")
	}
	if !errors.Is(err, secrets.ErrUnauthorized) {
		t.Errorf("error = %v, want ErrUnauthorized", err)
	}
}

// ---------------------------------------------------------------------------
// Validation tests
// ---------------------------------------------------------------------------

func TestValidateConfig_MissingAddress(t *testing.T) {
	cfg := Config{Auth: AuthConfig{Method: "token", Token: "t"}}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error for missing address")
	}
}

func TestValidateConfig_MissingMethod(t *testing.T) {
	cfg := Config{Address: "http://vault:8200"}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error for missing auth method")
	}
}

func TestValidateConfig_TokenBothLiteralAndRef(t *testing.T) {
	ref := secrets.SecretRef{Scheme: "keyring", Host: "svc", Path: "token"}
	cfg := Config{
		Address: "http://vault:8200",
		Auth:    AuthConfig{Method: "token", Token: "lit", TokenRef: &ref},
	}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error for both token and token_ref")
	}
}

func TestValidateConfig_TokenNeitherLiteralNorRef(t *testing.T) {
	cfg := Config{
		Address: "http://vault:8200",
		Auth:    AuthConfig{Method: "token"},
	}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected error for missing token and token_ref")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestProvider creates a Provider connected to the mock server.
func newTestProvider(t *testing.T, addr, token string) *Provider {
	t.Helper()
	cfg := Config{
		Address: addr,
		Auth: AuthConfig{
			Method: "token",
			Token:  token,
		},
	}
	p, err := New(context.Background(), cfg, noopResolver)
	if err != nil {
		t.Fatalf("newTestProvider: New() error = %v", err)
	}
	return p
}
