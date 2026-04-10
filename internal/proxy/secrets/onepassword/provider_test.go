package onepassword

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/secrets/secretstest"
)

type mockOPClient struct {
	GetItemByTitleFunc   func(title string, vaultUUID string) (mockItem, error)
	GetVaultsByTitleFunc func(title string) ([]mockVault, error)
}

func (m *mockOPClient) GetItemByTitle(title string, vaultUUID string) (mockItem, error) {
	return m.GetItemByTitleFunc(title, vaultUUID)
}

func (m *mockOPClient) GetVaultsByTitle(title string) ([]mockVault, error) {
	return m.GetVaultsByTitleFunc(title)
}

type mockHTTPError struct {
	statusCode int
	message    string
}

func (e *mockHTTPError) Error() string      { return e.message }
func (e *mockHTTPError) GetStatusCode() int { return e.statusCode }

func TestName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "op" {
		t.Errorf("Name() = %q, want %q", got, "op")
	}
}

func TestConfig_Dependencies_WithRef(t *testing.T) {
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "op_key"}
	cfg := Config{
		ServerURL: "https://op.internal",
		APIKeyRef: &ref,
	}
	deps := cfg.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("Dependencies() returned %d, want 1", len(deps))
	}
	if deps[0].Scheme != "keyring" {
		t.Errorf("dep scheme = %q, want keyring", deps[0].Scheme)
	}
}

func TestConfig_Dependencies_WithLiteral(t *testing.T) {
	cfg := Config{
		ServerURL: "https://op.internal",
		APIKey:    "literal-key",
	}
	deps := cfg.Dependencies()
	if len(deps) != 0 {
		t.Errorf("Dependencies() returned %d, want 0", len(deps))
	}
}

func TestConfig_Dependencies_BothSet(t *testing.T) {
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "op_key"}
	cfg := Config{
		ServerURL: "https://op.internal",
		APIKey:    "literal-key",
		APIKeyRef: &ref,
	}
	deps := cfg.Dependencies()
	if len(deps) != 0 {
		t.Errorf("Dependencies() returned %d, want 0 (both set is ambiguous)", len(deps))
	}
}

func TestFetch_WrongScheme(t *testing.T) {
	p := newFromClient(nil)
	ref := secrets.SecretRef{Scheme: "vault", Host: "Personal", Path: "my-item"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch wrong scheme = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_EmptyHost(t *testing.T) {
	p := newFromClient(nil)
	ref := secrets.SecretRef{Scheme: "op", Host: "", Path: "my-item"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch empty host = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_EmptyPath(t *testing.T) {
	p := newFromClient(nil)
	ref := secrets.SecretRef{Scheme: "op", Host: "Personal"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch empty path = %v, want wrapping ErrInvalidURI (item title required)", err)
	}
}

func TestFetch_ContextCanceled(t *testing.T) {
	p := newFromClient(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "my-item"}
	_, err := p.Fetch(ctx, ref)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Fetch with canceled ctx = %v, want context.Canceled", err)
	}
}

func TestFetch_SingleField(t *testing.T) {
	mock := &mockOPClient{
		GetVaultsByTitleFunc: func(title string) ([]mockVault, error) {
			if title != "Personal" {
				t.Errorf("vault title = %q, want %q", title, "Personal")
			}
			return []mockVault{{ID: "vault-uuid-1", Name: "Personal"}}, nil
		},
		GetItemByTitleFunc: func(title string, vaultUUID string) (mockItem, error) {
			if title != "github-token" {
				t.Errorf("item title = %q, want %q", title, "github-token")
			}
			if vaultUUID != "vault-uuid-1" {
				t.Errorf("vault UUID = %q, want %q", vaultUUID, "vault-uuid-1")
			}
			return mockItem{
				Fields: []mockItemField{
					{Label: "token", Value: "ghp_abc123"},
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "github-token", Field: "token"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "ghp_abc123" {
		t.Errorf("Value = %q, want %q", sv.Value, "ghp_abc123")
	}
	if sv.Version != "" {
		t.Errorf("Version = %q, want empty (1Password has no version IDs)", sv.Version)
	}
	if sv.FetchedAt.IsZero() {
		t.Error("FetchedAt not set")
	}
}

func TestFetch_FieldNotFound(t *testing.T) {
	mock := &mockOPClient{
		GetVaultsByTitleFunc: func(_ string) ([]mockVault, error) {
			return []mockVault{{ID: "vault-uuid-1", Name: "Personal"}}, nil
		},
		GetItemByTitleFunc: func(_ string, _ string) (mockItem, error) {
			return mockItem{
				Fields: []mockItemField{
					{Label: "token", Value: "ghp_abc123"},
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "github-token", Field: "missing"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch missing field = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_AutoResolveSingleField(t *testing.T) {
	mock := &mockOPClient{
		GetVaultsByTitleFunc: func(_ string) ([]mockVault, error) {
			return []mockVault{{ID: "vault-uuid-1", Name: "Personal"}}, nil
		},
		GetItemByTitleFunc: func(_ string, _ string) (mockItem, error) {
			return mockItem{
				Fields: []mockItemField{
					{Label: "password", Value: "secret123"},
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "my-item"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "secret123" {
		t.Errorf("Value = %q, want %q", sv.Value, "secret123")
	}
}

func TestFetch_MultiFieldNoFieldSpecified(t *testing.T) {
	mock := &mockOPClient{
		GetVaultsByTitleFunc: func(_ string) ([]mockVault, error) {
			return []mockVault{{ID: "vault-uuid-1", Name: "Personal"}}, nil
		},
		GetItemByTitleFunc: func(_ string, _ string) (mockItem, error) {
			return mockItem{
				Fields: []mockItemField{
					{Label: "username", Value: "admin"},
					{Label: "password", Value: "secret123"},
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "my-item"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if len(sv.Value) == 0 {
		t.Error("expected non-empty value for multi-field item")
	}
}

func TestFetch_VaultNotFound(t *testing.T) {
	mock := &mockOPClient{
		GetVaultsByTitleFunc: func(_ string) ([]mockVault, error) {
			return nil, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "op", Host: "Nonexistent", Path: "my-item"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch vault not found = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_ItemNotFound(t *testing.T) {
	mock := &mockOPClient{
		GetVaultsByTitleFunc: func(_ string) ([]mockVault, error) {
			return []mockVault{{ID: "vault-uuid-1", Name: "Personal"}}, nil
		},
		GetItemByTitleFunc: func(_ string, _ string) (mockItem, error) {
			return mockItem{}, &mockHTTPError{statusCode: 404, message: "item not found"}
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "missing-item"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch item not found = %v, want wrapping ErrNotFound", err)
	}
}

func TestMapOPError_AuthCodes(t *testing.T) {
	authCases := []struct {
		statusCode int
		name       string
	}{
		{401, "Unauthorized"},
		{403, "Forbidden"},
	}

	for _, tc := range authCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockOPClient{
				GetVaultsByTitleFunc: func(_ string) ([]mockVault, error) {
					return nil, &mockHTTPError{statusCode: tc.statusCode, message: "auth error: " + tc.name}
				},
			}
			p := newFromClient(mock)

			ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "my-item"}
			_, err := p.Fetch(context.Background(), ref)
			if !errors.Is(err, secrets.ErrUnauthorized) {
				t.Errorf("Fetch with %s = %v, want wrapping ErrUnauthorized", tc.name, err)
			}
		})
	}
}

func TestFetch_GenericOPError(t *testing.T) {
	mock := &mockOPClient{
		GetVaultsByTitleFunc: func(_ string) ([]mockVault, error) {
			return nil, &mockHTTPError{statusCode: 500, message: "internal server error"}
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "my-item"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for 1Password 500")
	}
	if errors.Is(err, secrets.ErrNotFound) || errors.Is(err, secrets.ErrUnauthorized) {
		t.Errorf("500 should be generic, got sentinel: %v", err)
	}
}

func TestFetch_NoFields(t *testing.T) {
	mock := &mockOPClient{
		GetVaultsByTitleFunc: func(_ string) ([]mockVault, error) {
			return []mockVault{{ID: "vault-uuid-1", Name: "Personal"}}, nil
		},
		GetItemByTitleFunc: func(_ string, _ string) (mockItem, error) {
			return mockItem{Fields: nil}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "empty-item"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch with no fields = %v, want wrapping ErrNotFound", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	p := newFromClient(&mockOPClient{})
	if err := p.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestFetch_AfterClose(t *testing.T) {
	p := newFromClient(&mockOPClient{})
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "my-item"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch after Close returned nil error")
	}
}

func TestFetch_ClosedBetweenLoadAndRLock(t *testing.T) {
	p := newFromClient(&mockOPClient{})

	hookRan := false
	t.Cleanup(func() { testFetchPreLockHook = nil })
	testFetchPreLockHook = func() {
		hookRan = true
		if err := p.Close(); err != nil {
			t.Errorf("hook Close: %v", err)
		}
	}

	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "my-item"}
	_, err := p.Fetch(context.Background(), ref)

	if !hookRan {
		t.Fatal("testFetchPreLockHook never fired")
	}
	if err == nil {
		t.Fatal("Fetch succeeded despite Close between Load and RLock")
	}
}

func TestProvider_CloseWaitsForInFlightFetch(t *testing.T) {
	mock := &mockOPClient{
		GetVaultsByTitleFunc: func(_ string) ([]mockVault, error) {
			return []mockVault{{ID: "vault-uuid-1", Name: "Personal"}}, nil
		},
		GetItemByTitleFunc: func(_ string, _ string) (mockItem, error) {
			return mockItem{
				Fields: []mockItemField{{Label: "token", Value: "val"}},
			}, nil
		},
	}
	p := newFromClient(mock)

	inFlight := make(chan struct{})
	release := make(chan struct{})
	var fetchHookOnce sync.Once
	var releaseOnce sync.Once
	releaseHook := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseHook)

	t.Cleanup(func() { testFetchPostRLockHook = nil })
	testFetchPostRLockHook = func() {
		fetchHookOnce.Do(func() {
			close(inFlight)
			<-release
		})
	}

	closeAtLock := make(chan struct{})
	t.Cleanup(func() { testClosePreLockHook = nil })
	testClosePreLockHook = func() { close(closeAtLock) }

	ref := secrets.SecretRef{Scheme: "op", Host: "Personal", Path: "my-item"}

	fetchDone := make(chan struct{})
	go func() {
		defer close(fetchDone)
		_, _ = p.Fetch(context.Background(), ref)
	}()

	<-inFlight

	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		_ = p.Close()
	}()

	<-closeAtLock

	select {
	case <-closeDone:
		t.Fatal("Close returned while an in-flight Fetch still held the read lock")
	default:
	}

	releaseHook()

	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the in-flight Fetch was released")
	}
	<-fetchDone

	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Error("post-Close Fetch should return error")
	}
}

func TestProviderContract(t *testing.T) {
	mock := &mockOPClient{
		GetVaultsByTitleFunc: func(_ string) ([]mockVault, error) {
			return nil, nil
		},
		GetItemByTitleFunc: func(_ string, _ string) (mockItem, error) {
			return mockItem{}, &mockHTTPError{statusCode: 404, message: "not found"}
		},
	}
	p := newFromClient(mock)

	probeRef := secrets.SecretRef{
		Scheme: "op",
		Host:   "contract-probe-nonexistent",
		Path:   "contract-probe-nonexistent",
	}
	secretstest.ProviderContract(t, "op", p, probeRef)
}
