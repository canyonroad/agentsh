package azurekv

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/secrets/secretstest"
)

type mockKVClient struct {
	GetSecretFunc func(ctx context.Context, name string, version string,
		options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

func (m *mockKVClient) GetSecret(ctx context.Context, name string, version string,
	options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	return m.GetSecretFunc(ctx, name, version, options)
}

func ptr(s string) *string { return &s }

type azID = azsecrets.ID

func mockAzureError(statusCode int, errorCode string) error {
	return &azcore.ResponseError{
		StatusCode: statusCode,
		ErrorCode:  errorCode,
	}
}

func TestName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "azure-kv" {
		t.Errorf("Name() = %q, want %q", got, "azure-kv")
	}
}

func TestFetch_WrongScheme(t *testing.T) {
	p := newFromClient(&mockKVClient{})
	ref := secrets.SecretRef{Scheme: "vault", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch wrong scheme = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_EmptyHost(t *testing.T) {
	p := newFromClient(&mockKVClient{})
	ref := secrets.SecretRef{Scheme: "azure-kv", Host: ""}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch empty host = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_PathRejected(t *testing.T) {
	p := newFromClient(&mockKVClient{})
	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret", Path: "nested/path"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch with path = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_ContextCanceled(t *testing.T) {
	p := newFromClient(&mockKVClient{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
	_, err := p.Fetch(ctx, ref)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Fetch with canceled ctx = %v, want context.Canceled", err)
	}
}

func TestFetch_StringSecret(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, name string, version string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			if name != "my-secret" {
				t.Errorf("name = %q, want %q", name, "my-secret")
			}
			if version != "" {
				t.Errorf("version = %q, want empty (latest)", version)
			}
			id := azID("https://myvault.vault.azure.net/secrets/my-secret/abc123")
			return azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value: ptr("hunter2"),
					ID:    &id,
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "hunter2" {
		t.Errorf("Value = %q, want %q", sv.Value, "hunter2")
	}
	if sv.Version != "abc123" {
		t.Errorf("Version = %q, want %q", sv.Version, "abc123")
	}
	if sv.FetchedAt.IsZero() {
		t.Error("FetchedAt not set")
	}
}

func TestFetch_NilValue(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{Value: nil},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch with nil value = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_NilID(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value: ptr("val"),
					ID:    nil,
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if sv.Version != "" {
		t.Errorf("Version = %q, want empty", sv.Version)
	}
}

func TestFetch_JSONFieldExtraction(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value: ptr(`{"token":"ghp_abc123","endpoint":"https://api.github.com"}`),
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret", Field: "token"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "ghp_abc123" {
		t.Errorf("Value = %q, want %q", sv.Value, "ghp_abc123")
	}
}

func TestFetch_JSONFieldNotFound(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value: ptr(`{"token":"ghp_abc123"}`),
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret", Field: "missing"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch missing field = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_FieldOnNonJSON(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value: ptr("plain-string-not-json"),
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret", Field: "key"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch field on non-JSON = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_AutoResolveSingleKeyJSON(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value: ptr(`{"token":"ghp_abc123"}`),
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "ghp_abc123" {
		t.Errorf("Value = %q, want %q", sv.Value, "ghp_abc123")
	}
}

func TestFetch_PlainStringNoField(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value: ptr("just-a-token"),
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "just-a-token" {
		t.Errorf("Value = %q, want %q", sv.Value, "just-a-token")
	}
}

func TestFetch_MultiKeyJSONNoField(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{
					Value: ptr(`{"user":"admin","pass":"secret"}`),
				},
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != `{"user":"admin","pass":"secret"}` {
		t.Errorf("Value = %q, want raw JSON", sv.Value)
	}
}

func TestFetch_NotFound(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{}, mockAzureError(http.StatusNotFound, "SecretNotFound")
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "missing"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch not found = %v, want wrapping ErrNotFound", err)
	}
}

func TestMapAzureError_AuthCodes(t *testing.T) {
	authCases := []struct {
		statusCode int
		errorCode  string
		name       string
	}{
		{http.StatusUnauthorized, "Unauthorized", "401_Unauthorized"},
		{http.StatusForbidden, "Forbidden", "403_Forbidden"},
	}

	for _, tc := range authCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockKVClient{
				GetSecretFunc: func(_ context.Context, _ string, _ string,
					_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
					return azsecrets.GetSecretResponse{}, mockAzureError(tc.statusCode, tc.errorCode)
				},
			}
			p := newFromClient(mock)

			ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
			_, err := p.Fetch(context.Background(), ref)
			if !errors.Is(err, secrets.ErrUnauthorized) {
				t.Errorf("Fetch with %s = %v, want wrapping ErrUnauthorized", tc.name, err)
			}
		})
	}
}

func TestFetch_GenericAzureError(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{}, mockAzureError(http.StatusServiceUnavailable, "ServiceUnavailable")
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for Azure 503")
	}
	if errors.Is(err, secrets.ErrNotFound) || errors.Is(err, secrets.ErrUnauthorized) {
		t.Errorf("ServiceUnavailable should be generic, got sentinel: %v", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	p := newFromClient(&mockKVClient{})
	if err := p.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestFetch_AfterClose(t *testing.T) {
	p := newFromClient(&mockKVClient{})
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch after Close returned nil error")
	}
}

func TestFetch_ClosedBetweenLoadAndRLock(t *testing.T) {
	p := newFromClient(&mockKVClient{})

	hookRan := false
	t.Cleanup(func() { testFetchPreLockHook = nil })
	testFetchPreLockHook = func() {
		hookRan = true
		if err := p.Close(); err != nil {
			t.Errorf("hook Close: %v", err)
		}
	}

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)

	if !hookRan {
		t.Fatal("testFetchPreLockHook never fired")
	}
	if err == nil {
		t.Fatal("Fetch succeeded despite Close between Load and RLock")
	}
}

func TestProvider_CloseWaitsForInFlightFetch(t *testing.T) {
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{
				Secret: azsecrets.Secret{Value: ptr("val")},
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

	ref := secrets.SecretRef{Scheme: "azure-kv", Host: "my-secret"}

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
	mock := &mockKVClient{
		GetSecretFunc: func(_ context.Context, _ string, _ string,
			_ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{}, mockAzureError(http.StatusNotFound, "SecretNotFound")
		},
	}
	p := newFromClient(mock)

	probeRef := secrets.SecretRef{
		Scheme: "azure-kv",
		Host:   "contract-probe-nonexistent",
	}
	secretstest.ProviderContract(t, "azure-kv", p, probeRef)
}
