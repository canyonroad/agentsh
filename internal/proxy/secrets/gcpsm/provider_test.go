package gcpsm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/secrets/secretstest"
)

type mockSMClient struct {
	AccessSecretVersionFunc func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest,
		opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
}

func (m *mockSMClient) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest,
	opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return m.AccessSecretVersionFunc(ctx, req, opts...)
}

func (m *mockSMClient) Close() error { return nil }

func TestName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "gcp-sm" {
		t.Errorf("Name() = %q, want %q", got, "gcp-sm")
	}
}

func TestFetch_WrongScheme(t *testing.T) {
	p := newFromClient(&mockSMClient{}, "test-project")
	ref := secrets.SecretRef{Scheme: "vault", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch wrong scheme = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_EmptyHost(t *testing.T) {
	p := newFromClient(&mockSMClient{}, "test-project")
	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: ""}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch empty host = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_ContextCanceled(t *testing.T) {
	p := newFromClient(&mockSMClient{}, "test-project")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	_, err := p.Fetch(ctx, ref)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Fetch with canceled ctx = %v, want context.Canceled", err)
	}
}

func TestFetch_StringSecret(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			wantName := "projects/test-project/secrets/my-secret/versions/latest"
			if req.Name != wantName {
				t.Errorf("Name = %q, want %q", req.Name, wantName)
			}
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/my-secret/versions/3",
				Payload: &secretmanagerpb.SecretPayload{Data: []byte("hunter2")},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "hunter2" {
		t.Errorf("Value = %q, want %q", sv.Value, "hunter2")
	}
	if sv.Version != "3" {
		t.Errorf("Version = %q, want %q", sv.Version, "3")
	}
	if sv.FetchedAt.IsZero() {
		t.Error("FetchedAt not set")
	}
}

func TestFetch_SecretNameFromHostAndPath(t *testing.T) {
	var gotName string
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			gotName = req.Name
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/path/to/secret/versions/1",
				Payload: &secretmanagerpb.SecretPayload{Data: []byte("val")},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "path", Path: "to/secret"}
	_, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	want := "projects/test-project/secrets/path/to/secret/versions/latest"
	if gotName != want {
		t.Errorf("resource name = %q, want %q", gotName, want)
	}
}

func TestFetch_JSONFieldExtraction(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/my-secret/versions/1",
				Payload: &secretmanagerpb.SecretPayload{Data: []byte(`{"token":"ghp_abc123","endpoint":"https://api.github.com"}`)},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret", Field: "token"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "ghp_abc123" {
		t.Errorf("Value = %q, want %q", sv.Value, "ghp_abc123")
	}
}

func TestFetch_JSONFieldNotFound(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/my-secret/versions/1",
				Payload: &secretmanagerpb.SecretPayload{Data: []byte(`{"token":"ghp_abc123"}`)},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret", Field: "missing"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch missing field = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_FieldOnNonJSON(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/my-secret/versions/1",
				Payload: &secretmanagerpb.SecretPayload{Data: []byte("plain-string-not-json")},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret", Field: "key"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch field on non-JSON = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_AutoResolveSingleKeyJSON(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/my-secret/versions/1",
				Payload: &secretmanagerpb.SecretPayload{Data: []byte(`{"token":"ghp_abc123"}`)},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "ghp_abc123" {
		t.Errorf("Value = %q, want %q", sv.Value, "ghp_abc123")
	}
}

func TestFetch_PlainStringNoField(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/my-secret/versions/1",
				Payload: &secretmanagerpb.SecretPayload{Data: []byte("just-a-token")},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "just-a-token" {
		t.Errorf("Value = %q, want %q", sv.Value, "just-a-token")
	}
}

func TestFetch_MultiKeyJSONNoField(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/my-secret/versions/1",
				Payload: &secretmanagerpb.SecretPayload{Data: []byte(`{"user":"admin","pass":"secret"}`)},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != `{"user":"admin","pass":"secret"}` {
		t.Errorf("Value = %q, want raw JSON", sv.Value)
	}
}

func TestFetch_NilPayload(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name: "projects/test-project/secrets/my-secret/versions/1",
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch with nil payload = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_EmptyPayloadData(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/my-secret/versions/1",
				Payload: &secretmanagerpb.SecretPayload{Data: nil},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch with empty payload data = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_VersionExtraction(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/my-secret/versions/42",
				Payload: &secretmanagerpb.SecretPayload{Data: []byte("val")},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if sv.Version != "42" {
		t.Errorf("Version = %q, want %q", sv.Version, "42")
	}
}

func TestFetch_NotFound(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.NotFound, "Secret [projects/test-project/secrets/missing/versions/latest] not found")
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "missing"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch not found = %v, want wrapping ErrNotFound", err)
	}
}

func TestMapGCPError_AuthCodes(t *testing.T) {
	authCodes := []struct {
		code codes.Code
		name string
	}{
		{codes.PermissionDenied, "PermissionDenied"},
		{codes.Unauthenticated, "Unauthenticated"},
	}

	for _, tc := range authCodes {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockSMClient{
				AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
					_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
					return nil, status.Error(tc.code, "auth error: "+tc.name)
				},
			}
			p := newFromClient(mock, "test-project")

			ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
			_, err := p.Fetch(context.Background(), ref)
			if !errors.Is(err, secrets.ErrUnauthorized) {
				t.Errorf("Fetch with %s = %v, want wrapping ErrUnauthorized", tc.name, err)
			}
		})
	}
}

func TestFetch_InvalidArgument(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "bad argument")
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch with InvalidArgument returned nil error")
	}
	if errors.Is(err, secrets.ErrInvalidURI) {
		t.Error("InvalidArgument should NOT map to ErrInvalidURI")
	}
	if errors.Is(err, secrets.ErrNotFound) {
		t.Error("InvalidArgument should NOT map to ErrNotFound")
	}
	if errors.Is(err, secrets.ErrUnauthorized) {
		t.Error("InvalidArgument should NOT map to ErrUnauthorized")
	}
}

func TestFetch_GenericGRPCError(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.Unavailable, "service unavailable")
		},
	}
	p := newFromClient(mock, "test-project")

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for gRPC Unavailable")
	}
	if errors.Is(err, secrets.ErrNotFound) || errors.Is(err, secrets.ErrUnauthorized) {
		t.Errorf("Unavailable should be generic, got sentinel: %v", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	p := newFromClient(&mockSMClient{}, "test-project")
	if err := p.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestFetch_AfterClose(t *testing.T) {
	p := newFromClient(&mockSMClient{}, "test-project")
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch after Close returned nil error")
	}
}

func TestFetch_ClosedBetweenLoadAndRLock(t *testing.T) {
	p := newFromClient(&mockSMClient{}, "test-project")

	hookRan := false
	t.Cleanup(func() { testFetchPreLockHook = nil })
	testFetchPreLockHook = func() {
		hookRan = true
		if err := p.Close(); err != nil {
			t.Errorf("hook Close: %v", err)
		}
	}

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)

	if !hookRan {
		t.Fatal("testFetchPreLockHook never fired")
	}
	if err == nil {
		t.Fatal("Fetch succeeded despite Close between Load and RLock")
	}
}

func TestProvider_CloseWaitsForInFlightFetch(t *testing.T) {
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    "projects/test-project/secrets/my-secret/versions/1",
				Payload: &secretmanagerpb.SecretPayload{Data: []byte("val")},
			}, nil
		},
	}
	p := newFromClient(mock, "test-project")

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

	ref := secrets.SecretRef{Scheme: "gcp-sm", Host: "my-secret"}

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
	mock := &mockSMClient{
		AccessSecretVersionFunc: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest,
			_ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
	}
	p := newFromClient(mock, "test-project")

	probeRef := secrets.SecretRef{
		Scheme: "gcp-sm",
		Host:   "contract-probe-nonexistent",
	}
	secretstest.ProviderContract(t, "gcp-sm", p, probeRef)
}
