package awssm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	smithy "github.com/aws/smithy-go"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/secrets/secretstest"
)

// mockSMClient implements smClient for testing.
type mockSMClient struct {
	GetSecretValueFunc func(ctx context.Context, input *secretsmanager.GetSecretValueInput,
		opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func (m *mockSMClient) GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput,
	opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.GetSecretValueFunc(ctx, input, opts...)
}

// mockAPIError implements smithy.APIError for testing auth error code mapping.
type mockAPIError struct {
	code    string
	message string
}

func (e *mockAPIError) Error() string                 { return e.message }
func (e *mockAPIError) ErrorCode() string              { return e.code }
func (e *mockAPIError) ErrorMessage() string           { return e.message }
func (e *mockAPIError) ErrorFault() smithy.ErrorFault  { return smithy.FaultServer }

func TestName(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "aws-sm" {
		t.Errorf("Name() = %q, want %q", got, "aws-sm")
	}
}

func TestFetch_WrongScheme(t *testing.T) {
	p := newFromClient(&mockSMClient{})
	ref := secrets.SecretRef{Scheme: "vault", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch wrong scheme = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_EmptyHost(t *testing.T) {
	p := newFromClient(&mockSMClient{})
	ref := secrets.SecretRef{Scheme: "aws-sm", Host: ""}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch empty host = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_ContextCanceled(t *testing.T) {
	p := newFromClient(&mockSMClient{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}
	_, err := p.Fetch(ctx, ref)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Fetch with canceled ctx = %v, want context.Canceled", err)
	}
}

func TestFetch_StringSecret(t *testing.T) {
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, input *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			if *input.SecretId != "my-secret" {
				t.Errorf("SecretId = %q, want %q", *input.SecretId, "my-secret")
			}
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("hunter2"),
				VersionId:    aws.String("v1"),
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != "hunter2" {
		t.Errorf("Value = %q, want %q", sv.Value, "hunter2")
	}
	if sv.Version != "v1" {
		t.Errorf("Version = %q, want %q", sv.Version, "v1")
	}
	if sv.FetchedAt.IsZero() {
		t.Error("FetchedAt not set")
	}
}

func TestFetch_BinarySecret(t *testing.T) {
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretBinary: want,
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "bin-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != string(want) {
		t.Errorf("Value = %x, want %x", sv.Value, want)
	}
}

func TestFetch_SecretIdFromHostAndPath(t *testing.T) {
	var gotID string
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, input *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			gotID = *input.SecretId
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("val"),
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "prod", Path: "github-token"}
	_, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if gotID != "prod/github-token" {
		t.Errorf("SecretId = %q, want %q", gotID, "prod/github-token")
	}
}

func TestFetch_JSONFieldExtraction(t *testing.T) {
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{"token":"ghp_abc123","endpoint":"https://api.github.com"}`),
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret", Field: "token"}
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
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{"token":"ghp_abc123"}`),
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret", Field: "missing"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch missing field = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_FieldOnNonJSON(t *testing.T) {
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("plain-string-not-json"),
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret", Field: "key"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch field on non-JSON = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_AutoResolveSingleKeyJSON(t *testing.T) {
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{"token":"ghp_abc123"}`),
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}
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
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("just-a-token"),
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}
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
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{"user":"admin","pass":"secret"}`),
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if string(sv.Value) != `{"user":"admin","pass":"secret"}` {
		t.Errorf("Value = %q, want raw JSON", sv.Value)
	}
}

func TestFetch_NoValue(t *testing.T) {
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch with no value = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_NilVersionId(t *testing.T) {
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("val"),
				VersionId:    nil,
			}, nil
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if sv.Version != "" {
		t.Errorf("Version = %q, want empty", sv.Version)
	}
}

func TestFetch_ResourceNotFound(t *testing.T) {
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, &types.ResourceNotFoundException{Message: aws.String("not found")}
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "missing"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch not found = %v, want wrapping ErrNotFound", err)
	}
}

// TestMapAWSError_AuthCodes verifies that all five auth-related AWS error codes
// are mapped to secrets.ErrUnauthorized via the smithy.APIError interface.
func TestMapAWSError_AuthCodes(t *testing.T) {
	authCodes := []string{
		"AccessDeniedException",
		"UnrecognizedClientException",
		"InvalidSignatureException",
		"ExpiredTokenException",
		"IncompleteSignature",
	}

	for _, code := range authCodes {
		code := code
		t.Run(code, func(t *testing.T) {
			mock := &mockSMClient{
				GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
					_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
					return nil, &mockAPIError{code: code, message: "auth error: " + code}
				},
			}
			p := newFromClient(mock)

			ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}
			_, err := p.Fetch(context.Background(), ref)
			if !errors.Is(err, secrets.ErrUnauthorized) {
				t.Errorf("Fetch with %s = %v, want wrapping ErrUnauthorized", code, err)
			}
		})
	}
}

func TestFetch_InvalidRequest(t *testing.T) {
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, &types.InvalidRequestException{Message: aws.String("bad id")}
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "bad"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch invalid request = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	p := newFromClient(&mockSMClient{})
	if err := p.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestFetch_AfterClose(t *testing.T) {
	p := newFromClient(&mockSMClient{})
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch after Close returned nil error")
	}
}

func TestFetch_ClosedBetweenLoadAndRLock(t *testing.T) {
	p := newFromClient(&mockSMClient{})

	hookRan := false
	t.Cleanup(func() { testFetchPreLockHook = nil })
	testFetchPreLockHook = func() {
		hookRan = true
		if err := p.Close(); err != nil {
			t.Errorf("hook Close: %v", err)
		}
	}

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}
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
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("val"),
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

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "my-secret"}

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
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, &types.ResourceNotFoundException{Message: aws.String("not found")}
		},
	}
	p := newFromClient(mock)

	probeRef := secrets.SecretRef{
		Scheme: "aws-sm",
		Host:   "contract-probe-nonexistent",
	}
	secretstest.ProviderContract(t, "aws-sm", p, probeRef)
}
