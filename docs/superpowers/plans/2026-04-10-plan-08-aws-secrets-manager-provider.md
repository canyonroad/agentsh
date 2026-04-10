# Plan 8: AWS Secrets Manager Provider — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `aws-sm://` secret provider backed by AWS Secrets Manager, following the established keyring/vault provider patterns.

**Architecture:** New `internal/proxy/secrets/awssm/` package with Config, Provider (implementing `secrets.SecretProvider`), and a mockable `smClient` interface for testing. Wired into the existing resolver (`secretsconfig.go`) and policy validator (`policy/secrets.go`). Uses AWS SDK for Go v2 with ambient credentials and explicit region.

**Tech Stack:** Go 1.25, AWS SDK for Go v2 (`github.com/aws/aws-sdk-go-v2`), existing `internal/proxy/secrets` interfaces

**Spec:** `docs/superpowers/specs/2026-04-10-plan-08-aws-secrets-manager-provider-design.md`

---

## File Structure

### New files

| File | Responsibility |
|------|---------------|
| `internal/proxy/secrets/awssm/doc.go` | Package doc comment |
| `internal/proxy/secrets/awssm/config.go` | Config struct, TypeName(), compile-time assertions |
| `internal/proxy/secrets/awssm/provider.go` | smClient interface, Provider struct, New(), Fetch(), Close(), error mapping, test seams |
| `internal/proxy/secrets/awssm/provider_test.go` | All unit tests (mock-based) |

### Modified files

| File | Change |
|------|--------|
| `internal/policy/secrets.go:59-61` | Add `"aws-sm": true` to `knownProviderTypes` |
| `internal/session/secretsconfig.go:9-11` | Add `awssm` import |
| `internal/session/secretsconfig.go:103-120` | Add `"aws-sm"` entry to `DefaultConstructors` |
| `internal/session/secretsconfig.go:124-139` | Add `case "aws-sm"` to `decodeProviderConfig` + YAML struct |
| `internal/session/secretsconfig_test.go` | Add `TestResolveProviderConfigs_AWSSM` |
| `internal/policy/secrets_test.go` | Add `TestValidateSecrets_AWSProvider` |

---

### Task 1: Add AWS SDK Dependency + Config + Doc

**Files:**
- Create: `internal/proxy/secrets/awssm/doc.go`
- Create: `internal/proxy/secrets/awssm/config.go`
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add AWS SDK dependencies**

```bash
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/service/secretsmanager
```

- [ ] **Step 2: Create doc.go**

```go
// Package awssm implements secrets.SecretProvider using AWS Secrets
// Manager. It wraps github.com/aws/aws-sdk-go-v2/service/secretsmanager.
//
// AWS SM URIs take the form
//
//	aws-sm://<name-or-prefix>[/<path>][#<field>]
//
// where <name-or-prefix> is the first segment of the secret name
// (the URI host), <path> is the rest of the name joined with "/",
// and the optional <field> selects one key from a JSON-valued
// secret.
//
// Auth uses the standard AWS SDK default credential chain: env vars,
// shared credentials file, IRSA, ECS task role, or EC2 instance
// profile. No explicit credentials in config.
package awssm
```

- [ ] **Step 3: Create config.go**

```go
package awssm

import (
	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Config configures the AWS Secrets Manager provider.
//
// Config satisfies secrets.ProviderConfig by embedding
// secrets.ProviderConfigMarker.
type Config struct {
	secrets.ProviderConfigMarker

	// Region is the AWS region to use (e.g. "us-east-1"). Required.
	Region string
}

// TypeName returns "aws-sm". Used by the registry to map aws-sm://
// URI scheme refs to this provider.
func (Config) TypeName() string { return "aws-sm" }

// Compile-time assertions.
var (
	_ secrets.ProviderConfig = Config{}
	_ secrets.SecretProvider = (*Provider)(nil)
)
```

Note: the `Provider` type does not exist yet — this file will not compile until Task 2 creates `provider.go`. That is fine; build this task in one commit with Task 2.

- [ ] **Step 4: Verify build compiles (expect failure)**

```bash
go build ./internal/proxy/secrets/awssm/...
```

Expected: build fails because `Provider` is not defined yet. This is expected — we commit config.go together with provider.go in Task 2.

---

### Task 2: Provider Core — smClient, New, Fetch, Close, Error Mapping

**Files:**
- Create: `internal/proxy/secrets/awssm/provider.go`

- [ ] **Step 1: Write provider.go**

```go
package awssm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// smClient is the subset of the AWS Secrets Manager API that the
// provider uses. The real *secretsmanager.Client satisfies it;
// tests inject a mock.
type smClient interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput,
		opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Provider is an AWS Secrets Manager-backed secrets.SecretProvider.
//
// Provider is safe for concurrent Fetch and Close. Close waits for
// any in-flight Fetch to finish before returning, so the contract
// "after Close returns, Fetch returns an error" holds even under
// concurrent access.
//
// Concurrency design mirrors keyring.Provider and vault.Provider:
//   - closed is an atomic flag checked lock-free on the Fetch fast
//     path.
//   - mu is an RWMutex held for read by Fetch for its entire duration
//     (including the AWS HTTP call) and for write by Close. The
//     write lock ensures Close waits for any in-flight Fetch to
//     finish before returning.
type Provider struct {
	mu     sync.RWMutex
	closed atomic.Bool
	client smClient
}

// probeSecretID is the sentinel secret name used by New to verify
// that AWS credentials are valid and the endpoint is reachable. A
// GetSecretValue that returns ResourceNotFoundException proves auth
// and connectivity work. Any other error means credentials are
// invalid or the endpoint is unreachable.
const probeSecretID = "agentsh-probe-nonexistent"

// testFetchPreLockHook is a test-only seam invoked (when non-nil)
// between Fetch's fast-path closed check and its RLock acquisition.
var testFetchPreLockHook func()

// testFetchPostRLockHook is a test-only seam invoked (when non-nil)
// immediately after Fetch has acquired its RLock and re-verified closed.
var testFetchPostRLockHook func()

// testClosePreLockHook is a test-only seam invoked (when non-nil)
// after Close has stored the closed flag and before it acquires
// the exclusive Lock.
var testClosePreLockHook func()

// New constructs an AWS Secrets Manager provider.
//
// Steps:
//  1. Validate the config (region required).
//  2. Load default AWS config with the specified region.
//  3. Create the Secrets Manager client.
//  4. Probe connectivity via GetSecretValue of a nonexistent secret.
func New(ctx context.Context, cfg Config, _ secrets.RefResolver) (*Provider, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("aws-sm: region is required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("aws-sm: loading AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(awsCfg)

	// Probe connectivity: a ResourceNotFoundException proves auth
	// and endpoint work. Any other error fails construction.
	_, probeErr := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(probeSecretID),
	})
	if probeErr != nil {
		var rnf *types.ResourceNotFoundException
		if !errors.As(probeErr, &rnf) {
			return nil, fmt.Errorf("aws-sm: connectivity probe failed: %w", probeErr)
		}
		// ResourceNotFoundException is success — backend is reachable.
	}

	return &Provider{client: client}, nil
}

// newFromClient constructs a Provider with an injected smClient.
// Used by tests to bypass AWS SDK initialization.
func newFromClient(client smClient) *Provider {
	return &Provider{client: client}
}

// Name returns "aws-sm". Used in audit events.
func (p *Provider) Name() string { return "aws-sm" }

// Fetch retrieves a secret from AWS Secrets Manager.
//
// The SecretRef must have:
//   - Scheme == "aws-sm"
//   - Host    (the secret name or first path segment)
//   - Path    (optional additional path segments, joined with "/")
//   - Field   (optional) selects one key from a JSON-valued secret
//
// If Field is empty and the value is a JSON object with exactly one
// key, the single value is auto-resolved. If the value is not JSON
// or has multiple keys, it is returned as-is (plain string).
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("aws-sm: provider closed")
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	if ref.Scheme != "aws-sm" {
		return secrets.SecretValue{}, fmt.Errorf("%w: wrong scheme %q", secrets.ErrInvalidURI, ref.Scheme)
	}
	if ref.Host == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: aws-sm URI missing secret name (host)", secrets.ErrInvalidURI)
	}

	if hook := testFetchPreLockHook; hook != nil {
		hook()
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("aws-sm: provider closed")
	}

	if hook := testFetchPostRLockHook; hook != nil {
		hook()
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	// Build SecretId from host + path.
	secretID := ref.Host
	if ref.Path != "" {
		secretID = ref.Host + "/" + ref.Path
	}

	output, err := p.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		return secrets.SecretValue{}, mapAWSError(err)
	}

	// Extract raw value: prefer SecretString, fall back to SecretBinary.
	var raw []byte
	if output.SecretString != nil {
		raw = []byte(*output.SecretString)
	} else if output.SecretBinary != nil {
		raw = output.SecretBinary
	} else {
		return secrets.SecretValue{}, fmt.Errorf("%w: secret has no value", secrets.ErrNotFound)
	}

	// Field extraction.
	value, err := extractField(raw, ref.Field)
	if err != nil {
		return secrets.SecretValue{}, err
	}

	var version string
	if output.VersionId != nil {
		version = *output.VersionId
	}

	return secrets.SecretValue{
		Value:     value,
		Version:   version,
		FetchedAt: time.Now(),
	}, nil
}

// Close marks the provider as closed. Safe to call concurrently and
// multiple times — subsequent calls are no-ops.
func (p *Provider) Close() error {
	p.closed.Store(true)

	if hook := testClosePreLockHook; hook != nil {
		hook()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.client = nil
	return nil
}

// extractField handles field extraction from the raw secret bytes.
//
// If field is non-empty: parse as JSON, look up key, return value.
// If field is empty and value is a JSON object with exactly one key:
// auto-resolve to that key's value. Otherwise return raw bytes as-is.
func extractField(raw []byte, field string) ([]byte, error) {
	if field != "" {
		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%w: cannot extract field %q: value is not JSON: %s",
				secrets.ErrInvalidURI, field, err)
		}
		v, ok := m[field]
		if !ok {
			return nil, fmt.Errorf("%w: field %q not found in secret", secrets.ErrNotFound, field)
		}
		return toBytes(v), nil
	}

	// No field specified — try auto-resolve for single-key JSON objects.
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err == nil && len(m) == 1 {
		for _, v := range m {
			return toBytes(v), nil
		}
	}

	// Not JSON or multiple keys — return raw.
	return raw, nil
}

// toBytes converts a value to []byte. Strings are converted
// directly; everything else is JSON-marshaled.
func toBytes(v interface{}) []byte {
	if s, ok := v.(string); ok {
		return []byte(s)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(fmt.Sprintf("%v", v))
	}
	return b
}

// mapAWSError translates AWS SDK errors to the appropriate secrets
// sentinel errors.
func mapAWSError(err error) error {
	var rnf *types.ResourceNotFoundException
	if errors.As(err, &rnf) {
		return fmt.Errorf("%w: %s", secrets.ErrNotFound, err.Error())
	}

	var ade *types.AccessDeniedException
	if errors.As(err, &ade) {
		return fmt.Errorf("%w: %s", secrets.ErrUnauthorized, err.Error())
	}

	var ire *types.InvalidRequestException
	if errors.As(err, &ire) {
		return fmt.Errorf("%w: %s", secrets.ErrInvalidURI, err.Error())
	}

	return fmt.Errorf("aws-sm: %w", err)
}
```

- [ ] **Step 2: Verify build compiles**

```bash
go build ./internal/proxy/secrets/awssm/...
```

Expected: PASS (no compilation errors).

- [ ] **Step 3: Commit config + doc + provider**

```bash
git add internal/proxy/secrets/awssm/ go.mod go.sum
git commit -m "feat(secrets): AWS Secrets Manager provider core (Plan 8)

Add internal/proxy/secrets/awssm package with Config, Provider,
smClient interface, New constructor, Fetch, Close, and error
mapping. Uses AWS SDK for Go v2 with ambient credentials."
```

---

### Task 3: Unit Tests — Validation, Mock Fetch, Error Mapping

**Files:**
- Create: `internal/proxy/secrets/awssm/provider_test.go`

- [ ] **Step 1: Write provider_test.go with mock and all unit tests**

```go
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
	// Multi-key JSON without field returns raw bytes.
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

func TestFetch_AccessDenied(t *testing.T) {
	mock := &mockSMClient{
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput,
			_ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, &types.AccessDeniedException{Message: aws.String("forbidden")}
		},
	}
	p := newFromClient(mock)

	ref := secrets.SecretRef{Scheme: "aws-sm", Host: "forbidden-secret"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrUnauthorized) {
		t.Errorf("Fetch access denied = %v, want wrapping ErrUnauthorized", err)
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
```

- [ ] **Step 2: Run tests**

```bash
go test ./internal/proxy/secrets/awssm/... -v -count=1
```

Expected: all PASS.

- [ ] **Step 3: Run race detector**

```bash
go test ./internal/proxy/secrets/awssm/... -race -count=1
```

Expected: PASS with no race conditions detected.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/secrets/awssm/provider_test.go
git commit -m "test(secrets): AWS SM provider unit tests (Plan 8)

Mock-based tests for Fetch (string, binary, JSON field extraction,
auto-resolve, error mapping), Close lifecycle, concurrency (test
hooks for TOCTOU race), and ProviderContract compliance."
```

---

### Task 4: Integration Wiring — Policy Validation + Session Config

**Files:**
- Modify: `internal/policy/secrets.go:59-61`
- Modify: `internal/session/secretsconfig.go:9-11,103-120,124-139`
- Modify: `internal/session/secretsconfig_test.go`

- [ ] **Step 1: Write failing test for policy validation**

Add to `internal/policy/secrets_test.go` (find the existing test file or create it):

First, check if `internal/policy/secrets_test.go` exists. If it does, append this test. If not, create the file with the test.

```go
func TestValidateSecrets_AWSProvider(t *testing.T) {
	providers := map[string]yaml.Node{
		"aws_sm": mustNode(t, "type: aws-sm\nregion: us-east-1"),
	}
	services := []ServiceYAML{
		{
			Name:   "myservice",
			Match:  ServiceMatchYAML{Hosts: []string{"api.example.com"}},
			Secret: ServiceSecretYAML{Ref: "aws-sm://prod/my-secret#token"},
			Fake:   ServiceFakeYAML{Format: "tok_{rand:36}"},
			Inject: ServiceInjectYAML{Header: &ServiceInjectHeaderYAML{
				Name: "Authorization", Template: "Bearer {{secret}}",
			}},
		},
	}
	warnings, err := ValidateSecrets(providers, services)
	if err != nil {
		t.Fatalf("ValidateSecrets error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}
```

Note: the existing test file uses `mustNode(t, yamlStr)` as its YAML helper (defined at `internal/policy/secrets_test.go:10`).

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/policy/... -run TestValidateSecrets_AWSProvider -v
```

Expected: FAIL — `unknown type "aws-sm"`.

- [ ] **Step 3: Add "aws-sm" to knownProviderTypes**

In `internal/policy/secrets.go`, change the `knownProviderTypes` map (lines 59-62):

```go
var knownProviderTypes = map[string]bool{
	"keyring": true,
	"vault":   true,
	"aws-sm":  true,
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/policy/... -run TestValidateSecrets_AWSProvider -v
```

Expected: PASS.

- [ ] **Step 5: Write failing test for secretsconfig resolver**

Add to `internal/session/secretsconfig_test.go`:

```go
func TestResolveProviderConfigs_AWSSM(t *testing.T) {
	providers := map[string]yaml.Node{
		"aws": mustYAMLNode(t, "type: aws-sm\nregion: us-west-2"),
	}
	configs, err := ResolveProviderConfigs(providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	if configs["aws"].TypeName() != "aws-sm" {
		t.Errorf("TypeName = %q, want aws-sm", configs["aws"].TypeName())
	}
	ac, ok := configs["aws"].(awssm.Config)
	if !ok {
		t.Fatalf("expected awssm.Config, got %T", configs["aws"])
	}
	if ac.Region != "us-west-2" {
		t.Errorf("Region = %q, want us-west-2", ac.Region)
	}
}
```

Also add the import `"github.com/agentsh/agentsh/internal/proxy/secrets/awssm"` to the test file's imports.

- [ ] **Step 6: Run test to verify it fails**

```bash
go test ./internal/session/... -run TestResolveProviderConfigs_AWSSM -v
```

Expected: FAIL — `unknown provider type "aws-sm"`.

- [ ] **Step 7: Wire aws-sm into secretsconfig.go**

Add import at `internal/session/secretsconfig.go:10`:

```go
"github.com/agentsh/agentsh/internal/proxy/secrets/awssm"
```

Add to `DefaultConstructors` (after the `"vault"` entry, around line 118):

```go
"aws-sm": func(ctx context.Context, cfg secrets.ProviderConfig, _ secrets.RefResolver) (secrets.SecretProvider, error) {
	ac, ok := cfg.(awssm.Config)
	if !ok {
		return nil, fmt.Errorf("expected awssm.Config, got %T", cfg)
	}
	return awssm.New(ctx, ac, nil)
},
```

Add `case "aws-sm"` to `decodeProviderConfig` (after the `"vault"` case, around line 137):

```go
case "aws-sm":
	return decodeAWSConfig(node)
```

Add the YAML struct and decoder function after `decodeVaultConfig`:

```go
// awssmYAML is the YAML representation of an AWS SM provider config.
type awssmYAML struct {
	Type   string `yaml:"type"`
	Region string `yaml:"region"`
}

func decodeAWSConfig(node yaml.Node) (secrets.ProviderConfig, error) {
	var raw awssmYAML
	if err := node.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode aws-sm config: %w", err)
	}
	return awssm.Config{
		Region: raw.Region,
	}, nil
}
```

- [ ] **Step 8: Run all tests**

```bash
go test ./internal/session/... -v -count=1
go test ./internal/policy/... -v -count=1
go test ./internal/proxy/secrets/awssm/... -v -count=1
```

Expected: all PASS.

- [ ] **Step 9: Verify cross-compilation**

```bash
GOOS=windows go build ./...
GOOS=darwin go build ./...
```

Expected: PASS.

- [ ] **Step 10: Run full test suite**

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 11: Commit**

```bash
git add internal/policy/secrets.go internal/session/secretsconfig.go internal/session/secretsconfig_test.go internal/policy/secrets_test.go
git commit -m "feat(secrets): wire AWS SM provider into policy + session config (Plan 8)

Add aws-sm to knownProviderTypes, YAML decoder, and
DefaultConstructors. Services can now reference aws-sm://
URIs and the resolver builds awssm.Config from policy YAML."
```

---

## Post-Implementation Checks

After all tasks are complete:

```bash
go build ./...
go test ./...
GOOS=windows go build ./...
```

All must pass. The AWS SM provider is then available for use in policy YAML via `type: aws-sm` with a `region` field.
