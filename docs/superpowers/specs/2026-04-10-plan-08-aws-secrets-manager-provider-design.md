# AWS Secrets Manager Provider — Design

**Date:** 2026-04-10
**Status:** Design (pre-implementation)
**Parent spec:** `docs/superpowers/specs/2026-04-07-external-secrets-design.md` (Section 2)

## Purpose

Add an `aws-sm://` secret provider to the secrets subsystem. This is the third provider (after keyring and vault) and the first cloud provider. It follows the established patterns from keyring and vault exactly — same interface, same concurrency model, same error mapping, same integration points.

## Scope

**In scope:**
- `internal/proxy/secrets/awssm/` package (config, provider, tests)
- Wire into `internal/session/secretsconfig.go` (constructor, YAML decoder)
- Wire into `internal/policy/secrets.go` (`knownProviderTypes`)
- AWS SDK for Go v2 dependency (`github.com/aws/aws-sdk-go-v2`)

**Out of scope:**
- Assume-role / cross-account STS. Ambient credentials only.
- Auth chaining (no `Dependencies()` override).
- Lease renewal or secret rotation mid-session.
- AWS Secrets Manager resource policies or tags.
- The AWS SigV4 service plugin (that's a separate plan for `internal/proxy/services/aws/`).

## Auth

Ambient only — the standard AWS SDK default credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. Shared credentials file (`~/.aws/credentials`)
3. IRSA (EKS pod identity)
4. ECS task role
5. EC2 instance profile

No explicit credentials in config. No auth chaining. If the host has valid AWS credentials, the provider works. If not, the constructor fails.

## Config

```go
// internal/proxy/secrets/awssm/config.go
type Config struct {
    secrets.ProviderConfigMarker
    Region string // required, e.g. "us-east-1"
}

func (Config) TypeName() string { return "aws-sm" }
// Dependencies() inherited from marker — returns nil
```

Policy YAML:

```yaml
providers:
  aws_sm:
    type: aws-sm
    region: us-east-1
```

The YAML decoder in `secretsconfig.go` reads the `region` field. No other fields.

## URI Mapping

```
aws-sm://my-secret              -> SecretRef{Scheme:"aws-sm", Host:"my-secret", Path:"", Field:""}
aws-sm://my-secret#password     -> SecretRef{Scheme:"aws-sm", Host:"my-secret", Path:"", Field:"password"}
aws-sm://path/to/secret         -> SecretRef{Scheme:"aws-sm", Host:"path", Path:"to/secret", Field:""}
aws-sm://path/to/secret#field   -> SecretRef{Scheme:"aws-sm", Host:"path", Path:"to/secret", Field:"field"}
```

The provider reconstructs the AWS `SecretId` by joining `ref.Host` and `ref.Path` with `/`. If `ref.Path` is empty, `SecretId` is just `ref.Host`. This follows the existing URI grammar — `ParseRef` already handles the `aws-sm` scheme.

## Provider

```go
// internal/proxy/secrets/awssm/provider.go

// smClient is the subset of the AWS Secrets Manager API that the
// provider uses. The real client satisfies it; tests inject a mock.
type smClient interface {
    GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput,
        opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type Provider struct {
    mu     sync.RWMutex
    closed atomic.Bool
    client smClient
}
```

### Constructor

```go
func New(ctx context.Context, cfg Config, _ secrets.RefResolver) (*Provider, error)
```

1. Validate: `cfg.Region` must be non-empty.
2. Load AWS config: `config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))`.
3. Create client: `secretsmanager.NewFromConfig(awsCfg)`.
4. Probe connectivity: call `GetSecretValue` with a known-nonexistent secret ID (`"agentsh-probe-nonexistent"`). Expect `ResourceNotFoundException` — that proves auth and connectivity work. Any other error (e.g., `InvalidSignatureException`, network error) fails the constructor.

The probe approach mirrors keyring's availability probe. AWS SM has no lightweight "ping" API, so a GetSecretValue that returns NotFound is the cheapest way to verify that credentials are valid and the endpoint is reachable.

### Fetch

Same concurrency pattern as keyring/vault: lock-free `closed.Load()` → ctx check → RLock → re-check closed → validate ref → call AWS → map errors → return.

**Ref validation:**
- `ref.Scheme` must be `"aws-sm"`.
- `ref.Host` must be non-empty (it is the secret name or the first path segment).

**SecretId construction:** `ref.Host` if `ref.Path == ""`, else `ref.Host + "/" + ref.Path`.

**AWS call:** `client.GetSecretValue(ctx, &GetSecretValueInput{SecretId: &secretId})`.

**Value extraction:**
- If `output.SecretString != nil`: use `*output.SecretString`.
- Else if `output.SecretBinary != nil`: use `output.SecretBinary`.
- Else: return `ErrNotFound` (deleted or pending secret with no value).

**Field extraction** (when `ref.Field != ""`):
- Parse the value as JSON into `map[string]interface{}`.
- Look up `ref.Field` in the map. Missing key → `ErrNotFound`.
- Convert the field value to `[]byte` (string directly, anything else via `json.Marshal`).

**Field auto-resolve** (when `ref.Field == ""`):
- If the value is valid JSON object with exactly one key, return that key's value.
- Otherwise return the raw value as-is. This differs slightly from Vault's behavior (which errors on multi-key maps without a field). For AWS SM, plain string secrets are the common case, so returning the raw value is the right default.

**Version:** `output.VersionId` (may be nil → empty string).

**Error mapping:**
- `ResourceNotFoundException` → `secrets.ErrNotFound`
- `AccessDeniedException` → `secrets.ErrUnauthorized`
- `InvalidRequestException` → `secrets.ErrInvalidURI` (bad secret ID format)
- All others: wrap as transport error.

AWS SDK v2 errors are typed via `smithy.APIError`, checked with `errors.As`.

### Close

1. Set `closed` flag.
2. Acquire write lock (waits for in-flight Fetches).
3. Nil the client.

No explicit cleanup needed — the SDK HTTP client pool is garbage-collected.

### Test seams

Same `testFetchPreLockHook` / `testFetchPostRLockHook` / `testClosePreLockHook` pattern as keyring, for deterministic concurrency testing.

## Testing Strategy

### Unit tests (`awssm/provider_test.go`)

The AWS SDK v2 supports interface-based mocking. Define a narrow interface covering `GetSecretValue` and inject a mock in tests:

```go
type smClient interface {
    GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput,
        opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}
```

The Provider struct stores `smClient` (not `*secretsmanager.Client`). The constructor assigns the real client; tests inject mocks.

**Test cases:**
- Fetch with string secret → returns value
- Fetch with binary secret → returns value
- Fetch with JSON secret + field → extracts field
- Fetch with JSON secret, single key, no field → auto-resolves
- Fetch with plain string, no field → returns raw
- Fetch wrong scheme → `ErrInvalidURI`
- Fetch empty host → `ErrInvalidURI`
- Fetch not found → `ErrNotFound`
- Fetch access denied → `ErrUnauthorized`
- Fetch after close → error
- Close idempotent
- Contract test via `secretstest.ProviderContract`
- Concurrency: close-while-fetch-in-flight (using test hooks)

### Integration test (`awssm/integration_test.go`)

Build-tagged `//go:build integration`. Requires real AWS credentials and a test secret. Runs the contract test + a round-trip fetch against a real secret. Skipped in CI unless credentials are present.

## Integration Points

### `internal/session/secretsconfig.go`

1. Add import: `"github.com/agentsh/agentsh/internal/proxy/secrets/awssm"`
2. `decodeProviderConfig`: add `case "aws-sm"` that decodes `region` into `awssm.Config`.
3. `DefaultConstructors`: add `"aws-sm"` entry that type-asserts `awssm.Config` and calls `awssm.New`.

### `internal/policy/secrets.go`

1. Add `"aws-sm": true` to `knownProviderTypes`.

### `go.mod`

1. `go get github.com/aws/aws-sdk-go-v2/config`
2. `go get github.com/aws/aws-sdk-go-v2/service/secretsmanager`

These pull in the AWS SDK v2 core as transitive dependencies.

## File Layout

```
internal/proxy/secrets/awssm/
    config.go           Config struct, TypeName(), compile-time assertions
    provider.go         Provider struct, New(), Fetch(), Close(), error mapping
    provider_test.go    Unit tests with mock client
    integration_test.go Build-tagged integration test
    doc.go              Package doc comment
```

## Policy YAML Example

```yaml
providers:
  keyring:
    type: keyring
  aws_sm:
    type: aws-sm
    region: us-east-1

services:
  - name: github
    match:
      hosts: ["api.github.com"]
    secret:
      ref: aws-sm://prod/github-token#token
    fake:
      format: "ghp_{rand:36}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"
```
