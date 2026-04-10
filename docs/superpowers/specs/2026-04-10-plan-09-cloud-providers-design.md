# Cloud & SaaS Secret Providers — Design

**Date:** 2026-04-10
**Status:** Design (pre-implementation)
**Parent spec:** `docs/superpowers/specs/2026-04-07-external-secrets-design.md` (Section 2)

## Purpose

Add GCP Secret Manager (`gcp-sm://`), Azure Key Vault (`azure-kv://`), and 1Password Connect (`op://`) providers to the secrets subsystem. These are the remaining Tier 1 providers from the main spec. All three follow the patterns established by keyring (Plan 3), Vault (Plan 4), and AWS SM (Plan 8).

## Scope

**In scope:**
- `internal/proxy/secrets/gcpsm/` package (config, provider, tests)
- `internal/proxy/secrets/azurekv/` package (config, provider, tests)
- `internal/proxy/secrets/onepassword/` package (config, provider, tests)
- Wire all three into `internal/session/secretsconfig.go` and `internal/policy/secrets.go`
- SDK dependencies: GCP Secret Manager, Azure Key Vault, 1Password Connect SDK

**Out of scope:**
- 1Password CLI backend (`op` binary) — deferred to a future plan
- Explicit credential fields for GCP/Azure (service account JSON, client ID/secret) — ambient only
- Lease renewal or secret rotation mid-session
- Cross-account or cross-tenant access

## Provider 1: GCP Secret Manager (`gcp-sm://`)

### Auth

Ambient only — Google Application Default Credentials (ADC):

1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable (service account JSON)
2. gcloud CLI default credentials (`~/.config/gcloud/application_default_credentials.json`)
3. GCE metadata service (Compute Engine, GKE, Cloud Run)
4. Workload Identity Federation

No explicit credentials in config. If the host has valid ADC, the provider works. If not, the constructor fails.

### Config

```go
// internal/proxy/secrets/gcpsm/config.go
type Config struct {
    secrets.ProviderConfigMarker
    ProjectID string // required, e.g. "my-gcp-project-123"
}

func (Config) TypeName() string { return "gcp-sm" }
// Dependencies() inherited from marker — returns nil
```

Policy YAML:

```yaml
providers:
  gcp_sm:
    type: gcp-sm
    project_id: my-gcp-project-123
```

### URI Mapping

```
gcp-sm://my-secret              -> SecretRef{Scheme:"gcp-sm", Host:"my-secret", Path:"", Field:""}
gcp-sm://my-secret#password     -> SecretRef{Scheme:"gcp-sm", Host:"my-secret", Path:"", Field:"password"}
gcp-sm://path/to/secret         -> SecretRef{Scheme:"gcp-sm", Host:"path", Path:"to/secret", Field:""}
gcp-sm://path/to/secret#field   -> SecretRef{Scheme:"gcp-sm", Host:"path", Path:"to/secret", Field:"field"}
```

The provider reconstructs the GCP secret name by joining `ref.Host` and `ref.Path` with `/`. The full resource name is built as `projects/<project_id>/secrets/<name>/versions/latest`.

### SDK

```
cloud.google.com/go/secretmanager/apiv1
cloud.google.com/go/secretmanager/apiv1/secretmanagerpb
```

The provider defines a narrow `smClient` interface covering `AccessSecretVersion` for mock-based testing:

```go
type smClient interface {
    AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest,
        opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
    Close() error
}
```

### Constructor

```go
func New(ctx context.Context, cfg Config, _ secrets.RefResolver) (*Provider, error)
```

1. Validate: `cfg.ProjectID` must be non-empty.
2. Create client: `secretmanager.NewClient(ctx)` (uses ADC).
3. Probe connectivity: `AccessSecretVersion` on a nonexistent secret (`projects/<id>/secrets/agentsh-probe-nonexistent/versions/latest`). Auth errors are fatal (`ErrUnauthorized`). Context errors are fatal. NotFound is success (proves auth works). Other errors are non-fatal (endpoint may not be reachable but ADC may still be valid).

### Fetch

Same flow as AWS SM:
- Validate scheme (`gcp-sm`) and host (non-empty)
- Build resource name: `projects/<project_id>/secrets/<name>/versions/latest`
- Call `AccessSecretVersion`
- Extract `response.Payload.Data` as raw bytes
- Apply field extraction (same JSON logic as AWS SM)
- Version: extract from `response.Name` (contains the version number)

### Error Mapping

- `codes.NotFound` (gRPC) -> `secrets.ErrNotFound`
- `codes.PermissionDenied`, `codes.Unauthenticated` -> `secrets.ErrUnauthorized`
- `codes.InvalidArgument` -> generic error (not `ErrInvalidURI` — same reasoning as AWS SM roborev fix)
- All others: wrap as transport error

GCP SDK uses gRPC status codes. Check with `status.Code(err)` from `google.golang.org/grpc/status`.

### Field Extraction

Same as AWS SM: JSON field lookup if `ref.Field` is set, single-key auto-resolve if no field and value is single-key JSON object, raw bytes otherwise.

---

## Provider 2: Azure Key Vault (`azure-kv://`)

### Auth

Ambient only — Azure `DefaultAzureCredential`:

1. Environment variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`)
2. Managed Identity (MI) on Azure VMs, AKS, App Service, Azure Functions
3. Azure CLI credentials (`az login`)
4. Azure Developer CLI (`azd`)

No explicit credentials in config.

### Config

```go
// internal/proxy/secrets/azurekv/config.go
type Config struct {
    secrets.ProviderConfigMarker
    VaultURL string // required, e.g. "https://myvault.vault.azure.net/"
}

func (Config) TypeName() string { return "azure-kv" }
// Dependencies() inherited from marker — returns nil
```

Policy YAML:

```yaml
providers:
  azure_kv:
    type: azure-kv
    vault_url: https://myvault.vault.azure.net/
```

### URI Mapping

```
azure-kv://my-secret              -> SecretRef{Scheme:"azure-kv", Host:"my-secret", Path:"", Field:""}
azure-kv://my-secret#password     -> SecretRef{Scheme:"azure-kv", Host:"my-secret", Path:"", Field:"password"}
azure-kv://path/to/secret         -> SecretRef{Scheme:"azure-kv", Host:"path", Path:"to/secret", Field:""}
azure-kv://path/to/secret#field   -> SecretRef{Scheme:"azure-kv", Host:"path", Path:"to/secret", Field:"field"}
```

The provider uses `ref.Host` as the secret name. Azure Key Vault secret names allow only alphanumerics and hyphens — forward slashes are not valid. If `ref.Path` is non-empty, Fetch returns `ErrInvalidURI` with a clear error message. The host-only form (`azure-kv://my-secret`) is the only valid form for the secret name.

### SDK

```
github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets
github.com/Azure/azure-sdk-for-go/sdk/azidentity
```

The provider defines a narrow `kvClient` interface covering `GetSecret` for mock-based testing:

```go
type kvClient interface {
    GetSecret(ctx context.Context, name string, version string,
        options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}
```

### Constructor

```go
func New(ctx context.Context, cfg Config, _ secrets.RefResolver) (*Provider, error)
```

1. Validate: `cfg.VaultURL` must be non-empty.
2. Create credential: `azidentity.NewDefaultAzureCredential(nil)`.
3. Create client: `azsecrets.NewClient(cfg.VaultURL, cred, nil)`.
4. Probe connectivity: `GetSecret` on a nonexistent secret (`agentsh-probe-nonexistent`, version `""`). Auth errors are fatal. Context errors are fatal. NotFound is success. Other errors are non-fatal.

### Fetch

- Validate scheme (`azure-kv`) and host (non-empty)
- Reject if `ref.Path` is non-empty (`ErrInvalidURI` — Azure KV names don't support `/`)
- Call `GetSecret(ctx, ref.Host, "", nil)` (empty version = latest)
- Extract `response.Value` (string pointer) as raw bytes
- Apply field extraction (same JSON logic)
- Version: extract from `response.ID` (the secret identifier URL contains the version)

### Error Mapping

Azure SDK uses `*azcore.ResponseError` with `StatusCode` and `ErrorCode` fields:

- HTTP 404 / ErrorCode `SecretNotFound` -> `secrets.ErrNotFound`
- HTTP 401, 403 / ErrorCode `Forbidden`, `Unauthorized` -> `secrets.ErrUnauthorized`
- All others: wrap as transport error

Check with `errors.As(err, &respErr)` where `respErr` is `*azcore.ResponseError`.

### Field Extraction

Same as AWS SM and GCP SM. Azure secrets are plain strings but may contain JSON — same extraction logic applies.

---

## Provider 3: 1Password Connect (`op://`)

### Auth

Connect API key — either literal or chained from another provider:

- `api_key`: literal API key string in config
- `api_key_ref`: URI reference to another provider (e.g. `keyring://agentsh/op_connect_key`)

At least one must be set. If both are set, the constructor rejects as ambiguous. If `api_key_ref` is set, `Dependencies()` returns it for topological resolution.

### Config

```go
// internal/proxy/secrets/onepassword/config.go
type Config struct {
    secrets.ProviderConfigMarker
    ServerURL string             // required, e.g. "https://onepass-connect.internal"
    APIKey    string             // literal API key (mutually exclusive with APIKeyRef)
    APIKeyRef *secrets.SecretRef // chained ref (mutually exclusive with APIKey)
}

func (Config) TypeName() string { return "op" }

func (c Config) Dependencies() []secrets.SecretRef {
    if c.APIKeyRef != nil && c.APIKey == "" {
        return []secrets.SecretRef{*c.APIKeyRef}
    }
    return nil
}
```

Policy YAML:

```yaml
providers:
  keyring:
    type: keyring
  onepassword:
    type: op
    server_url: https://onepass-connect.internal
    api_key_ref: keyring://agentsh/op_connect_key
```

Or with a literal key:

```yaml
providers:
  onepassword:
    type: op
    server_url: https://onepass-connect.internal
    api_key: "eyJhbGciOiJFUz..."
```

### URI Mapping

1Password URIs use the `op://vault/item[#field]` format:

```
op://Personal/github-token          -> SecretRef{Scheme:"op", Host:"Personal", Path:"github-token", Field:""}
op://Personal/github-token#token    -> SecretRef{Scheme:"op", Host:"Personal", Path:"github-token", Field:"token"}
op://Work/Stripe/api-key            -> SecretRef{Scheme:"op", Host:"Work", Path:"Stripe/api-key", Field:""}
```

- Host = vault name
- Path = item title (or `item/section` for nested items)
- Field = field label within the item

### SDK

```
github.com/1password/connect-sdk-go
```

The provider defines a narrow `opClient` interface for mock-based testing:

```go
type opClient interface {
    GetItem(itemTitle string, vaultUUID string) (*onepassword.Item, error)
    GetVaultsByTitle(title string) ([]onepassword.Vault, error)
}
```

Alternatively, if the SDK's interface is not easily mockable, the provider can define its own HTTP client wrapper against the Connect REST API (`GET /v1/vaults`, `GET /v1/vaults/{id}/items`).

### Constructor

```go
func New(ctx context.Context, cfg Config, resolver secrets.RefResolver) (*Provider, error)
```

1. Validate: `cfg.ServerURL` must be non-empty. Exactly one of `cfg.APIKey` or `cfg.APIKeyRef` must be set.
2. Resolve API key: if `cfg.APIKeyRef` is set, call `resolver.Fetch(ctx, *cfg.APIKeyRef)` to get the key.
3. Create client: `connect.NewClientWithUserAgent(cfg.ServerURL, apiKey, "agentsh")`.
4. Probe connectivity: `GET /health` or `GetVaultsByTitle("")` — any lightweight call that proves auth + endpoint work. Auth errors are fatal. Context errors are fatal. Other errors are non-fatal.

### Fetch

- Validate scheme (`op`) and host (non-empty — vault name required)
- Validate path (non-empty — item title required)
- Resolve vault: look up vault by title (`ref.Host`) to get vault UUID
- Resolve item: look up item by title (`ref.Path` first segment) in vault
- Extract value:
  - If `ref.Field` is set: find the field by label in the item's fields list, return its value
  - If no field and item has exactly one field: auto-resolve to that field's value
  - If no field and multiple fields: return the full item as JSON
- Version: empty (1Password Connect doesn't expose version IDs)

### Error Mapping

The 1Password Connect SDK returns HTTP errors. Map based on status code:

- 404 (vault or item not found) -> `secrets.ErrNotFound`
- 401, 403 (bad API key, insufficient permissions) -> `secrets.ErrUnauthorized`
- All others: wrap as transport error

### Field Extraction

Different from GCP/Azure/AWS SM — 1Password items have structured fields (label + value pairs), not raw JSON blobs. Field extraction works on the item's field list, not by JSON-parsing a string value:

```go
for _, f := range item.Fields {
    if f.Label == ref.Field {
        return []byte(f.Value), nil
    }
}
return nil, fmt.Errorf("%w: field %q not found in item", secrets.ErrNotFound, ref.Field)
```

---

## Integration Wiring (Shared)

### `internal/policy/secrets.go`

Add to `knownProviderTypes`:

```go
var knownProviderTypes = map[string]bool{
    "keyring":  true,
    "vault":    true,
    "aws-sm":   true,
    "gcp-sm":   true,
    "azure-kv": true,
    "op":       true,
}
```

### `internal/session/secretsconfig.go`

1. Add imports for all three packages.
2. Add `"gcp-sm"`, `"azure-kv"`, `"op"` entries to `DefaultConstructors`.
3. Add `case "gcp-sm"`, `case "azure-kv"`, `case "op"` to `decodeProviderConfig`.
4. Add YAML structs and decoder functions for each.

### `internal/proxy/secrets/uri.go`

Already supports all three schemes — no changes needed.

## Testing Strategy

Each provider gets the same test suite shape as AWS SM:
- Mock client interface for all SDK calls
- Test seams (`testFetchPreLockHook`, `testFetchPostRLockHook`, `testClosePreLockHook`)
- Validation tests (wrong scheme, empty host, context canceled)
- Happy path tests (string secret, field extraction, auto-resolve, multi-field raw)
- Error mapping tests (not found, unauthorized, generic)
- Close lifecycle (idempotent, fetch-after-close, close-while-fetch-in-flight)
- `secretstest.ProviderContract` compliance
- Race detector clean (`-race`)

1Password additionally tests:
- Auth chaining (`Dependencies()` returns the ref)
- Vault-by-title resolution
- Field-by-label extraction (instead of JSON parsing)

## Task Decomposition

| Task | Description |
|------|-------------|
| 1 | GCP Secret Manager: SDK dep + config + doc + provider + tests |
| 2 | Azure Key Vault: SDK dep + config + doc + provider + tests |
| 3 | 1Password Connect: SDK dep + config + doc + provider + tests |
| 4 | Integration wiring: policy + session config for all 3 providers |

Tasks 1-3 are independent. Task 4 depends on all three.

## Policy YAML Example (All Providers)

```yaml
providers:
  keyring:
    type: keyring
  vault:
    type: vault
    address: https://vault.corp.internal
    auth:
      method: token
      token_ref: keyring://agentsh/vault_token
  aws_sm:
    type: aws-sm
    region: us-east-1
  gcp_sm:
    type: gcp-sm
    project_id: my-gcp-project
  azure_kv:
    type: azure-kv
    vault_url: https://myvault.vault.azure.net/
  onepassword:
    type: op
    server_url: https://onepass-connect.internal
    api_key_ref: keyring://agentsh/op_connect_key

services:
  - name: github
    match:
      hosts: ["api.github.com"]
    secret:
      ref: gcp-sm://github-token#token
    fake:
      format: "ghp_{rand:36}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"

  - name: stripe
    match:
      hosts: ["api.stripe.com"]
    secret:
      ref: op://Work/Stripe#credential
    fake:
      format: "sk_live_{rand:24}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"
```
