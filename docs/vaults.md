# Secrets & Vaults in agentsh

This document is the operator reference for every vault, KMS, and secret
store that agentsh talks to. It covers what each subsystem does, how to
configure it, which auth methods are supported, and what is planned but
not yet built.

If you are an SRE standing up agentsh for the first time, jump to
**[Part 4 — Operator quickstart](#part-4--operator-quickstart)** and
come back for depth.

## Status legend

Every provider below is tagged with one of three statuses. Pay attention
to the tag — agentsh is mid-evolution and the set of "works today" is
smaller than the set of "designed."

| Tag | Meaning |
|---|---|
| **Operational** | Code is in `main`, wired into the server, covered by tests, safe to use in production. |
| **Scaffold** | Code exists in the tree but is **not yet wired into the running server**. The Go API is stable enough to read; the YAML config surface is not. Do not deploy with this. |
| **Planned** | Design-stage only. Referenced by a spec in `docs/superpowers/specs/` but no implementation has landed. |

---

## Part 0 — Overview

agentsh has **three distinct vault concerns**, and conflating them is the
single most common source of confusion:

1. **Audit integrity KMS** — **Operational.** The HMAC key used to sign
   the tamper-proof audit log chain. Lives in `internal/audit/kms/`. One
   key per agentsh instance. Read once at startup, cached in memory. See
   [Part 1](#part-1--audit-integrity-chain-kms-backends-operational).

2. **Runtime secret injection** — **Scaffold.** A secret manager that
   would fetch arbitrary secrets from a vault and expose them to spawned
   agent sessions. Lives in `pkg/secrets/`. The code is present; the
   wiring is not. See [Part 2](#part-2--runtime-secret-injection-pkgsecrets-scaffold).

3. **External-secrets fake-credential substitution** — **Planned.** The
   future direction: real credentials never enter the agent's address
   space; a substituting proxy swaps fake credentials for real ones at
   egress. Designed in
   [`docs/superpowers/specs/2026-04-07-external-secrets-design.md`][ext-spec].
   Plan 1 (package rename + Hook interface) is the only piece that has
   landed. See [Part 3](#part-3--external-secrets-substitution-planned).

### Quick selection guide

| I want to… | Go to |
|---|---|
| Sign my audit log with a key in AWS KMS | [Part 1.3 — AWS KMS](#aws-kms) |
| Sign my audit log with a HashiCorp Vault key | [Part 1.3 — HashiCorp Vault](#hashicorp-vault-audit-kms) |
| Understand why `pkg/secrets/` isn't loaded by my server | [Part 2.1 — Status](#21-status) |
| See what Plans 2–12 will add | [Part 3 — External-secrets substitution](#part-3--external-secrets-substitution-planned) |
| Stand up agentsh on Kubernetes | [Part 4.4 — Kubernetes](#44-kubernetes-deployment-vault--service-account) |
| Stand up agentsh on AWS | [Part 4.5 — AWS-native](#45-aws-native-deployment) |

---

## Part 1 — Audit integrity chain (KMS backends, **operational**)

### 1.1 What it protects

agentsh writes an append-only audit log of every security-relevant
event (policy decision, file access, network connection, approval,
session lifecycle). Without integrity protection, an attacker with
write access to the log file can rewrite history.

The integrity chain solves this by HMAC-signing each event with a key
the attacker does not have. Every event carries an HMAC that covers its
own fields **and** the previous event's HMAC, so a single tampered
record invalidates every entry after it.

The HMAC key is the one thing that must live outside the log. It is
loaded once at startup from a KMS provider and cached in memory until
shutdown. The KMS abstraction in `internal/audit/kms/` lets you choose
where that key comes from.

Design reference:
[`docs/superpowers/specs/2026-03-30-wire-hmac-integrity-chain-design.md`](superpowers/specs/2026-03-30-wire-hmac-integrity-chain-design.md).

### 1.1.1 Sidecar-backed chain continuity

The audit integrity chain now persists its last durable state in a sidecar file
next to the JSONL log:

- `<audit.output>.chain`

That sidecar stores the last sequence, the last entry hash, and a fingerprint of
the configured HMAC key. agentsh uses it at startup to resume the chain across
process restarts and rotated `audit.jsonl`, `audit.jsonl.1`, `audit.jsonl.2`, …
files.

If the sidecar is missing but the log contains v2 entries, agentsh writes an
`integrity_chain_rotated` event with `reason_code=sidecar_missing` and starts a
fresh chain. If the sidecar and log disagree, agentsh refuses to start and
points the operator at an explicit archival reset flow:

```bash
agentsh audit chain reset --reason "rotated audit integrity key" --reason-code key_rotated --legacy-archive
```

Changing the audit HMAC key or `audit.integrity.algorithm` requires
`--legacy-archive`. The current verifier and startup path replay the visible log
with one key and one algorithm, so in-place resets are only safe when the
existing visible entries still verify under the current signing parameters.

For envelope providers, losing the encrypted DEK or changing KMS config now
surfaces as a key-fingerprint mismatch on startup instead of silently forking
the chain.

### 1.2 YAML config shape

All KMS providers for the audit integrity chain are configured under
`audit.integrity` in the agentsh YAML config. The top-level shape:

```yaml
audit:
  integrity:
    enabled: true
    algorithm: hmac-sha256     # or hmac-sha512
    key_source: aws_kms        # file | env | aws_kms | azure_keyvault | hashicorp_vault | gcp_kms

    # Legacy sources (still supported)
    key_file: ""
    key_env:  ""

    # Provider-specific blocks — only the one matching key_source is used.
    aws_kms:         { ... }
    azure_keyvault:  { ... }
    hashicorp_vault: { ... }
    gcp_kms:         { ... }
```

`key_source` is the single switch. If you leave `key_source` empty,
agentsh auto-detects it in this order: `key_file` → `key_env` →
`aws_kms.key_id` → `azure_keyvault.vault_url` → `hashicorp_vault.address`
→ `gcp_kms.key_name`. Auto-detection is convenient for tests; in
production, set `key_source` explicitly.

**Where this lives in code:**

- Go types: `internal/config/config.go` — `AuditIntegrityConfig`,
  `AWSKMSConfig`, `AzureKeyVaultConfig`, `HashiCorpVaultConfig`,
  `GCPKMSConfig`.
- Provider dispatch: `internal/audit/kms/provider.go` — `NewProvider`.
- Wire-up into the audit pipeline: `internal/audit/integrity.go` —
  `NewKMSProvider`, `NewIntegrityChainFromConfig`.

### 1.3 Provider setup

#### File / Env

Use for local dev, CI, and anything where the audit log does not need
to survive a determined attacker on the box. The key is held in plain
text on disk or in an environment variable.

```yaml
audit:
  integrity:
    enabled: true
    key_source: file
    key_file: /etc/agentsh/audit-key.hex
```

Or via env var:

```yaml
audit:
  integrity:
    enabled: true
    key_source: env
    key_env: AGENTSH_AUDIT_KEY
```

The key file must contain a hex-encoded secret, trimmed of whitespace.
Generate one with:

```bash
openssl rand -hex 32 > /etc/agentsh/audit-key.hex
chmod 0400 /etc/agentsh/audit-key.hex
chown agentsh:agentsh /etc/agentsh/audit-key.hex
```

Code reference: `internal/audit/kms/file.go` — `NewFileProvider`.

**Caveats:**

- The key is cached after first read. Editing `audit-key.hex` on disk
  does not take effect until the daemon restarts.
- For env var mode, the env var is read at startup only. Empty or unset
  yields `ErrKeyNotFound`.
- Do **not** use file or env for production. The threat model assumes
  the attacker can read the agentsh working directory; the whole point
  of the integrity chain is defeated if the key sits next to the log.

#### AWS KMS

Envelope-encryption model: KMS never sees the HMAC plaintext. agentsh
asks KMS to generate a data encryption key (DEK), uses the DEK
plaintext as the HMAC secret, and caches the KMS-encrypted ciphertext
to disk. On restart, agentsh decrypts the cached DEK and recovers the
same HMAC key.

```yaml
audit:
  integrity:
    enabled: true
    key_source: aws_kms
    aws_kms:
      key_id: arn:aws:kms:us-east-1:123456789012:key/abcd1234-...
      region: us-east-1
      encrypted_dek_file: /var/lib/agentsh/audit.dek
```

| Field | Purpose |
|---|---|
| `key_id` | ARN or alias (e.g. `alias/agentsh-audit`) of the KMS key. **Required.** |
| `region` | AWS region for the KMS client. Defaults to the credential provider chain if empty. |
| `encrypted_dek_file` | Path to cache the encrypted DEK. **Strongly recommended** — otherwise each restart generates a new DEK and the integrity chain resets. |

**IAM permissions required on `key_id`:**

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:GenerateDataKey",
    "kms:Decrypt"
  ],
  "Resource": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-..."
}
```

`GenerateDataKey` is only called on first startup (when the DEK file
is missing or unreadable). `Decrypt` is called on every subsequent
startup.

**Credentials.** The AWS SDK default credential chain is used —
environment variables, `~/.aws/credentials`, IAM role on EC2/ECS/EKS,
IMDS, etc. agentsh does not ship a `role_arn` field for audit KMS;
use the standard AWS credential mechanisms.

Code reference: `internal/audit/kms/aws.go` — `NewAWSKMSProvider`.

**Caveats:**

- If `encrypted_dek_file` is writable but the filesystem is wiped
  (container restart with ephemeral storage), the new DEK is different
  from the old one and the integrity chain forks. Use persistent
  storage.
- The `encrypted_dek_file` is written mode 0600. Make sure the agentsh
  user owns it.
- KMS throttling is rare for this use case — `GenerateDataKey` once
  and `Decrypt` once per restart — but set up a CloudWatch alarm on
  `ThrottledCount` if you're paranoid.

#### Azure Key Vault

Treats Key Vault as a passive secret store: the HMAC key is placed in
Key Vault as a **secret** (not a key), and agentsh reads it at startup.
No envelope encryption.

```yaml
audit:
  integrity:
    enabled: true
    key_source: azure_keyvault
    azure_keyvault:
      vault_url: https://agentsh-vault.vault.azure.net
      key_name: audit-hmac-key
      key_version: ""   # empty = latest version
```

| Field | Purpose |
|---|---|
| `vault_url` | Key Vault URL. **Required.** |
| `key_name` | Name of the secret inside the vault. **Required.** |
| `key_version` | Specific version, or empty for latest. |

**Authentication.** Uses `DefaultAzureCredential` from the Azure
Go SDK, which tries in order: env vars → workload identity →
managed identity → Azure CLI → developer credentials. In production,
configure a managed identity on the VM/container and grant it
**Key Vault Secrets User** on the target vault.

```bash
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee <managed-identity-principal-id> \
  --scope /subscriptions/.../providers/Microsoft.KeyVault/vaults/agentsh-vault
```

**Secret format.** The secret value is either:

- A hex/base64-encoded key (agentsh tries base64 first, falls back to
  raw bytes).
- A raw string (treated as the literal HMAC key).

Create one with:

```bash
openssl rand -base64 32 | az keyvault secret set \
  --vault-name agentsh-vault \
  --name audit-hmac-key \
  --file /dev/stdin
```

Code reference: `internal/audit/kms/azure.go` —
`NewAzureKeyVaultProvider`.

**Caveats:**

- Key Vault firewall rules apply. If your vault is locked down to
  specific networks/VNets, agentsh must run inside one of them.
- Rotating the secret in Key Vault has no effect until the daemon
  restarts — the key is cached in memory.
- The current provider does not support Key Vault **keys** (HSM-backed
  crypto operations), only Key Vault **secrets**. If you need the
  HMAC key to never leave the HSM, use AWS KMS or GCP KMS instead,
  which do envelope encryption.

#### HashiCorp Vault (audit KMS)

Reads the HMAC key from a Vault KV engine (v1 or v2). Supports token,
Kubernetes, and AppRole authentication.

```yaml
audit:
  integrity:
    enabled: true
    key_source: hashicorp_vault
    hashicorp_vault:
      address:         https://vault.corp.internal:8200
      auth_method:     kubernetes     # token | kubernetes | approle
      kubernetes_role: agentsh
      secret_path:     secret/data/agentsh/audit-key
      key_field:       key            # default: "key"
```

| Field | Purpose |
|---|---|
| `address` | Vault server URL. **Required.** |
| `auth_method` | `token`, `kubernetes`, or `approle`. Defaults to `token`. |
| `secret_path` | Full Vault path to the secret. **Required.** KV v2 paths like `secret/data/agentsh/audit-key` are auto-detected; KV v1 is a fallback. |
| `key_field` | Field name inside the KV entry. Defaults to `key`. |
| `token_file` | (token auth only) File to read the token from. Falls back to `VAULT_TOKEN` env var. |
| `kubernetes_role` | (kubernetes auth only) Vault role bound to the service account. |
| `approle_id` | (approle auth only) AppRole role ID. |
| `secret_id` | (approle auth only) AppRole secret ID. Falls back to `VAULT_SECRET_ID` env var. |

**Authentication cheat sheet:**

- **Token (dev/staging).** Put a long-lived token in `VAULT_TOKEN` or a
  file. Easy to set up, but the token is static and should be revoked
  when rotated. Do not use in production.

- **Kubernetes (recommended for k8s deployments).** Bind a Vault role
  to the agentsh service account. Vault authenticates via the
  in-pod projected service-account JWT. No static secrets anywhere.
  ```
  vault write auth/kubernetes/role/agentsh \
      bound_service_account_names=agentsh \
      bound_service_account_namespaces=agentsh \
      policies=agentsh-audit \
      ttl=1h
  ```

- **AppRole (bare-metal / non-k8s).** Use a delivery mechanism
  (Chef/Ansible/Puppet) to push `secret_id` to the host; keep the
  `role_id` in config. The `secret_id` can be wrapped with
  `response wrapping` for extra safety.

**Policy required on Vault side:**

```hcl
path "secret/data/agentsh/audit-key" {
  capabilities = ["read"]
}
```

Add `path "secret/metadata/agentsh/audit-key"` if you plan to use
versioned reads later.

Code reference: `internal/audit/kms/vault.go` —
`NewVaultProvider`, `authToken`, `authKubernetes`, `authAppRole`.

**Caveats:**

- The current audit KMS provider reads a **secret** (KV value), not a
  Vault Transit key. If you want the HMAC key to live inside Transit
  and never be returned plaintext, that is a future enhancement — file
  an issue.
- Vault **namespaces** (Enterprise feature) are not exposed in the
  audit KMS config. If you need namespace support, override via the
  `VAULT_NAMESPACE` env var before launching agentsh.
- A sealed Vault returns an error from `GetKey`; agentsh fails to
  start until Vault is unsealed.

#### GCP Cloud KMS

Same envelope-encryption model as AWS KMS: agentsh generates a 256-bit
DEK locally, encrypts it with a Cloud KMS crypto key, and caches the
ciphertext.

```yaml
audit:
  integrity:
    enabled: true
    key_source: gcp_kms
    gcp_kms:
      key_name:            projects/my-project/locations/us-central1/keyRings/agentsh/cryptoKeys/audit-hmac
      encrypted_dek_file:  /var/lib/agentsh/audit.dek
```

| Field | Purpose |
|---|---|
| `key_name` | Full resource name of the Cloud KMS crypto key. **Required.** |
| `encrypted_dek_file` | Path to cache the encrypted DEK. **Strongly recommended.** |

**Authentication.** Uses Application Default Credentials (ADC). On
GKE, attach a service account via Workload Identity. On GCE, the VM
service account is picked up automatically.

**IAM permissions required on `key_name`:**

- `roles/cloudkms.cryptoKeyEncrypterDecrypter` — covers both
  `Encrypt` (first start) and `Decrypt` (every subsequent start).

```bash
gcloud kms keys add-iam-policy-binding audit-hmac \
    --keyring agentsh \
    --location us-central1 \
    --member serviceAccount:agentsh@my-project.iam.gserviceaccount.com \
    --role roles/cloudkms.cryptoKeyEncrypterDecrypter
```

Code reference: `internal/audit/kms/gcp.go` — `NewGCPKMSProvider`.

**Caveats:**

- Same DEK caching caveat as AWS: if `encrypted_dek_file` gets wiped
  on container restart, the integrity chain forks.
- GCP KMS has per-region pricing and quota. For audit HMAC, the
  traffic is negligible (one encrypt, one decrypt per restart), but
  be aware that `key_name` pins you to a region.

### 1.4 Key rotation runbook

The integrity chain HMAC key is deliberately **not** auto-rotated —
rotation breaks the chain (any event before rotation cannot be
verified with the new key). The correct rotation procedure is:

1. Drain the current audit log: flush all buffered events, close the
   current log file, and archive it with its HMAC key ID recorded in
   the archive's sidecar.
2. Restart agentsh with the new KMS config (or, for envelope
   providers, delete the old `encrypted_dek_file` so a new DEK is
   generated).
3. Start fresh chain.

For envelope providers (AWS KMS, GCP KMS), the underlying KMS crypto
key can be rotated on the KMS side without touching agentsh — the
encrypted DEK keeps working as long as the KMS key alias still
resolves to a version that can decrypt the existing ciphertext.

### 1.5 Troubleshooting

| Symptom | Likely cause |
|---|---|
| `authentication failed: no token provided` | Token auth selected but neither `token_file` nor `VAULT_TOKEN` is set. |
| `key not found: key file ... is empty` | `key_file` exists but has zero length. Generate a new one with `openssl rand -hex 32`. |
| `provider unavailable: failed to decrypt DEK` (AWS/GCP) | `encrypted_dek_file` was generated with a different KMS key. Delete the file to regenerate. |
| `provider unavailable: secret ... is empty` (Azure) | Azure Key Vault secret has no value, or `key_version` points at a deleted version. |
| `unsupported auth method: ""` (Vault) | `hashicorp_vault.auth_method` not set. Defaults to `token` when empty — check the field name is spelled correctly. |
| Daemon restarts but audit log verification fails on the first new event | The DEK file was lost or the KMS key was rotated out. See [1.4 Key rotation](#14-key-rotation-runbook). |

If a provider returns `ErrKeyNotFound` at startup, agentsh fails to
start — it refuses to run without integrity if integrity is enabled.
To disable integrity temporarily, set `audit.integrity.enabled: false`.

---

## Part 2 — Runtime secret injection (`pkg/secrets/`, **scaffold**)

### 2.1 Status

**This subsystem is not yet wired into the running server.** The
package `pkg/secrets/` contains provider code, a secret manager, a
cache, and a test suite, but nothing in `internal/server/` or the
session pipeline instantiates a `secrets.Manager` or calls
`GetInjections`. The scaffold was added as a forward-looking
placeholder (commit `71b993a9`, PR #40) and is kept in the tree as a
reference for the future [external-secrets](#part-3--external-secrets-substitution-planned)
work.

You cannot deploy with `pkg/secrets/` today. The YAML config surface
described below is what the code **reads** if you manually build a
`ManagerConfig` in tests; it is **not** exposed through the top-level
`Config` struct in `internal/config/config.go`. If you need runtime
secret injection today, the operational answer is
`sessions.env_inject` (plain environment variables, no vault) — not
`pkg/secrets`.

### 2.2 Manager architecture

The scaffold implements a straightforward provider-registry pattern.

```
                    ┌──────────────────────┐
                    │   secrets.Manager    │
                    │                      │
  Provider IF ─────►│  providers map[..]   │
  (Vault, AWS, ...) │  cache (TTL)         │
                    │  approvals (IF)      │
                    │  auditLog (IF)       │
                    └──────────┬───────────┘
                               │
                     Get(SecretRequest)
                               │
               ┌───────────────┼───────────────┐
               ▼               ▼               ▼
        path allowed?    check cache      approval required?
               │               │               │
               └───────────────┼───────────────┘
                               ▼
                    provider.Get(ctx, path)
                               ▼
                          cache.set
                               ▼
                     return *Secret
```

Key types (in `pkg/secrets/manager.go`):

- `Provider` — `Name()`, `Get()`, `List()`, `IsHealthy()`.
- `Secret` — `Path`, `Data map[string]string`, `Version`, `ExpiresAt`, `Metadata`.
- `Manager` — coordinates providers, cache, approvals, audit log.
- `ApprovalService` — interface for human-in-the-loop approval of
  secret access. Not yet implemented.
- `AuditLogger` — interface for emitting secret-access events to the
  audit pipeline. Not yet implemented.
- `InjectConfig` — maps a provider path to an env var or file inside
  the spawned session.

### 2.3 Provider setup (scaffold config)

The `secrets.ManagerConfig` struct (see `pkg/secrets/manager.go`) uses
this shape when loaded from YAML:

```yaml
secrets:
  providers:
    vault:
      enabled: true
      address: https://vault.corp.internal:8200
      auth_method: approle
      role_id: 11111111-2222-3333-4444-555555555555
      secret_id: ${VAULT_SECRET_ID}   # read from env at load time, scaffold only
      namespace: ""
      allowed_paths:
        - "secret/data/agentsh/*"
    aws:
      enabled: true
      region: us-east-1
      role_arn: arn:aws:iam::123456789012:role/agentsh-secrets
      allowed_secrets:
        - "agentsh/*"
    azure:
      enabled: false           # stubbed, no implementation
      vault_url: https://agentsh-vault.vault.azure.net
      tenant_id: 00000000-0000-0000-0000-000000000000
      client_id: 00000000-0000-0000-0000-000000000000
      allowed_keys:
        - "agentsh-*"

  allowed_paths:
    - "*"

  inject:
    - provider: vault
      path: secret/data/agentsh/github
      key: token
      env_var: GITHUB_TOKEN
    - provider: aws
      path: agentsh/db-password
      env_var: DB_PASSWORD

  require_approval: true
  cache_ttl: 5m
  audit_log: true
```

**Providers implemented:**

| Provider | Package file | Status |
|---|---|---|
| HashiCorp Vault | `pkg/secrets/vault.go` | Complete: token, AppRole, Kubernetes auth; KV v1, KV v2; namespaces. |
| AWS Secrets Manager | `pkg/secrets/aws.go` | Complete: Get/List/Create/Update/Delete/Rotate; JSON multi-field secrets; `role_arn` assumption via STS. |
| Azure Key Vault | *(no file)* | **Stubbed.** `AzureConfig` struct exists in `manager.go` but no `AzureProvider` implementation. |

#### HashiCorp Vault (runtime secrets)

Almost identical shape to the audit-KMS Vault provider, but a
**separate implementation**. Key differences:

- Uses a hand-rolled HTTP client (`net/http`) rather than the
  official `github.com/hashicorp/vault/api` library. See
  `pkg/secrets/vault.go`.
- Supports token, AppRole, and Kubernetes auth.
- Reads the Kubernetes service account JWT from the default path
  `/var/run/secrets/kubernetes.io/serviceaccount/token`.
- Supports Vault namespaces via `X-Vault-Namespace` header.
- `allowed_paths` provides a per-provider allowlist; paths outside
  the allowlist return `ErrSecretPathNotAllowed`.

**Auth method fields:**

| `auth_method` | Required fields |
|---|---|
| `token` | `token` |
| `approle` | `role_id`, `secret_id` |
| `kubernetes` | `kube_role` |

#### AWS Secrets Manager

Uses `github.com/aws/aws-sdk-go-v2/service/secretsmanager`.

- Standard AWS credential chain; optional `role_arn` to assume a
  specific IAM role via STS.
- Secrets stored as JSON get parsed into `Secret.Data` as a
  `map[string]string`.
- Binary secrets are exposed as `Data["binary"]`.
- `allowed_secrets` is a per-provider allowlist; matched with simple
  prefix/exact semantics.

Extras not present in the audit KMS equivalent: `CreateSecret`,
`UpdateSecret`, `DeleteSecret`, `RotateSecret`, `GetSecretVersions`.
These are exposed as methods on `AWSProvider` — they are **not** on
the `Provider` interface, so a caller would need to type-assert to
`*AWSProvider`.

### 2.4 Injection config

`ManagerConfig.Inject` describes how fetched secrets become visible
to the spawned session:

```go
type InjectConfig struct {
    Provider string  // "vault" | "aws" | "azure"
    Path     string  // provider-specific secret path
    Key      string  // optional: specific field inside a multi-field secret
    EnvVar   string  // env var name inside the session
    File     string  // optional: write secret to a file
}
```

At session-start time, `Manager.GetInjections(ctx, agentID)` iterates
every `Inject` entry, calls `Get`, extracts the configured `Key` (or
the first value if `Key` is empty), and returns a
`map[string]string{envVarName: secretValue}` that the session
launcher can splice into the spawned process's environment.

**File injection (`File` field) is not yet wired** — the struct field
exists but `GetInjections` only returns env vars. File injection is
tracked as part of the external-secrets design.

### 2.5 Approval flow + audit

`ManagerConfig.RequireApproval: true` makes every `Get` call block
until an `ApprovalService` returns `ApprovalApproved`. The
`ApprovalService` interface:

```go
type ApprovalService interface {
    Request(ctx, *ApprovalRequest) ApprovalDecision
    GetPending(ctx) ([]*ApprovalRequest, error)
    Approve(ctx, requestID, approver string) error
    Deny(ctx, requestID, approver, reason string) error
}
```

No implementation of `ApprovalService` exists yet — this is one of
the pieces that will be filled in when the scaffold moves into
production. For now, setting `require_approval: true` with no
approval service will panic on first `Get`.

The `AuditLogger` interface emits four event types:

- `SecretAccessed(agentID, path, provider, granted)` — every `Get`
  call, pass or fail.
- `SecretInjected(agentID, path, envVar)` — every successful
  injection.
- `ApprovalRequested(req)` — when an approval is queued.
- `ApprovalDecided(requestID, decision, approver)` — when an
  approval is resolved.

These events would flow into the same audit pipeline that the
integrity chain in Part 1 protects. The wiring from
`secrets.AuditLogger` to `audit.Logger` is one of the outstanding
pieces — it does not exist in the scaffold.

---

## Part 3 — External-secrets substitution (**planned**)

### 3.1 Problem

The runtime-injection model in Part 2 still puts the real secret into
the agent's address space. An agent that gets subverted — prompt
injection, a malicious tool call, a subtly wrong HTTP destination —
can exfiltrate whatever it can read. For high-value credentials
(GitHub tokens, cloud IAM keys, database passwords), this is too much
trust.

The external-secrets design flips the model: the real credential
**never enters the agent's memory**. The agent only sees a fake with
the same shape as the real thing. agentsh's embedded proxy intercepts
the agent's outbound HTTP, rewrites the fake to the real credential
at the last moment, and forwards the reconstructed request upstream.

Full spec:
[`docs/superpowers/specs/2026-04-07-external-secrets-design.md`][ext-spec].

### 3.2 Mechanism A — local substituting proxy (v1 target)

Three mechanisms are considered in the spec; only Mechanism A ships
in v1.

- **A. Explicit local proxy (v1).** The spawned process's environment
  sends cooperating SDKs to agentsh's local proxy. The proxy
  terminates HTTP, scans the body and headers for known fake values,
  rewrites them to real credentials, and forwards upstream.
- **B. Linux TLS uprobes (future).** eBPF uprobes on `SSL_write`,
  `gnutls_record_send`, and Go's `crypto/tls.(*Conn).Write` catch
  plaintext before encryption. Linux-only, requires `CAP_BPF`, not
  in v1.
- **C. Per-tool credential helpers (future).** `git credential.helper`,
  `aws credential_process`, `gh` auth, `kubectl` exec plugins,
  `docker` credsStore. Cross-platform but unbounded per-tool work,
  not in v1.

Mechanism A requires cooperation from the SDK (honor `*_BASE_URL` or
`HTTPS_PROXY`) but covers the common case. The existing LLM proxy
(`internal/proxy/`) already implements the core of Mechanism A for
Anthropic and OpenAI — external-secrets generalizes it.

### 3.3 Planned `SecretProvider` interface

From the spec, Section 2:

```go
// internal/proxy/secrets/provider.go  (not yet created)
type SecretProvider interface {
    Name() string
    Fetch(ctx context.Context, ref SecretRef) (SecretValue, error)
    Close() error
}

type SecretRef struct {
    URI      string            // "vault://kv/data/github#token"
    Metadata map[string]string // provider-specific hints
}

type SecretValue struct {
    Value     []byte
    TTL       time.Duration
    LeaseID   string
    Version   string
    FetchedAt time.Time
}
```

**Planned provider set (v1):**

| URI scheme | Provider | Tier | Notes |
|---|---|---|---|
| `vault://` | HashiCorp Vault + OpenBao | 1 | KV v1/v2, generic; token/approle/kubernetes auth |
| `aws-sm://` | AWS Secrets Manager | 1 | SigV4, ambient or explicit IAM role |
| `gcp-sm://` | GCP Secret Manager | 1 | ADC or explicit SA key |
| `azure-kv://` | Azure Key Vault | 1 | MSI or explicit service principal |
| `op://` | 1Password (Connect API or CLI) | 1 | Connect by default, `op` CLI pluggable |
| `keyring://` | OS keyring | 1 | macOS Keychain, Linux libsecret, Windows Credential Manager |

Each lives in its own subpackage under `internal/proxy/secrets/`. Note
that this is a **new hierarchy** — not the same as the existing
`pkg/secrets/` scaffold from Part 2. The external-secrets design
treats `pkg/secrets/` as a reference implementation that the new
code will cannibalize.

### 3.4 Service declarations (YAML-first)

Each external service (GitHub, Stripe, Anthropic, …) gets a
declarative entry that answers five questions: **identity, secret
source, fake shape, injection, substitution.** Example from the
spec:

```yaml
services:
  - name: github
    match:
      hosts: ["api.github.com", "*.github.com"]
    secret:
      ref: vault://kv/data/github#token
    fake:
      format: "ghp_{rand:36}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"
    scrub_response: true
```

The "80%" case is fully declarative. The "20%" that need custom auth
(AWS SigV4, OAuth refresh flows) get a Go plugin interface.

### 3.5 Hook interface — **landed in Plan 1**

This is the only piece of the external-secrets design that has
already merged. The `Hook` interface + `Registry` in
`internal/proxy/hooks.go` is the extension point that later plans
will use to move DLP, MCP interception, dialect detection, and
eventually secret substitution behind a pluggable interface.

```go
// internal/proxy/hooks.go
type Hook interface {
    Name() string
    PreHook(*http.Request, *RequestContext) error
    PostHook(*http.Response, *RequestContext) error
}

type Registry struct { /* ... */ }
func (r *Registry) Register(serviceName string, h Hook)
func (r *Registry) ApplyPreHooks(serviceName string, req *http.Request, ctx *RequestContext) error
func (r *Registry) ApplyPostHooks(serviceName string, resp *http.Response, ctx *RequestContext) error
```

Key properties (verified by tests in `internal/proxy/hooks_test.go`):

- **Registration is keyed by service name.** An empty service name
  means "run for every request regardless of which service matched."
- **`ApplyPreHooks` short-circuits** on the first error — a failing
  pre-hook aborts the request.
- **`ApplyPostHooks` runs every hook** even if one fails, then
  returns the first error it saw.
- **Registration is safe during apply.** Hooks are snapshotted under
  a read lock and invoked outside the lock, so a hook that calls
  `Register` during execution does not deadlock.
- **Nil hooks are rejected at registration time** — both bare nil and
  typed-nil (`var h *myHook = nil`) panic with a clear message.

The registry is **not yet wired into `Proxy.ServeHTTP`.** Plan 1 was
deliberately additive — the interface exists, but no hooks are
registered and the proxy does not call `ApplyPreHooks` /
`ApplyPostHooks` anywhere yet. That wiring lands in Plan 2+.

### 3.6 Migration roadmap

| Plan | Status | Scope |
|---|---|---|
| 1 | ✅ Merged (PR #193) | Rename `internal/llmproxy` → `internal/proxy`. Add Hook interface skeleton. |
| 2 | Pending | Wire Hook registry into `Proxy.ServeHTTP`. Migrate DLP into a `DLPHook`. |
| 3 | Pending | Migrate MCP interception + dialect detection into hooks. |
| 4 | Pending | Add `SecretProvider` interface. Implement Vault, AWS SM, GCP SM, Azure KV. |
| 5 | Pending | Service declarations (YAML) + fake credential generator. |
| 6 | Pending | Substitution engine: body scan, header rewrite, streaming-aware. |
| 7 | Pending | `op://` (1Password) + `keyring://` providers. |
| 8 | Pending | Response scrubbing (substitute real → fake in responses). |
| 9 | Pending | Audit event integration — every substitution is an auditable event. |
| 10 | Pending | CLI / config surface for operators. |
| 11 | Pending | Observability — metrics, health checks, debug endpoints. |
| 12 | Pending | Docs + migration guide for existing operators. |

Plans 2–12 do not exist as written-plan documents yet. They will be
created as Plan 1's follow-on work.

---

## Part 4 — Operator quickstart

### 4.1 Which provider should I use?

Start here. Pick your **audit KMS provider** first — that is the only
thing you can configure today. Runtime secret injection is scaffold
only; external-secrets is planned.

```
Where does agentsh run?
├── Laptop / CI                     → File / Env (Part 1.3, File/Env)
├── Kubernetes cluster
│   ├── AWS (EKS)                   → AWS KMS       (Part 1.3, AWS KMS)
│   ├── GCP (GKE)                   → GCP KMS       (Part 1.3, GCP KMS)
│   ├── Azure (AKS)                 → Azure KV      (Part 1.3, Azure KV)
│   └── On-prem / multi-cloud       → HashiCorp Vault (kubernetes auth)
├── Bare-metal / VM
│   ├── AWS EC2                     → AWS KMS       (instance profile)
│   ├── GCP Compute                 → GCP KMS       (service account)
│   ├── Azure VM                    → Azure KV      (managed identity)
│   └── Other                       → HashiCorp Vault (approle)
└── Multi-provider / hybrid         → HashiCorp Vault as the single integration point
```

**Rule of thumb:** if you already run Vault for other workloads, use
it for audit HMAC too. If you are cloud-native on one provider, use
that provider's KMS — the envelope encryption model (AWS/GCP) is
stronger than the "read a secret" model (Azure) or the direct-key
model (File/Env), and the operational integration is tighter.

### 4.2 Auth method cheat sheet

| Provider | Dev | Production |
|---|---|---|
| File / Env | `openssl rand -hex 32 > key.hex` | **Not recommended.** |
| AWS KMS | Env vars or `~/.aws/credentials` | Instance profile / IRSA |
| GCP KMS | `gcloud auth application-default login` | Workload Identity / VM service account |
| Azure KV | `az login` | Managed Identity |
| HashiCorp Vault | `token` with dev token | `kubernetes` (k8s), `approle` (bare metal) |

### 4.3 Local development (File / Env)

```bash
mkdir -p ~/.agentsh
openssl rand -hex 32 > ~/.agentsh/audit-key.hex
chmod 0400 ~/.agentsh/audit-key.hex
```

`~/.agentsh/agentsh.yaml`:

```yaml
audit:
  integrity:
    enabled: true
    key_source: file
    key_file: ~/.agentsh/audit-key.hex
```

This is the full setup. No cloud, no Vault, no network dependencies.
Good for `go test ./...` and `make dev`.

### 4.4 Kubernetes deployment (Vault + service account)

**Vault side (one-time):**

```bash
# Enable Kubernetes auth
vault auth enable kubernetes
vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"

# Policy
vault policy write agentsh-audit - <<EOF
path "secret/data/agentsh/audit-key" {
  capabilities = ["read"]
}
EOF

# Role
vault write auth/kubernetes/role/agentsh \
    bound_service_account_names=agentsh \
    bound_service_account_namespaces=agentsh \
    policies=agentsh-audit \
    ttl=1h

# Put the key in Vault
vault kv put secret/agentsh/audit-key key="$(openssl rand -hex 32)"
```

**Kubernetes side:**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: agentsh
  namespace: agentsh
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: agentsh-config
  namespace: agentsh
data:
  agentsh.yaml: |
    audit:
      integrity:
        enabled: true
        key_source: hashicorp_vault
        hashicorp_vault:
          address: https://vault.corp.internal:8200
          auth_method: kubernetes
          kubernetes_role: agentsh
          secret_path: secret/data/agentsh/audit-key
          key_field: key
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentsh
  namespace: agentsh
spec:
  template:
    spec:
      serviceAccountName: agentsh
      containers:
      - name: agentsh
        image: agentsh:latest
        volumeMounts:
        - name: config
          mountPath: /etc/agentsh
      volumes:
      - name: config
        configMap:
          name: agentsh-config
```

No static tokens, no secrets in the manifest. agentsh authenticates to
Vault using the projected service account JWT at startup.

### 4.5 AWS-native deployment

**KMS side (one-time):**

```bash
aws kms create-key \
    --description "agentsh audit integrity HMAC" \
    --key-usage ENCRYPT_DECRYPT
aws kms create-alias \
    --alias-name alias/agentsh-audit \
    --target-key-id <key-id-from-above>
```

**IAM role (attached to the agentsh EC2 instance / ECS task / EKS SA):**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
    "Resource": "arn:aws:kms:us-east-1:123456789012:key/abcd1234-..."
  }]
}
```

**agentsh config:**

```yaml
audit:
  integrity:
    enabled: true
    key_source: aws_kms
    aws_kms:
      key_id: alias/agentsh-audit
      region: us-east-1
      encrypted_dek_file: /var/lib/agentsh/audit.dek
```

`/var/lib/agentsh` must be on persistent storage. On ECS/EKS, mount an
EBS volume. On plain EC2, use the local disk with a backup policy.

### 4.6 Security considerations

- **Key material in memory.** Once loaded, every KMS provider keeps
  the HMAC key in plaintext in the agentsh daemon's address space.
  Local root attackers can read it. This is considered out-of-scope
  for the current threat model (see the external-secrets design).
- **DEK caching.** The AWS/GCP envelope providers cache the encrypted
  DEK on disk at `encrypted_dek_file`. The file is mode 0600 and
  owned by the agentsh user. It must be on **persistent** storage —
  losing it breaks the integrity chain.
- **Network exposure.** Every KMS provider makes outbound HTTPS calls
  at startup. If agentsh runs in a restricted network, allowlist the
  KMS endpoints. AWS/GCP/Azure publish IP ranges; Vault is your own
  infrastructure.
- **Sealed Vault.** If HashiCorp Vault is sealed at agentsh startup,
  the daemon fails to start. This is deliberate — running without
  integrity protection is worse than being down.
- **Rotation.** See [1.4](#14-key-rotation-runbook). The integrity
  chain intentionally does not auto-rotate.
- **Runtime secret injection (Part 2) is not production-ready.** Do
  not deploy `pkg/secrets/` as if it were operational — it is not
  wired into the server.
- **External-secrets substitution (Part 3) is not implemented.** Do
  not plan a migration off your current secret injection flow
  assuming Part 3 will be available on a specific date — only the
  Hook interface skeleton has landed.

### 4.7 Health checks and monitoring

The audit KMS providers do not expose a dedicated health endpoint.
They are exercised once at startup; a failure there prevents the
daemon from starting, which your orchestrator's liveness check will
catch naturally.

For HashiCorp Vault deployments, monitor the Vault sidecar or the
`sys/health` endpoint independently — agentsh does not poll Vault
after the initial key fetch.

The `pkg/secrets/` scaffold does expose an `IsHealthy(ctx) bool`
method on each provider and a `Manager.Health(ctx)` aggregator, but
since the scaffold is not wired into the server there is no HTTP
endpoint to query today.

---

## Appendix A — Config reference

### A.1 Full `AuditIntegrityConfig` YAML

```yaml
audit:
  integrity:
    enabled: true
    algorithm: hmac-sha256            # hmac-sha256 | hmac-sha512
    key_source: ""                    # file | env | aws_kms | azure_keyvault | hashicorp_vault | gcp_kms (empty = auto-detect)

    key_file: ""                      # used when key_source=file
    key_env: ""                       # used when key_source=env

    aws_kms:
      key_id: ""                      # required for aws_kms
      region: ""                      # defaults to credential chain
      encrypted_dek_file: ""          # strongly recommended

    azure_keyvault:
      vault_url: ""                   # required for azure_keyvault
      key_name: ""                    # required for azure_keyvault
      key_version: ""                 # empty = latest

    hashicorp_vault:
      address: ""                     # required for hashicorp_vault
      auth_method: "token"            # token | kubernetes | approle (default token)
      token_file: ""                  # token auth: file to read token from (fallback: VAULT_TOKEN env)
      kubernetes_role: ""             # kubernetes auth
      approle_id: ""                  # approle auth
      secret_id: ""                   # approle auth (fallback: VAULT_SECRET_ID env)
      secret_path: ""                 # required
      key_field: "key"                # field name inside secret (default "key")

    gcp_kms:
      key_name: ""                    # required: full resource name
      encrypted_dek_file: ""          # strongly recommended
```

### A.2 Full `secrets.ManagerConfig` YAML (scaffold)

**Not exposed in `Config` today.** Included here for reference only —
the field names are what `pkg/secrets.ManagerConfig` would accept if
it were wired up.

```yaml
secrets:
  providers:
    vault:
      enabled: false
      address: ""
      auth_method: "token"            # token | approle | kubernetes
      token: ""
      role_id: ""
      secret_id: ""
      kube_role: ""
      namespace: ""
      allowed_paths: []

    aws:
      enabled: false
      region: ""
      allowed_secrets: []
      role_arn: ""

    azure:                            # config exists, provider does not
      enabled: false
      vault_url: ""
      tenant_id: ""
      client_id: ""
      allowed_keys: []

  allowed_paths: []                   # global path allowlist
  inject: []                          # []InjectConfig
  require_approval: false
  cache_ttl: 5m
  audit_log: true
```

## Appendix B — Links

**Code:**

- `internal/audit/kms/provider.go` — KMS provider dispatch
- `internal/audit/kms/file.go` — File / Env
- `internal/audit/kms/aws.go` — AWS KMS
- `internal/audit/kms/azure.go` — Azure Key Vault
- `internal/audit/kms/vault.go` — HashiCorp Vault
- `internal/audit/kms/gcp.go` — GCP Cloud KMS
- `internal/audit/integrity.go` — audit pipeline wire-up
- `internal/config/config.go` — `AuditIntegrityConfig` and friends
- `pkg/secrets/manager.go` — scaffold secret manager
- `pkg/secrets/vault.go` — scaffold HashiCorp Vault provider
- `pkg/secrets/aws.go` — scaffold AWS Secrets Manager provider
- `internal/proxy/hooks.go` — Hook interface (Plan 1)
- `internal/proxy/hooks_test.go` — Hook interface tests

**Specs & plans:**

- [`docs/superpowers/specs/2026-04-07-external-secrets-design.md`][ext-spec] — external-secrets master design
- [`docs/superpowers/specs/2026-03-30-wire-hmac-integrity-chain-design.md`](superpowers/specs/2026-03-30-wire-hmac-integrity-chain-design.md) — audit integrity chain design
- [`docs/superpowers/plans/2026-04-07-plan-01-proxy-rename-hooks.md`](superpowers/plans/2026-04-07-plan-01-proxy-rename-hooks.md) — Plan 1 (this branch)

**Related docs:**

- [`docs/approval-auth.md`](approval-auth.md) — approval service (referenced by runtime secret injection)
- [`docs/llm-proxy.md`](llm-proxy.md) — existing LLM proxy (being generalized into `internal/proxy`)
- [`docs/operations/disaster-recovery.md`](operations/disaster-recovery.md) — audit log restoration
- [`docs/operations/backup-restore.md`](operations/backup-restore.md) — backup procedures

[ext-spec]: superpowers/specs/2026-04-07-external-secrets-design.md
