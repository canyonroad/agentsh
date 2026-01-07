# Tier 3 P1 Security Gaps Implementation Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan phase-by-phase.

**Goal:** Address the three highest-priority Tier 3 security gaps: Checkpoint/Rollback, External KMS Integration, and SIEM Log Shipping.

**Architecture:** Three parallel workstreams that enhance existing infrastructure (checkpoint system, audit integrity, webhook store) with enterprise-grade capabilities.

**Tech Stack:** Go, AWS SDK, Azure SDK, HashiCorp Vault client, Syslog RFC5424, Splunk HEC, OpenTelemetry

---

## Phase 1: Checkpoint/Rollback

Build on existing `internal/session/checkpoint.go` to add true filesystem rollback capability.

### 1.1 Current State Analysis

**What exists:**
- `CheckpointManager` with `CreateCheckpoint`, `ListCheckpoints`, `GetCheckpoint`
- `Checkpoint` struct with `WorkspaceHash`, `ModifiedFiles`, `CanRollback`
- `hashWorkspace()` calculates SHA-256 of workspace contents
- In-memory storage only (`InMemoryCheckpointStorage`)
- **NO actual rollback/restore implementation**

**Gap:** Cannot restore workspace to previous state. `CanRollback` is set but never used.

### 1.2 Solution: Copy-on-Write Checkpoint Storage

**Design:** Before risky operations, snapshot affected files to a checkpoint directory. Rollback copies them back.

**Checkpoint storage layout:**
```
/var/lib/agentsh/checkpoints/
  <session-id>/
    <checkpoint-id>/
      metadata.json       # Checkpoint struct as JSON
      files/
        path/to/file1.txt # Actual file content
        path/to/file2.py
```

**Entry format (metadata.json):**
```json
{
  "id": "cp-abc123",
  "session_id": "sess-xyz",
  "created_at": "2026-01-07T10:00:00Z",
  "reason": "pre_command:rm -rf ./cache",
  "workspace_hash": "sha256:abc...",
  "files": [
    {
      "path": "src/main.py",
      "hash": "sha256:def...",
      "size": 1234,
      "mode": 420
    }
  ],
  "can_rollback": true
}
```

### 1.3 Config

```yaml
sessions:
  checkpoints:
    enabled: true
    storage_dir: /var/lib/agentsh/checkpoints
    max_per_session: 10
    max_size_mb: 500
    auto_checkpoint:
      enabled: true
      triggers:
        - "rm"
        - "mv"
        - "git reset"
        - "git checkout"
    retention:
      max_age: 24h
      cleanup_interval: 1h
```

### 1.4 New Interface

```go
// internal/session/checkpoint.go

// FileCheckpointStorage provides persistent checkpoint storage with file backup.
type FileCheckpointStorage interface {
    CheckpointStorage

    // CreateSnapshot backs up specified files to checkpoint storage.
    // Returns the checkpoint with CanRollback=true if successful.
    CreateSnapshot(sessionID, checkpointID string, files []string, workspacePath string) error

    // Rollback restores files from checkpoint to workspace.
    // Returns list of restored files.
    Rollback(sessionID, checkpointID string, workspacePath string) ([]string, error)

    // Diff returns files that changed between checkpoint and current workspace.
    Diff(sessionID, checkpointID string, workspacePath string) ([]FileDiff, error)
}

type FileDiff struct {
    Path       string
    Status     string // "added", "modified", "deleted"
    OldHash    string
    NewHash    string
}
```

### 1.5 CLI Commands

```bash
# Create checkpoint manually
agentsh checkpoint create --session <id> --reason "before refactor"

# List checkpoints
agentsh checkpoint list --session <id>

# Show checkpoint details and diff
agentsh checkpoint show <checkpoint-id> --diff

# Rollback to checkpoint
agentsh checkpoint rollback <checkpoint-id> [--dry-run]

# Purge old checkpoints
agentsh checkpoint purge --older-than 24h
```

### 1.6 Auto-Checkpoint Integration

Modify command execution to auto-checkpoint before risky commands:

```go
// internal/api/core.go - in executeCommand()

func (a *App) executeCommand(ctx context.Context, session *Session, cmd string, args []string) {
    // Check if command triggers auto-checkpoint
    if a.shouldAutoCheckpoint(cmd, args) {
        // Get files that would be affected (heuristic based on args)
        affectedFiles := a.predictAffectedFiles(session.Workspace, cmd, args)

        // Create checkpoint
        cp, err := a.checkpointManager.CreateCheckpointWithSnapshot(
            session,
            fmt.Sprintf("pre_command:%s", cmd),
            affectedFiles,
        )
        if err != nil {
            a.logger.Warn("auto-checkpoint failed", "error", err)
        }
    }

    // ... proceed with command execution
}
```

### 1.7 Files

- `internal/session/checkpoint.go` - Add `FileCheckpointStorage`, `Rollback`, `Diff`
- `internal/session/checkpoint_file.go` - File-based storage implementation
- `internal/session/checkpoint_file_test.go` - Tests
- `internal/cli/checkpoint.go` - CLI commands
- `internal/api/checkpoint_handlers.go` - REST API endpoints
- Update `internal/config/config.go` - Add `SessionCheckpointConfig`

### 1.8 Edge Cases

- **Large files:** Skip files > configurable size limit (default 100MB)
- **Binary files:** Store as-is, no special handling needed
- **Symlinks:** Store target path, not followed content
- **Permissions:** Preserve mode, uid, gid (use existing trash metadata pattern)
- **Concurrent access:** Use file locking during snapshot/rollback
- **Disk space:** Check available space before snapshot, fail gracefully

---

## Phase 2: External KMS Integration

Add support for external Key Management Systems for HMAC keys used in audit integrity chains.

### 2.1 Current State Analysis

**What exists:**
- `internal/audit/integrity.go` - HMAC chain with `LoadKey(keyFile, keyEnv)`
- Keys loaded from local file or environment variable only
- `AuditIntegrityConfig` has `KeyFile` and `KeyEnv` fields

**Gap:** No HSM/KMS support. Keys stored in plaintext on disk.

### 2.2 Solution: KMS Provider Interface

**Design:** Abstract key loading behind a provider interface. Implement providers for:
1. Local file (existing)
2. AWS KMS (data key envelope encryption)
3. Azure Key Vault
4. HashiCorp Vault
5. GCP Cloud KMS

**Key derivation model:** For HMAC, we need raw key bytes. KMS services typically provide:
- AWS: `GenerateDataKey` returns plaintext + encrypted DEK
- Azure: `UnwrapKey` for envelope encryption
- Vault: Transit secrets engine or direct key retrieval
- GCP: `decrypt` for envelope encryption

### 2.3 Config

```yaml
audit:
  integrity:
    enabled: true
    algorithm: hmac-sha256

    # Key source (mutually exclusive)
    key_source: aws_kms  # file, env, aws_kms, azure_keyvault, hashicorp_vault, gcp_kms

    # File source (existing)
    key_file: /etc/agentsh/audit.key
    key_env: AGENTSH_AUDIT_KEY

    # AWS KMS
    aws_kms:
      key_id: "arn:aws:kms:us-east-1:123456789:key/abc-123"
      region: us-east-1
      # Uses default credential chain (env, shared config, IAM role)
      encrypted_dek_file: /etc/agentsh/audit-dek.enc  # Cached encrypted DEK

    # Azure Key Vault
    azure_keyvault:
      vault_url: "https://myvault.vault.azure.net"
      key_name: "agentsh-audit-key"
      key_version: ""  # Empty = latest
      # Uses DefaultAzureCredential

    # HashiCorp Vault
    hashicorp_vault:
      address: "https://vault.example.com:8200"
      auth_method: kubernetes  # token, kubernetes, approle
      token_file: /var/run/secrets/vault/token
      kubernetes_role: agentsh
      secret_path: "secret/data/agentsh/audit-key"
      key_field: "hmac_key"

    # GCP Cloud KMS
    gcp_kms:
      key_name: "projects/my-proj/locations/us/keyRings/agentsh/cryptoKeys/audit"
      encrypted_dek_file: /etc/agentsh/audit-dek.enc
```

### 2.4 KMS Provider Interface

```go
// internal/audit/kms/provider.go

package kms

import "context"

// Provider abstracts key retrieval from various KMS backends.
type Provider interface {
    // Name returns the provider identifier (for logging).
    Name() string

    // GetKey retrieves or derives the HMAC key.
    // For envelope encryption providers, this decrypts the DEK.
    GetKey(ctx context.Context) ([]byte, error)

    // Close releases any resources (connections, caches).
    Close() error
}

// Config holds provider-specific configuration.
type Config struct {
    Source string // file, env, aws_kms, azure_keyvault, hashicorp_vault, gcp_kms

    // File/Env
    KeyFile string
    KeyEnv  string

    // AWS
    AWSKeyID           string
    AWSRegion          string
    AWSEncryptedDEKFile string

    // Azure
    AzureVaultURL   string
    AzureKeyName    string
    AzureKeyVersion string

    // Vault
    VaultAddress    string
    VaultAuthMethod string
    VaultTokenFile  string
    VaultK8sRole    string
    VaultSecretPath string
    VaultKeyField   string

    // GCP
    GCPKeyName          string
    GCPEncryptedDEKFile string
}

// NewProvider creates a provider based on configuration.
func NewProvider(cfg Config) (Provider, error) {
    switch cfg.Source {
    case "file", "env", "":
        return NewFileProvider(cfg.KeyFile, cfg.KeyEnv)
    case "aws_kms":
        return NewAWSKMSProvider(cfg.AWSKeyID, cfg.AWSRegion, cfg.AWSEncryptedDEKFile)
    case "azure_keyvault":
        return NewAzureKeyVaultProvider(cfg.AzureVaultURL, cfg.AzureKeyName, cfg.AzureKeyVersion)
    case "hashicorp_vault":
        return NewVaultProvider(cfg.VaultAddress, cfg.VaultAuthMethod, cfg.VaultTokenFile, cfg.VaultK8sRole, cfg.VaultSecretPath, cfg.VaultKeyField)
    case "gcp_kms":
        return NewGCPKMSProvider(cfg.GCPKeyName, cfg.GCPEncryptedDEKFile)
    default:
        return nil, fmt.Errorf("unknown key source: %s", cfg.Source)
    }
}
```

### 2.5 AWS KMS Provider (Envelope Encryption)

```go
// internal/audit/kms/aws.go

package kms

import (
    "context"
    "os"

    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/kms"
)

type AWSKMSProvider struct {
    keyID           string
    region          string
    encryptedDEKFile string
    client          *kms.Client
    cachedKey       []byte
}

func NewAWSKMSProvider(keyID, region, encryptedDEKFile string) (*AWSKMSProvider, error) {
    cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
    if err != nil {
        return nil, err
    }
    return &AWSKMSProvider{
        keyID:           keyID,
        region:          region,
        encryptedDEKFile: encryptedDEKFile,
        client:          kms.NewFromConfig(cfg),
    }, nil
}

func (p *AWSKMSProvider) GetKey(ctx context.Context) ([]byte, error) {
    if p.cachedKey != nil {
        return p.cachedKey, nil
    }

    // Try to load and decrypt existing DEK
    if p.encryptedDEKFile != "" {
        if encDEK, err := os.ReadFile(p.encryptedDEKFile); err == nil {
            resp, err := p.client.Decrypt(ctx, &kms.DecryptInput{
                KeyId:          &p.keyID,
                CiphertextBlob: encDEK,
            })
            if err == nil {
                p.cachedKey = resp.Plaintext
                return p.cachedKey, nil
            }
        }
    }

    // Generate new DEK
    resp, err := p.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
        KeyId:   &p.keyID,
        KeySpec: "AES_256",
    })
    if err != nil {
        return nil, err
    }

    // Cache encrypted DEK to file
    if p.encryptedDEKFile != "" {
        _ = os.WriteFile(p.encryptedDEKFile, resp.CiphertextBlob, 0600)
    }

    p.cachedKey = resp.Plaintext
    return p.cachedKey, nil
}
```

### 2.6 Files

- `internal/audit/kms/provider.go` - Provider interface
- `internal/audit/kms/file.go` - File/env provider (refactor from integrity.go)
- `internal/audit/kms/aws.go` - AWS KMS provider
- `internal/audit/kms/azure.go` - Azure Key Vault provider
- `internal/audit/kms/vault.go` - HashiCorp Vault provider
- `internal/audit/kms/gcp.go` - GCP Cloud KMS provider
- `internal/audit/kms/*_test.go` - Tests (with mocks)
- Update `internal/audit/integrity.go` - Use Provider interface
- Update `internal/config/config.go` - Add KMS config structs

### 2.7 Dependencies

```go
// go.mod additions
require (
    github.com/aws/aws-sdk-go-v2 v1.x
    github.com/aws/aws-sdk-go-v2/config v1.x
    github.com/aws/aws-sdk-go-v2/service/kms v1.x
    github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys v1.x
    github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.x
    github.com/hashicorp/vault/api v1.x
    cloud.google.com/go/kms v1.x
)
```

### 2.8 Edge Cases

- **Key rotation:** DEK cached locally; rotation = delete cache file + restart
- **Network failure:** Cache key in memory after first successful fetch
- **Credential refresh:** Use SDK default credential chains with auto-refresh
- **Startup without network:** Fail fast with clear error if KMS unreachable
- **Testing:** Provide mock provider for unit tests

---

## Phase 3: SIEM Log Shipping

Extend audit event shipping beyond simple HTTP webhooks to support enterprise SIEM systems.

### 3.1 Current State Analysis

**What exists:**
- `internal/store/webhook/webhook.go` - HTTP POST with JSON batching
- `AuditWebhookConfig` with URL, headers, batch settings
- Composite store pattern (`internal/store/composite/`) for multi-destination

**Gap:** No syslog, Splunk HEC, or OpenTelemetry support.

### 3.2 Solution: SIEM Shipper Interface

**Design:** Create a shipper abstraction with implementations for:
1. HTTP Webhook (existing, refactored)
2. Syslog (RFC5424 over TCP/UDP/TLS)
3. Splunk HEC (HTTP Event Collector)
4. OpenTelemetry (OTLP logs exporter)

### 3.3 Config

```yaml
audit:
  enabled: true

  # Multiple shippers can be enabled simultaneously
  shippers:
    # Existing webhook (enhanced)
    webhook:
      enabled: false
      url: "https://siem.example.com/events"
      batch_size: 100
      flush_interval: 10s
      timeout: 5s
      headers:
        Authorization: "Bearer ${SIEM_TOKEN}"
      retry:
        max_attempts: 3
        backoff: exponential
        initial_delay: 1s

    # Syslog RFC5424
    syslog:
      enabled: true
      protocol: tcp+tls  # udp, tcp, tcp+tls
      address: "syslog.example.com:6514"
      facility: local0   # kern, user, mail, daemon, auth, syslog, lpr, news, uucp, cron, local0-7
      app_name: agentsh
      hostname: ""       # Empty = auto-detect
      tls:
        cert_file: /etc/agentsh/syslog-client.crt
        key_file: /etc/agentsh/syslog-client.key
        ca_file: /etc/agentsh/syslog-ca.crt
        insecure_skip_verify: false
      structured_data:
        enterprise_id: "12345"  # Your IANA enterprise number

    # Splunk HTTP Event Collector
    splunk_hec:
      enabled: true
      url: "https://splunk.example.com:8088/services/collector/event"
      token: "${SPLUNK_HEC_TOKEN}"
      index: "agentsh"
      source: "agentsh"
      sourcetype: "agentsh:audit"
      batch_size: 50
      flush_interval: 5s
      timeout: 10s
      tls:
        insecure_skip_verify: false

    # OpenTelemetry OTLP
    otlp:
      enabled: false
      endpoint: "otel-collector.example.com:4317"
      protocol: grpc  # grpc, http
      headers:
        api-key: "${OTEL_API_KEY}"
      tls:
        insecure: false
        cert_file: ""
        key_file: ""
        ca_file: ""
      resource_attributes:
        service.name: agentsh
        service.version: "${AGENTSH_VERSION}"
        deployment.environment: production
```

### 3.4 Shipper Interface

```go
// internal/audit/shipper/shipper.go

package shipper

import (
    "context"
    "github.com/agentsh/agentsh/pkg/types"
)

// Shipper sends audit events to external systems.
type Shipper interface {
    // Name returns the shipper identifier.
    Name() string

    // Ship sends events to the destination.
    // May buffer and batch internally.
    Ship(ctx context.Context, events []types.Event) error

    // Flush forces pending events to be sent.
    Flush(ctx context.Context) error

    // Close releases resources and flushes remaining events.
    Close() error

    // Healthy returns nil if the shipper is operational.
    Healthy(ctx context.Context) error
}

// MultiShipper sends events to multiple destinations.
type MultiShipper struct {
    shippers []Shipper
    failMode string // "any" (fail if any fails), "all" (fail only if all fail)
}

func (m *MultiShipper) Ship(ctx context.Context, events []types.Event) error {
    var errs []error
    for _, s := range m.shippers {
        if err := s.Ship(ctx, events); err != nil {
            errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
        }
    }
    return m.handleErrors(errs)
}
```

### 3.5 Syslog Shipper (RFC5424)

```go
// internal/audit/shipper/syslog.go

package shipper

import (
    "crypto/tls"
    "fmt"
    "net"
    "time"

    "github.com/agentsh/agentsh/pkg/types"
)

type SyslogShipper struct {
    protocol   string // udp, tcp, tcp+tls
    address    string
    facility   int
    appName    string
    hostname   string
    entID      string // Enterprise ID for structured data

    conn       net.Conn
    tlsConfig  *tls.Config
}

// RFC5424 format:
// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID SD-PARAMS] MSG

func (s *SyslogShipper) Ship(ctx context.Context, events []types.Event) error {
    for _, ev := range events {
        msg := s.formatRFC5424(ev)
        if _, err := s.conn.Write([]byte(msg)); err != nil {
            return err
        }
    }
    return nil
}

func (s *SyslogShipper) formatRFC5424(ev types.Event) string {
    // PRI = Facility * 8 + Severity
    severity := s.eventSeverity(ev.Type)
    pri := s.facility*8 + severity

    // Structured data with event details
    sd := fmt.Sprintf(`[agentsh@%s session_id="%s" event_type="%s"]`,
        s.entID, ev.SessionID, ev.Type)

    // JSON payload as message
    msg, _ := json.Marshal(ev.Payload)

    return fmt.Sprintf("<%d>1 %s %s %s - - %s %s\n",
        pri,
        ev.Timestamp.UTC().Format(time.RFC3339Nano),
        s.hostname,
        s.appName,
        sd,
        msg,
    )
}
```

### 3.6 Splunk HEC Shipper

```go
// internal/audit/shipper/splunk.go

package shipper

import (
    "bytes"
    "encoding/json"
    "net/http"

    "github.com/agentsh/agentsh/pkg/types"
)

type SplunkHECShipper struct {
    url        string
    token      string
    index      string
    source     string
    sourcetype string

    client     *http.Client
    buffer     []splunkEvent
    batchSize  int
}

type splunkEvent struct {
    Time       float64        `json:"time"`
    Host       string         `json:"host,omitempty"`
    Source     string         `json:"source,omitempty"`
    Sourcetype string         `json:"sourcetype,omitempty"`
    Index      string         `json:"index,omitempty"`
    Event      any            `json:"event"`
}

func (s *SplunkHECShipper) Ship(ctx context.Context, events []types.Event) error {
    for _, ev := range events {
        se := splunkEvent{
            Time:       float64(ev.Timestamp.UnixNano()) / 1e9,
            Source:     s.source,
            Sourcetype: s.sourcetype,
            Index:      s.index,
            Event:      ev,
        }
        s.buffer = append(s.buffer, se)

        if len(s.buffer) >= s.batchSize {
            if err := s.flush(ctx); err != nil {
                return err
            }
        }
    }
    return nil
}

func (s *SplunkHECShipper) flush(ctx context.Context) error {
    if len(s.buffer) == 0 {
        return nil
    }

    // Splunk HEC accepts newline-delimited JSON
    var body bytes.Buffer
    for _, ev := range s.buffer {
        json.NewEncoder(&body).Encode(ev)
    }

    req, _ := http.NewRequestWithContext(ctx, "POST", s.url, &body)
    req.Header.Set("Authorization", "Splunk "+s.token)
    req.Header.Set("Content-Type", "application/json")

    resp, err := s.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return fmt.Errorf("splunk hec: %s", resp.Status)
    }

    s.buffer = nil
    return nil
}
```

### 3.7 OpenTelemetry Shipper

```go
// internal/audit/shipper/otlp.go

package shipper

import (
    "context"

    "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
    "go.opentelemetry.io/otel/log"
    sdklog "go.opentelemetry.io/otel/sdk/log"
    "go.opentelemetry.io/otel/sdk/resource"

    "github.com/agentsh/agentsh/pkg/types"
)

type OTLPShipper struct {
    exporter *otlploggrpc.Exporter
    provider *sdklog.LoggerProvider
    logger   log.Logger
}

func NewOTLPShipper(endpoint string, headers map[string]string, resourceAttrs map[string]string) (*OTLPShipper, error) {
    ctx := context.Background()

    // Create exporter
    exporter, err := otlploggrpc.New(ctx,
        otlploggrpc.WithEndpoint(endpoint),
        otlploggrpc.WithHeaders(headers),
    )
    if err != nil {
        return nil, err
    }

    // Create resource
    res, _ := resource.New(ctx,
        resource.WithAttributes(attrsFromMap(resourceAttrs)...),
    )

    // Create provider
    provider := sdklog.NewLoggerProvider(
        sdklog.WithResource(res),
        sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
    )

    return &OTLPShipper{
        exporter: exporter,
        provider: provider,
        logger:   provider.Logger("agentsh.audit"),
    }, nil
}

func (s *OTLPShipper) Ship(ctx context.Context, events []types.Event) error {
    for _, ev := range events {
        record := log.Record{}
        record.SetTimestamp(ev.Timestamp)
        record.SetSeverity(s.eventSeverity(ev.Type))
        record.SetBody(log.StringValue(ev.Type))

        record.AddAttributes(
            log.String("session_id", ev.SessionID),
            log.String("event_type", ev.Type),
        )

        // Add payload as nested attributes
        if payload, err := json.Marshal(ev.Payload); err == nil {
            record.AddAttributes(log.String("payload", string(payload)))
        }

        s.logger.Emit(ctx, record)
    }
    return nil
}
```

### 3.8 Files

- `internal/audit/shipper/shipper.go` - Interface and MultiShipper
- `internal/audit/shipper/webhook.go` - Refactored from webhook store
- `internal/audit/shipper/syslog.go` - RFC5424 implementation
- `internal/audit/shipper/splunk.go` - Splunk HEC implementation
- `internal/audit/shipper/otlp.go` - OpenTelemetry implementation
- `internal/audit/shipper/*_test.go` - Tests
- Update `internal/config/config.go` - Add shipper configs
- Update `internal/server/server.go` - Wire up shippers

### 3.9 Dependencies

```go
// go.mod additions
require (
    go.opentelemetry.io/otel v1.x
    go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc v0.x
    go.opentelemetry.io/otel/sdk/log v0.x
)
```

### 3.10 Edge Cases

- **Network failure:** Buffer events in memory (up to configurable limit), retry with backoff
- **Slow destination:** Don't block command execution; buffer asynchronously
- **Large events:** Truncate oversized payloads with marker
- **TLS failures:** Clear error messages, support skip-verify for testing
- **Multiple destinations:** Configurable fail mode (any vs all)
- **Graceful shutdown:** Flush pending events before exit

---

## Summary

| Phase | Feature | Complexity | Dependencies |
|-------|---------|------------|--------------|
| Phase 1 | Checkpoint/Rollback | Medium | None (pure Go) |
| Phase 2 | External KMS | High | AWS/Azure/GCP/Vault SDKs |
| Phase 3 | SIEM Integration | Medium | OpenTelemetry SDK |

**Implementation Order:**
1. Phase 1 (Checkpoint/Rollback) - No external dependencies, foundational
2. Phase 3 (SIEM Integration) - High enterprise value, moderate complexity
3. Phase 2 (External KMS) - Most external dependencies, can be incremental

**Total Estimated Files:** ~25 new files + ~10 modified files

---

## CLI Summary

```bash
# Checkpoints
agentsh checkpoint create --session <id> --reason "before deploy"
agentsh checkpoint list --session <id>
agentsh checkpoint show <cp-id> --diff
agentsh checkpoint rollback <cp-id> [--dry-run]
agentsh checkpoint purge --older-than 24h

# KMS (diagnostic)
agentsh audit key-source   # Show current key source
agentsh audit test-kms     # Test KMS connectivity

# SIEM (diagnostic)
agentsh audit shipper status           # Show shipper health
agentsh audit shipper test --shipper syslog  # Test specific shipper
```

---

> **Status:** Design complete. Ready for implementation.
