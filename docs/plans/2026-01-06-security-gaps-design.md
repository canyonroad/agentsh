# Security Gaps Implementation Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan phase-by-phase.

**Goal:** Address Tier 1 and Tier 2 security gaps identified in the agentsh security audit.

**Architecture:** Three phased releases - Audit Hardening, Auth Expansion, MCP Security - each building on the previous to create defense-in-depth.

**Tech Stack:** Go, SQLCipher, go-webauthn, go-oidc, token bucket rate limiting

---

## Phase 1: Audit Hardening

Foundation for compliance and forensics. ~3 weeks.

### 1.1 Tamper-Proof Audit Logs

**Problem:** Current audit logs (JSONL/SQLite) can be modified if the agentsh process or disk is compromised. No cryptographic proof of integrity.

**Solution:** HMAC chain where each log entry includes a hash of the previous entry, creating an append-only verifiable chain.

**Entry format:**
```json
{
  "...event fields...",
  "integrity": {
    "sequence": 12345,
    "prev_hash": "sha256:abc123...",
    "entry_hash": "sha256:def456..."
  }
}
```

**Key management:** HMAC key derived from a root secret in config. For higher security, support external KMS (future phase).

**Verification:** New CLI command `agentsh audit verify --path <log>` walks the chain and reports any breaks or tampering.

**Config:**
```yaml
audit:
  integrity:
    enabled: true
    key_file: /etc/agentsh/audit-integrity.key
```

**Files:**
- `internal/audit/integrity.go` - Chain logic, HMAC computation
- `internal/audit/verify.go` - Verification logic
- `internal/cli/audit_verify.go` - CLI command
- Update `internal/events/broker.go` - Add integrity wrapper before writing

**Edge cases:**
- Log rotation: Each rotated file ends with a "rotation" entry containing the final hash; new file starts with reference to it
- Crash recovery: On startup, read last N entries to find valid chain tail

---

### 1.2 Encryption at Rest

**Problem:** Audit logs and session data stored as plaintext. Disk theft or backup compromise exposes all history.

**Solution:** SQLCipher for SQLite audit DB + envelope encryption for JSONL exports.

**Config:**
```yaml
audit:
  encryption:
    enabled: true
    key_source: file
    key_file: /etc/agentsh/audit.key
```

**Key rotation:** Support re-encryption command `agentsh audit rekey --new-key <path>`.

**Files:**
- `internal/audit/crypto.go` - encryption/decryption helpers
- Update `internal/audit/sqlite.go` to use SQLCipher driver
- `internal/cli/audit_rekey.go` - Key rotation command

**Dependencies:**
- `github.com/mutecomm/go-sqlcipher/v4` - SQLCipher Go bindings (CGO)

---

### 1.3 Policy Change Audit

**Problem:** No record of who changed policies, when, or what changed. Can't investigate security incidents involving policy tampering.

**Solution:** Emit audit events whenever policies are loaded or changed, with diff.

**Events:**
```json
{
  "event_type": "policy.loaded",
  "policy_name": "default",
  "policy_version": "sha256:abc123",
  "policy_path": "/etc/agentsh/policies/default.yaml",
  "loaded_by": "startup"
}

{
  "event_type": "policy.changed",
  "policy_name": "default",
  "old_version": "sha256:abc123",
  "new_version": "sha256:def456",
  "diff_summary": "+2 rules, -1 rule, ~3 modified",
  "changed_by": "api:operator-123"
}
```

**Storage:** Policy history in SQLite `policy_versions` table with full content.

**Files:**
- `internal/policies/audit.go` - diff and event emission
- `internal/policies/history.go` - version storage
- New event types in `internal/events/types.go`

---

### 1.4 DR Documentation + Backup CLI

**Problem:** No documented procedure for backup, restore, or disaster recovery.

**Deliverables:**
1. `docs/operations/backup-restore.md` - What to backup, how to restore
2. `docs/operations/disaster-recovery.md` - Full DR runbook
3. CLI commands for backup/restore automation

**Backup scope:**
- SQLite audit DB
- Policy files
- Config files
- MCP pins (Phase 3)

**CLI commands:**
```bash
agentsh backup --output /path/to/backup.tar.gz
agentsh restore --input /path/to/backup.tar.gz --verify
```

**Files:**
- `internal/cli/backup.go` - backup command
- `internal/cli/restore.go` - restore command
- `docs/operations/backup-restore.md`
- `docs/operations/disaster-recovery.md`

---

## Phase 2: Auth Expansion

Stronger identity and approval mechanisms. ~3 weeks.

### 2.1 WebAuthn/FIDO2 Approval Mode

**Problem:** TOTP is phishable. Hardware security keys provide cryptographic proof of presence and origin binding.

**Solution:** Add `webauthn` as a fourth approval mode.

**Flow:**
1. Session creation → Generate WebAuthn challenge, store in session
2. Approval needed → Return challenge to approval UI
3. User touches security key → Browser/CLI signs challenge
4. agentsh verifies signature against registered credential
5. Approval granted

**Config:**
```yaml
approvals:
  enabled: true
  mode: webauthn
  timeout: 5m
  webauthn:
    rp_id: "agentsh.local"
    rp_name: "agentsh"
    rp_origins:
      - "http://localhost:18080"
    user_verification: preferred
```

**Files:**
- `internal/approvals/webauthn.go` - challenge/response logic
- `internal/approvals/webauthn_store.go` - credential storage
- `internal/api/webauthn_handlers.go` - registration/authentication endpoints
- `internal/cli/auth_webauthn.go` - CLI for credential management

**Dependencies:**
- `github.com/go-webauthn/webauthn`

---

### 2.2 OAuth/SSO Integration

**Problem:** Operators authenticate with static API keys. Enterprises need SSO.

**Solution:** Support OAuth 2.0 / OpenID Connect for operator authentication.

**Config:**
```yaml
auth:
  type: oidc
  oidc:
    issuer: "https://corp.okta.com"
    client_id: "agentsh-server"
    audience: "agentsh"
    jwks_cache_ttl: 1h
    claim_mappings:
      operator_id: "sub"
      groups: "groups"
    allowed_groups:
      - "agentsh-operators"
    group_policy_map:
      "sre-team": "privileged"
      "dev-team": "restricted"
```

**Hybrid mode:** Support both API keys AND OIDC simultaneously.

**Files:**
- `internal/auth/oidc.go` - JWT validation, JWKS fetching
- `internal/auth/oidc_claims.go` - claim extraction and mapping
- Update `internal/api/middleware.go` - support both auth types

**Dependencies:**
- `github.com/coreos/go-oidc/v3`

---

## Phase 3: MCP Security

Hardening the MCP attack surface. ~3 weeks.

### 3.1 MCP Tool Whitelisting

**Problem:** Any discovered MCP tool can be invoked. No way to restrict which tools are allowed.

**Solution:** Policy-based tool allowlist with hash verification.

**Policy syntax:**
```yaml
mcp:
  tool_policy: allowlist
  allowed_tools:
    - server: "filesystem"
      tool: "read_file"
    - server: "github"
      tool: "*"
    - server: "custom-server"
      tool: "query_db"
      content_hash: "sha256:abc123..."
  denied_tools:
    - server: "*"
      tool: "execute_shell"
```

**Config:**
```yaml
sandbox:
  mcp:
    enforce_policy: true
    fail_closed: true
```

**Files:**
- `internal/mcpinspect/policy.go` - tool policy evaluation
- `internal/policies/mcp.go` - MCP policy section parsing

---

### 3.2 MCP Version Pinning

**Problem:** MCP tool implementations can change between invocations (rug pull).

**Solution:** Record tool content hash on first discovery, alert or block if it changes.

**Config:**
```yaml
sandbox:
  mcp:
    version_pinning:
      enabled: true
      on_change: block
      auto_trust_first: false
```

**CLI commands:**
```bash
agentsh mcp pins list
agentsh mcp pins trust --server github --tool create_issue
agentsh mcp pins diff --server github --tool create_issue
agentsh mcp pins reset --server github --tool create_issue
```

**Files:**
- `internal/mcpinspect/pins.go` - Pin storage and comparison
- `internal/cli/mcp_pins.go` - CLI commands

---

### 3.3 Rate Limiting

**Problem:** No limits on API/network calls. Agent can exhaust external API quotas.

**Solution:** Token bucket rate limiting at multiple layers.

**Config:**
```yaml
sandbox:
  rate_limits:
    enabled: true
    global:
      requests_per_minute: 600
      burst: 50
    domains:
      "api.openai.com":
        requests_per_minute: 60
        burst: 10
      "*":
        requests_per_minute: 300
        burst: 30
    mcp:
      "*":
        calls_per_minute: 120
        burst: 20
```

**Files:**
- `internal/ratelimit/limiter.go` - Token bucket implementation
- `internal/ratelimit/registry.go` - Per-domain/server limiter registry
- Integration in `internal/netmonitor/proxy.go` and `internal/mcpinspect/registry.go`

---

## Summary

| Phase | Features | Est. Effort |
|-------|----------|-------------|
| Phase 1: Audit Hardening | Tamper-proof logs, Encryption at rest, Policy audit, DR docs | ~3 weeks |
| Phase 2: Auth Expansion | WebAuthn/FIDO2, OAuth/SSO | ~3 weeks |
| Phase 3: MCP Security | Tool whitelisting, Version pinning, Rate limiting | ~3 weeks |

**Total:** ~9 weeks
