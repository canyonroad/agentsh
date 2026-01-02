# Windows Registry Monitoring and Blocking Design

**Date:** 2026-01-02
**Status:** Approved

## Overview

Implement full registry monitoring and blocking for Windows via the mini filter driver. This provides workspace-scoped enforcement for sandboxed processes plus always-on monitoring of high-risk persistence paths.

## Goals

- Block sandboxed processes from writing to sensitive registry locations
- Monitor high-risk paths (Run keys, Services, LSA, etc.) regardless of sandbox state
- Support allow, deny (silent), deny (notify), and approve (with timeout) actions
- Integrate with existing approval flow and event system
- Cache decisions for performance with per-rule TTL override

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     User-Mode (agentsh.exe)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │ PolicyEngine │  │ PolicyAdapter│  │  ApprovalManager   │    │
│  │ (rules eval) │◄─┤ .CheckReg()  │◄─┤ (timeout handling) │    │
│  └──────────────┘  └──────────────┘  └────────────────────┘    │
│         ▲                  ▲                    ▲               │
│         │                  │                    │               │
│  ┌──────┴──────────────────┴────────────────────┴──────────┐   │
│  │                    DriverClient                          │   │
│  │  - handleRegistryPolicyCheck()                           │   │
│  │  - registryPolicyHandler callback                        │   │
│  └──────────────────────────┬──────────────────────────────┘   │
└─────────────────────────────┼───────────────────────────────────┘
                              │ FilterPort
┌─────────────────────────────┼───────────────────────────────────┐
│  Kernel-Mode (agentsh.sys)  │                                   │
│  ┌──────────────────────────┴──────────────────────────────┐   │
│  │              CmRegisterCallbackEx                        │   │
│  │  - Intercepts: RegNtPreSetValueKey, RegNtPreCreateKey,  │   │
│  │    RegNtPreDeleteKey, RegNtPreDeleteValueKey, etc.      │   │
│  │  - Sends MsgPolicyCheckRegistry to user-mode            │   │
│  │  - Caches decisions (path+op → TTL)                     │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Policy Configuration Format

```yaml
registry_policy:
  default_action: deny          # deny | allow | approve
  log_all: true                 # Log all operations (even allowed)
  default_cache_ttl: 30         # Seconds, 0 = no cache
  notify_on_deny: true          # Emit event on denied operations

  rules:
    # Workspace-scoped rules (evaluated first)
    - name: allow-app-settings
      paths:
        - "HKCU\\SOFTWARE\\${APP_NAME}\\*"
      operations: [read, write, create, delete]
      action: allow
      cache_ttl: 60

    # High-risk path overrides (always evaluated)
    - name: block-run-keys
      paths:
        - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        - "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
      operations: [write, create, delete]
      action: deny
      priority: 1000
      notify: true

    # Approve mode for sensitive but sometimes legitimate
    - name: approve-service-install
      paths:
        - "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*"
      operations: [create]
      action: approve
      timeout_seconds: 30
      cache_ttl: 0
```

### Rule Evaluation

1. Rules sorted by `priority` (higher first, default 0)
2. First matching rule wins
3. If no rule matches → `default_action`

### Variable Expansion

- `${WORKSPACE}` - Current workspace path
- `${APP_NAME}` - Application identifier
- `*` glob matches any subpath segment

## Driver Protocol

### Request Message (driver → user-mode)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | MessageType (2 = MsgPolicyCheckRegistry) |
| 2 | 2 | MessageSize |
| 4 | 8 | SessionToken |
| 12 | 4 | ProcessId |
| 16 | 4 | ThreadId |
| 20 | 4 | Operation (enum) |
| 24 | 4 | ValueType (REG_SZ, REG_DWORD, etc.) |
| 28 | 4 | DataSize |
| 32 | 1040 | KeyPath (UTF-16LE, 520 chars max) |
| 1072 | 512 | ValueName (UTF-16LE, 256 chars max) |

### Operation Enum

```go
const (
    RegOpQueryValue   = 1
    RegOpSetValue     = 2
    RegOpDeleteValue  = 3
    RegOpCreateKey    = 4
    RegOpDeleteKey    = 5
    RegOpEnumKeys     = 6
    RegOpEnumValues   = 7
    RegOpOpenKey      = 8
    RegOpRenameKey    = 9
)
```

### Response Message (user-mode → driver)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | MessageType (2) |
| 2 | 2 | Reserved |
| 4 | 4 | Decision (0=deny, 1=allow, 2=pending) |
| 8 | 4 | CacheTTL (seconds) |
| 12 | 4 | Flags (bit 0: notify, bit 1: log) |
| 16 | 8 | Reserved |

### Kernel Callbacks

Intercepted via `CmRegisterCallbackEx` at altitude "385200":

- `RegNtPreSetValueKey` → block/allow value writes
- `RegNtPreDeleteValueKey` → block/allow value deletes
- `RegNtPreCreateKeyEx` → block/allow key creation
- `RegNtPreDeleteKey` → block/allow key deletion
- `RegNtPreRenameKey` → block/allow key rename

Read operations monitored but typically allowed by default.

## User-Mode Implementation

### Files to Modify

**`internal/platform/windows/driver_client.go`**
```go
type RegistryPolicyHandler func(req *RegistryPolicyRequest) *RegistryPolicyResponse

type RegistryPolicyRequest struct {
    SessionToken uint64
    ProcessID    uint32
    ThreadID     uint32
    Operation    RegistryOperation
    ValueType    uint32
    DataSize     uint32
    KeyPath      string
    ValueName    string
}

type RegistryPolicyResponse struct {
    Decision  PolicyDecision
    CacheTTL  uint32
    Notify    bool
    LogEvent  bool
}
```

**`internal/platform/policy_adapter.go`**
```go
func (a *PolicyAdapter) CheckRegistry(
    ctx context.Context,
    req *RegistryPolicyRequest,
) (*RegistryPolicyResponse, error) {
    // 1. Check if process belongs to a registered session
    // 2. If not sandboxed → allow (unless high-risk path)
    // 3. Evaluate rules in priority order
    // 4. If action=approve → delegate to ApprovalManager
    // 5. Return decision with cache TTL
}
```

**`internal/policy/model.go`**
```go
type RegistryRule struct {
    Name           string   `yaml:"name"`
    Paths          []string `yaml:"paths"`
    Operations     []string `yaml:"operations"`
    Action         string   `yaml:"action"`
    Priority       int      `yaml:"priority"`
    CacheTTL       int      `yaml:"cache_ttl"`
    TimeoutSeconds int      `yaml:"timeout_seconds"`
    Notify         bool     `yaml:"notify"`
}
```

**`internal/platform/windows/registry.go`**
- Remove polling-based `RegistryMonitor` (driver handles interception)
- Keep `HighRiskPaths` definitions
- Keep event emission helpers
- Keep risk level classification

## Event Format

### Event Types

```go
const (
    EventRegistryRead            = "registry_read"
    EventRegistryWrite           = "registry_write"
    EventRegistryCreate          = "registry_create"
    EventRegistryDelete          = "registry_delete"
    EventRegistryRename          = "registry_rename"
    EventRegistryBlocked         = "registry_blocked"
    EventRegistryApprovalRequest = "registry_approval_request"
    EventRegistryApprovalResponse = "registry_approval_response"
)
```

### Event Payload

```go
type RegistryEvent struct {
    Timestamp   time.Time `json:"timestamp"`
    Type        string    `json:"type"`
    SessionID   string    `json:"session_id"`
    KeyPath     string    `json:"key_path"`
    ValueName   string    `json:"value_name,omitempty"`
    Operation   string    `json:"operation"`
    ProcessID   uint32    `json:"process_id"`
    ProcessName string    `json:"process_name,omitempty"`
    Decision    string    `json:"decision"`
    RuleName    string    `json:"rule_name,omitempty"`
    RiskLevel   string    `json:"risk_level,omitempty"`
    MitreTactic string    `json:"mitre_tactic,omitempty"`
    MitreID     string    `json:"mitre_id,omitempty"`
    Description string    `json:"description,omitempty"`
}
```

## High-Risk Paths

Always monitored regardless of policy:

| Path | Risk | MITRE ID | Default |
|------|------|----------|---------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*` | Critical | T1547.001 | deny |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*` | Critical | T1547.001 | deny |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Critical | T1543.003 | approve |
| `HKLM\...\Winlogon` | Critical | T1547.004 | deny |
| `HKLM\...\Image File Execution Options` | Critical | T1546.012 | deny |
| `HKLM\SOFTWARE\Classes\CLSID\*\InprocServer32` | High | T1546.015 | deny |
| `HKLM\SOFTWARE\Classes\*\shell\open\command` | High | T1546.001 | deny |
| `HKLM\...\Windows Defender` | Critical | T1562.001 | deny |
| `HKLM\...\Control\Lsa` | Critical | T1003 | deny |
| `HKLM\...\SecurityProviders` | Critical | T1547.005 | deny |
| `HKLM\...\Policies` | High | T1112 | approve |
| `HKLM\...\Cryptography\OID` | Medium | T1553.004 | deny |
| `HKLM\...\EnterpriseCertificates` | Medium | T1553.004 | deny |

### Behavior Rules

1. High-risk paths always evaluated, even for non-sandboxed processes
2. User policy rules can override defaults
3. Sandboxed processes default to deny for writes outside app keys
4. Read operations on high-risk paths allowed but logged

## Testing Strategy

### Unit Tests

- Policy matching: exact path, glob, operation filter, priority order
- Cache behavior: default TTL, per-rule override, zero disables
- Serialization: UTF-16 paths, response format

### Integration Tests (Windows + driver)

- Driver communication roundtrip
- Approval flow end-to-end
- Cache hit verification

### Manual Test Scenarios

1. Sandboxed Python → `winreg.SetValue()` on Run key → blocked
2. Same process → writes to `HKCU\SOFTWARE\TestApp\config` → allowed
3. Approval mode → create service key → prompt → approve → succeeds
4. Approval timeout → auto-denied
5. Non-sandboxed process → Run key write → logged, allowed

## Out of Scope

- Registry value redirection
- WinFsp-based registry virtualization
- Cross-session registry policy
