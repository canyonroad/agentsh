# macOS XPC Sandbox Design

**Status:** Implemented
**Created:** 2026-01-04
**Author:** Claude + Eran

## Overview

This design adds XPC/Mach IPC control to agentsh on macOS, providing the ability to monitor and block cross-process communication via XPC services. The implementation uses a two-layer approach: sandbox profiles for enforcement (blocking) and ESF for monitoring (audit).

## Goals

1. **Data exfiltration prevention**: Block XPC services that could leak data (pasteboard, AppleScript)
2. **Privilege escalation prevention**: Block services that enable privilege escalation (authhost, tccd)
3. **Visibility/audit**: Log all XPC connection attempts for forensics and compliance
4. **C2 prevention**: Restrict communication channels available to sandboxed processes

## Constraints

| Constraint | Implication |
|------------|-------------|
| No AUTH for XPC in ESF | Cannot block via ESF, only monitor |
| Sandbox is process-level | Must apply before exec, cannot change after |
| ESF requires entitlement | Monitoring optional, sandbox always works |
| macOS 14+ for XPC events | Older versions rely on sandbox logs only |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          agentsh server                                  │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ Session Manager                                                    │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐   │   │
│  │  │ Policy      │  │ ESF Handler  │  │ XPC Policy             │   │   │
│  │  │ Engine      │  │ (monitor)    │  │ (mach-lookup rules)    │   │   │
│  │  └─────────────┘  └──────────────┘  └────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                              ▲                                           │
│                              │ ES_EVENT_TYPE_NOTIFY_XPC_CONNECT         │
│                              │ (audit only, macOS 14+)                  │
└──────────────────────────────┼───────────────────────────────────────────┘
                               │
┌──────────────────────────────┼───────────────────────────────────────────┐
│  agentsh-macwrap             │                                           │
│  ┌───────────────────────────┴─────────────────────────────────────┐    │
│  │ 1. Parse config from env (AGENTSH_SANDBOX_CONFIG)               │    │
│  │ 2. Generate SBPL profile with mach-lookup restrictions          │    │
│  │ 3. Apply sandbox via sandbox_init_with_parameters()             │    │
│  │ 4. exec() the target command                                    │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              │                                           │
│                              ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    Target Process                                │    │
│  │  XPC to allowed services → succeeds                             │    │
│  │  XPC to blocked services → EPERM (sandbox violation logged)     │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Two-Layer Security

1. **Sandbox (blocking)**: Restricts which XPC services process can connect to
2. **ESF (monitoring)**: Logs all XPC connection attempts for audit trail

### Comparison with Linux (agentsh-unixwrap)

| Aspect | Linux (seccomp) | macOS (sandbox) |
|--------|-----------------|-----------------|
| Enforcement | Kernel kills process | Syscall returns EPERM |
| Granularity | Syscall level | XPC service name level |
| FD passing | Notify fd to server | Not needed (no user-notify) |
| Monitoring | Same filter | Separate ESF subscription |
| Blocking | `SECCOMP_RET_KILL_PROCESS` | `(deny mach-lookup ...)` |

## Configuration Schema

```yaml
sandbox:
  xpc:
    enabled: true
    mode: enforce  # enforce | audit | disabled

    # Wrapper binary (like agentsh-unixwrap for Linux)
    wrapper_bin: ""  # defaults to "agentsh-macwrap" in PATH

    # Mach service access control
    mach_services:
      # Default action for services not in any list
      default_action: deny  # allow | deny

      # Services to explicitly allow (when default is deny)
      allow:
        - "com.apple.system.logger"
        - "com.apple.system.notification_center"
        - "com.apple.CoreServices.coreservicesd"
        - "com.apple.lsd.mapdb"
        - "com.apple.SecurityServer"

      # Services to explicitly block (when default is allow)
      block:
        - "com.apple.security.authhost"
        - "com.apple.coreservices.appleevents"

      # Prefix-based rules
      allow_prefixes:
        - "com.apple.system."
        - "com.apple.coreservices."

      block_prefixes:
        - "com.apple.accessibility."
        - "com.apple.tccd."

    # ESF monitoring (requires entitlement, macOS 14+)
    esf_monitoring:
      enabled: true
```

### Go Types

```go
// SandboxXPCConfig configures macOS XPC/Mach IPC control.
type SandboxXPCConfig struct {
    Enabled       bool                 `yaml:"enabled"`
    Mode          string               `yaml:"mode"` // enforce, audit, disabled
    WrapperBin    string               `yaml:"wrapper_bin"`
    MachServices  SandboxXPCMachConfig `yaml:"mach_services"`
    ESFMonitoring SandboxXPCESFConfig  `yaml:"esf_monitoring"`
}

type SandboxXPCMachConfig struct {
    DefaultAction string   `yaml:"default_action"` // allow, deny
    Allow         []string `yaml:"allow"`
    Block         []string `yaml:"block"`
    AllowPrefixes []string `yaml:"allow_prefixes"`
    BlockPrefixes []string `yaml:"block_prefixes"`
}

type SandboxXPCESFConfig struct {
    Enabled bool `yaml:"enabled"`
}
```

### Default XPC Lists

```go
// Safe services for CLI tools
var DefaultXPCAllowList = []string{
    "com.apple.system.logger",
    "com.apple.system.notification_center",
    "com.apple.CoreServices.coreservicesd",
    "com.apple.lsd.mapdb",
    "com.apple.SecurityServer",
    "com.apple.cfprefsd.daemon",
    "com.apple.cfprefsd.agent",
    "com.apple.fonts",
    "com.apple.FontObjectsServer",
    "com.apple.system.opendirectoryd",
}

// Dangerous service prefixes
var DefaultXPCBlockPrefixes = []string{
    "com.apple.accessibility.",   // Input injection, screen reading
    "com.apple.tccd.",            // TCC bypass attempts
    "com.apple.security.syspolicy.",
}

// Dangerous specific services
var DefaultXPCBlockList = []string{
    "com.apple.security.authhost",        // Auth dialog spoofing
    "com.apple.coreservices.appleevents", // AppleScript execution
    "com.apple.pasteboard.1",             // Clipboard exfiltration
}
```

## Wrapper Binary Implementation

### `cmd/agentsh-macwrap/main.go`

```go
//go:build darwin

// agentsh-macwrap: applies macOS sandbox profile with XPC restrictions,
// then execs the target command.
// Usage: agentsh-macwrap -- <command> [args...]
// Requires env AGENTSH_SANDBOX_CONFIG set to JSON config.

package main

/*
#cgo LDFLAGS: -framework Foundation
#include <sandbox.h>
#include <stdlib.h>

int apply_sandbox(const char *profile, char **errorbuf) {
    return sandbox_init_with_parameters(profile, 0, NULL, errorbuf);
}

void free_error(char *errorbuf) {
    sandbox_free_error(errorbuf);
}
*/
import "C"

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "strings"
    "syscall"
    "unsafe"
)

func main() {
    log.SetFlags(0)
    if len(os.Args) < 3 || os.Args[1] != "--" {
        log.Fatalf("usage: %s -- <command> [args...]", os.Args[0])
    }

    cfg, err := loadConfig()
    if err != nil {
        log.Fatalf("load config: %v", err)
    }

    profile := generateProfile(cfg)

    if err := applySandbox(profile); err != nil {
        log.Fatalf("apply sandbox: %v", err)
    }

    cmd := os.Args[2]
    args := os.Args[2:]
    if err := syscall.Exec(cmd, args, os.Environ()); err != nil {
        log.Fatalf("exec %s failed: %v", cmd, err)
    }
}

func applySandbox(profile string) error {
    cProfile := C.CString(profile)
    defer C.free(unsafe.Pointer(cProfile))

    var errorbuf *C.char
    rc := C.apply_sandbox(cProfile, &errorbuf)
    if rc != 0 {
        var errMsg string
        if errorbuf != nil {
            errMsg = C.GoString(errorbuf)
            C.free_error(errorbuf)
        }
        return fmt.Errorf("sandbox_init failed (rc=%d): %s", rc, errMsg)
    }
    return nil
}
```

### Profile Generation

The wrapper generates SBPL (Sandbox Profile Language) profiles:

```scheme
(version 1)
(deny default)

;; Basic process operations
(allow process-fork)
(allow process-exec)
(allow signal (target self))
(allow sysctl-read)

;; System libraries and frameworks
(allow file-read*
    (subpath "/usr/lib")
    (subpath "/usr/share")
    (subpath "/System/Library")
    (subpath "/Library/Frameworks")
    (subpath "/private/var/db/dyld"))

;; Workspace (full access)
(allow file-read* file-write* file-ioctl
    (subpath "/Users/dev/project"))

;; POSIX IPC
(allow ipc-posix*)

;; Mach/XPC services (allowlist mode)
(allow mach-register)
(allow mach-lookup
    (global-name "com.apple.system.logger")
    (global-name "com.apple.CoreServices.coreservicesd")
    (global-name "com.apple.lsd.mapdb")
    (global-name-prefix "com.apple.cfprefsd."))
```

### Mach-lookup Filter Types

| Filter | Example | Use Case |
|--------|---------|----------|
| `global-name` | `"com.apple.foo"` | Exact service name |
| `global-name-prefix` | `"com.apple."` | Service name prefix |
| `global-name-regex` | `"com\\.apple\\..*"` | Regex matching |
| `local-name` | `"MyService"` | Process-local services |

## Server-Side Integration

### Wrapper Config Type

```go
// macSandboxWrapperConfig is passed to agentsh-macwrap via
// AGENTSH_SANDBOX_CONFIG environment variable.
type macSandboxWrapperConfig struct {
    WorkspacePath string                       `json:"workspace_path"`
    AllowedPaths  []string                     `json:"allowed_paths"`
    AllowNetwork  bool                         `json:"allow_network"`
    MachServices  macSandboxMachServicesConfig `json:"mach_services"`
}

type macSandboxMachServicesConfig struct {
    DefaultAction string   `json:"default_action"`
    Allow         []string `json:"allow"`
    Block         []string `json:"block"`
    AllowPrefixes []string `json:"allow_prefixes"`
    BlockPrefixes []string `json:"block_prefixes"`
}
```

### Exec Handler Integration

```go
func (a *App) handleExec(w http.ResponseWriter, r *http.Request) {
    // ... existing code ...

    // macOS: sandbox wrapper with XPC control
    if runtime.GOOS == "darwin" && a.cfg.Sandbox.XPC.Enabled {
        extraCfg = a.wrapWithMacSandbox(&wrappedReq, origCommand, origArgs, sess)
    }

    // ... rest of exec handling ...
}

func (a *App) wrapWithMacSandbox(
    req *types.ExecRequest,
    origCommand string,
    origArgs []string,
    sess *session.Session,
) *extraProcConfig {
    wrapperBin := strings.TrimSpace(a.cfg.Sandbox.XPC.WrapperBin)
    if wrapperBin == "" {
        wrapperBin = "agentsh-macwrap"
    }

    cfg := macSandboxWrapperConfig{
        WorkspacePath: sess.WorkspacePath(),
        AllowedPaths:  a.getAllowedPaths(sess),
        AllowNetwork:  a.isNetworkAllowed(sess),
        MachServices: macSandboxMachServicesConfig{
            DefaultAction: a.cfg.Sandbox.XPC.MachServices.DefaultAction,
            Allow:         a.cfg.Sandbox.XPC.MachServices.Allow,
            Block:         a.cfg.Sandbox.XPC.MachServices.Block,
            AllowPrefixes: a.cfg.Sandbox.XPC.MachServices.AllowPrefixes,
            BlockPrefixes: a.cfg.Sandbox.XPC.MachServices.BlockPrefixes,
        },
    }

    cfgJSON, _ := json.Marshal(cfg)

    req.Env["AGENTSH_SANDBOX_CONFIG"] = string(cfgJSON)
    req.Command = wrapperBin
    req.Args = append([]string{"--", origCommand}, origArgs...)

    return &extraProcConfig{
        env: map[string]string{"AGENTSH_SANDBOX_CONFIG": string(cfgJSON)},
    }
}
```

## ESF Monitoring & Audit Events

### Event Schema

```go
// XPCConnectEvent - XPC/Mach service connection attempt (macOS).
type XPCConnectEvent struct {
    BaseEvent

    PID         int    `json:"pid"`
    PPID        int    `json:"ppid"`
    Comm        string `json:"comm"`
    Exe         string `json:"exe"`
    SigningID   string `json:"signing_id,omitempty"`
    ServiceName string `json:"service_name"`
    Allowed     bool   `json:"allowed"`
    Reason      string `json:"reason"`
    BlockedBy   string `json:"blocked_by,omitempty"`
    Source      string `json:"source"` // "esf", "sandbox_log"
}

// XPCSandboxViolationEvent - Sandbox denied mach-lookup.
type XPCSandboxViolationEvent struct {
    BaseEvent

    PID         int    `json:"pid"`
    Comm        string `json:"comm"`
    ServiceName string `json:"service_name"`
    Operation   string `json:"operation"` // "mach-lookup", "mach-register"
}
```

### Example Events

**XPC Connection Allowed (ESF)**
```json
{
  "type": "xpc_connect",
  "timestamp": "2026-01-04T15:30:00Z",
  "session_id": "sess_abc123",
  "pid": 12345,
  "comm": "python3",
  "service_name": "com.apple.CoreServices.coreservicesd",
  "allowed": true,
  "reason": "allowlist",
  "source": "esf"
}
```

**XPC Connection Blocked (Sandbox)**
```json
{
  "type": "xpc_sandbox_violation",
  "timestamp": "2026-01-04T15:30:05Z",
  "session_id": "sess_abc123",
  "pid": 12345,
  "comm": "malicious-tool",
  "service_name": "com.apple.security.authhost",
  "operation": "mach-lookup"
}
```

### Monitoring Sources

| Source | Availability | Blocking | Notes |
|--------|--------------|----------|-------|
| Sandbox profile | Always | Yes | Primary enforcement |
| Sandbox violation logs | Always | No (post-block) | Via `log stream` |
| ESF XPC events | macOS 14+, entitled | No | Observes all connections |

## Testing Strategy

### Unit Tests

- Profile generation (default deny, default allow, escaping)
- Config parsing (JSON, defaults, invalid input)
- Mach rules generation (allow, block, prefixes)

### Integration Tests

- Sandbox blocks XPC connections
- Allowlisted services work
- `agentsh-macwrap` applies sandbox correctly
- Session integration with XPC config

### Smoke Tests

```bash
# Basic wrapper test
AGENTSH_SANDBOX_CONFIG='{"mach_services":{"default_action":"allow"}}' \
    agentsh-macwrap -- echo "macwrap-ok"

# Restrictive mode - verify violations logged
restrictive_cfg='{"mach_services":{"default_action":"deny","allow":["com.apple.system.logger"]}}'
AGENTSH_SANDBOX_CONFIG="$restrictive_cfg" agentsh-macwrap -- ls /
log show --last 5s --predicate 'subsystem == "com.apple.sandbox"' | grep deny
```

## File Structure

```
cmd/
└── agentsh-macwrap/
    ├── main.go           # Entry point, sandbox application
    ├── config.go         # JSON config parsing
    ├── config_test.go
    ├── profile.go        # SBPL generation
    └── profile_test.go

internal/
├── config/
│   └── config.go         # Add SandboxXPCConfig
├── api/
│   ├── core.go           # Add wrapWithMacSandbox()
│   ├── xpc_darwin.go     # Default allow/block lists
│   └── xpc_other.go      # Stub for non-darwin
├── events/
│   └── schema.go         # Add XPC event types
└── platform/darwin/
    ├── sandbox_log.go    # Violation log parser
    └── xpc/
        └── bridge.go     # ESF monitor bridge (optional)
```

## Implementation Phases

### Phase 1: Configuration
- Add `SandboxXPCConfig` to `internal/config/config.go`
- Add defaults and validation
- Add `xpc_darwin.go` and `xpc_other.go` for default lists

### Phase 2: Wrapper Binary
- Create `cmd/agentsh-macwrap/` with cgo sandbox integration
- Implement profile generation with mach-lookup rules
- Unit tests for profile generation

### Phase 3: Server Integration
- Add `wrapWithMacSandbox()` to `internal/api/core.go`
- Wire up exec handler for darwin
- Pass config via environment

### Phase 4: Audit Events
- Add `XPCConnectEvent` and `XPCSandboxViolationEvent` to schema
- Implement sandbox log watcher
- Integration with event store

### Phase 5: ESF Monitoring (Optional)
- Swift ESF monitor for `ES_EVENT_TYPE_NOTIFY_XPC_CONNECT`
- XPC bridge to Go
- Requires Apple entitlement

### Phase 6: Testing
- Unit tests for all components
- Integration tests on macOS
- Smoke test additions
- Manual test checklist

## Security Considerations

1. **Sandbox inheritance**: Children inherit sandbox, cannot escalate
2. **Profile validation**: Validate SBPL before applying to prevent injection
3. **Default deny**: Recommended default is restrictive allowlist
4. **Fail-open vs fail-closed**: If wrapper fails, command runs unsandboxed (configurable)
5. **Service discovery**: Use `log stream` tracing to discover required services

## References

- [Apple Sandbox Guide](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)
- [Chromium Mac Sandbox](https://chromium.googlesource.com/chromium/src/+/HEAD/sandbox/mac/seatbelt_sandbox_design.md)
- [ESF Documentation](https://developer.apple.com/documentation/endpointsecurity)
- [HackTricks macOS Sandbox](https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox/index.html)
