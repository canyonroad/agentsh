# Dynamic Seatbelt: Policy-Driven macOS Sandbox Enforcement

**Date:** 2026-03-23
**Status:** Spec
**Scope:** macOS enforcement — SBPL generation, extension tokens, Mach service restriction

## Summary

Replace the static, blanket-allow seatbelt profile in agentsh-macwrap with policy-driven SBPL generation. Add sandbox extension tokens for runtime file access grants. Restrict Mach service access. This closes the macOS enforcement gap for command control, isolation, and Mach service restriction without requiring ESF or Network Extension entitlements.

## Context

The macOS sandbox implementation (`darwin/sandbox.go`, `agentsh-macwrap`) uses seatbelt via `sandbox_init_with_parameters` (private C API). The SBPL profile is generated from a static template with blanket `(allow mach-lookup)`, `(allow process-exec)`, and binary network (`allow network*` or nothing). The policy engine's file/command/network rules are not reflected in the sandbox profile.

Note: `sandbox-exec` is deprecated by Apple, but `sandbox_init_with_parameters` remains functional on all current macOS versions. The long-term migration path is ESF + Network Extension (Spec B) for enforcement, with seatbelt as a defense-in-depth layer. This spec strengthens seatbelt enforcement while it remains available.

On Linux, seccomp user-notify, ptrace, Landlock, and eBPF provide fine-grained enforcement. This spec brings macOS closer to parity by making the seatbelt profile enforce the same policy rules the rest of the stack uses.

This is Spec A of two. Spec B (Network Extension) covers domain-level network filtering and is independent.

## Architecture

Three new components, one enhanced:

```
Policy YAML
    │
    ▼
┌─────────────────────────────┐
│  sandbox.go                 │
│  CompileDarwinSandbox()     │  ← existing file, new method
└──────┬──────────┬───────────┘
       │          │
       ▼          ▼
┌────────────┐  ┌──────────────────┐
│ sbpl/      │  │ sandboxext/      │
│ Builder    │  │ TokenManager     │
└────────────┘  └──────────────────┘
       │          │
       ▼          ▼
┌─────────────────────────────┐
│  WrapperConfig (enhanced)   │
│  .CompiledProfile  string   │
│  .ExtensionTokens  []string │
└──────────────┬──────────────┘
               │ JSON via AGENTSH_SANDBOX_CONFIG env var
               ▼
┌─────────────────────────────┐
│  agentsh-macwrap            │
│  consumeTokens() →         │
│  sandbox_init(profile) →   │
│  exec(child)               │
└─────────────────────────────┘
```

Profile generation moves out of macwrap into the **server process** (`internal/api/core.go`), where the policy engine already lives. Today, `wrapWithMacSandbox()` in `core.go` builds a `macSandboxWrapperConfig` and passes it to macwrap via `AGENTSH_SANDBOX_CONFIG`. In the new design, this method calls `CompileDarwinSandbox()` to produce the full SBPL string and extension tokens, then passes both through the same env var. Macwrap becomes a thin applier: consume tokens, apply profile, exec.

The compiled SBPL is also written to `~/.agentsh/sessions/<id>/sandbox.sb` for inspection/debugging. This file is informational — macwrap receives the profile via `WrapperConfig`, never from disk.

**Token issuance:** `sandbox_extension_issue_file()` must be called from an **unsandboxed process**. The server process (which runs unsandboxed) issues all tokens and serializes the opaque token strings into the `WrapperConfig`. Macwrap (which is also unsandboxed at the time of token consumption — it consumes tokens before calling `sandbox_init`) calls `sandbox_extension_consume()` for each token, granting access to itself and its future child process.

**Environment variable size:** The compiled SBPL + serialized tokens will be larger than the current simple JSON config. For policies with many rules, the combined payload could approach shell environment limits (~128KB). If the payload exceeds 64KB, the server writes it to a temp file (`/tmp/agentsh-sandbox-<session>.json`) and passes the file path via `AGENTSH_SANDBOX_CONFIG_FILE` instead. Macwrap reads and deletes the file atomically.

### Layered Perimeter Model

- **Seatbelt = outer perimeter.** Generated at session start from the policy snapshot. Deny-default base. Immutable — cannot be modified after `sandbox_init`.
- **Extension tokens = runtime file access.** Static policy paths: tokens consumed by macwrap before exec, inherited by child. Dynamic approvals mid-session: only possible via FUSE-T.
- **FUSE-T = fine-grained file policy.** Per-operation decisions, soft-delete, redirect. Seatbelt allows the FUSE mount point; FUSE makes the real decision.
- **Shell shim = command policy.** Fine-grained command control (redirect, approval). Seatbelt provides kernel-level backstop for exec path restriction.

Mid-session policy changes for file paths are handled by FUSE-T. Command and Mach service policy changes require a new session (seatbelt is immutable). This is acceptable — policy changes to commands/services typically apply to new sessions.

## Component 1: SBPL Builder (`internal/platform/darwin/sbpl/`)

Pure Go package. No CGo, no templates. Constructs valid SBPL via a typed API.

### Types

```go
type Profile struct {
    rules []rule
}

type PathMatch int
const (
    Literal PathMatch = iota  // (literal "/exact/path")
    Subpath                   // (subpath "/dir")
    Regex                     // (regex #"/pattern"#)
)
```

### API

```go
p := sbpl.New()  // starts with (version 1) (deny default)

// File access
p.AllowFileRead(Subpath, "/usr/lib")
p.AllowFileReadWrite(Subpath, "/workspace/project")
p.AllowFileRead(Literal, "/etc/hosts")

// Process exec
p.AllowProcessExec(Subpath, "/usr/bin")
p.DenyProcessExec(Literal, "/usr/bin/osascript")

// Mach services
p.AllowMachLookup("com.apple.system.logger")
p.AllowMachLookupPrefix("com.apple.system.")
p.DenyMachLookup("com.apple.security.authtrampoline")

// Network (static, port-level only)
p.AllowNetworkOutbound("tcp", "*:443")

// System essentials (convenience)
p.AllowSystemEssentials()

// Build
sbplString, err := p.Build()
```

### `AllowSystemEssentials()` includes

Mirrors all paths currently in `profile.go`'s `generateProfile()`:

- **Dev files:** `/dev/null`, `/dev/random`, `/dev/urandom`, `/dev/zero`
- **System libraries:** `/usr/lib`, `/usr/share`, `/System/Library`, `/Library/Frameworks`, `/private/var/db/dyld` (dyld shared cache)
- **Process operations:** `process-fork`, `signal (target self)`, `sysctl-read`
- **TTY access:** `/dev/ttys*` (regex), `/dev/pty*` (regex), `/dev/tty` (literal)
- **Common tool paths (read-only):** `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/opt/homebrew/Cellar`
- **Temp files:** `/tmp`, `/private/tmp`, `/var/folders`
- **IPC:** `ipc-posix*`, `mach-register` (needed for own XPC services)

### Rule ordering

SBPL with `(deny default)` denies anything not explicitly allowed. Explicit `(deny ...)` rules override `(allow ...)` rules for the same operation regardless of order, because the sandbox evaluates deny rules with higher priority. However, the builder emits deny rules before allow rules within each category for readability and to make the intent clear when inspecting the profile.

For the exec blocklist, this means `(deny process-exec (literal "/usr/bin/osascript"))` takes precedence over `(allow process-exec (subpath "/usr/bin"))` regardless of emission order — the kernel enforces the deny.

### Validation in `Build()`

- All paths must be absolute
- No contradictory rules (allow and deny same literal)
- Deny-default always present
- Returns error on invalid profile

## Component 2: Extension Token Manager (`internal/platform/darwin/sandboxext/`)

CGo package wrapping Apple's sandbox extension C API.

### Types

```go
type ExtClass string
const (
    ReadOnly  ExtClass = "com.apple.app-sandbox.read"
    ReadWrite ExtClass = "com.apple.app-sandbox.read-write"
)

type Token struct {
    Path    string
    Class   ExtClass
    Value   string    // opaque token from sandbox_extension_issue
    Issued  time.Time
}

type Manager struct {
    mu     sync.Mutex
    tokens map[string]*Token
}
```

### API

```go
mgr := sandboxext.NewManager()
token, err := mgr.Issue("/workspace/src", ReadWrite)
tokens := mgr.ActiveTokens()
err := mgr.Revoke("/workspace/src")
mgr.RevokeAll()  // session cleanup
```

### Why both SBPL rules AND tokens for the same path

Belt and suspenders. The SBPL `subpath` rule declares structural permission. The extension token activates runtime access. Some macOS versions enforce one or both. Cost is negligible (one C call per path at session start).

## Component 3: Policy-to-Sandbox Compilation

`CompileDarwinSandbox()` in `internal/platform/darwin/sandbox.go` orchestrates the builder and token manager.

### File rule mapping

Policy file rules use `FileRule{Paths: []string, Operations: []string, Decision: string}` from `internal/policy/model.go`.

| `FileRule` fields | SBPL | Extension token |
|---|---|---|
| `Paths: ["/x"], Operations: ["read"], Decision: "allow"` | `AllowFileRead(Subpath, "/x")` | `Issue("/x", ReadOnly)` |
| `Paths: ["/x"], Operations: ["write", "read"], Decision: "allow"` | `AllowFileReadWrite(Subpath, "/x")` | `Issue("/x", ReadWrite)` |
| `Paths: ["/x/file.txt"], Operations: ["read"], Decision: "allow"` | `AllowFileRead(Literal, "/x/file.txt")` | `Issue("/x/file.txt", ReadOnly)` |
| `Paths: ["/x"], Decision: "deny"` | Omitted (deny-default handles it) | No token |
| No matching rule | Omitted (deny-default) | No token |

Path type detection: glob patterns or directory paths → `Subpath`. Paths with a file extension or no trailing `/` that resolve to a file → `Literal`. The `Operations` field determines read-only vs read-write: if operations include `"write"`, `"*"`, or `"delete"` → `ReadWrite` token and `AllowFileReadWrite`; otherwise → `ReadOnly` and `AllowFileRead`.

### Command rule mapping

Policy command rules use `CommandRule{Commands: []string, Decision: string}` from `internal/policy/model.go`.

| `CommandRule` fields | SBPL |
|---|---|
| `Commands: ["/usr/bin/git"], Decision: "allow"` | `AllowProcessExec(Literal, "/usr/bin/git")` |
| `Commands: ["python*"], Decision: "allow"` | Resolve to full path, `AllowProcessExec(Literal, resolved)` |
| `Commands: ["osascript"], Decision: "deny"` | `DenyProcessExec(Literal, "/usr/bin/osascript")` |
| `Decision: "approve"` or `"redirect"` | Not mapped to SBPL (handled by shell shim/ESF) |

Default exec path allowlist (always emitted):
- `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/bin`, `/opt/homebrew/bin`, workspace path

Default exec blocklist (always emitted):
- `osascript`, `security`, `systemsetup`, `tccutil`, `csrutil`

### Network rule mapping

Policy network rules use `NetworkRule{Domains: []string, Ports: []int, CIDRs: []string, Decision: string}` from `internal/policy/model.go`.

| `NetworkRule` fields | SBPL |
|---|---|
| `Ports: [443], Decision: "allow"` | `(allow network-outbound (remote tcp "*:443"))` |
| `Decision: "allow"` (no port/domain restriction) | `(allow network*)` |
| `Domains: ["*.github.com"], Decision: "allow"` | `(allow network*)` + log warning |
| No network rules | Deny-default blocks all |

**Caveat:** SBPL port-level network filtering (`network-outbound` with `remote` filters) has limited reliability on macOS 12+. The primary enforcement model is binary: `(allow network*)` or deny-default. Port-level rules are emitted as best-effort defense-in-depth. Domain-based filtering is not expressible in SBPL and requires Network Extension (Spec B). If the policy has domain-specific rules, network is allowed at the SBPL level and a log notes that domain filtering requires NE.

### Mach service mapping

Essential allowlist (always emitted):
- `com.apple.system.logger`
- `com.apple.SecurityServer`
- `com.apple.distributed_notifications@Gv0`
- `com.apple.system.notification_center`
- `com.apple.CoreServices.coreservicesd`
- `com.apple.DiskArbitration.diskarbitrationd`
- `com.apple.xpc.launchd.domain.system`

Dangerous blocklist (always emitted, deny-before-allow):
- `com.apple.security.authtrampoline`
- `com.apple.coreservices.launchservicesd`
- `com.apple.pasteboard.*` (clipboard)
- `com.apple.securityd` (keychain direct)

Policy YAML can override with explicit allows for agents that need clipboard or keychain access.

## Component 4: WrapperConfig Changes

### Enhanced struct

```go
type WrapperConfig struct {
    // Existing fields (kept for backwards compatibility)
    WorkspacePath string
    AllowedPaths  []string
    AllowNetwork  bool
    MachServices  MachServicesConfig

    // New fields
    CompiledProfile string   // pre-compiled SBPL string
    ExtensionTokens []string // token strings to consume before sandbox_init
}
```

### macwrap flow

```
loadConfig() → consumeTokens(config.ExtensionTokens) → sandbox_init(config.CompiledProfile) → exec(child)
```

If `CompiledProfile` is empty, macwrap falls back to current `generateProfile()` behavior (backwards compatible with old server versions).

### Token consumption

Token consumption failures are warnings, not errors. The SBPL rule still provides access even if the token fails. Tokens must be consumed before `sandbox_init`. Child inherits consumed extensions through exec.

## Capability Detection & Scoring

### New tiers in `detect_darwin.go`

```
ESF:                        90  (unchanged)
Lima:                       85  (unchanged)
Dynamic seatbelt + FUSE-T:  75  (new)
Dynamic seatbelt only:      65  (new)
FUSE-T (legacy profile):    70  (existing, fallback)
Sandbox-exec (legacy):      60  (existing, fallback)
```

### Protection domain changes

| Domain | Weight | Before | After |
|---|---|---|---|
| file_protection | 25 | Requires FUSE-T | Requires FUSE-T (unchanged) |
| command_control | 25 | Requires ESF | Always available (dynamic seatbelt) |
| network | 20 | Requires NE | Requires NE (unchanged, Spec B) |
| resource_limits | 15 | Always (launchd) | Always (unchanged) |
| isolation | 15 | Requires ESF | Always available (deny-default seatbelt) |

Command control and isolation become always-available because dynamic seatbelt provides real enforcement (exec path restriction + deny-default + Mach restriction).

Scoring is conservative (75 with FUSE-T, 65 without) pending real-world validation.

### Detection criteria

"Dynamic seatbelt" is a code capability, not a system dependency — it's always available when the updated server code is running. Detection in `selectDarwinMode()`: if `agentsh-macwrap` is available in PATH (existing check), select dynamic seatbelt mode. The distinction from the old "sandbox-exec" mode is code-level: the server now sends `CompiledProfile` in the config. No runtime probe needed — the mode is determined by server version, not system capabilities. FUSE-T detection remains unchanged (library file check).

### Seatbelt-only mode

When FUSE-T is not installed, dynamic seatbelt is a standalone supported mode at score ~65. Provides: kernel-enforced exec path restriction, Mach service restriction, file path boundaries. Does not provide: per-operation file policy, file redirect, soft-delete, dynamic mid-session file grants.

## Testing Strategy

### Layer 1: SBPL builder unit tests (`sbpl/builder_test.go`)

Pure Go, no CGo, runs on any OS. Tests SBPL string output for given inputs: correct syntax per rule type, deny-before-allow ordering, rejects relative paths, rejects contradictory rules, system essentials completeness, empty builder produces valid deny-default profile.

### Layer 2: Token manager unit tests (`sandboxext/manager_test.go`)

CGo, darwin-only. Tests real `sandbox_extension_issue/consume/release` calls: issue returns valid token, consume succeeds for valid token, revoke removes from active set, RevokeAll clears, double-revoke is safe, issue for nonexistent path returns error, consume of invalid token string returns -1 handle.

### Layer 3: Policy compilation integration tests (`darwin/sandbox_test.go`)

Darwin-only. Full policy-to-SandboxConfig pipeline with YAML fixtures: file rules produce correct SBPL + tokens, command rules produce correct exec allow/deny, Mach essential allowlist always present, Mach blocklist emitted before allowlist, empty policy produces minimal valid profile.

### Layer 4: Sandbox enforcement integration tests (`darwin/sandbox_integration_test.go`)

Darwin-only, `integration` build tag. Launches macwrap with compiled profile: exec denied outside allowed paths, blocked exec denied even within /usr/bin, extension token grants file access, Mach service deny prevents lookup, backwards compatibility with empty CompiledProfile.

## Files Changed

| File | Change |
|---|---|
| `internal/platform/darwin/sbpl/builder.go` | New — SBPL builder |
| `internal/platform/darwin/sbpl/builder_test.go` | New — builder tests |
| `internal/platform/darwin/sandboxext/manager.go` | New — token manager |
| `internal/platform/darwin/sandboxext/manager_test.go` | New — token manager tests |
| `internal/platform/darwin/sandbox.go` | Add `CompileDarwinSandbox()` method |
| `internal/platform/darwin/sandbox_test.go` | Add compilation integration tests |
| `internal/api/core.go` | Update `wrapWithMacSandbox()` to call `CompileDarwinSandbox()`, populate `CompiledProfile` and `ExtensionTokens` in config |
| `cmd/agentsh-macwrap/main.go` | Add `consumeTokens()`, use `CompiledProfile` |
| `cmd/agentsh-macwrap/config.go` | Add `CompiledProfile`, `ExtensionTokens` fields to `WrapperConfig` |
| `cmd/agentsh-macwrap/profile.go` | Keep as legacy fallback |
| `internal/capabilities/detect_darwin.go` | Add dynamic seatbelt tiers, update domain availability |

## Out of Scope

- **Network Extension** — Spec B, independent
- **ESF integration** — requires Apple entitlement approval, orthogonal
- **SBPL hot-reload** — not possible (kernel limitation). Layered perimeter handles this.
- **Dynamic mid-session file grants without FUSE-T** — would require DYLD_INSERT_LIBRARIES injection, blocked by SIP for system binaries. Accepted limitation of seatbelt-only mode.
- **Per-binary exec allowlists** — too fragile. Path-based restriction provides sufficient defense-in-depth alongside the shell shim.
