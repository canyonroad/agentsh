# Real Paths: Preserve Host Paths in Agent Sessions

## Overview

Add a `real-paths` option that uses the actual host directory path as the session's virtual root instead of hardcoding `/workspace`. When enabled, an agent (e.g., Claude Code) sees `/home/user/work/myproject` rather than `/workspace`, eliminating confusion around file paths, git operations, and tool output.

## Problem Statement

agentsh virtualizes all workspace access under `/workspace`. This confuses path-aware agents like Claude Code that:
- Read `git status` output containing real paths
- Use absolute paths in tool calls
- Reference file paths in their output

The mismatch between what the agent sees (`/workspace`) and where the code actually lives causes navigation errors and broken path references.

## Solution

Make the virtual root configurable per-session. When `real-paths` is enabled, the session uses the absolute workspace path as its virtual root. Access to paths outside the workspace is governed by the policy engine and enforced by seccomp.

## Configuration

### CLI Flag

```bash
agentsh session create --workspace /home/user/work/myproject --real-paths
```

### YAML Config

```yaml
sessions:
  real_paths: false  # default: off for backwards compatibility
```

CLI flag `--real-paths` overrides the config value.

### API Request

```json
{
  "workspace": "/home/user/work/myproject",
  "real_paths": true
}
```

## Design

### Session Virtual Root

Add a `VirtualRoot` field to the `Session` struct:

```go
type Session struct {
    // ... existing fields ...
    VirtualRoot string  // "/workspace" or real path
}
```

At session creation:
- `real_paths: false` -> `VirtualRoot = "/workspace"` (current behavior)
- `real_paths: true` -> `VirtualRoot = Workspace` (absolute real path)

All hardcoded `/workspace` references (~30 runtime occurrences across 8 files) become `s.VirtualRoot`.

### Path Resolution

The `resolvePathForBuiltin` function changes from:

```go
if !strings.HasPrefix(path, "/workspace") {
    return error("path must be under /workspace")
}
rel := strings.TrimPrefix(path, "/workspace")
real = filepath.Join(s.WorkspaceMountPath(), rel)
```

To:

```go
if strings.HasPrefix(path, s.VirtualRoot) {
    // Inside workspace - resolve through FUSE mount
    rel := strings.TrimPrefix(path, s.VirtualRoot)
    real = filepath.Join(s.WorkspaceMountPath(), rel)
} else {
    // Outside workspace - pass through as-is
    // Seccomp + policy engine enforce access control
    real = path
}
```

Same pattern applies in `exec.go` for `working_dir` resolution.

### Outside-Workspace Path Access

When the agent references a path outside the workspace (e.g., `~/.gitconfig`):

1. The path passes through without FUSE translation
2. Seccomp traps the syscall (`openat`, etc.)
3. `FileHandler` sees the path is not under a FUSE mount
4. `FileHandler` calls `policy.CheckFile(path, operation)`
5. If denied and `EnforceWithoutFUSE: true` -> returns EACCES
6. If allowed -> syscall proceeds normally

This requires no new interception code. The seccomp `FileHandler` already has full enforcement for non-FUSE paths (`internal/netmonitor/unix/file_handler.go:69-115`).

### Policy Configuration

The policy engine already uses default-deny with first-match-wins evaluation. A policy for real-paths mode:

```yaml
file_rules:
  # Workspace - full access
  - name: allow-workspace
    paths: ["${PROJECT_ROOT}/**"]
    operations: ["*"]
    decision: allow

  # Additional read-only paths
  - name: allow-git-config
    paths: ["${HOME}/.gitconfig"]
    operations: [read, open, stat]
    decision: allow

  - name: allow-ssh-known-hosts
    paths: ["${HOME}/.ssh/known_hosts"]
    operations: [read, open, stat]
    decision: allow

  # Default deny covers everything else (implicit in engine)
```

### FUSE Virtual Path Construction

The FUSE layer constructs virtual paths for events and audit logs. `FSConfig` gets a new field:

```go
type FSConfig struct {
    // ... existing fields ...
    VirtualRoot string
}
```

`fuse.go` replaces hardcoded `/workspace` with `cfg.VirtualRoot` in path construction, so events report paths matching what the agent sees.

## Files Changed

| File | Changes |
|------|---------|
| `internal/config/config.go` | Add `RealPaths bool` to sessions config |
| `internal/cli/session.go` | Add `--real-paths` flag |
| `internal/session/manager.go` | Add `VirtualRoot` field, replace ~11 `/workspace` literals |
| `internal/api/exec.go` | Replace 3 `/workspace` references with `VirtualRoot` |
| `internal/api/core.go` | Pass `RealPaths` config when creating sessions |
| `internal/api/app.go` | Replace 2 `/workspace` references in event validation |
| `internal/fsmonitor/fuse.go` | Replace 5 `/workspace` references, use `VirtualRoot` from config |
| `internal/fsmonitor/path.go` | Replace 3 `/workspace` references |
| `internal/platform/` types | Add `VirtualRoot` to `FSConfig` |
| `pkg/types/sessions.go` | Add `RealPaths` to `CreateSessionRequest` |

**Not changed:**
- Policy engine - already supports real paths and default deny
- Seccomp/FileHandler - already enforces on non-FUSE paths
- K8s sidecar - separate concern, keeps its own `/workspace` default

## Edge Cases

### Symlinks escaping the workspace

Agent reads a workspace symlink pointing outside. FUSE resolves symlinks before policy checking for workspace paths. For outside-workspace paths, seccomp traps the resolved path. No change needed.

### Relative path traversal

Agent runs `cat ../../etc/passwd` from inside the workspace. Path resolution cleans and resolves to absolute before checking. The resolved path falls outside the workspace, goes through seccomp, and policy denies it.

### Broad workspace paths

If the workspace is `$HOME` or `/`, the workspace prefix is very broad. Policy still controls access, but this is a user footgun. Document that `--real-paths` works best with project-level directories.

### Trailing slashes

Normalize `VirtualRoot` to strip trailing slashes at session creation to prevent prefix-matching bugs.

### EnforceWithoutFUSE interaction

When `real_paths: true` and `EnforceWithoutFUSE: false`, outside-workspace accesses are audit-only (logged but allowed). Emit a warning at startup when this combination is detected.

## Testing Strategy

### Unit tests

- Session creation with `real_paths: true` sets `VirtualRoot` to the workspace path
- Session creation with `real_paths: false` sets `VirtualRoot` to `/workspace`
- `resolvePathForBuiltin` with real virtual root: inside-workspace paths resolve through mount, outside-workspace paths pass through
- `cd` builtin with real paths: navigates within workspace, outside paths handled by policy
- `working_dir` validation in exec uses `VirtualRoot`

### Integration tests

- Session with `--real-paths`: `pwd` returns real path
- Outside-workspace access with allowing policy: succeeds
- Outside-workspace access with no policy rule: gets EACCES
- Session without `--real-paths`: existing `/workspace` behavior unchanged

### Manual verification

- Run Claude Code through agentsh with `--real-paths`
- Confirm `git status`, file paths, and navigation all use real paths
