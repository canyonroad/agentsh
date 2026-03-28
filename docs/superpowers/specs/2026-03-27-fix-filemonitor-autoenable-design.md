# Fix file_monitor auto-enable ignoring explicit false — Design Spec

**Date:** 2026-03-27
**Status:** Draft
**Problem:** When `seccomp.enabled: true` and `file_monitor.enabled: false`, the config defaults logic force-enables file_monitor because `bool` can't distinguish "user set false" from "not set". This causes openat to be trapped by the BPF filter, and the handler denies read-only opens of shared libraries with EACCES.

## Root Cause

`SandboxSeccompFileMonitorConfig.Enabled` is a plain `bool`. In Go, an unset `bool` defaults to `false` — indistinguishable from an explicit `false`. The auto-enable logic at `config.go:1119`:

```go
if cfg.Sandbox.Seccomp.Enabled && !cfg.Sandbox.Seccomp.FileMonitor.Enabled {
    cfg.Sandbox.Seccomp.FileMonitor.Enabled = true
}
```

fires in both cases, overriding the user's explicit `false`.

## Approach

Change `Enabled` (and `EnforceWithoutFUSE`) from `bool` to `*bool`. This follows the existing pattern in the same struct — `InterceptMetadata`, `OpenatEmulation`, and `BlockIOUring` are already `*bool`.

Update the auto-enable logic to only default when `nil` (user didn't set it), not when explicitly `false`.

## Detailed Design

### 1. Config Struct Change

**File:** `internal/config/config.go`

```go
type SandboxSeccompFileMonitorConfig struct {
    Enabled            *bool `yaml:"enabled"`
    EnforceWithoutFUSE *bool `yaml:"enforce_without_fuse"`
    InterceptMetadata  *bool `yaml:"intercept_metadata"`
    OpenatEmulation    *bool `yaml:"openat_emulation"`
    BlockIOUring       *bool `yaml:"block_io_uring"`
}
```

### 2. Auto-Enable Logic Fix

**File:** `internal/config/config.go`, lines 1119-1127

```go
// Only auto-enable file_monitor when user didn't explicitly set it (nil).
// If user set enabled: false, respect that — forcing it on causes EACCES
// on shared library opens because the handler denies read-only opens
// that don't match policy paths.
if cfg.Sandbox.Seccomp.Enabled && cfg.Sandbox.Seccomp.FileMonitor.Enabled == nil {
    cfg.Sandbox.Seccomp.FileMonitor.Enabled = boolPtr(true)
}

// When file_monitor is enabled, default to enforcing policy decisions.
if FileMonitorBoolWithDefault(cfg.Sandbox.Seccomp.FileMonitor.Enabled, false) &&
    cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE == nil {
    cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = boolPtr(true)
}
```

Note: `boolPtr` helper may already exist in the codebase. If not, add:
```go
func boolPtr(v bool) *bool { return &v }
```

### 3. Consumer Updates

All consumers of `Enabled` and `EnforceWithoutFUSE` must be updated to handle `*bool`. Use `FileMonitorBoolWithDefault(field, defaultVal)` which already exists at `config.go:506`.

**`internal/api/core.go`:**

- Line 204: `FileMonitorEnabled: config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.Enabled, false)`
- Line 208: `fmDefault := config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE, false)`
- Line 260: No change needed — reads `seccompCfg.FileMonitorEnabled` (already `bool`, resolved at line 204)
- Line 1609: `if !config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE, false)`

**`internal/api/file_monitor_linux.go`:**

- Line 45: `if !config.FileMonitorBoolWithDefault(cfg.Enabled, false)` (was `!cfg.Enabled`)
- Line 55: `enforce := config.FileMonitorBoolWithDefault(cfg.EnforceWithoutFUSE, false)` (was `cfg.EnforceWithoutFUSE`)
- Line 62: `defaultVal := config.FileMonitorBoolWithDefault(cfg.EnforceWithoutFUSE, false)` (was `cfg.EnforceWithoutFUSE`)

**`internal/api/app.go`:**

- Line 95: `if cfg.Sessions.RealPaths && !config.FileMonitorBoolWithDefault(cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE, false)`

### 4. Testing

**4a. Config defaults test**: When `seccomp.enabled: true` and `file_monitor.enabled` is explicitly `false` in YAML, verify `FileMonitor.Enabled` is `*false` (not nil, not overridden to true). When `file_monitor` is omitted, verify it's auto-enabled to `*true`.

**4b. Compile-time safety**: Changing `bool` to `*bool` breaks any unconverted consumer at compile time — the compiler catches missed updates.

**4c. Runloop integration**: `unix_sockets.enabled: true`, `seccomp.enabled: true`, `file_monitor.enabled: false` — bash starts without EACCES.

### 5. Files Changed

| File | Change |
|------|--------|
| `internal/config/config.go` | `Enabled` and `EnforceWithoutFUSE` → `*bool`; fix auto-enable logic; add `boolPtr` helper |
| `internal/api/core.go` | Dereference `*bool` via `FileMonitorBoolWithDefault` at lines 204, 208, 1609 |
| `internal/api/file_monitor_linux.go` | Dereference `*bool` at lines 45, 55, 62 |
| `internal/api/app.go` | Dereference `*bool` at line 95 |
| Config test file | Add nil vs explicit false test |
