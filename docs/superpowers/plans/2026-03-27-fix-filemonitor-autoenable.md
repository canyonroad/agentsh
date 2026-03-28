# Fix file_monitor auto-enable Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix file_monitor being force-enabled when user explicitly sets `file_monitor.enabled: false`, by changing the `Enabled` and `EnforceWithoutFUSE` fields to `*bool`.

**Architecture:** Change two struct fields from `bool` to `*bool`, fix the auto-enable logic to check `== nil` instead of `!val`, and update all consumers to dereference via the existing `FileMonitorBoolWithDefault` helper.

**Tech Stack:** Go, YAML config parsing

**Spec:** `docs/superpowers/specs/2026-03-27-fix-filemonitor-autoenable-design.md`

---

### Task 1: Change struct fields to `*bool` and fix all consumers

This is a single atomic task because all changes must compile together — changing a field from `bool` to `*bool` breaks every consumer at compile time.

**Files:**
- Modify: `internal/config/config.go:498-500` (struct fields)
- Modify: `internal/config/config.go:1119-1127` (auto-enable logic)
- Modify: `internal/api/core.go:204,208,1609` (consumers)
- Modify: `internal/api/file_monitor_linux.go:45,55,62` (consumers)
- Modify: `internal/api/app.go:95` (consumer)
- Test: `internal/config/seccomp_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/config/seccomp_test.go`:

```go
func boolPtr(v bool) *bool { return &v }

func TestFileMonitorAutoEnable_ExplicitFalse(t *testing.T) {
	// When user explicitly sets file_monitor.enabled: false,
	// it must NOT be overridden to true by the auto-enable logic.
	yamlData := []byte(`
sandbox:
  seccomp:
    enabled: true
    file_monitor:
      enabled: false
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	// Before defaults: user's explicit false should be preserved as *false
	require.NotNil(t, cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"explicit false must parse as non-nil *bool")
	require.False(t, *cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"explicit false must be *false")
}

func TestFileMonitorAutoEnable_Omitted(t *testing.T) {
	// When user omits file_monitor entirely, Enabled should be nil
	// (so auto-enable logic can default it to true).
	yamlData := []byte(`
sandbox:
  seccomp:
    enabled: true
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	require.Nil(t, cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"omitted field must be nil")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run "TestFileMonitorAutoEnable" -v`
Expected: FAIL — `cfg.Sandbox.Seccomp.FileMonitor.Enabled` is `bool`, not `*bool` (compile error or wrong assertion).

- [ ] **Step 3: Change struct fields**

In `internal/config/config.go`, change the struct (around line 498):

```go
type SandboxSeccompFileMonitorConfig struct {
	Enabled            *bool `yaml:"enabled"`
	EnforceWithoutFUSE *bool `yaml:"enforce_without_fuse"`
	InterceptMetadata  *bool `yaml:"intercept_metadata"`
	OpenatEmulation    *bool `yaml:"openat_emulation"`
	BlockIOUring       *bool `yaml:"block_io_uring"`
}
```

Add `boolPtr` helper near the `FileMonitorBoolWithDefault` function (around line 512):

```go
// boolPtr returns a pointer to the given bool value.
func boolPtr(v bool) *bool { return &v }
```

- [ ] **Step 4: Fix auto-enable logic**

In `internal/config/config.go`, replace lines 1119-1128:

Old:
```go
if cfg.Sandbox.Seccomp.Enabled && !cfg.Sandbox.Seccomp.FileMonitor.Enabled {
    cfg.Sandbox.Seccomp.FileMonitor.Enabled = true
}

// When file_monitor is enabled, default to enforcing policy decisions.
// Without this, the file_monitor only audits violations without blocking them,
// allowing writes to sensitive files like /etc/hostname or ~/.bashrc.
if cfg.Sandbox.Seccomp.FileMonitor.Enabled && !cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE {
    cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = true
}
```

New:
```go
// Only auto-enable file_monitor when user didn't explicitly set it (nil).
// If user set enabled: false, respect that — forcing it on causes EACCES
// on shared library opens because the handler denies read-only opens
// that don't match policy paths.
if cfg.Sandbox.Seccomp.Enabled && cfg.Sandbox.Seccomp.FileMonitor.Enabled == nil {
    cfg.Sandbox.Seccomp.FileMonitor.Enabled = boolPtr(true)
}

// When file_monitor is enabled, default to enforcing policy decisions.
// Without this, the file_monitor only audits violations without blocking them,
// allowing writes to sensitive files like /etc/hostname or ~/.bashrc.
if FileMonitorBoolWithDefault(cfg.Sandbox.Seccomp.FileMonitor.Enabled, false) &&
    cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE == nil {
    cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = boolPtr(true)
}
```

- [ ] **Step 5: Fix consumers in `internal/api/core.go`**

Line 204:
```go
FileMonitorEnabled:  config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.Enabled, false),
```

Line 208:
```go
fmDefault := config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE, false)
```

Line 1609:
```go
if !config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE, false) {
```

- [ ] **Step 6: Fix consumers in `internal/api/file_monitor_linux.go`**

Line 45:
```go
if !config.FileMonitorBoolWithDefault(cfg.Enabled, false) {
```

Line 55:
```go
enforce := config.FileMonitorBoolWithDefault(cfg.EnforceWithoutFUSE, false)
```

Line 62:
```go
defaultVal := config.FileMonitorBoolWithDefault(cfg.EnforceWithoutFUSE, false)
```

- [ ] **Step 7: Fix consumer in `internal/api/app.go`**

Line 95:
```go
if cfg.Sessions.RealPaths && !config.FileMonitorBoolWithDefault(cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE, false) {
```

- [ ] **Step 8: Build and run all tests**

Run: `go build ./... && go test ./internal/config/ -run "TestFileMonitorAutoEnable" -v && go test ./... -count=1`
Expected: Build succeeds, new tests pass, all existing tests pass.

- [ ] **Step 9: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: Build succeeds.

- [ ] **Step 10: Commit**

```bash
git add internal/config/config.go internal/config/seccomp_test.go \
       internal/api/core.go internal/api/file_monitor_linux.go internal/api/app.go
git commit -m "fix(config): respect explicit file_monitor.enabled: false

Change Enabled and EnforceWithoutFUSE from bool to *bool so the
auto-enable logic can distinguish 'user set false' (respect it) from
'user didn't set it' (default to true). Fixes EACCES on shared library
opens when user explicitly disables file_monitor.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```
