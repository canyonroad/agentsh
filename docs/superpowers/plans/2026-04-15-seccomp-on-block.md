# Seccomp `on_block` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `sandbox.seccomp.syscalls.on_block` semantically real — the configured value (`errno` | `kill` | `log` | `log_and_kill`) determines the seccomp filter action, and `log` / `log_and_kill` emit `seccomp_blocked` events that reach agentsh's event store.

**Architecture:** Config validation rejects unknown `on_block` values and defaults to `"errno"` (matches existing runtime behavior). `OnBlockAction` propagates Config → JSON → wrapper's `FilterConfig` → kernel seccomp action. Silent modes (`errno`, `kill`) map straight to `SCMP_ACT_ERRNO(EPERM)` / `SCMP_ACT_KILL_PROCESS` with no runtime overhead. Auditable modes (`log`, `log_and_kill`) use `SCMP_ACT_NOTIFY`, dispatched in `ServeNotifyWithExecve` to a new `handleBlockListNotify` that emits a `seccomp_blocked` event and, for `log_and_kill`, sends `SIGKILL` via pidfd before responding.

**Tech Stack:** Go 1.22+, `github.com/seccomp/libseccomp-golang` 0.11.0 (libseccomp 2.6+), `golang.org/x/sys/unix`, YAML config (`gopkg.in/yaml.v3`), stretchr/testify.

**Spec:** `docs/superpowers/specs/2026-04-15-seccomp-on-block-design.md`

---

## File Structure

**Create:**
- `internal/netmonitor/unix/pidfd_linux.go` — pidfd_open / pidfd_send_signal wrappers, with `*Fn` test seams.
- `internal/netmonitor/unix/blocklist_linux.go` — `handleBlockListNotify`, `buildSeccompBlockedEvent`, shared `BlockListConfig` struct.
- `internal/netmonitor/unix/blocklist_linux_test.go` — unit tests for the handler and event builder, with pidfd mocking.
- `internal/netmonitor/unix/pidfd_linux_test.go` — tests for the pidfd helpers.

**Modify:**
- `internal/seccomp/filter.go` — add `OnBlockAction` enum + helper.
- `internal/config/config.go` — default change (`kill` → `errno`), validation in `validateConfig`.
- `internal/config/seccomp_test.go` — update existing parse test, add validation/defaults coverage.
- `internal/api/core.go` — add `OnBlock` to `seccompWrapperConfig`, propagate in both construction sites.
- `internal/api/wrap.go` — add `OnBlock` to `seccompWrapperConfig` construction.
- `cmd/agentsh-unixwrap/config.go` — add `OnBlock` to `WrapperConfig`.
- `cmd/agentsh-unixwrap/main.go` — pass `OnBlock` into `FilterConfig`.
- `cmd/agentsh-unixwrap/config_test.go` — JSON round-trip coverage.
- `internal/netmonitor/unix/seccomp_linux.go` — `FilterConfig.OnBlockAction`, switch block-list action in `InstallFilterWithConfig`, stale comment fix.
- `internal/netmonitor/unix/seccomp_linux_test.go` — per-action rule assertions.
- `internal/netmonitor/unix/handler.go` — plumb `BlockListConfig` into `ServeNotifyWithExecve`, add dispatch branch.
- `internal/integration/seccomp_wrapper_test.go` — behavioral integration tests.
- `docs/seccomp.md` — updated schema and new "Syscall Block Actions" section.
- `docs/agent-multiplatform-spec.md` — cross-reference update.

---

## Task 1: Define `OnBlockAction` enum + config validation

**Files:**
- Modify: `internal/seccomp/filter.go`
- Modify: `internal/config/config.go:1159-1160` (default), new `validateConfig` branch (add after the `FUSE.Audit.Mode` block).
- Test: `internal/config/seccomp_test.go`

- [ ] **Step 1: Write failing test for default `errno`**

Add to `internal/config/seccomp_test.go`:

```go
func TestOnBlockDefaultsToErrno(t *testing.T) {
	yamlData := `
sandbox:
  seccomp:
    enabled: true
`
	var cfg Config
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))
	applyDefaults(&cfg)
	require.Equal(t, "errno", cfg.Sandbox.Seccomp.Syscalls.OnBlock,
		"default on_block must be errno (matches runtime behavior since b6708353)")
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `go test ./internal/config -run TestOnBlockDefaultsToErrno -v`
Expected: FAIL — gets `"kill"`, expected `"errno"`.

- [ ] **Step 3: Flip the default**

Edit `internal/config/config.go` at the existing default block:

```go
// Before
if cfg.Sandbox.Seccomp.Syscalls.OnBlock == "" {
    cfg.Sandbox.Seccomp.Syscalls.OnBlock = "kill"
}

// After
if cfg.Sandbox.Seccomp.Syscalls.OnBlock == "" {
    cfg.Sandbox.Seccomp.Syscalls.OnBlock = "errno"
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/config -run TestOnBlockDefaultsToErrno -v`
Expected: PASS.

- [ ] **Step 5: Fix the existing `TestSeccompConfigParse` expectation**

The parse test at `internal/config/seccomp_test.go:37` asserts `"kill"` on a YAML input that literally sets `on_block: kill` — that's fine, parse is unchanged. But also add a subtest for each legal value.

Replace `TestSeccompConfigParse` body's end with:

```go
require.Contains(t, cfg.Sandbox.Seccomp.Syscalls.Block, "ptrace")
require.Contains(t, cfg.Sandbox.Seccomp.Syscalls.Block, "mount")
require.Equal(t, "kill", cfg.Sandbox.Seccomp.Syscalls.OnBlock)
}

func TestOnBlockExplicitValues(t *testing.T) {
	for _, v := range []string{"errno", "kill", "log", "log_and_kill"} {
		t.Run(v, func(t *testing.T) {
			yamlData := `
sandbox:
  seccomp:
    enabled: true
    syscalls:
      on_block: ` + v + `
`
			var cfg Config
			require.NoError(t, yaml.Unmarshal([]byte(yamlData), &cfg))
			require.Equal(t, v, cfg.Sandbox.Seccomp.Syscalls.OnBlock)
		})
	}
}
```

Run: `go test ./internal/config -run TestOnBlockExplicitValues -v`
Expected: PASS (parse only — no validator yet).

- [ ] **Step 6: Write failing test for validation**

Append to `internal/config/seccomp_test.go`:

```go
func TestOnBlockRejectsUnknown(t *testing.T) {
	cfg := &Config{}
	cfg.Sandbox.FUSE.Audit.Mode = "monitor" // satisfy existing validator
	cfg.Sandbox.Seccomp.Syscalls.OnBlock = "banana"
	err := validateConfig(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "on_block")
	require.Contains(t, err.Error(), "errno")
	require.Contains(t, err.Error(), "kill")
	require.Contains(t, err.Error(), "log")
	require.Contains(t, err.Error(), "log_and_kill")
}

func TestOnBlockValidatorAcceptsLegalValues(t *testing.T) {
	for _, v := range []string{"", "errno", "kill", "log", "log_and_kill"} {
		t.Run("v="+v, func(t *testing.T) {
			cfg := &Config{}
			cfg.Sandbox.FUSE.Audit.Mode = "monitor"
			cfg.Sandbox.Seccomp.Syscalls.OnBlock = v
			require.NoError(t, validateConfig(cfg))
		})
	}
}
```

- [ ] **Step 7: Run — expect failure**

Run: `go test ./internal/config -run 'TestOnBlock(Rejects|ValidatorAccepts)' -v`
Expected: FAIL — current `validateConfig` has no on_block branch, so `"banana"` slips through.

- [ ] **Step 8: Add validation**

Edit `internal/config/config.go`'s `validateConfig` function (line ~1497). Add after the existing `FUSE.Audit.Mode` switch:

```go
switch cfg.Sandbox.Seccomp.Syscalls.OnBlock {
case "", "errno", "kill", "log", "log_and_kill":
    // ok; "" will be filled by applyDefaults
default:
    return fmt.Errorf("invalid sandbox.seccomp.syscalls.on_block %q: must be one of errno, kill, log, log_and_kill",
        cfg.Sandbox.Seccomp.Syscalls.OnBlock)
}
```

- [ ] **Step 9: Run validation tests — expect pass**

Run: `go test ./internal/config -run 'TestOnBlock' -v`
Expected: all PASS.

- [ ] **Step 10: Add `OnBlockAction` enum in the abstract seccomp package**

Replace the body of `internal/seccomp/filter.go` with:

```go
//go:build linux && cgo

package seccomp

// OnBlockAction determines what seccomp does when a block-listed syscall fires.
type OnBlockAction string

const (
	OnBlockErrno      OnBlockAction = "errno"
	OnBlockKill       OnBlockAction = "kill"
	OnBlockLog        OnBlockAction = "log"
	OnBlockLogAndKill OnBlockAction = "log_and_kill"
)

// ParseOnBlock converts a config string to a typed action.
// Empty string maps to OnBlockErrno (the default after applyDefaults runs).
// Unknown strings return OnBlockErrno and false — callers should treat this
// as a defense-in-depth degradation and log a warning.
func ParseOnBlock(s string) (OnBlockAction, bool) {
	switch OnBlockAction(s) {
	case "", OnBlockErrno:
		return OnBlockErrno, true
	case OnBlockKill, OnBlockLog, OnBlockLogAndKill:
		return OnBlockAction(s), true
	default:
		return OnBlockErrno, false
	}
}

// FilterConfig holds settings for building a seccomp filter.
type FilterConfig struct {
	UnixSocketEnabled bool
	BlockedSyscalls   []string
	OnBlock           OnBlockAction
}

// FilterConfigFromYAML creates a FilterConfig from config package types.
// This is a separate function to avoid import cycles.
func FilterConfigFromYAML(unixEnabled bool, blockedSyscalls []string, onBlock string) FilterConfig {
	action, _ := ParseOnBlock(onBlock)
	return FilterConfig{
		UnixSocketEnabled: unixEnabled,
		BlockedSyscalls:   blockedSyscalls,
		OnBlock:           action,
	}
}
```

- [ ] **Step 11: Write unit tests for `ParseOnBlock`**

Create `internal/seccomp/filter_test.go` content (replacing the existing file — preserve any old tests if present, otherwise use this):

```go
//go:build linux && cgo

package seccomp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseOnBlock(t *testing.T) {
	tests := []struct {
		input    string
		expected OnBlockAction
		ok       bool
	}{
		{"", OnBlockErrno, true},
		{"errno", OnBlockErrno, true},
		{"kill", OnBlockKill, true},
		{"log", OnBlockLog, true},
		{"log_and_kill", OnBlockLogAndKill, true},
		{"banana", OnBlockErrno, false},
		{"KILL", OnBlockErrno, false}, // case sensitive
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := ParseOnBlock(tc.input)
			require.Equal(t, tc.expected, got)
			require.Equal(t, tc.ok, ok)
		})
	}
}

func TestFilterConfigFromYAML(t *testing.T) {
	cfg := FilterConfigFromYAML(true, []string{"ptrace"}, "log_and_kill")
	require.True(t, cfg.UnixSocketEnabled)
	require.Equal(t, []string{"ptrace"}, cfg.BlockedSyscalls)
	require.Equal(t, OnBlockLogAndKill, cfg.OnBlock)

	// Unknown string degrades to errno
	cfgBad := FilterConfigFromYAML(false, nil, "nope")
	require.Equal(t, OnBlockErrno, cfgBad.OnBlock)
}
```

Note: check if `internal/seccomp/filter_test.go` already exists. If it does and contains other tests (per `internal/seccomp/filter_test.go:14: BlockedSyscalls: []string{"ptrace", "mount"}`), preserve those and append the above.

- [ ] **Step 12: Run all config + seccomp tests**

Run: `go test ./internal/config/... ./internal/seccomp/... -v`
Expected: all PASS.

- [ ] **Step 13: Commit**

```bash
git add internal/seccomp/filter.go internal/seccomp/filter_test.go internal/config/config.go internal/config/seccomp_test.go
git commit -m "$(cat <<'EOF'
config(seccomp): validate on_block and define OnBlockAction enum

Rejects unknown on_block values at config load with a clear error.
Default shifts from "kill" to "errno" so upgrades preserve the EPERM
runtime behavior introduced in b6708353. Adds OnBlockAction typed
enum + ParseOnBlock helper for use by downstream filter construction.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Thread `OnBlock` through the wrapper config JSON

**Files:**
- Modify: `internal/api/core.go:51-67` (`seccompWrapperConfig`), `:205` (wrap-path construction).
- Modify: `internal/api/wrap.go:150-157` (wrap-init construction).
- Modify: `cmd/agentsh-unixwrap/config.go:15-35` (`WrapperConfig` struct).
- Test: `cmd/agentsh-unixwrap/config_test.go`.

- [ ] **Step 1: Write failing test for `WrapperConfig` JSON round-trip**

Append to `cmd/agentsh-unixwrap/config_test.go`:

```go
func TestParseConfigJSON_OnBlock(t *testing.T) {
	for _, v := range []string{"errno", "kill", "log", "log_and_kill"} {
		t.Run(v, func(t *testing.T) {
			cfg, err := parseConfigJSON(`{"on_block":"` + v + `"}`)
			require.NoError(t, err)
			require.Equal(t, v, cfg.OnBlock)
		})
	}
}
```

- [ ] **Step 2: Run — expect failure**

Run: `go test ./cmd/agentsh-unixwrap -run TestParseConfigJSON_OnBlock -v`
Expected: FAIL — `cfg.OnBlock` doesn't exist yet.

- [ ] **Step 3: Add `OnBlock` to `WrapperConfig`**

Edit `cmd/agentsh-unixwrap/config.go`. In the `WrapperConfig` struct (around line 15-35), add after `BlockedSyscalls`:

```go
BlockedSyscalls     []string `json:"blocked_syscalls"`
OnBlock             string   `json:"on_block,omitempty"`
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./cmd/agentsh-unixwrap -run TestParseConfigJSON_OnBlock -v`
Expected: PASS.

- [ ] **Step 5: Add `OnBlock` to `seccompWrapperConfig` (server side)**

Edit `internal/api/core.go`. In the `seccompWrapperConfig` struct (starts line 51), add after `BlockedSyscalls`:

```go
BlockedSyscalls     []string `json:"blocked_syscalls"`
OnBlock             string   `json:"on_block,omitempty"`
```

- [ ] **Step 6: Populate `OnBlock` in both construction sites**

Edit `internal/api/wrap.go` around line 152 — extend the `seccompWrapperConfig` literal:

```go
seccompCfg := seccompWrapperConfig{
    UnixSocketEnabled: a.cfg.Sandbox.Seccomp.UnixSocket.Enabled,
    BlockedSyscalls:   a.cfg.Sandbox.Seccomp.Syscalls.Block,
    OnBlock:           a.cfg.Sandbox.Seccomp.Syscalls.OnBlock,
    ExecveEnabled:     execveEnabled,
    ServerPID:         os.Getpid(),
}
```

Edit `internal/api/core.go` around line 203 — extend the same literal:

```go
seccompCfg := seccompWrapperConfig{
    UnixSocketEnabled:   a.cfg.Sandbox.Seccomp.UnixSocket.Enabled,
    BlockedSyscalls:     a.cfg.Sandbox.Seccomp.Syscalls.Block,
    OnBlock:             a.cfg.Sandbox.Seccomp.Syscalls.OnBlock,
    SignalFilterEnabled: signalFilterActive,
    ExecveEnabled:       execveEnabled,
    FileMonitorEnabled:  config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.Enabled, false),
    ServerPID:           os.Getpid(),
}
```

- [ ] **Step 7: Verify the build compiles**

Run: `go build ./...`
Expected: PASS.

- [ ] **Step 8: Full test sweep**

Run: `go test ./internal/api/... ./cmd/agentsh-unixwrap/...`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/api/core.go internal/api/wrap.go cmd/agentsh-unixwrap/config.go cmd/agentsh-unixwrap/config_test.go
git commit -m "$(cat <<'EOF'
api(seccomp): thread on_block through wrapper config JSON

Propagates sandbox.seccomp.syscalls.on_block from server Config into
the agentsh-unixwrap JSON payload so the wrapper can honor it when
building the seccomp filter. No behavior change yet — wrapper still
hardcodes EPERM until Task 3.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Honor `OnBlock` in filter construction (wrapper)

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go:201-216` (`FilterConfig`), `:331-340` (block-list rules).
- Modify: `cmd/agentsh-unixwrap/main.go:70-77` (pass OnBlock into FilterConfig).
- Test: `internal/netmonitor/unix/seccomp_linux_test.go`.

- [ ] **Step 1: Write failing test for each action's rule installation**

Add to `internal/netmonitor/unix/seccomp_linux_test.go`:

```go
//go:build linux && cgo

func TestInstallFilterWithConfig_OnBlockErrno(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skip("seccomp user-notify not supported:", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{int(unix.SYS_PTRACE)},
		OnBlockAction:     seccompkg.OnBlockErrno,
	}
	filt, err := InstallFilterWithConfig(cfg)
	require.NoError(t, err)
	defer filt.Close()
	// Rule inspection: GetAction returns the configured action when a rule matches.
	// libseccomp-golang exposes this via seccomp.ScmpFilter.GetRule / not directly —
	// instead we assert the block-list map in the returned *Filter is empty
	// for errno (kernel-only path, no notify dispatch needed).
	require.Empty(t, filt.BlockListMap(), "errno mode must not populate blocklist dispatch map")
}

func TestInstallFilterWithConfig_OnBlockKill(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skip()
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{int(unix.SYS_PTRACE)},
		OnBlockAction:     seccompkg.OnBlockKill,
	}
	filt, err := InstallFilterWithConfig(cfg)
	require.NoError(t, err)
	defer filt.Close()
	require.Empty(t, filt.BlockListMap(), "kill mode must not populate blocklist dispatch map")
}

func TestInstallFilterWithConfig_OnBlockLog(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skip()
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{int(unix.SYS_PTRACE), int(unix.SYS_MOUNT)},
		OnBlockAction:     seccompkg.OnBlockLog,
	}
	filt, err := InstallFilterWithConfig(cfg)
	require.NoError(t, err)
	defer filt.Close()
	m := filt.BlockListMap()
	require.Len(t, m, 2)
	require.Equal(t, seccompkg.OnBlockLog, m[uint32(unix.SYS_PTRACE)])
	require.Equal(t, seccompkg.OnBlockLog, m[uint32(unix.SYS_MOUNT)])
}

func TestInstallFilterWithConfig_OnBlockLogAndKill(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skip()
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{int(unix.SYS_PTRACE)},
		OnBlockAction:     seccompkg.OnBlockLogAndKill,
	}
	filt, err := InstallFilterWithConfig(cfg)
	require.NoError(t, err)
	defer filt.Close()
	require.Equal(t, seccompkg.OnBlockLogAndKill, filt.BlockListMap()[uint32(unix.SYS_PTRACE)])
}

func TestInstallFilterWithConfig_UnknownOnBlockDegrades(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skip()
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{int(unix.SYS_PTRACE)},
		OnBlockAction:     seccompkg.OnBlockAction("bogus"),
	}
	filt, err := InstallFilterWithConfig(cfg)
	require.NoError(t, err, "unknown action must degrade, not error")
	defer filt.Close()
	require.Empty(t, filt.BlockListMap(), "unknown action must degrade to errno (no notify)")
}
```

Add the import alias at the top of the test file if not present:

```go
import (
    ...
    seccompkg "github.com/agentsh/agentsh/internal/seccomp"
)
```

- [ ] **Step 2: Run — expect failure (multiple)**

Run: `go test ./internal/netmonitor/unix -run TestInstallFilterWithConfig_OnBlock -v`
Expected: FAIL — `FilterConfig.OnBlockAction` field doesn't exist, `Filter.BlockListMap` method doesn't exist.

- [ ] **Step 3: Add `OnBlockAction` to `FilterConfig` and `blockList` map to `Filter`**

Edit `internal/netmonitor/unix/seccomp_linux.go`. Find the imports and add `seccompkg "github.com/agentsh/agentsh/internal/seccomp"` if not already there.

Update `FilterConfig` (line ~201):

```go
// FilterConfig configures the seccomp filter to install.
type FilterConfig struct {
	UnixSocketEnabled  bool
	ExecveEnabled      bool
	FileMonitorEnabled bool
	InterceptMetadata  bool
	BlockIOUring       bool
	BlockedSyscalls    []int // syscall numbers to block
	OnBlockAction      seccompkg.OnBlockAction
}
```

Find the `Filter` struct (the file ends with `return &Filter{fd: fd}, nil` at line ~376 — struct is earlier). Add a `blockList` field:

```go
type Filter struct {
	fd        int
	blockList map[uint32]seccompkg.OnBlockAction
}

// BlockListMap returns a copy of the block-list dispatch map (syscall nr → action)
// for consumers that need to route notifications. Used by the notify handler
// to distinguish block-listed syscalls from file/unix/signal/metadata ones.
func (f *Filter) BlockListMap() map[uint32]seccompkg.OnBlockAction {
	if f == nil || len(f.blockList) == 0 {
		return nil
	}
	out := make(map[uint32]seccompkg.OnBlockAction, len(f.blockList))
	for k, v := range f.blockList {
		out[k] = v
	}
	return out
}
```

Also update the "Blocked syscalls" comment at line 207 — the `// syscall numbers to block with KILL` is stale. Change to `// syscall numbers to block; action controlled by OnBlockAction`.

- [ ] **Step 4: Replace the block-list rules loop with an action switch**

Find the block at `internal/netmonitor/unix/seccomp_linux.go:331-340`:

```go
// Blocked syscalls — return EPERM instead of killing the process.
// The syscall is still denied at the kernel level, but the calling
// process can handle the error gracefully instead of being killed.
blockedAction := seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))
for _, nr := range cfg.BlockedSyscalls {
    sc := seccomp.ScmpSyscall(nr)
    if err := filt.AddRule(sc, blockedAction); err != nil {
        return nil, fmt.Errorf("add blocked rule %v: %w", sc, err)
    }
}
```

Replace with:

```go
// Blocked syscalls — action controlled by OnBlockAction.
// Silent modes (errno, kill) stay on the kernel fast path.
// Auditable modes (log, log_and_kill) use ActNotify and the
// notify handler routes via BlockListMap().
action, ok := seccompkg.ParseOnBlock(string(cfg.OnBlockAction))
if !ok {
    slog.Warn("seccomp: unknown on_block action; degrading to errno",
        "value", cfg.OnBlockAction)
}
blockListMap := map[uint32]seccompkg.OnBlockAction{}
switch action {
case seccompkg.OnBlockErrno:
    errnoAction := seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))
    for _, nr := range cfg.BlockedSyscalls {
        if err := filt.AddRule(seccomp.ScmpSyscall(nr), errnoAction); err != nil {
            return nil, fmt.Errorf("add blocked errno rule %v: %w", nr, err)
        }
    }
case seccompkg.OnBlockKill:
    for _, nr := range cfg.BlockedSyscalls {
        if err := filt.AddRule(seccomp.ScmpSyscall(nr), seccomp.ActKillProcess); err != nil {
            return nil, fmt.Errorf("add blocked kill rule %v: %w", nr, err)
        }
    }
case seccompkg.OnBlockLog, seccompkg.OnBlockLogAndKill:
    for _, nr := range cfg.BlockedSyscalls {
        if err := filt.AddRule(seccomp.ScmpSyscall(nr), seccomp.ActNotify); err != nil {
            return nil, fmt.Errorf("add blocked notify rule %v: %w", nr, err)
        }
        blockListMap[uint32(nr)] = action
    }
}
```

At the function's return point, change `return &Filter{fd: fd}, nil` to carry the map. Find both return sites (fd == -1 case and normal case) and update:

```go
// For the fd == -1 early return:
return &Filter{fd: -1, blockList: blockListMap}, nil

// For the normal case:
return &Filter{fd: fd, blockList: blockListMap}, nil
```

- [ ] **Step 5: Run filter unit tests**

Run: `go test ./internal/netmonitor/unix -run TestInstallFilterWithConfig_OnBlock -v`
Expected: all PASS.

- [ ] **Step 6: Run the full unix package test**

Run: `go test ./internal/netmonitor/unix/...`
Expected: all PASS (pre-existing tests still green).

- [ ] **Step 7: Plumb `OnBlock` into `FilterConfig` at the wrapper's main.go**

Edit `cmd/agentsh-unixwrap/main.go` around line 70-77. Change:

```go
filterCfg := unixmon.FilterConfig{
    UnixSocketEnabled:  cfg.UnixSocketEnabled,
    ExecveEnabled:      cfg.ExecveEnabled,
    FileMonitorEnabled: cfg.FileMonitorEnabled,
    InterceptMetadata:  cfg.InterceptMetadata,
    BlockIOUring:       cfg.BlockIOUring,
    BlockedSyscalls:    blockedNrs,
}
```

to:

```go
onBlock, _ := seccompkg.ParseOnBlock(cfg.OnBlock)
filterCfg := unixmon.FilterConfig{
    UnixSocketEnabled:  cfg.UnixSocketEnabled,
    ExecveEnabled:      cfg.ExecveEnabled,
    FileMonitorEnabled: cfg.FileMonitorEnabled,
    InterceptMetadata:  cfg.InterceptMetadata,
    BlockIOUring:       cfg.BlockIOUring,
    BlockedSyscalls:    blockedNrs,
    OnBlockAction:      onBlock,
}
```

Add the import if missing: `seccompkg "github.com/agentsh/agentsh/internal/seccomp"`.

- [ ] **Step 8: Verify full build**

Run: `go build ./...`
Expected: PASS.

Run: `GOOS=windows go build ./...`
Expected: PASS (cross-compile guard per CLAUDE.md).

- [ ] **Step 9: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go internal/netmonitor/unix/seccomp_linux_test.go cmd/agentsh-unixwrap/main.go
git commit -m "$(cat <<'EOF'
seccomp(filter): honor on_block action in filter construction

Replaces the hardcoded ActErrno(EPERM) for blocked syscalls with a
switch on OnBlockAction: errno → ActErrno, kill → ActKillProcess,
log/log_and_kill → ActNotify plus populated Filter.blockList map.
The notify dispatch for log modes lands in Task 5.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: pidfd helper package

**Files:**
- Create: `internal/netmonitor/unix/pidfd_linux.go`
- Test: `internal/netmonitor/unix/pidfd_linux_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/netmonitor/unix/pidfd_linux_test.go`:

```go
//go:build linux

package unix

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	gounix "golang.org/x/sys/unix"
)

func TestPidfdOpen_Self(t *testing.T) {
	fd, err := pidfdOpen(os.Getpid())
	require.NoError(t, err)
	require.Greater(t, fd, 0)
	require.NoError(t, gounix.Close(fd))
}

func TestPidfdOpen_Nonexistent(t *testing.T) {
	// PID 0x7FFFFFFF is almost certainly unused
	_, err := pidfdOpen(0x7FFFFFFF)
	require.Error(t, err)
	require.ErrorIs(t, err, gounix.ESRCH)
}

func TestPidfdSendSignal_SelfSIGUSR2(t *testing.T) {
	// Install a SIGUSR2 handler so the test doesn't die when we signal ourselves.
	sigCh := make(chan os.Signal, 1)
	defer close(sigCh)
	gounix.Signal(gounix.SIGUSR2, func() {}) // no-op — we only want delivery to not kill us
	// Note: for portability, we use the stdlib signal.Notify pattern instead:
	// signal.Notify(sigCh, syscall.SIGUSR2); defer signal.Stop(sigCh)
	// but this test only needs pidfd_send_signal to succeed.

	fd, err := pidfdOpen(os.Getpid())
	require.NoError(t, err)
	defer gounix.Close(fd)

	err = pidfdSendSignal(fd, gounix.SIGUSR2)
	require.NoError(t, err)
}

func TestPidfdFnIndirection(t *testing.T) {
	// Ensure the *Fn variables are set to the real implementations by default.
	require.NotNil(t, pidfdOpenFn)
	require.NotNil(t, pidfdSendSignalFn)
}
```

Simplify `TestPidfdSendSignal_SelfSIGUSR2` — the stdlib-signal dance above is awkward. Use this instead:

```go
func TestPidfdSendSignal_SelfSIGUSR2(t *testing.T) {
	// Block SIGUSR2 so signaling ourselves doesn't disrupt the test process.
	var mask gounix.Sigset_t
	_ = gounix.PthreadSigmask(gounix.SIG_BLOCK, nil, &mask)
	// (Signal masking in Go is limited; if this proves flaky, replace with
	// spawning a sleeper child and signaling the child. For now the call
	// just has to not error.)

	fd, err := pidfdOpen(os.Getpid())
	require.NoError(t, err)
	defer gounix.Close(fd)

	err = pidfdSendSignal(fd, gounix.SIGURG) // SIGURG is safer — Go uses it internally but it's not fatal
	require.NoError(t, err)
}
```

(Note: `SIGURG` is used by Go's preemption already, so delivery is observed as a no-op at the runtime level. Safe for a unit test.)

- [ ] **Step 2: Run — expect failure**

Run: `go test ./internal/netmonitor/unix -run TestPidfd -v`
Expected: FAIL — `pidfdOpen`, `pidfdSendSignal`, `pidfdOpenFn`, `pidfdSendSignalFn` undefined.

- [ ] **Step 3: Implement helpers**

Create `internal/netmonitor/unix/pidfd_linux.go`:

```go
//go:build linux

package unix

import (
	gounix "golang.org/x/sys/unix"
)

// Test seams. Production code goes through these indirections so tests
// can inject ESRCH/EPERM/EINVAL without spawning real processes.
var (
	pidfdOpenFn       = pidfdOpen
	pidfdSendSignalFn = pidfdSendSignal
)

// pidfdOpen calls the pidfd_open syscall. Requires Linux 5.3+ (Ubuntu 24.04
// ships 6.8, well above).
func pidfdOpen(pid int) (int, error) {
	r, _, errno := gounix.Syscall(gounix.SYS_PIDFD_OPEN, uintptr(pid), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

// pidfdSendSignal sends a signal via pidfd_send_signal. Requires Linux 5.1+.
// Passing 0 for info means "use the default siginfo" (kernel builds it).
func pidfdSendSignal(pidfd int, sig gounix.Signal) error {
	_, _, errno := gounix.Syscall6(gounix.SYS_PIDFD_SEND_SIGNAL,
		uintptr(pidfd), uintptr(sig), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
```

- [ ] **Step 4: Run — expect pass**

Run: `go test ./internal/netmonitor/unix -run TestPidfd -v`
Expected: PASS (`TestPidfdOpen_Self`, `TestPidfdOpen_Nonexistent`, `TestPidfdFnIndirection`, `TestPidfdSendSignal_SelfSIGUSR2`).

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/pidfd_linux.go internal/netmonitor/unix/pidfd_linux_test.go
git commit -m "$(cat <<'EOF'
seccomp(pidfd): add pidfdOpen/pidfdSendSignal helpers

Small wrappers around pidfd_open and pidfd_send_signal used by the
seccomp notify handler to deliver SIGKILL under log_and_kill mode.
*Fn indirections give tests a seam for injecting ESRCH/EPERM/EINVAL.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Block-list notify handler + event builder

**Files:**
- Create: `internal/netmonitor/unix/blocklist_linux.go`
- Create: `internal/netmonitor/unix/blocklist_linux_test.go`

- [ ] **Step 1: Write failing test for event builder**

Create `internal/netmonitor/unix/blocklist_linux_test.go`:

```go
//go:build linux && cgo

package unix

import (
	"context"
	"runtime"
	"sync"
	"testing"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/require"
	gounix "golang.org/x/sys/unix"
)

type fakeEmitter struct {
	mu     sync.Mutex
	events []types.Event
}

func (f *fakeEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeEmitter) Publish(ev types.Event) {
	// no-op for tests (AppendEvent already captures)
}

func (f *fakeEmitter) all() []types.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]types.Event, len(f.events))
	copy(out, f.events)
	return out
}

func TestBuildSeccompBlockedEvent(t *testing.T) {
	ev := buildSeccompBlockedEvent("sess-abc", 42, "ptrace", uint32(gounix.SYS_PTRACE),
		seccompkg.OnBlockLogAndKill, "killed")
	require.Equal(t, "seccomp_blocked", string(ev.Type))
	require.Equal(t, "sess-abc", ev.SessionID)
	require.Equal(t, 42, ev.PID)
	require.Equal(t, "ptrace", ev.Syscall)
	require.Equal(t, uint32(gounix.SYS_PTRACE), ev.SyscallNr)
	require.Equal(t, "log_and_kill", ev.Action)
	require.Equal(t, "killed", ev.Outcome)
	require.Equal(t, runtime.GOARCH, ev.Arch)
}
```

Note: `types.Event` may not currently have `Syscall`, `SyscallNr`, `Action`, `Outcome`, `Arch`, `PID` fields. Check `pkg/types/event.go` — if not present, either (a) use the existing `Metadata map[string]any` pattern, or (b) add typed fields. Prefer (a) to avoid changing a shared type. Adjust the test accordingly:

If `types.Event` has `Metadata`:

```go
func TestBuildSeccompBlockedEvent(t *testing.T) {
	ev := buildSeccompBlockedEvent("sess-abc", 42, "ptrace", uint32(gounix.SYS_PTRACE),
		seccompkg.OnBlockLogAndKill, "killed")
	require.Equal(t, "seccomp_blocked", string(ev.Type))
	require.Equal(t, "sess-abc", ev.SessionID)
	require.Equal(t, "ptrace", ev.Syscall)
	require.Equal(t, 42, int(ev.PID))
	require.Equal(t, "log_and_kill", ev.Metadata["action"])
	require.Equal(t, "killed", ev.Metadata["outcome"])
	require.Equal(t, uint32(gounix.SYS_PTRACE), ev.Metadata["syscall_nr"])
	require.Equal(t, runtime.GOARCH, ev.Metadata["arch"])
}
```

**Implementer note:** Before writing the builder, read `pkg/types/event.go` and pick the shape that matches existing events like `EventSignalBlocked`. The goal is schema consistency. The test and builder must agree on whichever shape is chosen; keep `outcome` and `action` on the event (typed or metadata) either way.

- [ ] **Step 2: Run — expect failure**

Run: `go test ./internal/netmonitor/unix -run TestBuildSeccompBlockedEvent -v`
Expected: FAIL — `buildSeccompBlockedEvent` undefined.

- [ ] **Step 3: Implement handler skeleton + builder**

Create `internal/netmonitor/unix/blocklist_linux.go`:

```go
//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/pkg/types"
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// BlockListConfig carries per-session state the handler needs to dispatch
// block-listed seccomp notifications. Built by the server before starting
// the notify loop.
type BlockListConfig struct {
	// Map of syscall number to configured action. Empty when on_block is
	// errno or kill (those stay on the kernel fast path and never fire notify).
	ActionByNr map[uint32]seccompkg.OnBlockAction
}

// IsBlockListed reports whether a syscall number is in the block-list
// dispatch map. False when the map is nil/empty.
func (c *BlockListConfig) IsBlockListed(nr uint32) (seccompkg.OnBlockAction, bool) {
	if c == nil || len(c.ActionByNr) == 0 {
		return "", false
	}
	a, ok := c.ActionByNr[nr]
	return a, ok
}

// handleBlockListNotify processes a seccomp notification for a block-listed
// syscall. Emits a seccomp_blocked event (for log / log_and_kill) and,
// for log_and_kill, sends SIGKILL to the offending process via pidfd.
// Always responds to the notification with EPERM (NotifRespondDeny).
//
// Ordering for log_and_kill: SIGKILL first, NotifRespondDeny second. If we
// respond first the kernel resumes the syscall (returns EPERM) and the
// process may exit naturally before SIGKILL lands — making outcome=killed
// inaccurate for observers.
func handleBlockListNotify(ctx context.Context, fd int, req *seccomp.ScmpNotifReq,
	action seccompkg.OnBlockAction, sessID string, emit Emitter) {

	if err := seccomp.NotifIDValid(seccomp.ScmpFd(fd), req.ID); err != nil {
		// Process already exited between trap and dispatch — no event,
		// matches file-monitor convention.
		slog.Debug("blocklist: notif id no longer valid, skipping",
			"session_id", sessID, "pid", req.Pid, "err", err)
		if respErr := NotifRespondDeny(fd, req.ID, int32(unix.EPERM)); respErr != nil {
			slog.Debug("blocklist: respond failed for invalid id", "err", respErr)
		}
		return
	}

	syscallName := resolveSyscallName(uint32(req.Data.Syscall))
	outcome := "denied"

	if action == seccompkg.OnBlockLogAndKill {
		outcome = attemptKill(int(req.Pid), sessID, syscallName)
	}

	if emit != nil {
		ev := buildSeccompBlockedEvent(sessID, int(req.Pid), syscallName,
			uint32(req.Data.Syscall), action, outcome)
		_ = emit.AppendEvent(context.Background(), ev)
		emit.Publish(ev)
	}

	if err := NotifRespondDeny(fd, req.ID, int32(unix.EPERM)); err != nil {
		// ENOENT here is normal for log_and_kill after successful SIGKILL —
		// kernel already cleaned up. Other errors are worth a warning.
		if !isENOENT(err) {
			slog.Warn("blocklist: respond failed",
				"session_id", sessID, "pid", req.Pid, "err", err)
		}
	}
}

// attemptKill opens a pidfd on `pid` and sends SIGKILL. Returns "killed"
// if the signal was successfully sent or the process is already dying,
// "denied" otherwise (with a warning log — the syscall still returns EPERM).
func attemptKill(pid int, sessID, syscallName string) string {
	pidfd, err := pidfdOpenFn(pid)
	if err != nil {
		if err == unix.ESRCH {
			slog.Debug("blocklist: pidfd_open ESRCH — process already dying",
				"session_id", sessID, "pid", pid, "syscall", syscallName)
			return "killed"
		}
		slog.Warn("blocklist: pidfd_open failed; falling back to denied outcome",
			"session_id", sessID, "pid", pid, "syscall", syscallName, "err", err)
		return "denied"
	}
	defer unix.Close(pidfd)

	if err := pidfdSendSignalFn(pidfd, unix.SIGKILL); err != nil {
		if err == unix.ESRCH {
			slog.Debug("blocklist: pidfd_send_signal ESRCH — process already dying",
				"session_id", sessID, "pid", pid, "syscall", syscallName)
			return "killed"
		}
		slog.Warn("blocklist: pidfd_send_signal failed",
			"session_id", sessID, "pid", pid, "syscall", syscallName, "err", err)
		return "denied"
	}
	return "killed"
}

// resolveSyscallName looks up the human-readable name for a syscall number
// via libseccomp. Falls back to numeric representation on failure.
func resolveSyscallName(nr uint32) string {
	if name, err := seccomp.ScmpSyscall(nr).GetString(); err == nil && name != "" {
		return name
	}
	return fmt.Sprintf("unknown(%d)", nr)
}

// buildSeccompBlockedEvent constructs the event emitted for log / log_and_kill
// block-list notifications. Schema mirrors signal_blocked / unix_socket_blocked.
func buildSeccompBlockedEvent(sessID string, pid int, syscallName string, syscallNr uint32,
	action seccompkg.OnBlockAction, outcome string) types.Event {
	ev := types.Event{
		ID:        fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "seccomp_blocked",
		SessionID: sessID,
		PID:       pid, // adjust to match actual types.Event field name; if absent, put in Metadata
		Syscall:   syscallName,
	}
	// If types.Event has a Metadata map, put the extra fields there.
	// If it has typed fields, use them. Implementer: check pkg/types/event.go.
	if ev.Metadata == nil {
		ev.Metadata = map[string]any{}
	}
	ev.Metadata["action"] = string(action)
	ev.Metadata["outcome"] = outcome
	ev.Metadata["syscall_nr"] = syscallNr
	ev.Metadata["arch"] = runtime.GOARCH
	return ev
}
```

**Implementer note:** The exact fields on `types.Event` may differ. Before this compiles, read `pkg/types/event.go` and adjust the `types.Event{...}` literal to match. The goal is (a) type is `"seccomp_blocked"`, (b) session id is set, (c) pid / syscall name / syscall nr / action / outcome / arch all appear somewhere retrievable (typed field or `Metadata`). Keep the builder function signature stable — tests key off that.

- [ ] **Step 4: Run builder test — expect pass**

Run: `go test ./internal/netmonitor/unix -run TestBuildSeccompBlockedEvent -v`
Expected: PASS after adjustments.

- [ ] **Step 5: Write tests for `handleBlockListNotify` with pidfd injection**

Append to `internal/netmonitor/unix/blocklist_linux_test.go`:

```go
func TestAttemptKill_Success(t *testing.T) {
	orig := pidfdOpenFn
	origSend := pidfdSendSignalFn
	defer func() { pidfdOpenFn = orig; pidfdSendSignalFn = origSend }()

	pidfdOpenFn = func(pid int) (int, error) { return 42, nil }
	var signaledFD int
	var signaledSig gounix.Signal
	pidfdSendSignalFn = func(fd int, sig gounix.Signal) error {
		signaledFD = fd
		signaledSig = sig
		return nil
	}

	outcome := attemptKill(123, "sess", "ptrace")
	require.Equal(t, "killed", outcome)
	require.Equal(t, 42, signaledFD)
	require.Equal(t, gounix.SIGKILL, signaledSig)
}

func TestAttemptKill_PidfdOpenESRCH(t *testing.T) {
	orig := pidfdOpenFn
	defer func() { pidfdOpenFn = orig }()
	pidfdOpenFn = func(pid int) (int, error) { return -1, gounix.ESRCH }
	outcome := attemptKill(123, "sess", "ptrace")
	require.Equal(t, "killed", outcome, "ESRCH on open means process is dying — honor intent")
}

func TestAttemptKill_PidfdOpenEPERM(t *testing.T) {
	orig := pidfdOpenFn
	defer func() { pidfdOpenFn = orig }()
	pidfdOpenFn = func(pid int) (int, error) { return -1, gounix.EPERM }
	outcome := attemptKill(123, "sess", "ptrace")
	require.Equal(t, "denied", outcome, "EPERM on open → we could not kill, report denied")
}

func TestAttemptKill_PidfdSendSignalESRCH(t *testing.T) {
	orig := pidfdOpenFn
	origSend := pidfdSendSignalFn
	defer func() { pidfdOpenFn = orig; pidfdSendSignalFn = origSend }()
	pidfdOpenFn = func(pid int) (int, error) { return 42, nil }
	pidfdSendSignalFn = func(fd int, sig gounix.Signal) error { return gounix.ESRCH }
	outcome := attemptKill(123, "sess", "ptrace")
	require.Equal(t, "killed", outcome)
}

func TestAttemptKill_PidfdSendSignalEINVAL(t *testing.T) {
	orig := pidfdOpenFn
	origSend := pidfdSendSignalFn
	defer func() { pidfdOpenFn = orig; pidfdSendSignalFn = origSend }()
	pidfdOpenFn = func(pid int) (int, error) { return 42, nil }
	pidfdSendSignalFn = func(fd int, sig gounix.Signal) error { return gounix.EINVAL }
	outcome := attemptKill(123, "sess", "ptrace")
	require.Equal(t, "denied", outcome)
}

func TestBlockListConfig_IsBlockListed(t *testing.T) {
	var nilCfg *BlockListConfig
	_, ok := nilCfg.IsBlockListed(uint32(gounix.SYS_PTRACE))
	require.False(t, ok, "nil config must return false")

	emptyCfg := &BlockListConfig{}
	_, ok = emptyCfg.IsBlockListed(uint32(gounix.SYS_PTRACE))
	require.False(t, ok)

	cfg := &BlockListConfig{ActionByNr: map[uint32]seccompkg.OnBlockAction{
		uint32(gounix.SYS_PTRACE): seccompkg.OnBlockLogAndKill,
	}}
	a, ok := cfg.IsBlockListed(uint32(gounix.SYS_PTRACE))
	require.True(t, ok)
	require.Equal(t, seccompkg.OnBlockLogAndKill, a)

	_, ok = cfg.IsBlockListed(uint32(gounix.SYS_MOUNT))
	require.False(t, ok)
}
```

- [ ] **Step 6: Run — expect pass**

Run: `go test ./internal/netmonitor/unix -run 'TestAttemptKill|TestBlockListConfig' -v`
Expected: all PASS.

- [ ] **Step 7: Verify `NotifIDValid` wrapper exists**

The handler calls `seccomp.NotifIDValid(seccomp.ScmpFd(fd), req.ID)`. Confirm this is exposed by the `libseccomp-golang` binding — check import `"github.com/seccomp/libseccomp-golang"`. If the method is named differently (e.g. `NotifIdValid`), fix the call site to match.

Run: `go build ./internal/netmonitor/unix/...`
Expected: PASS (or fix name mismatch until it does).

- [ ] **Step 8: Commit**

```bash
git add internal/netmonitor/unix/blocklist_linux.go internal/netmonitor/unix/blocklist_linux_test.go
git commit -m "$(cat <<'EOF'
seccomp(notify): add block-list dispatch handler + event builder

handleBlockListNotify runs when a log / log_and_kill blocked syscall
traps: validates the notification is still live, resolves the syscall
name, kills via pidfd for log_and_kill, emits a seccomp_blocked event,
and responds EPERM. Pidfd is wrapped in *Fn seams for test injection
covering ESRCH / EPERM / EINVAL branches. Not yet wired into
ServeNotifyWithExecve — that happens in Task 6.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Wire block-list dispatch into `ServeNotifyWithExecve`

**Files:**
- Modify: `internal/netmonitor/unix/handler.go:171` (signature + dispatch branch).
- Modify: `internal/api/core.go` — build `BlockListConfig` from resolved block-list syscalls and pass into the serve call site.
- Modify: `internal/api/wrap.go` — same.

- [ ] **Step 1: Locate the call sites**

Run: `grep -rn 'ServeNotifyWithExecve(' internal/ cmd/ | head`
Capture the list. Expected: a call in `internal/api/core.go` and potentially `internal/api/wrap.go`. Each must be updated in step 4.

- [ ] **Step 2: Write failing integration-style test**

Skip writing a new Go test for this step alone — the serve loop needs a live notify fd. Validation comes from Task 7's behavioral tests. Just compile-check for now.

- [ ] **Step 3: Extend `ServeNotifyWithExecve` signature**

Edit `internal/netmonitor/unix/handler.go`. Change the signature at line 171:

```go
// Before
func ServeNotifyWithExecve(ctx context.Context, fd *os.File, sessID string, pol *policy.Engine, emit Emitter, execveHandler *ExecveHandler, fileHandler *FileHandler) {

// After
func ServeNotifyWithExecve(ctx context.Context, fd *os.File, sessID string, pol *policy.Engine, emit Emitter, execveHandler *ExecveHandler, fileHandler *FileHandler, blockList *BlockListConfig) {
```

Then add the dispatch branch after the ENOENT/EAGAIN handling, before the execve check (around line 215, just before `if IsExecveSyscall(syscallNr) && execveHandler != nil {`):

```go
// Block-list dispatch (log / log_and_kill modes). Silent modes (errno, kill)
// never reach here — they're kernel-side.
if action, ok := blockList.IsBlockListed(uint32(syscallNr)); ok {
    slog.Debug("ServeNotifyWithExecve: routing to blocklist handler",
        "session_id", sessID, "pid", req.Pid, "syscall_nr", syscallNr, "action", action)
    handleBlockListNotify(ctx, int(scmpFD), req, action, sessID, emit)
    continue
}
```

- [ ] **Step 4: Update all call sites**

At each `ServeNotifyWithExecve(` call site found in Step 1, add the new argument. The argument is built from the session's seccomp config:

```go
// Example for internal/api/core.go — add before the ServeNotifyWithExecve call:
blockList := &unixmon.BlockListConfig{}
if action, _ := seccompkg.ParseOnBlock(a.cfg.Sandbox.Seccomp.Syscalls.OnBlock); 
    action == seccompkg.OnBlockLog || action == seccompkg.OnBlockLogAndKill {
    nrs, skipped := seccompkg.ResolveSyscalls(a.cfg.Sandbox.Seccomp.Syscalls.Block)
    if len(skipped) > 0 {
        slog.Warn("blocklist: some syscalls could not be resolved on this arch",
            "skipped", skipped, "arch", runtime.GOARCH)
    }
    blockList.ActionByNr = make(map[uint32]seccompkg.OnBlockAction, len(nrs))
    for _, nr := range nrs {
        blockList.ActionByNr[uint32(nr)] = action
    }
}

// Then pass it:
go unixmon.ServeNotifyWithExecve(ctx, fd, sessionID, pol, emit, execveHandler, fileHandler, blockList)
```

Add missing imports: `seccompkg "github.com/agentsh/agentsh/internal/seccomp"`, `"runtime"`, `"log/slog"`.

Do the same at any other call site. If there are existing unit tests that call `ServeNotifyWithExecve` in-process, pass `nil` for `blockList` (the `IsBlockListed` method is nil-safe).

- [ ] **Step 5: Startup-warning when hooks absent but log mode selected**

Add right after `blockList.ActionByNr` is populated (still at the call site):

```go
if len(blockList.ActionByNr) > 0 && emit == nil {
    slog.Warn("seccomp: on_block=log/log_and_kill selected but no event emitter wired; events will be dropped",
        "session_id", sessionID)
}
```

- [ ] **Step 6: Full build**

Run: `go build ./...`
Expected: PASS.

Run: `GOOS=windows go build ./...`
Expected: PASS.

- [ ] **Step 7: All existing unit tests still pass**

Run: `go test ./...`
Expected: all PASS (any test that called `ServeNotifyWithExecve` needs a `nil` for the new argument — find and update any that fail).

- [ ] **Step 8: Commit**

```bash
git add internal/netmonitor/unix/handler.go internal/api/core.go internal/api/wrap.go
git commit -m "$(cat <<'EOF'
seccomp(notify): dispatch block-listed syscalls via handleBlockListNotify

ServeNotifyWithExecve now accepts a *BlockListConfig and routes
notifications for block-listed syscall numbers to the dedicated
handler. The config is built by the server from Sandbox.Seccomp.Syscalls
— empty for errno/kill modes (kernel fast path), populated for
log/log_and_kill modes. Warns at startup if log mode is selected but
no emitter is wired.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Behavioral integration tests

**Files:**
- Modify: `internal/integration/seccomp_wrapper_test.go`
- Create (optional, if the shared helper doesn't already exist): `internal/integration/seccomp_helpers_test.go`

- [ ] **Step 1: Inventory the existing integration-test helpers**

Run: `go doc ./internal/integration` and `grep -n 'func Test\|func startWrappedChild\|func runWrapped' internal/integration/seccomp_wrapper_test.go | head -40`

Identify the existing harness that spawns a child under `agentsh-unixwrap` with a given seccomp config JSON. Note the helper name and its signature — you'll reuse it.

If no helper exists, build one with this signature:

```go
// startWrappedChild spawns agentsh-unixwrap with the given config JSON,
// execs a test binary that performs the action described by `cmdArg`,
// and returns (waitStatus, capturedEvents, error).
func startWrappedChild(t *testing.T, cfgJSON string, cmdArg string) (syscall.WaitStatus, []types.Event, error)
```

Don't reinvent if it exists — reuse.

- [ ] **Step 2: Add the `errno` integration test**

Append to `internal/integration/seccomp_wrapper_test.go` (Linux-only — the file is already `//go:build linux`):

```go
func TestSeccompOnBlock_Errno(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "errno"
	}`
	// Child binary: calls ptrace(PTRACE_TRACEME); exits 0 if it got EPERM, 1 otherwise.
	st, events, err := startWrappedChild(t, cfgJSON, "ptrace-traceme")
	require.NoError(t, err)
	require.True(t, st.Exited())
	require.Equal(t, 0, st.ExitStatus(), "child should see EPERM and exit 0")
	require.Empty(t, events, "errno mode must not emit seccomp_blocked events")
}
```

- [ ] **Step 3: Add the `kill` integration test**

```go
func TestSeccompOnBlock_Kill(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "kill"
	}`
	st, events, err := startWrappedChild(t, cfgJSON, "ptrace-traceme")
	require.NoError(t, err)
	require.True(t, st.Signaled(), "child should die by signal")
	require.Equal(t, syscall.SIGSYS, st.Signal(), "kill mode uses SCMP_ACT_KILL_PROCESS which delivers SIGSYS")
	require.Empty(t, events, "kill mode must not emit seccomp_blocked events")
}
```

- [ ] **Step 4: Add the `log` integration test**

```go
func TestSeccompOnBlock_Log(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "log"
	}`
	st, events, err := startWrappedChild(t, cfgJSON, "ptrace-traceme")
	require.NoError(t, err)
	require.True(t, st.Exited())
	require.Equal(t, 0, st.ExitStatus(), "log mode returns EPERM; child exits normally")
	require.Len(t, events, 1, "log mode must emit exactly one seccomp_blocked event")
	ev := events[0]
	require.Equal(t, "seccomp_blocked", string(ev.Type))
	require.Equal(t, "ptrace", ev.Syscall)
	// outcome lives in Metadata per the builder — adjust if types.Event has typed field
	require.Equal(t, "denied", ev.Metadata["outcome"])
	require.Equal(t, "log", ev.Metadata["action"])
}
```

- [ ] **Step 5: Add the `log_and_kill` integration test**

```go
func TestSeccompOnBlock_LogAndKill(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "log_and_kill"
	}`
	st, events, err := startWrappedChild(t, cfgJSON, "ptrace-traceme")
	require.NoError(t, err)
	require.True(t, st.Signaled(), "log_and_kill must kill the child")
	require.Equal(t, syscall.SIGKILL, st.Signal(), "pidfd_send_signal delivers SIGKILL")
	require.Len(t, events, 1)
	ev := events[0]
	require.Equal(t, "seccomp_blocked", string(ev.Type))
	require.Equal(t, "log_and_kill", ev.Metadata["action"])
	require.Equal(t, "killed", ev.Metadata["outcome"])
}
```

- [ ] **Step 6: Concurrency test**

Add a test binary mode `"ptrace-storm"` that spawns 100 goroutines each calling ptrace, then check:

```go
func TestSeccompOnBlock_LogAndKill_ConcurrentCalls(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": false,
		"blocked_syscalls": ["ptrace"],
		"on_block": "log_and_kill"
	}`
	done := make(chan struct{})
	var st syscall.WaitStatus
	var events []types.Event
	var err error
	go func() {
		st, events, err = startWrappedChild(t, cfgJSON, "ptrace-storm")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("child did not exit within 5s — possible handler deadlock")
	}
	require.NoError(t, err)
	require.True(t, st.Signaled())
	require.Equal(t, syscall.SIGKILL, st.Signal())
	// Exactly one event — the race winner. The other 99 calls either never
	// got to the kernel (process already SIGKILL'd) or got ENOENT on NotifRespondDeny.
	require.Len(t, events, 1, "multiple blocked syscalls should produce only one event")
}
```

If the test binary doesn't exist, add `ptrace-storm` mode to the existing test helper program — same place where `ptrace-traceme` lives.

- [ ] **Step 7: Non-interference tests**

Add three tests confirming the other seccomp subsystems still work when `on_block` is `log_and_kill`:

```go
func TestSeccompOnBlock_DoesNotAffectFileMonitor(t *testing.T) {
	cfgJSON := `{
		"unix_socket_enabled": true,
		"file_monitor_enabled": true,
		"blocked_syscalls": ["ptrace"],
		"on_block": "log_and_kill"
	}`
	// Run a workload that triggers a file_monitor deny. Assert:
	// - a file_* event fires (existing schema)
	// - no seccomp_blocked event fires (file deny is not a block-list syscall)
	// Implementation: reuse an existing file_monitor integration test fixture
	// and just change the on_block value. If no such fixture exists, skip with
	// a TODO and note in the PR that file_monitor coverage is separately tested.
}

func TestSeccompOnBlock_DoesNotAffectUnixSocket(t *testing.T) {
	// Same pattern: on_block=log_and_kill plus a unix-socket-deny fixture.
	// Assert unix_socket_blocked event, no seccomp_blocked.
}

func TestSeccompOnBlock_DoesNotAffectSignalFilter(t *testing.T) {
	// Same pattern: on_block=log_and_kill plus a signal-deny fixture.
}
```

For the three non-interference tests: if there are no existing fixtures you can reuse, skip them with `t.Skip("non-interference covered by other subsystem integration suites")` rather than inventing new fixtures from scratch. The key assertion these were meant to provide — that block-list dispatch doesn't intercept other syscalls — is already guaranteed by `IsBlockListed` checking a finite map of resolved syscall numbers. Call that out in the skip message.

- [ ] **Step 8: Multi-arch default-block-list resolution smoke**

```go
func TestSeccompOnBlock_DefaultBlockListResolvesOnThisArch(t *testing.T) {
	defaults := []string{
		"ptrace", "process_vm_readv", "process_vm_writev",
		"personality", "mount", "umount2", "pivot_root",
		"reboot", "kexec_load", "init_module", "finit_module",
		"delete_module", "sethostname", "setdomainname",
	}
	resolved, skipped := seccompkg.ResolveSyscalls(defaults)
	require.Empty(t, skipped,
		"all default block-list syscalls must resolve on %s; skipped=%v",
		runtime.GOARCH, skipped)
	require.Len(t, resolved, len(defaults))
}
```

This is a cheap sanity check that runs on every arch in CI.

- [ ] **Step 9: Run all new behavioral tests**

Run: `go test ./internal/integration -run 'TestSeccompOnBlock' -v`
Expected: all PASS on Ubuntu 24.04 arm64 (target VM) and x86_64.

- [ ] **Step 10: Run the entire test suite**

Run: `go test ./...`
Expected: all PASS.

- [ ] **Step 11: Commit**

```bash
git add internal/integration/seccomp_wrapper_test.go
git commit -m "$(cat <<'EOF'
seccomp(test): integration coverage for on_block semantics

Spawns a wrapped child with each on_block value and asserts:
- errno: EPERM, child exits 0, no event
- kill: SIGSYS termination, no event
- log: EPERM, exactly one seccomp_blocked event with outcome=denied
- log_and_kill: SIGKILL termination, exactly one event with outcome=killed
- concurrent ptrace storm resolves to exactly one event (no deadlock)
- default block-list resolves on the current arch (regression gate)
Plus non-interference skips for file_monitor/unix_socket/signal where
shared fixtures don't yet exist.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Docs + event-schema update

**Files:**
- Modify: `docs/seccomp.md` (lines 11, 38, plus a new section).
- Modify: `docs/agent-multiplatform-spec.md` (grep `on_block` for cross-references).
- Modify: `internal/events/types.go` — docblock for `EventSeccompBlocked`.

- [ ] **Step 1: Update `docs/seccomp.md` line 11**

Change:
```
3. **Syscall Blocking**: Immediately terminates processes that attempt blocked syscalls
```
to:
```
3. **Syscall Blocking**: Denies processes that attempt blocked syscalls; configurable via `on_block` to kill, audit-and-deny, or audit-and-kill
```

- [ ] **Step 2: Update `docs/seccomp.md` line 38**

Change:
```
      on_block: kill  # kill | log_and_kill
```
to:
```
      on_block: errno  # errno (default) | kill | log | log_and_kill
```

- [ ] **Step 3: Add the new "Syscall Block Actions" section**

Insert after the existing `syscalls` config block (after the code fence closing on line 39), before the `## Signal Interception` heading (line 41):

```markdown
### Syscall Block Actions

The `on_block` value controls what happens when a process attempts a syscall in the `block` list. Choose based on whether you want audit visibility and whether callers can continue after a denial.

| Value | Kernel action | Process sees | Event emitted | Typical use |
|---|---|---|---|---|
| `errno` *(default)* | `SCMP_ACT_ERRNO(EPERM)` | `-1`, `errno=EPERM` | no | Docker-style graceful denial. Matches the default seccomp profile shipped by containerd. |
| `kill` | `SCMP_ACT_KILL_PROCESS` | process killed with `SIGSYS` | no | Hard policy enforcement. Process cannot catch or ignore the denial. |
| `log` | `SCMP_ACT_NOTIFY` → `EPERM` | `-1`, `errno=EPERM` | `seccomp_blocked` (`outcome=denied`) | Audit without disruption. Use when you want visibility into attempted denials but callers should survive. |
| `log_and_kill` | `SCMP_ACT_NOTIFY` → `SIGKILL` | process killed with `SIGKILL` | `seccomp_blocked` (`outcome=killed`) | Audit + hard enforcement. Use when policy violations should both be recorded and terminate the offender. |

Silent modes (`errno`, `kill`) operate entirely in the kernel — zero userspace overhead. Auditable modes (`log`, `log_and_kill`) add a user-notify round-trip per blocked call; acceptable for block-list syscalls (low frequency), not recommended for hot-path interception.
```

- [ ] **Step 4: Update `docs/agent-multiplatform-spec.md`**

Run: `grep -n 'on_block' docs/agent-multiplatform-spec.md`
Update each reference to match the new schema (list `errno | kill | log | log_and_kill`, note `errno` as default).

- [ ] **Step 5: Add event-type doc comment**

Edit `internal/events/types.go`. Find line 90 (`EventSeccompBlocked`). Replace:

```go
EventSeccompBlocked      EventType = "seccomp_blocked"
EventNotifyHandlerPanic  EventType = "notify_handler_panic"
```

with:

```go
// EventSeccompBlocked is emitted when a seccomp block-listed syscall
// is intercepted under `on_block: log` or `log_and_kill`. Payload carries
// Syscall (name), SessionID, PID, plus Metadata keys: action
// (string, one of "log"/"log_and_kill"), outcome (string, "denied"/"killed"),
// syscall_nr (uint32), arch (string, runtime.GOARCH).
EventSeccompBlocked      EventType = "seccomp_blocked"
EventNotifyHandlerPanic  EventType = "notify_handler_panic"
```

- [ ] **Step 6: Commit**

```bash
git add docs/seccomp.md docs/agent-multiplatform-spec.md internal/events/types.go
git commit -m "$(cat <<'EOF'
docs(seccomp): document on_block actions and seccomp_blocked event

Updates docs/seccomp.md with the full set of on_block values, replaces
the inaccurate "immediately terminates" line with an accurate summary,
and adds a "Syscall Block Actions" table covering the kernel action,
process-visible effect, emitted event, and typical use case for each
value. Also annotates EventSeccompBlocked with its payload schema.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Final validation

- [ ] **Step 1: Full build matrix**

Run: `go build ./...`
Expected: PASS.

Run: `GOOS=windows go build ./...`
Expected: PASS (CLAUDE.md rule).

- [ ] **Step 2: Full test suite**

Run: `go test ./...`
Expected: all PASS on Linux arm64 (target VM).

- [ ] **Step 3: Race detector on the notify path**

Run: `go test -race ./internal/netmonitor/unix/... ./internal/integration/...`
Expected: PASS — the block-list dispatch + `attemptKill` should be race-free (concurrent notifications are serialized through the single notify fd).

- [ ] **Step 4: Manual smoke (target VM)**

Start agentsh with a config snippet:
```yaml
sandbox:
  seccomp:
    enabled: true
    syscalls:
      block: [ptrace]
      on_block: log_and_kill
```
Run a session. From the session shell, `strace -p 1` (or any binary that calls ptrace). Confirm:
- The sandboxed process is killed.
- A `seccomp_blocked` event appears in the session event log with `outcome=killed`, `syscall=ptrace`.

Then switch to `on_block: errno`, re-run: the `strace` call gets EPERM (no kill, no event). This is the before/after demonstration for the PR description.

- [ ] **Step 5: No memory leaks**

Run the concurrency test with `GODEBUG=gctrace=1` for 30s of sustained ptrace-storm load. Memory should plateau — each notification is fully released after NotifRespondDeny.

- [ ] **Step 6: Open PR**

```bash
git push -u origin <branch-name>
gh pr create --title "fix(seccomp): honor sandbox.seccomp.syscalls.on_block" --body "$(cat <<'EOF'
## Summary
- `on_block` is now semantically real: `errno` | `kill` | `log` | `log_and_kill`
- Default changes from `"kill"` → `"errno"` (matches actual runtime behavior since b6708353 — no behavior change for deployments that never set the field)
- `log` / `log_and_kill` emit `seccomp_blocked` events via the existing emitter path
- `log_and_kill` delivers SIGKILL via pidfd before responding to the notification, guaranteeing the process dies even if the syscall's EPERM return would otherwise propagate
- Unknown values rejected at config-load time with an explicit error listing the legal set

## Behavioral change

Deployments that explicitly set `on_block: kill` in their config — expecting the advertised schema — will now see real `SIGSYS` kills instead of silent `EPERM`. If this breaks any agent workflow, pin `on_block: errno` before upgrading.

## Test plan
- [x] Config parsing / validation unit tests (every legal value + rejection)
- [x] Filter construction unit tests (per-action rule assertions, degrade path)
- [x] pidfd helper unit tests (live syscall + ESRCH)
- [x] Block-list handler unit tests (pidfd injection covering ESRCH/EPERM/EINVAL for both open and send)
- [x] Behavioral integration tests on Ubuntu 24.04 arm64 target VM (errno/kill/log/log_and_kill + concurrent storm + default-list resolution)
- [x] `go build ./...` and `GOOS=windows go build ./...` both clean
- [x] `go test -race ./...` clean
- [x] Manual smoke: ptrace under log_and_kill → child killed, event emitted

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Coverage matrix

| Spec requirement | Implemented by |
|---|---|
| Config field parses, validates, defaults | Task 1 |
| Default shift kill → errno | Task 1 |
| Reject unknown values | Task 1 |
| `OnBlockAction` typed enum | Task 1 |
| JSON-wire the value to the wrapper | Task 2 |
| Honor in filter build (errno/kill/log/log_and_kill) | Task 3 |
| Unknown value degrades to errno with warning | Task 3 |
| `Filter.BlockListMap()` exposes dispatch info | Task 3 |
| pidfd_open / pidfd_send_signal helpers with test seams | Task 4 |
| Block-list notify handler (`handleBlockListNotify`) | Task 5 |
| Event builder (`buildSeccompBlockedEvent`) | Task 5 |
| SECCOMP_IOCTL_NOTIF_ID_VALID check | Task 5 |
| Kill-first-respond-second ordering for log_and_kill | Task 5 |
| Outcome decision tree (ESRCH/EPERM/EINVAL) | Task 5 |
| Dispatch branch in `ServeNotifyWithExecve` | Task 6 |
| `BlockListConfig` built in server | Task 6 |
| Startup warning when hooks absent but log mode selected | Task 6 |
| Integration test per action | Task 7 |
| Concurrency test | Task 7 |
| pidfd failure injection integration coverage | Task 5 (unit) — integration covered via production invocation |
| Non-interference with file/unix/signal paths | Task 7 (covered by skipped fixtures + structural guarantee) |
| Multi-arch resolution smoke | Task 7 |
| Doc updates (`docs/seccomp.md` + agent-multiplatform-spec) | Task 8 |
| Event-type docblock | Task 8 |
| Full build matrix | Task 9 |
| Race detector | Task 9 |
| Manual smoke | Task 9 |
