# Wrap Seccomp Config Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `agentsh wrap` derive the same seccomp wrapper config as the `exec` path for file-monitor fields, restoring fine-grained `file_rules` enforcement and eliminating config-construction drift.

**Architecture:** Add a shared `buildSeccompWrapperConfig` helper in `internal/api` that owns config-derived fields (`FileMonitorEnabled`, `InterceptMetadata`, `BlockIOUring`, block-list transport, and Landlock wiring). Keep runtime-only decisions (`UnixSocketEnabled`, `ExecveEnabled`, `SignalFilterEnabled`) in the two callers and pass them into the helper via a small params struct. Prove the fix with JSON-based regression tests on both the wrap-init and exec surfaces.

**Tech Stack:** Go 1.22+, stdlib `encoding/json`, `internal/api`, `internal/config`, Linux seccomp wrapper plumbing, existing `go test` package tests, Windows cross-compile via `GOOS=windows go build ./...`.

**Spec:** `docs/superpowers/specs/2026-04-20-wrap-seccomp-config-parity-design.md`

---

## File Structure

**Create:**
- `internal/api/seccomp_wrapper_config.go` — shared `seccompWrapperConfig` home, runtime params struct, and `buildSeccompWrapperConfig` helper.

**Modify:**
- `internal/api/core.go` — remove inline `seccompWrapperConfig` definition and duplicated assembly; call the shared helper.
- `internal/api/wrap.go` — replace duplicated config assembly with the shared helper after runtime-only signal/unix decisions are known.
- `internal/api/wrap_test.go` — convert wrap config smoke test into JSON assertions for file-monitor fields.
- `internal/api/seccomp_wrapper_test.go` — add exec-path JSON regression coverage for the same file-monitor fields.

---

### Task 1: Add regression tests for both JSON surfaces

**Files:**
- Modify: `internal/api/wrap_test.go`
- Modify: `internal/api/seccomp_wrapper_test.go`

- [ ] **Step 1: Replace the wrap smoke test with a JSON regression test**

In `internal/api/wrap_test.go`, replace `TestWrapInit_SeccompConfigContent` with:

```go
func TestWrapInit_SeccompConfigContent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.Execve.Enabled = true
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = true
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = &enabled
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &parsed); err != nil {
		t.Fatalf("unmarshal SeccompConfig: %v\n%s", err, resp.SeccompConfig)
	}

	if got, _ := parsed["unix_socket_enabled"].(bool); !got {
		t.Fatalf("unix_socket_enabled = %v, want true (JSON: %s)", got, resp.SeccompConfig)
	}
	if got, _ := parsed["execve_enabled"].(bool); !got {
		t.Fatalf("execve_enabled = %v, want true (JSON: %s)", got, resp.SeccompConfig)
	}
	if got, _ := parsed["file_monitor_enabled"].(bool); !got {
		t.Fatalf("file_monitor_enabled = %v, want true (JSON: %s)", got, resp.SeccompConfig)
	}
	if got, _ := parsed["intercept_metadata"].(bool); !got {
		t.Fatalf("intercept_metadata = %v, want true (JSON: %s)", got, resp.SeccompConfig)
	}
	if got, _ := parsed["block_io_uring"].(bool); !got {
		t.Fatalf("block_io_uring = %v, want true (JSON: %s)", got, resp.SeccompConfig)
	}
}
```

- [ ] **Step 2: Add the exec-path regression test**

In `internal/api/seccomp_wrapper_test.go`, add `encoding/json` to the import block, then append:

```go
func TestSetupSeccompWrapper_FileMonitorDefaults(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp wrapper only available on Linux")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = &enabled

	app := newTestAppForSeccomp(t, cfg)

	req := types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	}

	result := app.setupSeccompWrapper(req, "test-session", nil)
	if result == nil || result.extraCfg == nil {
		t.Fatal("expected non-nil wrapper setup result with extraCfg")
	}
	defer func() {
		if result.extraCfg.notifyParentSock != nil {
			result.extraCfg.notifyParentSock.Close()
		}
		for _, f := range result.extraCfg.extraFiles {
			if f != nil {
				f.Close()
			}
		}
	}()

	seccompJSON, ok := result.wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"]
	if !ok {
		t.Fatal("AGENTSH_SECCOMP_CONFIG env var not set")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(seccompJSON), &parsed); err != nil {
		t.Fatalf("unmarshal seccomp config: %v\n%s", err, seccompJSON)
	}

	if got, _ := parsed["file_monitor_enabled"].(bool); !got {
		t.Fatalf("file_monitor_enabled = %v, want true (JSON: %s)", got, seccompJSON)
	}
	if got, _ := parsed["intercept_metadata"].(bool); !got {
		t.Fatalf("intercept_metadata = %v, want true (JSON: %s)", got, seccompJSON)
	}
	if got, _ := parsed["block_io_uring"].(bool); !got {
		t.Fatalf("block_io_uring = %v, want true (JSON: %s)", got, seccompJSON)
	}
}
```

- [ ] **Step 3: Run the two regression tests and confirm the current bug**

Run:

```bash
go test ./internal/api -run 'TestWrapInit_SeccompConfigContent|TestSetupSeccompWrapper_FileMonitorDefaults' -count=1
```

Expected:

- overall command exits non-zero
- `TestWrapInit_SeccompConfigContent` fails because `file_monitor_enabled` is absent/false in `resp.SeccompConfig`
- `TestSetupSeccompWrapper_FileMonitorDefaults` passes, proving the drift is only on the wrap path

---

### Task 2: Extract the shared config builder and wire both callers to it

**Files:**
- Create: `internal/api/seccomp_wrapper_config.go`
- Modify: `internal/api/core.go`
- Modify: `internal/api/wrap.go`

- [ ] **Step 1: Create the shared helper file**

Create `internal/api/seccomp_wrapper_config.go` with:

```go
package api

import (
	"os"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/session"
)

// seccompWrapperConfig is passed to the agentsh-unixwrap wrapper via
// AGENTSH_SECCOMP_CONFIG environment variable to configure seccomp-bpf filtering.
type seccompWrapperConfig struct {
	UnixSocketEnabled   bool     `json:"unix_socket_enabled"`
	SignalFilterEnabled bool     `json:"signal_filter_enabled"`
	ExecveEnabled       bool     `json:"execve_enabled"`
	FileMonitorEnabled  bool     `json:"file_monitor_enabled"`
	BlockedSyscalls     []string `json:"blocked_syscalls"`
	OnBlock             string   `json:"on_block,omitempty"`

	// File monitor sub-options
	InterceptMetadata bool `json:"intercept_metadata,omitempty"`
	BlockIOUring      bool `json:"block_io_uring,omitempty"`

	// Landlock filesystem restrictions
	LandlockEnabled bool     `json:"landlock_enabled,omitempty"`
	LandlockABI     int      `json:"landlock_abi,omitempty"`
	Workspace       string   `json:"workspace,omitempty"`
	AllowExecute    []string `json:"allow_execute,omitempty"`
	AllowRead       []string `json:"allow_read,omitempty"`
	AllowWrite      []string `json:"allow_write,omitempty"`
	DenyPaths       []string `json:"deny_paths,omitempty"`
	AllowNetwork    bool     `json:"allow_network,omitempty"`
	AllowBind       bool     `json:"allow_bind,omitempty"`

	// Server PID for PR_SET_PTRACER (Yama ptrace_scope=1 workaround)
	ServerPID int `json:"server_pid,omitempty"`
}

type seccompWrapperParams struct {
	UnixSocketEnabled   bool
	SignalFilterEnabled bool
	ExecveEnabled       bool
}

func (a *App) buildSeccompWrapperConfig(s *session.Session, p seccompWrapperParams) seccompWrapperConfig {
	seccompCfg := seccompWrapperConfig{
		UnixSocketEnabled:   p.UnixSocketEnabled,
		SignalFilterEnabled: p.SignalFilterEnabled,
		ExecveEnabled:       p.ExecveEnabled,
		FileMonitorEnabled:  config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.Enabled, false),
		BlockedSyscalls:     a.cfg.Sandbox.Seccomp.Syscalls.Block,
		OnBlock:             a.cfg.Sandbox.Seccomp.Syscalls.OnBlock,
		ServerPID:           os.Getpid(),
	}

	fmDefault := config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE, false)
	seccompCfg.InterceptMetadata = config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata, fmDefault)
	seccompCfg.BlockIOUring = config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.BlockIOUring, fmDefault)

	if a.cfg.Landlock.Enabled {
		llResult := capabilities.DetectLandlock()
		if llResult.Available {
			workspace := s.WorkspaceMountPath()
			seccompCfg.LandlockEnabled = true
			seccompCfg.LandlockABI = llResult.ABI
			seccompCfg.Workspace = workspace

			seccompCfg.AllowExecute, seccompCfg.AllowRead, seccompCfg.AllowWrite = a.deriveLandlockAllowPaths(s)
			seccompCfg.AllowExecute = append(seccompCfg.AllowExecute, a.cfg.Landlock.AllowExecute...)
			seccompCfg.AllowRead = append(seccompCfg.AllowRead, a.cfg.Landlock.AllowRead...)
			seccompCfg.AllowWrite = append(seccompCfg.AllowWrite, a.cfg.Landlock.AllowWrite...)
			seccompCfg.DenyPaths = append(seccompCfg.DenyPaths, a.cfg.Landlock.DenyPaths...)

			if a.cfg.Landlock.Network.AllowConnectTCP != nil {
				seccompCfg.AllowNetwork = *a.cfg.Landlock.Network.AllowConnectTCP
			}
			if a.cfg.Landlock.Network.AllowBindTCP != nil {
				seccompCfg.AllowBind = *a.cfg.Landlock.Network.AllowBindTCP
			}
		}
	}

	return seccompCfg
}
```

- [ ] **Step 2: Replace the exec-path inline construction with the helper**

In `internal/api/core.go`, delete the old `seccompWrapperConfig` type definition and replace the inline construction block with:

```go
	seccompCfg := a.buildSeccompWrapperConfig(s, seccompWrapperParams{
		UnixSocketEnabled:   a.cfg.Sandbox.Seccomp.UnixSocket.Enabled,
		SignalFilterEnabled: signalFilterActive,
		ExecveEnabled:       execveEnabled,
	})
```

Keep the rest of `setupSeccompWrapper` unchanged, including `sessionPolicy`,
`hasNotifyFeatures`, `extraEnv`, and `extraCfg`.

- [ ] **Step 3: Replace the wrap-path inline construction with the helper**

In `internal/api/wrap.go`, delete the old early `seccompCfg := seccompWrapperConfig{...}` block and the later `seccompCfg.SignalFilterEnabled = signalFilterEnabled` assignment. After the signal-socket setup and just before `json.Marshal`, insert:

```go
	unixSocketEnabled := a.cfg.Sandbox.Seccomp.UnixSocket.Enabled
	if a.cfg.Sandbox.UnixSockets.Enabled != nil && *a.cfg.Sandbox.UnixSockets.Enabled {
		unixSocketEnabled = true
	}

	seccompCfg := a.buildSeccompWrapperConfig(s, seccompWrapperParams{
		UnixSocketEnabled:   unixSocketEnabled,
		SignalFilterEnabled: signalFilterEnabled,
		ExecveEnabled:       execveEnabled,
	})
```

Do not change the surrounding notify/socket flow. The only behavior change in this task should be that `wrap-init` now gets the same config-derived file-monitor fields as the exec path.

- [ ] **Step 4: Run the focused regression tests plus existing Landlock coverage**

Run:

```bash
go test ./internal/api -run 'TestWrapInit_SeccompConfigContent|TestSetupSeccompWrapper_FileMonitorDefaults|TestSetupSeccompWrapper_LandlockNetwork_HonorsConfig|TestWrapInit_LandlockNetwork_HonorsConfig|TestWrapInit_LandlockNetwork_BackCompatDefaults' -count=1
```

Expected:

- all listed tests PASS
- the two new file-monitor assertions are green
- the pre-existing Landlock JSON tests stay green, proving the refactor did not break network/allow-path propagation

- [ ] **Step 5: Commit the shared-builder refactor**

Run:

```bash
git add internal/api/seccomp_wrapper_config.go internal/api/core.go internal/api/wrap.go internal/api/wrap_test.go internal/api/seccomp_wrapper_test.go
git commit -m "refactor: share seccomp wrapper config builder"
```

Expected:

- commit succeeds with the helper extraction and both regression tests included

---

### Task 3: Run broad verification for Linux tests and Windows compilation

**Files:**
- Verify: `internal/api/*`
- Verify: repository build graph

- [ ] **Step 1: Run the full `internal/api` package tests**

Run:

```bash
go test ./internal/api -count=1
```

Expected:

- PASS
- Linux-only tests may skip when host capabilities are unavailable; skips are acceptable

- [ ] **Step 2: Run the repository-wide Windows compile check**

Run:

```bash
GOOS=windows go build ./...
```

Expected:

- command exits 0
- no Windows compile regressions from the new shared helper

- [ ] **Step 3: Run the full repository test suite**

Run:

```bash
go test ./... -count=1
```

Expected:

- PASS
- platform/capability-based skips are acceptable where already expected by the suite

---

## Self-Review

### Spec coverage

- Shared builder for config-derived fields: covered in Task 2, Steps 1-3.
- Preserve runtime-only toggles in the callers: covered in Task 2, Steps 2-3.
- Wrap JSON regression for file-monitor fields: covered in Task 1, Step 1.
- Exec JSON regression for file-monitor fields: covered in Task 1, Step 2.
- Broader verification, including Windows compile: covered in Task 3.

### Placeholder scan

- No `TBD`, `TODO`, or deferred implementation markers remain.
- Every code-changing step includes concrete code blocks.
- Every verification step includes an exact command and expected outcome.

### Type consistency

- `seccompWrapperConfig` remains the transport type used by both callers.
- `seccompWrapperParams` only carries runtime booleans, matching the design spec.
- `buildSeccompWrapperConfig` returns the same config object shape currently marshaled into `AGENTSH_SECCOMP_CONFIG`.
