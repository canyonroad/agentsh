# Shim-installed kernel enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the file/network/signal-policy gap when commands are spawned outside agentsh server's process tree (sandbox-SDK pattern: Tensorlake, E2B, Modal). The shim invokes the existing `agentsh-unixwrap` machinery on its own process before execve, so kernel filters govern the user's command even though it isn't a descendant of the agentsh server.

**Architecture:** Reuse `/api/v1/sessions/{id}/wrap-init` with a new `Mode: "shim"` request field. Server returns an empty response (no `WrapperBinary`/`NotifySocket`) when no enforcement is configured; the shim treats presence-of-`WrapperBinary` as the install/skip signal (fail-closed: an old server returning a populated response triggers an install). Per-invocation listener cleanup for shim-mode wraps. Shim opens the server's notify Unix socket directly (no socketpair relay), clears CLOEXEC on the fd, then `syscall.Exec`s `agentsh-unixwrap` with `AGENTSH_NOTIFY_SOCK_FD` set. **The shim always installs** when mode != off and the server has something to install — there is no portable, unforgeable way to detect "already installed by us" (env-var markers are caller-controlled; `Seccomp:2` is true for any container default profile). Filter stacking up to the kernel's 64-filter limit covers realistic nesting depths. Default-on with one operator override (`sandbox.shim_install.mode = auto|on|off`). Fail-closed.

**Tech Stack:** Go 1.x, Linux-only (`+build linux`), seccomp-bpf user-notify, Landlock, Unix domain sockets with SCM_RIGHTS. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-05-02-shim-kernel-enforcement-design.md`

---

## File Structure

**Created:**
- `internal/shim/kernelinstall/install_linux.go` — orchestrates wrap-init RPC, socket open, env build, execve to wrapper. Linux-only.
- `internal/shim/kernelinstall/install_other.go` — non-Linux stub returning "unsupported" so cross-compilation passes.
- `internal/shim/kernelinstall/mode.go` — pure parsing of `auto|on|off` from string; cross-platform.
- `internal/shim/kernelinstall/mode_test.go` — table tests for mode parsing.
- `internal/shim/kernelinstall/install_linux_test.go` — unit tests against an httptest server simulating wrap-init.
- `internal/api/wrap_shim_mode_test.go` — server-side tests for `Mode: "shim"` short-circuit (empty `WrapperBinary` when nothing enabled).
- `internal/api/seccomp_wrapper_shim_install_test.go` — integration test: bash spawns in a sibling process tree; assert `cat /etc/shadow` is blocked.
- `docs/cookbook/sandbox-sdk-integrations.md` — operator-facing doc for `sandbox.shim_install.mode` and the integration model.

**Modified:**
- `pkg/types/sessions.go` — `WrapInitRequest.Mode` field. (No new response field — install/skip is signalled by `WrapperBinary` presence; see Architecture.)
- `internal/api/wrap.go` — `wrapInitCore` honors `Mode == "shim"` (lifecycle + auto-detect short-circuit).
- `internal/api/wrap_linux.go` — `acceptNotifyFD` accepts an optional teardown context for per-invocation cleanup.
- `internal/config/config.go` — `SandboxConfig.ShimInstall` block with `Mode string`.
- `internal/shim/conf.go` — `ShimConf.ShimInstall string` (parsed from `shim_install=` line in `/etc/agentsh/shim.conf`).
- `internal/shim/conf_test.go` — coverage for the new key.
- `cmd/agentsh-shell-shim/main.go` — insert kernelinstall branch before existing agentsh-exec proxy (~line 224).

---

## Phase 1 — Server-side wrap-init `Mode` parameter and auto-detect

### Task 1: Add `Mode` to WrapInitRequest

**Status: COMPLETED.** Implementation already merged at commits b8863afc + 55422355 + a follow-up that removed the originally-planned `InstallRequired` field. The protocol now uses **presence of `WrapperBinary`/`NotifySocket` in the wrap-init response** as the install/skip signal (see Architecture). This change was driven by a roborev review finding: a plain `bool InstallRequired` cannot distinguish a deliberate `false` from an old server that omits the field, which would silently bypass enforcement in mixed-version deployments.

**Files:**
- Modify: `pkg/types/sessions.go:125-142`

- [x] **Step 1: Modify the types**

In `pkg/types/sessions.go`, the final form is:

```go
// WrapInitRequest is sent by the CLI or shim to initialize seccomp wrapping for a session.
type WrapInitRequest struct {
	AgentCommand string   `json:"agent_command"`
	AgentArgs    []string `json:"agent_args,omitempty"`
	CallerUID    int      `json:"caller_uid,omitempty"`
	// Mode selects wrap lifecycle. "agent" (default, used by `agentsh wrap`)
	// keeps the notify listener alive for the session lifetime. "shim"
	// (used by the shell shim) tears the listener down when the wrapped
	// process exits. An empty string (field absent on the wire) is treated
	// the same as "agent".
	Mode string `json:"mode,omitempty"`
}

// WrapInitResponse returns the seccomp wrapper configuration to the caller.
//
// To decide whether to install kernel filters, the caller MUST inspect the
// presence of WrapperBinary (and NotifySocket): both populated means
// install; either empty means skip. Do not infer install/skip from a
// single boolean field — it is impossible to distinguish a deliberate
// "skip" from an old server that omits the field, and treating an absent
// field as "skip" would silently bypass enforcement in mixed-version
// deployments. The presence-of-WrapperBinary check is fail-closed: an old
// server that knows nothing about Mode==shim still returns its standard
// populated response, which the caller installs from.
type WrapInitResponse struct {
	PtraceMode            bool              `json:"ptrace_mode,omitempty"`
	SafeToBypassShellShim bool              `json:"safe_to_bypass_shell_shim"`
	WrapperBinary         string            `json:"wrapper_binary"`
	StubBinary            string            `json:"stub_binary,omitempty"`
	SeccompConfig         string            `json:"seccomp_config"`
	NotifySocket          string            `json:"notify_socket"`
	SignalSocket          string            `json:"signal_socket,omitempty"`
	WrapperEnv            map[string]string `json:"wrapper_env"`
}
```

- [x] **Step 2: Build to verify compile** — passed.
- [x] **Step 3: Commit** — done at b8863afc; follow-ups at 55422355 and the InstallRequired-removal commit.

---

### Task 2: Server returns `InstallRequired:false` when nothing enabled (Mode==shim) — SUPERSEDED, see body below

**Note:** Title kept for stability; content rewritten to reflect the empty-`WrapperBinary` signal instead of a removed boolean field. See Task 1's superseded note and the spec's "Install/skip signal (no `install_required` field)" section.

**Files:**
- Create: `internal/api/wrap_shim_mode_test.go`
- Modify: `internal/api/wrap.go` (in `wrapInitCore` around line 215; add helper at end of file)

### Task 2: Server returns empty `WrapperBinary` when nothing enabled (Mode==shim)

**Files:**
- Create: `internal/api/wrap_shim_mode_test.go`
- Modify: `internal/api/wrap.go` (in `wrapInitCore` around line 215; add helper at end of file)

- [ ] **Step 1: Write the failing test**

Create `internal/api/wrap_shim_mode_test.go`:

```go
//go:build linux

package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestWrapInit_ShimMode_NothingEnabled verifies that shim-mode wrap-init
// returns an empty response (no WrapperBinary, no NotifySocket) when neither
// the seccomp wrapper nor Landlock are configured. The shim treats absent
// WrapperBinary as the skip signal and falls through to the existing
// agentsh-exec proxy path. (We intentionally do NOT use a boolean
// install_required field — see pkg/types/sessions.go's WrapInitResponse
// doc comment for why presence-of-WrapperBinary is the fail-closed choice.)
func TestWrapInit_ShimMode_NothingEnabled(t *testing.T) {
	cfg := config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = boolPtr(false)
	cfg.Landlock.Enabled = false

	app := newTestApp(t, cfg)
	s := session.New("test-session", "/tmp")
	app.sessions.Add(s)

	resp, code, err := app.wrapInitCore(s, "test-session", types.WrapInitRequest{
		AgentCommand: "/bin/bash",
		AgentArgs:    []string{"-c", "echo hi"},
		Mode:         "shim",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("got code %d, want 200", code)
	}
	if resp.WrapperBinary != "" {
		t.Fatalf("got WrapperBinary=%q, want empty (nothing enabled)", resp.WrapperBinary)
	}
	if resp.NotifySocket != "" {
		t.Fatalf("got NotifySocket=%q, want empty (nothing enabled)", resp.NotifySocket)
	}
}

func boolPtr(b bool) *bool { return &b }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestWrapInit_ShimMode_NothingEnabled ./internal/api/`
Expected: FAIL — either compilation error (helper not present) or non-empty WrapperBinary.

- [ ] **Step 3: Implement the auto-detect short-circuit**

In `internal/api/wrap.go`, immediately after the ptrace-mode branch ends (around line 214, just before the comment `// Resolve wrapper binary`), insert:

```go
	// Mode == "shim" auto-detect: when shim-mode callers ask the server
	// what to install, return an empty response if no enforcement features
	// are configured. The shim sees the absent WrapperBinary as the skip
	// signal and falls back to its existing agentsh-exec proxy path
	// without paying any kernel setup cost. We deliberately do NOT use a
	// bool install_required field — see pkg/types/sessions.go's
	// WrapInitResponse doc comment for the wire-protocol rationale.
	if req.Mode == "shim" && !shimInstallRequired(a.cfg) {
		return types.WrapInitResponse{}, http.StatusOK, nil
	}
```

At the bottom of `internal/api/wrap.go`, add the helper:

```go
// shimInstallRequired reports whether shim-mode wrap-init has any kernel
// enforcement to apply. Mirrors the gates used elsewhere in this file:
// the seccomp wrapper requires unix_sockets.enabled, and Landlock requires
// landlock.enabled. Either alone is sufficient to require an install.
func shimInstallRequired(cfg *config.Config) bool {
	unixOn := cfg.Sandbox.UnixSockets.Enabled != nil && *cfg.Sandbox.UnixSockets.Enabled
	return unixOn || cfg.Landlock.Enabled
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run TestWrapInit_ShimMode_NothingEnabled ./internal/api/`
Expected: PASS.

- [ ] **Step 5: Run the full wrap test suite to check no regressions**

Run: `go test -run TestWrapInit ./internal/api/`
Expected: all PASS (existing tests don't set `Mode`, so they hit the legacy paths unchanged).

- [ ] **Step 6: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_shim_mode_test.go
git commit -m "feat(api): wrap-init Mode==shim returns empty response when nothing to install"
```

---

### Task 3: Per-invocation listener teardown for `Mode == "shim"`

**Files:**
- Modify: `internal/api/wrap.go` (pass mode to `acceptNotifyFD`)
- Modify: `internal/api/wrap_linux.go:31-100` (`acceptNotifyFD` accepts a "shim mode" flag and exits the listener after one connection's wrapped process completes)
- Create: `internal/api/wrap_shim_teardown_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/api/wrap_shim_teardown_test.go`:

```go
//go:build linux

package api

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestWrapInit_ShimMode_ListenerExitsAfterOneConnection verifies that when
// wrap-init is called with Mode=="shim", the listener goroutine accepts at
// most one connection and then exits, instead of staying alive for the
// session lifetime. This prevents goroutine leaks on per-invocation use.
func TestWrapInit_ShimMode_ListenerExitsAfterOneConnection(t *testing.T) {
	cfg := minimalSeccompEnabledConfig(t)
	app := newTestApp(t, cfg)
	s := session.New("test-session", "/tmp")
	app.sessions.Add(s)

	// Track active acceptNotifyFD goroutines via a counter the test injects.
	var active int32
	app.acceptNotifyFDForTest = func(fn func()) {
		atomic.AddInt32(&active, 1)
		go func() {
			defer atomic.AddInt32(&active, -1)
			fn()
		}()
	}

	resp, code, err := app.wrapInitCore(s, "test-session", types.WrapInitRequest{
		AgentCommand: "/bin/true",
		Mode:         "shim",
	})
	if err != nil || code != 200 {
		t.Fatalf("wrap-init: code=%d err=%v", code, err)
	}
	defer os.Remove(resp.NotifySocket)
	defer os.RemoveAll(filepath.Dir(resp.NotifySocket))

	if got := atomic.LoadInt32(&active); got != 1 {
		t.Fatalf("expected 1 active listener, got %d", got)
	}

	// Connect and immediately close: simulates a wrapper that exited
	// without sending a notify fd. Listener should exit.
	c, err := net.DialTimeout("unix", resp.NotifySocket, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&active) == 0 {
			return // success
		}
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener still active after 5s; expected exit after one connection")
}
```

(`minimalSeccompEnabledConfig` and `newTestApp` use existing helpers in `internal/api/*_test.go` — see how `TestWrapInit_NotifyDirPermissions_Fallback` constructs them.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestWrapInit_ShimMode_ListenerExitsAfterOneConnection ./internal/api/`
Expected: FAIL — listener counter doesn't drop, or test injection point doesn't compile.

- [ ] **Step 3: Add the test injection point on App**

In `internal/api/app.go` (find the `App` struct definition), add:

```go
	// acceptNotifyFDForTest is a test seam for wrapping the goroutine that
	// runs acceptNotifyFD so tests can observe its lifecycle. Production
	// code passes nil and uses a plain `go fn()`.
	acceptNotifyFDForTest func(fn func())
```

- [ ] **Step 4: Plumb shim-mode flag through to acceptNotifyFD**

In `internal/api/wrap.go`, change the goroutine launch (around line 290) from:

```go
	go a.acceptNotifyFD(ctx, listener, notifySocketPath, sessionID, s, execveEnabled, req.CallerUID)
```

to:

```go
	shimMode := req.Mode == "shim"
	startListener := func() {
		a.acceptNotifyFD(ctx, listener, notifySocketPath, sessionID, s, execveEnabled, req.CallerUID, shimMode)
	}
	if a.acceptNotifyFDForTest != nil {
		a.acceptNotifyFDForTest(startListener)
	} else {
		go startListener()
	}
```

- [ ] **Step 5: Update acceptNotifyFD to honor shim-mode**

In `internal/api/wrap_linux.go`, change the signature of `acceptNotifyFD` to accept the new `shimMode bool` parameter, and at the end of the existing accept loop (where it currently runs forever) insert:

```go
	// In shim mode the listener owns exactly one wrapped process. Once we
	// have accepted that one connection (or it closes without sending an
	// fd), exit the goroutine so per-invocation use doesn't leak.
	if shimMode {
		_ = listener.Close()
		_ = os.RemoveAll(filepath.Dir(socketPath))
		return
	}
```

(Place this after the existing one-connection block; in agent mode the function continues its existing behavior unchanged.)

- [ ] **Step 6: Run test to verify it passes**

Run: `go test -run TestWrapInit_ShimMode_ListenerExitsAfterOneConnection ./internal/api/`
Expected: PASS.

- [ ] **Step 7: Run the full wrap suite to check no regressions**

Run: `go test -run TestWrapInit ./internal/api/`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_linux.go internal/api/app.go internal/api/wrap_shim_teardown_test.go
git commit -m "feat(api): per-invocation listener teardown for wrap-init Mode==shim"
```

---

## Phase 2 — Shim config and mode resolver

### Task 4: Add `shim_install` to `ShimConf` parser

**Files:**
- Modify: `internal/shim/conf.go:11-71`
- Modify: `internal/shim/conf_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/shim/conf_test.go`:

```go
func TestShimConf_ShimInstall(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "shim_install=on\n"
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	conf, err := ReadShimConf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if conf.ShimInstall != "on" {
		t.Fatalf("got %q, want %q", conf.ShimInstall, "on")
	}
}

func TestShimConf_ShimInstall_DefaultsAuto(t *testing.T) {
	conf, err := ReadShimConf(t.TempDir()) // no shim.conf present
	if err != nil {
		t.Fatal(err)
	}
	if conf.ShimInstall != "auto" {
		t.Fatalf("got %q, want %q", conf.ShimInstall, "auto")
	}
}

func TestShimConf_ShimInstall_InvalidValue(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "etc", "agentsh")
	_ = os.MkdirAll(confDir, 0o755)
	_ = os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte("shim_install=maybe\n"), 0o644)

	_, err := ReadShimConf(dir)
	if err == nil {
		t.Fatal("expected error for invalid shim_install value")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestShimConf_ShimInstall ./internal/shim/`
Expected: FAIL.

- [ ] **Step 3: Implement the parser update**

In `internal/shim/conf.go`, change the `ShimConf` struct:

```go
type ShimConf struct {
	Force       bool              // force=true|1
	ReadyGate   bool              // ready_gate=true|1
	ShimInstall string            // shim_install=auto|on|off (default: auto)
	Raw         map[string]string // all key=value pairs for forward compat
}
```

Then in `ReadShimConf`, after the existing `ReadyGate` parse block (around line 50), add:

```go
	conf.ShimInstall = "auto"
	if v, ok := conf.Raw["shim_install"]; ok {
		switch v {
		case "auto", "on", "off":
			conf.ShimInstall = v
		default:
			return conf, fmt.Errorf("shim.conf: invalid shim_install value %q (expected auto, on, or off)", v)
		}
	}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/shim/`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shim/conf.go internal/shim/conf_test.go
git commit -m "feat(shim): parse shim_install=auto|on|off from shim.conf"
```

---

### Task 5: Mode resolver (config + env var)

**Files:**
- Create: `internal/shim/kernelinstall/mode.go`
- Create: `internal/shim/kernelinstall/mode_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/shim/kernelinstall/mode_test.go`:

```go
package kernelinstall

import "testing"

func TestResolveMode(t *testing.T) {
	cases := []struct {
		name    string
		conf    string
		env     string
		want    Mode
		wantErr bool
	}{
		{name: "default", conf: "", env: "", want: ModeAuto},
		{name: "conf_auto", conf: "auto", env: "", want: ModeAuto},
		{name: "conf_on", conf: "on", env: "", want: ModeOn},
		{name: "conf_off", conf: "off", env: "", want: ModeOff},
		{name: "env_overrides_conf", conf: "off", env: "on", want: ModeOn},
		{name: "env_invalid", conf: "auto", env: "maybe", wantErr: true},
		{name: "conf_invalid", conf: "yolo", env: "", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := ResolveMode(c.conf, c.env)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mode=%v", m)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m != c.want {
				t.Fatalf("got %v, want %v", m, c.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shim/kernelinstall/`
Expected: FAIL — package doesn't exist.

- [ ] **Step 3: Implement mode.go**

Create `internal/shim/kernelinstall/mode.go`:

```go
// Package kernelinstall lets the shim install seccomp + Landlock on its own
// process before execve, so the user's command inherits the filter even when
// the shim is not a child of the agentsh server (sandbox-SDK pattern).
package kernelinstall

import "fmt"

// Mode controls whether the shim attempts kernel-filter install.
type Mode int

const (
	ModeAuto Mode = iota // call wrap-init; install when server says it's required
	ModeOn               // install or fail-closed
	ModeOff              // never install; fall back to existing agentsh-exec proxy
)

func (m Mode) String() string {
	switch m {
	case ModeAuto:
		return "auto"
	case ModeOn:
		return "on"
	case ModeOff:
		return "off"
	default:
		return "unknown"
	}
}

// ResolveMode picks the effective mode from config-file value and env-var
// override. Empty string means unset; env wins over config.
func ResolveMode(conf, env string) (Mode, error) {
	pick := conf
	if env != "" {
		pick = env
	}
	if pick == "" {
		return ModeAuto, nil
	}
	switch pick {
	case "auto":
		return ModeAuto, nil
	case "on":
		return ModeOn, nil
	case "off":
		return ModeOff, nil
	default:
		return ModeAuto, fmt.Errorf("invalid shim_install value %q (expected auto, on, or off)", pick)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/shim/kernelinstall/`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/shim/kernelinstall/
git commit -m "feat(shim): kernelinstall package with Mode resolver"
```

---

## Phase 3 — Shim install path (Linux)

### Task 6: Implement `Install` (HTTP wrap-init + socket open + execve)

**Files:**
- Create: `internal/shim/kernelinstall/install_linux.go`
- Create: `internal/shim/kernelinstall/install_other.go`
- Create: `internal/shim/kernelinstall/install_linux_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/shim/kernelinstall/install_linux_test.go`:

```go
//go:build linux

package kernelinstall

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// TestInstall_ShortCircuitsWhenNothingRequired asserts that when wrap-init
// returns an empty response (no WrapperBinary), Install returns ResultSkip
// without opening any socket or building any execve plan. The empty
// response is the server's "nothing to install" signal in shim mode.
func TestInstall_ShortCircuitsWhenNothingRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(types.WrapInitResponse{}) // empty WrapperBinary
	}))
	defer srv.Close()

	res, err := Install(InstallParams{
		ServerBaseURL: srv.URL,
		SessionID:     "sess1",
		Mode:          ModeAuto,
		RealShell:     "/bin/bash",
		ShellArgs:     []string{"-c", "echo hi"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Fatalf("got action %v, want ResultSkip", res.Action)
	}
}

// TestInstall_FailsClosedOnServerError covers Mode=on: any error from
// wrap-init must surface as a fail-closed result, not a silent skip.
func TestInstall_FailsClosedOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Install(InstallParams{
		ServerBaseURL: srv.URL,
		SessionID:     "sess1",
		Mode:          ModeOn,
		RealShell:     "/bin/bash",
		ShellArgs:     []string{"-c", "echo hi"},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "wrap-init") {
		t.Fatalf("error %q does not mention wrap-init", err)
	}
}

// TestInstall_AutoSilentSkipOnServerError covers Mode=auto: server errors
// should fall through to skip (the shim then continues with its existing
// agentsh-exec proxy path).
func TestInstall_AutoSilentSkipOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	res, err := Install(InstallParams{
		ServerBaseURL: srv.URL,
		SessionID:     "sess1",
		Mode:          ModeAuto,
		RealShell:     "/bin/bash",
		ShellArgs:     []string{"-c", "echo hi"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultSkip {
		t.Fatalf("got action %v, want ResultSkip", res.Action)
	}
}

// TestInstall_BuildsExecPlan exercises the success path: wrap-init returns
// a notify socket, Install dials it, builds the wrapper exec plan with a
// non-CLOEXEC fd in env. We don't actually exec; the test inspects the plan.
func TestInstall_BuildsExecPlan(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(types.WrapInitResponse{
			WrapperBinary: "/usr/bin/agentsh-unixwrap",
			NotifySocket:  socketPath,
			WrapperEnv:    map[string]string{"AGENTSH_SECCOMP_CONFIG": "{}"},
		})
	}))
	defer srv.Close()

	res, err := Install(InstallParams{
		ServerBaseURL: srv.URL,
		SessionID:     "sess1",
		Mode:          ModeOn,
		RealShell:     "/bin/bash",
		ShellArgs:     []string{"-c", "echo hi"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != ResultExec {
		t.Fatalf("got action %v, want ResultExec", res.Action)
	}
	if res.ExecPath != "/usr/bin/agentsh-unixwrap" {
		t.Fatalf("got ExecPath %q", res.ExecPath)
	}
	wantArgs := []string{"agentsh-unixwrap", "--", "/bin/bash", "-c", "echo hi"}
	if len(res.ExecArgs) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", res.ExecArgs, wantArgs)
	}
	hasFD := false
	for _, e := range res.ExecEnv {
		if strings.HasPrefix(e, "AGENTSH_NOTIFY_SOCK_FD=") {
			hasFD = true
		}
	}
	if !hasFD {
		t.Fatal("AGENTSH_NOTIFY_SOCK_FD not in env")
	}
	// The fd must be open and CLOEXEC must be cleared (defaults to set).
	if res.NotifyFD <= 2 {
		t.Fatalf("got NotifyFD=%d, want >2", res.NotifyFD)
	}
	defer os.NewFile(uintptr(res.NotifyFD), "notify").Close()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOOS=linux go test ./internal/shim/kernelinstall/`
Expected: FAIL — `Install` not defined.

- [ ] **Step 3: Create the non-Linux stub**

Create `internal/shim/kernelinstall/install_other.go`:

```go
//go:build !linux

package kernelinstall

import "fmt"

// Install is unsupported on non-Linux targets.
func Install(p InstallParams) (Result, error) {
	return Result{Action: ResultSkip}, nil
}

// InstallParams declared here so the type compiles cross-platform.
type InstallParams struct {
	ServerBaseURL string
	SessionID     string
	Mode          Mode
	RealShell     string
	ShellArgs     []string
	Env           []string
	CallerUID     int
}

// Result and ResultAction declared cross-platform for the same reason.
type Result struct {
	Action   ResultAction
	ExecPath string
	ExecArgs []string
	ExecEnv  []string
	NotifyFD int
	Reason   string
}

type ResultAction int

const (
	ResultSkip ResultAction = iota
	ResultExec
	ResultFailClosed
)

var ErrNotSupported = fmt.Errorf("kernelinstall: not supported on this platform")
```

- [ ] **Step 4: Implement install_linux.go**

Create `internal/shim/kernelinstall/install_linux.go`:

```go
//go:build linux

package kernelinstall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

// InstallParams collects everything Install needs. ServerBaseURL is the
// HTTP base (e.g. "http://127.0.0.1:18080"); the session ID identifies
// which session's policy to apply; RealShell + ShellArgs is the user's
// command (whatever the shim was about to execve). Env is the environment
// the shim would have passed to that command — Install appends marker and
// fd-number entries and returns the merged list.
type InstallParams struct {
	ServerBaseURL string
	SessionID     string
	Mode          Mode
	RealShell     string
	ShellArgs     []string
	Env           []string
	CallerUID     int
}

// ResultAction tells the caller (the shim) what to do next.
type ResultAction int

const (
	// ResultSkip = take the existing path (agentsh-exec proxy or real
	// shell). Returned for ModeAuto when wrap-init reports nothing to do
	// or when the server is unreachable.
	ResultSkip ResultAction = iota
	// ResultExec = syscall.Exec the returned ExecPath/Args/Env. The
	// NotifyFD is open and CLOEXEC-cleared on the calling process.
	ResultExec
	// ResultFailClosed = caller must exit 126 with the Reason.
	ResultFailClosed
)

// Result is what Install returns. Inspect Action; only ExecPath/Args/Env/
// NotifyFD are populated when Action == ResultExec; only Reason is
// populated when Action == ResultFailClosed.
type Result struct {
	Action   ResultAction
	ExecPath string
	ExecArgs []string
	ExecEnv  []string
	NotifyFD int
	Reason   string
}

const wrapInitTimeout = 5 * time.Second

// Install is the entry point used by the shim.
func Install(p InstallParams) (Result, error) {
	if p.Mode == ModeOff {
		return Result{Action: ResultSkip}, nil
	}

	resp, err := callWrapInit(p)
	if err != nil {
		if p.Mode == ModeOn {
			return Result{}, fmt.Errorf("wrap-init: %w", err)
		}
		// ModeAuto: silent skip on server unreachable / 5xx. The shim's
		// existing agentsh-exec proxy path will handle the request.
		return Result{Action: ResultSkip, Reason: err.Error()}, nil
	}

	// Install/skip signal: presence of WrapperBinary AND NotifySocket.
	// We deliberately do NOT use a boolean install_required field — see
	// pkg/types/sessions.go's WrapInitResponse doc comment for why
	// presence-of-WrapperBinary is the fail-closed wire choice.
	if resp.WrapperBinary == "" || resp.NotifySocket == "" {
		return Result{Action: ResultSkip}, nil
	}

	notifyFD, err := openNotifySocket(resp.NotifySocket)
	if err != nil {
		// Always fail-closed once we've committed to install — the
		// server is expecting a connection on the listener it created.
		return Result{}, fmt.Errorf("dial notify socket %s: %w", resp.NotifySocket, err)
	}

	env := append([]string{}, p.Env...)
	env = appendOrReplace(env, "AGENTSH_NOTIFY_SOCK_FD="+strconv.Itoa(notifyFD))
	for k, v := range resp.WrapperEnv {
		env = appendOrReplace(env, k+"="+v)
	}

	// argv[0] for the wrapper is its own basename, by convention.
	wrapperArgv0 := basename(resp.WrapperBinary)
	args := append([]string{wrapperArgv0, "--", p.RealShell}, p.ShellArgs...)

	return Result{
		Action:   ResultExec,
		ExecPath: resp.WrapperBinary,
		ExecArgs: args,
		ExecEnv:  env,
		NotifyFD: notifyFD,
	}, nil
}

func callWrapInit(p InstallParams) (types.WrapInitResponse, error) {
	body, _ := json.Marshal(types.WrapInitRequest{
		AgentCommand: p.RealShell,
		AgentArgs:    p.ShellArgs,
		CallerUID:    p.CallerUID,
		Mode:         "shim",
	})
	url := strings.TrimRight(p.ServerBaseURL, "/") + "/api/v1/sessions/" + p.SessionID + "/wrap-init"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return types.WrapInitResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: wrapInitTimeout}
	httpResp, err := client.Do(req)
	if err != nil {
		return types.WrapInitResponse{}, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode/100 != 2 {
		return types.WrapInitResponse{}, fmt.Errorf("status %d", httpResp.StatusCode)
	}
	var resp types.WrapInitResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return types.WrapInitResponse{}, fmt.Errorf("decode: %w", err)
	}
	return resp, nil
}

// openNotifySocket dials the server's notify Unix socket and returns a raw
// fd that survives execve. The dup-then-close-File pattern is required:
// *os.File has a finalizer that closes its fd, so we dup to escape it.
// The wrapper inherits the open raw fd and writes the seccomp notify fd
// back over it via SCM_RIGHTS (see agentsh-unixwrap's sendFD path).
func openNotifySocket(path string) (int, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return -1, err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return -1, fmt.Errorf("dialed connection is not *net.UnixConn (%T)", conn)
	}
	f, err := uc.File() // f is a dup of the underlying fd
	uc.Close()
	if err != nil {
		return -1, fmt.Errorf("File: %w", err)
	}
	// Dup once more to escape the *os.File finalizer.
	rawFD, err := unix.Dup(int(f.Fd()))
	f.Close()
	if err != nil {
		return -1, fmt.Errorf("dup: %w", err)
	}
	// Clear CLOEXEC so the fd survives execve into the wrapper.
	if _, err := unix.FcntlInt(uintptr(rawFD), unix.F_SETFD, 0); err != nil {
		unix.Close(rawFD)
		return -1, fmt.Errorf("fcntl F_SETFD 0: %w", err)
	}
	return rawFD, nil
}

func appendOrReplace(env []string, kv string) []string {
	eq := strings.IndexByte(kv, '=')
	if eq < 0 {
		return append(env, kv)
	}
	key := kv[:eq+1]
	for i, e := range env {
		if strings.HasPrefix(e, key) {
			env[i] = kv
			return env
		}
	}
	return append(env, kv)
}

func basename(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/shim/kernelinstall/`
Expected: all PASS.

- [ ] **Step 6: Verify cross-compile**

Run: `GOOS=darwin go build ./internal/shim/kernelinstall/ && GOOS=windows go build ./internal/shim/kernelinstall/`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/shim/kernelinstall/install_linux.go internal/shim/kernelinstall/install_other.go internal/shim/kernelinstall/install_linux_test.go
git commit -m "feat(shim): kernelinstall.Install dials wrap-init and builds exec plan"
```

---

## Phase 4 — Wire kernelinstall into the shell shim

### Task 7: Insert install branch in `cmd/agentsh-shell-shim/main.go`

**Files:**
- Modify: `cmd/agentsh-shell-shim/main.go` (insert before line 224 `args := []string{agentshBin, "exec"}`)

- [ ] **Step 1: Add the call site**

In `cmd/agentsh-shell-shim/main.go`, after the `tty := term.IsTerminal(...)` line (~line 224), add:

```go
	// Try shim-installed kernel enforcement (issues #267 + #268). When the
	// shim is not in the agentsh server's process tree (sandbox-SDK
	// pattern), file/network/signal policy needs to be installed by the
	// shim itself before execve. The kernelinstall package decides
	// whether to skip, exec the wrapper, or fail-closed based on the
	// shim_install mode and the server's wrap-init response.
	//
	// We deliberately do NOT short-circuit nested invocations on any
	// "already-filtered" signal: env-var markers are caller-controlled,
	// and Seccomp:2 is true for any container default profile (Docker,
	// k8s) so it can't be used to recognize "agentsh already installed
	// here". Always install. Filter stacking up to the kernel's 64-filter
	// limit covers realistic nesting depths.
	{
		mode, modeErr := kernelinstall.ResolveMode(conf.ShimInstall, os.Getenv("AGENTSH_SHIM_INSTALL"))
		if modeErr != nil {
			fatalWithHint(127, "agentsh-shell-shim: "+modeErr.Error(),
				"Set shim_install in /etc/agentsh/shim.conf or AGENTSH_SHIM_INSTALL to one of: auto, on, off.")
		}
		serverBase := serverHTTPBaseURL() // helper added below
		res, instErr := kernelinstall.Install(kernelinstall.InstallParams{
			ServerBaseURL: serverBase,
			SessionID:     sessID,
			Mode:          mode,
			RealShell:     realShell,
			ShellArgs:     shellArgs,
			Env:           os.Environ(),
			CallerUID:     os.Getuid(),
		})
		if instErr != nil {
			// Mode=on path with wrap-init error: fail-closed.
			fatalWithHint(126, "agentsh-shell-shim: kernel install: "+instErr.Error(),
				"Disable shim install via shim_install=off or AGENTSH_SHIM_INSTALL=off if this is breaking workloads.")
		}
		switch res.Action {
		case kernelinstall.ResultExec:
			debugLog("kernel install: execve %s with NotifyFD=%d", res.ExecPath, res.NotifyFD)
			if err := syscall.Exec(res.ExecPath, res.ExecArgs, res.ExecEnv); err != nil {
				fatalWithHint(126, "agentsh-shell-shim: exec wrapper: "+err.Error(),
					"Verify agentsh-unixwrap is installed and on PATH.")
			}
			return // unreachable
		case kernelinstall.ResultFailClosed:
			fatalWithHint(126, "agentsh-shell-shim: kernel install fail-closed: "+res.Reason,
				"Disable shim install via shim_install=off if this is breaking workloads.")
		case kernelinstall.ResultSkip:
			debugLog("kernel install: skip (%s)", res.Reason)
			// fall through to existing agentsh-exec proxy path
		}
	}

	// Existing agentsh-exec proxy path:
	args := []string{agentshBin, "exec"}
```

Add the import at the top of the file:

```go
	"github.com/agentsh/agentsh/internal/shim/kernelinstall"
```

- [ ] **Step 2: Add the `serverHTTPBaseURL` helper**

At the bottom of `cmd/agentsh-shell-shim/main.go` (next to `serverAddrFromEnv`), add:

```go
// serverHTTPBaseURL returns the HTTP base URL for the agentsh server,
// suitable for kernelinstall.Install. Defaults to the local server when
// AGENTSH_SERVER is unset. Returns the URL even when the server is
// unreachable; the caller's Mode dictates how that error is handled.
func serverHTTPBaseURL() string {
	v := strings.TrimSpace(os.Getenv("AGENTSH_SERVER"))
	if v != "" {
		return v
	}
	return "http://127.0.0.1:18080"
}
```

- [ ] **Step 3: Build to verify compile**

Run: `go build ./cmd/agentsh-shell-shim/`
Expected: no errors.

- [ ] **Step 4: Verify cross-compile**

Run: `GOOS=windows go build ./cmd/agentsh-shell-shim/`
Expected: no errors (kernelinstall has the non-Linux stub).

- [ ] **Step 5: Commit**

```bash
git add cmd/agentsh-shell-shim/main.go
git commit -m "feat(shim): wire kernelinstall before agentsh-exec proxy path"
```

---

## Phase 5 — Integration coverage

### Task 8: Sibling-process integration test

**Files:**
- Create: `internal/api/seccomp_wrapper_shim_install_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/api/seccomp_wrapper_shim_install_test.go`:

```go
//go:build linux && cgo

package api

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestShimInstall_SiblingProcessTree starts the agentsh server, then
// spawns bash via the shim from a process tree that is *not* a child of
// the server (mirroring the sandbox-SDK pattern from issue #267/#268).
// Asserts that `cat /etc/shadow` is blocked even though the shim is in
// a different process tree.
//
// Skips when the test environment lacks the kernel features (Landlock or
// seccomp-notify).
//
// We use a tempdir-based deny target instead of /etc/shadow because the
// latter is already 0600 root:root in most test environments, so a read
// attempt fails on Unix DAC alone — the test would pass even with no
// agentsh enforcement at all (false positive). The tempdir file is
// readable by the test user by default, so a successful deny *only*
// happens if Landlock actually blocks the read.
func TestShimInstall_SiblingProcessTree(t *testing.T) {
	denyDir := t.TempDir()
	denyFile := filepath.Join(denyDir, "secret.txt")
	if err := os.WriteFile(denyFile, []byte("SHOULD_NOT_LEAK"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sanity check: without agentsh, the test user can read the file.
	// If this fails, the environment is wrong (not the policy).
	if _, err := os.ReadFile(denyFile); err != nil {
		t.Fatalf("environment check failed: test user cannot read %s without policy: %v", denyFile, err)
	}

	srv, _ := startTestServerWithLandlockDeny(t, denyFile)
	defer srv.Close()

	shimPath := buildShim(t)
	wrapPath := buildWrap(t) // ensures agentsh-unixwrap is on PATH

	cmd := exec.CommandContext(context.Background(), shimPath, "-c", "cat "+denyFile)
	cmd.Env = append(os.Environ(),
		"AGENTSH_SERVER="+srv.URL,
		"AGENTSH_SESSION_ID=test-shim-install",
		"AGENTSH_SHIM_INSTALL=on",
		"PATH="+filepath.Dir(wrapPath)+":"+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	t.Logf("output: %s", out)
	if err == nil {
		t.Fatalf("expected non-zero exit, got 0; output:\n%s", out)
	}
	if strings.Contains(string(out), "SHOULD_NOT_LEAK") {
		t.Fatalf("denyFile contents leaked; filter not enforced:\n%s", out)
	}
}

// startTestServerWithLandlockDeny, buildShim, buildWrap are helpers that
// already exist or live alongside seccomp_wrapper_test.go. If they do not,
// add them next to the existing seccompWrapper helpers using
// go test -count=1 to drive their TDD.
```

- [ ] **Step 2: Run test to verify it fails (or skips)**

Run: `go test -tags=cgo -run TestShimInstall_SiblingProcessTree ./internal/api/`
Expected: FAIL (filter not enforced) or SKIP (if /etc/shadow not present in dev env). Document which.

- [ ] **Step 3: Make the helpers exist**

If `startTestServerWithLandlockDeny`, `buildShim`, `buildWrap` are missing, model them on the existing `seccomp_wrapper_test.go` helpers (it already builds the wrapper and starts a test server). Add the helpers in a new file `internal/api/shim_test_helpers.go` with `//go:build linux && cgo`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -tags=cgo -run TestShimInstall_SiblingProcessTree ./internal/api/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/seccomp_wrapper_shim_install_test.go internal/api/shim_test_helpers.go
git commit -m "test(api): integration test for shim-installed Landlock on sibling process tree"
```

---

### Task 9: Nested-shim filters compose, inner shell still enforced

**Files:**
- Modify: `internal/api/seccomp_wrapper_shim_install_test.go`

- [ ] **Step 1: Append the failing test**

Add to `seccomp_wrapper_shim_install_test.go`:

```go
// TestShimInstall_NestedInstallsCompose verifies that bash -c "bash -c cat <denyFile>"
// installs filters at BOTH levels (filter stacking is allowed up to the
// kernel's 64-filter limit), and that the inner shell's read of the
// deny-target is still blocked. We don't try to deduplicate nested
// installs — there's no portable, unforgeable signal for "agentsh already
// installed here", so always-install is the safe choice.
//
// Uses a tempdir-based deny target (not /etc/shadow) so the test cannot
// pass on Unix DAC alone — see TestShimInstall_SiblingProcessTree.
func TestShimInstall_NestedInstallsCompose(t *testing.T) {
	denyDir := t.TempDir()
	denyFile := filepath.Join(denyDir, "secret.txt")
	if err := os.WriteFile(denyFile, []byte("SHOULD_NOT_LEAK"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(denyFile); err != nil {
		t.Fatalf("environment check failed: cannot read %s without policy: %v", denyFile, err)
	}

	srv, callCount := startTestServerCountingWithLandlockDeny(t, denyFile)
	defer srv.Close()

	shimPath := buildShim(t)
	wrapPath := buildWrap(t)

	cmd := exec.Command(shimPath, "-c", "bash -c 'cat "+denyFile+"'")
	cmd.Env = append(os.Environ(),
		"AGENTSH_SERVER="+srv.URL,
		"AGENTSH_SESSION_ID=test-shim-nested",
		"AGENTSH_SHIM_INSTALL=on",
		"PATH="+filepath.Dir(wrapPath)+":"+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	t.Logf("output: %s", out)
	if err == nil {
		t.Fatalf("expected non-zero exit (inner read blocked), got 0:\n%s", out)
	}
	if strings.Contains(string(out), "SHOULD_NOT_LEAK") {
		t.Fatalf("denyFile contents leaked from inner shell; nested filter not enforced:\n%s", out)
	}
	if got := callCount(); got != 2 {
		t.Fatalf("got %d wrap-init calls, want 2 (one per nested invocation)", got)
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test -tags=cgo -run TestShimInstall_NestedInstallsCompose ./internal/api/`
Expected: PASS — both levels install, inner read blocked, count == 2. If it fails, check the inner wrapper is actually installing on top of the outer (filter stacking) and the server's notify handler is processing both filter chains correctly.

- [ ] **Step 3: Commit**

```bash
git add internal/api/seccomp_wrapper_shim_install_test.go
git commit -m "test(api): nested shim invocations compose filters; inner shell still enforced"
```

---

## Phase 6 — Config block + docs

### Task 10: Add `sandbox.shim_install` config block

**Files:**
- Modify: `internal/config/config.go:343-365`
- Create: a small unit test for the new block in `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/config/config_test.go`:

```go
func TestSandboxConfig_ShimInstall_Default(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte("sandbox:\n  shim_install:\n    mode: on\n"), &c); err != nil {
		t.Fatal(err)
	}
	if c.Sandbox.ShimInstall.Mode != "on" {
		t.Fatalf("got %q, want %q", c.Sandbox.ShimInstall.Mode, "on")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestSandboxConfig_ShimInstall_Default ./internal/config/`
Expected: FAIL (field not defined).

- [ ] **Step 3: Add the config block**

In `internal/config/config.go`, add a new field to `SandboxConfig`:

```go
type SandboxConfig struct {
	// ... existing fields ...
	ShimInstall SandboxShimInstallConfig `yaml:"shim_install"`
}

// SandboxShimInstallConfig governs whether the shell shim installs kernel
// filters (seccomp-notify + Landlock) on its own process before execve.
// See docs/cookbook/sandbox-sdk-integrations.md.
type SandboxShimInstallConfig struct {
	// Mode is one of "auto" (default), "on", "off".
	Mode string `yaml:"mode"`
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/config/`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add sandbox.shim_install.mode config block"
```

---

### Task 11: Cookbook doc

**Files:**
- Create: `docs/cookbook/sandbox-sdk-integrations.md`

- [ ] **Step 1: Write the doc**

Create `docs/cookbook/sandbox-sdk-integrations.md`:

```markdown
# Sandbox SDK integrations (Tensorlake / E2B / Modal / Daytona)

When agentsh runs as a service that supervises commands spawned by a
sandbox SDK, the spawned commands are siblings of the agentsh server,
not descendants. Kernel filters loaded on the agentsh server's process
(Landlock, seccomp-notify) do not govern them.

`sandbox.shim_install` closes that gap by having the shell shim install
the same filters on its own process before exec'ing the user's command,
so the inherited filter follows the command into whatever process tree
the SDK spawned it into.

## Configuration

```yaml
sandbox:
  shim_install:
    mode: auto    # auto | on | off  (default: auto)
```

- `auto` (default): shim asks the server via `wrap-init`. Installs when
  the server reports any enforcement is configured; falls through
  silently when nothing is configured or the server is unreachable.
- `on`: shim must install. Any failure (server unreachable, kernel
  rejects the filter) exits 126 with a hint pointing at this doc.
- `off`: shim never attempts install. Equivalent to pre-#267 behavior.

The override env var is `AGENTSH_SHIM_INSTALL=auto|on|off`. Env wins
over `/etc/agentsh/shim.conf` and over the server-side YAML config.

## What it does

Per shim invocation, when install is required:

1. Shim opens the server's notify socket directly (no relay).
2. Sets `AGENTSH_NOTIFY_SOCK_FD=<n>`.
3. `syscall.Exec`s `agentsh-unixwrap` with the user's shell command.
4. `agentsh-unixwrap` installs seccomp-notify, sends the notify fd back
   over the socket, applies Landlock, then execve's the user's shell.
5. The user's command runs under both filters.

Nested shim invocations (`bash -c "bash -c ..."`) **install at every
level** — filter stacking up to the kernel's 64-filter limit is allowed
and easily covers realistic nesting depths. There is no portable,
unforgeable way to detect "the active filter is *our* filter" without
elevated privileges (env-var markers are caller-controlled; a
container's default seccomp profile already sets `Seccomp:2` so that
kernel-state field can't be used to recognize agentsh's install). The
safe choice is to always install when the shim is not in-session.

## Limitations

- **Direct SDK exec** (`sb.exec("cat", [...])` without going through
  any shell) bypasses the shim. The fix on that path is to integrate
  the SDK with `agentsh exec` directly. Tracked as a separate concern.
- **No-new-privileges environments** (Daytona, Fargate) reject the
  seccomp install. `mode=auto` will detect this server-side and fall
  through; ptrace-pid mode (#269) remains the enforcement path on
  those environments.
- **Per-invocation cost** is ~5–10 ms (HTTP wrap-init + exec hop +
  filter install). Acceptable for sandbox-SDK use; not recommended for
  workloads that fork thousands of short-lived commands per second.
```

- [ ] **Step 2: Commit**

```bash
git add docs/cookbook/sandbox-sdk-integrations.md
git commit -m "docs(cookbook): sandbox-SDK integrations and shim_install config"
```

---

## Phase 7 — Final verification

### Task 12: Full build + test suite

- [ ] **Step 1: Cross-compile**

```bash
go build ./...
GOOS=windows go build ./...
GOOS=darwin go build ./...
```

Expected: no errors anywhere.

- [ ] **Step 2: Run unit tests**

```bash
go test ./internal/shim/... ./internal/api/... ./internal/config/... ./pkg/types/...
```

Expected: all PASS.

- [ ] **Step 3: Run the integration suite (Linux + cgo)**

```bash
go test -tags=cgo ./internal/api/ -run 'TestShimInstall|TestWrapInit'
```

Expected: all PASS or documented SKIP (Landlock/seccomp-notify not available in CI).

- [ ] **Step 4: Smoke test the issue's repro grid**

Create a tiny throwaway script that exercises the same set of denies as Eran's `agentsh-tensorlake/DETECT.md`:

```bash
for cmd in 'sudo whoami' 'kill -9 1' 'cat /etc/shadow' 'touch /etc/x'; do
  out=$(/bin/bash -c "$cmd" 2>&1; echo "exit=$?")
  echo "[$cmd] $out"
done
```

Run it inside an environment where the new shim is installed and `shim_install: on` is set. Expected: every line shows non-zero exit / blocked behavior. Capture this output and paste it into the PR description for #267 + #268.

- [ ] **Step 5: Commit-free verification of the spec checklist**

Re-read `docs/superpowers/specs/2026-05-02-shim-kernel-enforcement-design.md`. For each section ("Goals", "Server-side changes", "Client-side changes", "Config", "Failure modes", "Performance", "Testing"), check there is at least one task in this plan that implements it. If not, add a task before declaring the plan done.
