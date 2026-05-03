# Shim-installed kernel enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the file/network/signal-policy gap when commands are spawned outside agentsh server's process tree (sandbox-SDK pattern: Tensorlake, E2B, Modal). The shim invokes the existing `agentsh-unixwrap` machinery on its own process before execve, so kernel filters govern the user's command even though it isn't a descendant of the agentsh server.

**Architecture:** Reuse `/api/v1/sessions/{id}/wrap-init` with a new `Mode: "shim"` request field. The server always returns the same populated response regardless of Mode — install/skip is the shim's decision, governed by its `mode=auto/on/off` config (fail-closed: an old server returning a populated response triggers an install). Per-invocation listener cleanup for shim-mode wraps. Shim opens the server's notify Unix socket directly (no socketpair relay), clears CLOEXEC on the fd, then launches `agentsh-unixwrap` as a **child process** via `runAndExit` (NOT `syscall.Exec`) with `AGENTSH_NOTIFY_SOCK_FD` set. **The shim always installs** when mode != off — there is no portable, unforgeable way to detect "already installed by us" (env-var markers are caller-controlled; `Seccomp:2` is true for any container default profile). Filter stacking up to the kernel's 64-filter limit covers realistic nesting depths. Default-on with one operator override (`sandbox.shim_install.mode = auto|on|off`). Fail-closed. **IMPORTANT: the install branch runs BEFORE the `AGENTSH_IN_SESSION=1` recursion guard** — `AGENTSH_IN_SESSION` is caller-controllable, so gating install on it would let a malicious sandbox-SDK supervisor pre-set the env var and bypass enforcement. The recursion guard remains in place for the agentsh-exec proxy path only (where recursion would deadlock). Server-spawned children running the install branch install again — wasteful but safe.

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
- `internal/api/wrap_shim_mode_test.go` — server-side regression test that `Mode: "shim"` returns the same shape of response as agent mode (populated `WrapperBinary`); locks in the no-server-side-predicate contract.
- `internal/api/seccomp_wrapper_shim_install_test.go` — integration test: bash spawns in a sibling process tree; assert reads of a tempdir-based deny target are blocked.
- `docs/cookbook/sandbox-sdk-integrations.md` — operator-facing doc for `sandbox.shim_install.mode` and the integration model.

**Modified:**
- `pkg/types/sessions.go` — `WrapInitRequest.Mode` field. (No new response field — install/skip is signalled by `WrapperBinary` presence; see Architecture.)
- `internal/api/wrap.go` — `wrapInitCore` accepts `Mode == "shim"` (consumed only by Task 3 lifecycle change; no install/skip predicate — see iter-2 simplification in Task 2).
- `internal/api/wrap_linux.go` — `acceptNotifyFD` accepts an optional teardown context for per-invocation cleanup.
- `internal/config/config.go` — `SandboxConfig.ShimInstall` block with `Mode string`.
- `internal/shim/conf.go` — `ShimConf.ShimInstall string` (parsed from `shim_install=` line in `/etc/agentsh/shim.conf`).
- `internal/shim/conf_test.go` — coverage for the new key.
- `cmd/agentsh-shell-shim/main.go` — insert kernelinstall branch BEFORE the existing `if inSession == "1"` recursion guard (not after the agentsh-exec proxy, before it — install branch must run before the caller-controllable `AGENTSH_IN_SESSION` check).

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

### Task 2: No server-side install/skip predicate — COMPLETED (simplified, see note)

**Roborev iteration 2 simplification:** The original plan added a `shimInstallRequired` predicate and short-circuit. That predicate could not be made complete: `mainFilterUsesUserNotify` covers notify-based configs but misses non-notify paths (errno/kill blocked syscalls, blocked socket families with errno/kill, `block_io_uring`, and the older `sandbox.unix_sockets.enabled` override). Each missed gate was a silent policy bypass.

**Resolution (commit 94fd906b):** The short-circuit and `shimInstallRequired` were dropped entirely. `wrapInitCore` now always returns the same populated response regardless of `Mode`, matching agent-mode behavior exactly. The install/skip decision belongs to the shim (via its `mode=auto/on/off` config), not the server. `Mode=="shim"` stays in the request type and is still consumed by Task 3 (per-invocation listener cleanup vs session-scoped).

**Files changed:**
- `internal/api/wrap.go` — removed `if req.Mode == "shim" && !a.shimInstallRequired()` block and `shimInstallRequired` method
- `internal/api/wrap_shim_mode_test.go` — replaced two tests (NothingEnabled / LandlockEnabled) with one test (`TestWrapInit_ShimMode_PopulatesWrapperBinary`) proving shim-mode returns a populated `WrapperBinary` just like agent-mode

- [x] **Step 1: Drop the short-circuit and helper** — done (94fd906b)
- [x] **Step 2: Replace test file** — done (94fd906b)
- [x] **Step 3: Build + tests pass** — `go test -run TestWrapInit ./internal/api/` and cross-compile both clean

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
		{name: "env_strengthens_auto_to_on", conf: "auto", env: "on", want: ModeOn},
		{name: "env_cannot_weaken_on_to_off", conf: "on", env: "off", want: ModeOn},
		{name: "env_cannot_weaken_on_to_auto", conf: "on", env: "auto", want: ModeOn},
		{name: "env_cannot_weaken_auto_to_off", conf: "auto", env: "off", want: ModeAuto},
		{name: "env_off_with_conf_off_stays_off", conf: "off", env: "off", want: ModeOff},
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
// Order is meaningful: off < auto < on (lower = weaker enforcement).
type Mode int

const (
	ModeOff  Mode = iota // never install (admin opt-out)
	ModeAuto             // install when wrap-init returns a populated response
	ModeOn               // install or fail-closed
)

func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeAuto:
		return "auto"
	case ModeOn:
		return "on"
	default:
		return "unknown"
	}
}

// ResolveMode picks the effective mode from the trusted config-file value
// and the (untrusted, caller-controlled) env-var override.
//
// Trust model: /etc/agentsh/shim.conf is root-owned and admin-managed,
// so its value is authoritative. The AGENTSH_SHIM_INSTALL env var is
// readable from the caller's environment, so a malicious sandbox-SDK
// supervisor could pre-set it. To prevent silent bypass, the env var
// is honored ONLY if it would STRENGTHEN the effective mode (i.e.,
// produce a higher Mode value in the off < auto < on ordering). An
// env-var attempt to weaken is silently ignored — the config wins.
//
// Empty conf defaults to ModeAuto. Empty env is ignored.
func ResolveMode(conf, env string) (Mode, error) {
	confMode, err := parseMode(conf, ModeAuto)
	if err != nil {
		return ModeAuto, fmt.Errorf("conf: %w", err)
	}
	if env == "" {
		return confMode, nil
	}
	envMode, err := parseMode(env, confMode)
	if err != nil {
		return confMode, fmt.Errorf("env: %w", err)
	}
	// Env may only strengthen.
	if envMode > confMode {
		return envMode, nil
	}
	return confMode, nil
}

// parseMode parses a mode string. Empty string returns the supplied default.
// Unknown values return an error.
func parseMode(s string, def Mode) (Mode, error) {
	if s == "" {
		return def, nil
	}
	switch s {
	case "off":
		return ModeOff, nil
	case "auto":
		return ModeAuto, nil
	case "on":
		return ModeOn, nil
	default:
		return def, fmt.Errorf("invalid mode %q (expected auto, on, or off)", s)
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
	APIKey        string // for X-API-Key auth header (read from AGENTSH_API_KEY in the shim wiring)
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
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

// InstallParams collects everything Install needs. ServerBaseURL is the
// HTTP base (e.g. "http://127.0.0.1:18080"); the session ID identifies
// which session's policy to apply; APIKey is the X-API-Key credential
// required by API-key-protected deployments (read from AGENTSH_API_KEY
// in the shim wiring). RealShell + ShellArgs is the user's command
// (whatever the shim was about to execve). Env is the environment the
// shim would have passed to that command — Install appends marker and
// fd-number entries and returns the merged list.
type InstallParams struct {
	ServerBaseURL string
	SessionID     string
	APIKey        string // for X-API-Key auth header (read from AGENTSH_API_KEY in the shim wiring)
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
	// ResultExec = launch the returned ExecPath/Args/Env as a CHILD process
	// (use runAndExit, not syscall.Exec). The NotifyFD is open and
	// CLOEXEC-cleared on the calling process; the child inherits it. The
	// shim must not replace itself via syscall.Exec — see
	// cmd/agentsh-shell-shim/main.go's existing runAndExit comment for
	// the SDK output-capture rationale (Daytona/E2B toolboxes track the
	// originally-spawned PID's pipes).
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

// callWrapInit wraps internal/client's WrapInit so kernelinstall picks
// up the canonical auth (X-API-Key), transport (HTTP / Unix socket /
// gRPC), timeouts, and path-escaping. Hand-rolled HTTP would silently
// miss API-key headers and skip enforcement on protected deployments.
func callWrapInit(p InstallParams) (types.WrapInitResponse, error) {
	cl, err := client.NewForCLI(client.CLIOptions{
		HTTPBaseURL:   p.ServerBaseURL,
		APIKey:        p.APIKey,
		ClientTimeout: wrapInitTimeout,
	})
	if err != nil {
		return types.WrapInitResponse{}, fmt.Errorf("client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), wrapInitTimeout)
	defer cancel()
	return cl.WrapInit(ctx, p.SessionID, types.WrapInitRequest{
		AgentCommand: p.RealShell,
		AgentArgs:    p.ShellArgs,
		CallerUID:    p.CallerUID,
		Mode:         "shim",
	})
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
- Modify: `cmd/agentsh-shell-shim/main.go` (insert BEFORE the existing `if inSession == "1"` block — the install branch must run before the recursion guard)

- [ ] **Step 1: Add the call site**

In `cmd/agentsh-shell-shim/main.go`, insert the kernelinstall block BEFORE the existing `if inSession == "1"` recursion guard (around line 41). The placement is deliberate — see the comment in the code:

```go
// Try shim-installed kernel enforcement (issues #267 + #268). When the
// shim is not in the agentsh server's process tree (sandbox-SDK
// pattern), file/network/signal policy needs to be installed by the
// shim itself before execve.
//
// IMPORTANT: this branch deliberately runs BEFORE the AGENTSH_IN_SESSION
// recursion guard. The env var is caller-controllable, so gating the
// install branch on it would let a malicious sandbox-SDK supervisor
// pre-set AGENTSH_IN_SESSION=1 and bypass kernel enforcement entirely.
// In the legitimate server-spawned-child case, the install branch
// just installs again — wasteful (filter stacking) but safe. The
// in-session guard remains in place for the agentsh-exec proxy that
// follows it (where recursion would actually deadlock).
{
    mode, modeErr := kernelinstall.ResolveMode(conf.ShimInstall, os.Getenv("AGENTSH_SHIM_INSTALL"))
    if modeErr != nil {
        fatalWithHint(126, fmt.Sprintf("agentsh-shell-shim: shim_install mode: %v", modeErr), "")
    }
    res, installErr := kernelinstall.Install(kernelinstall.InstallParams{
        ServerBaseURL: serverHTTPBaseURL(),
        SessionID:     sessID,
        APIKey:        os.Getenv("AGENTSH_API_KEY"),
        Mode:          mode,
        RealShell:     realShell,
        ShellArgs:     os.Args[1:],
        Env:           os.Environ(),
    })
    if installErr != nil {
        fatalWithHint(126, fmt.Sprintf("agentsh-shell-shim: kernel install: %v", installErr),
            "To disable, set sandbox.shim_install.mode=off in /etc/agentsh/shim.conf")
    }
    if res.Action == kernelinstall.ResultExec {
        // Launch agentsh-unixwrap as a CHILD process, not via syscall.Exec.
        // Sandbox toolboxes (Daytona, E2B) capture output by reading pipes
        // attached to the process they started (the shim). syscall.Exec
        // would replace the shim and the toolbox would lose its output pipe.
        // runAndExit forks the wrapper, copies pipes through, and exits with
        // the wrapper's exit code — keeping the shim's PID alive until done.
        // The NotifyFD has CLOEXEC cleared; the child inherits it.
        runAndExit(res.ExecPath, "", res.ExecArgs[1:], res.ExecEnv)
        // runAndExit calls os.Exit; the line below is unreachable.
    }
}

// Existing recursion guard (unchanged):
if inSession == "1" {
    ... (existing block) ...
}

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

The override env var is `AGENTSH_SHIM_INSTALL=auto|on|off`. The env var
may only **strengthen** enforcement, never weaken it: the trusted source
is `/etc/agentsh/shim.conf` (root-owned, admin-managed). If the env var
would produce a weaker mode than the config (e.g., config says `on` and
env says `off`), the env var is silently ignored and the config wins.

## What it does

Per shim invocation, when install is required:

1. Shim opens the server's notify socket directly (no relay).
2. Sets `AGENTSH_NOTIFY_SOCK_FD=<n>`.
3. Launches `agentsh-unixwrap` as a **child process** via `runAndExit` (NOT `syscall.Exec`). The shim stays alive as the parent, keeping its pipes open so sandbox toolboxes (Daytona, E2B) that track the spawned PID's output don't lose it when the wrapper runs.
4. `agentsh-unixwrap` installs seccomp-notify, sends the notify fd back
   over the socket, applies Landlock, then execve's the user's shell.
5. The user's command runs under both filters. The wrapper's exit code
   propagates back through the shim via `runAndExit`.

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
  seccomp install with EPERM. Once the shim has committed to install
  (wrap-init returned a usable response and the wrapper was launched),
  the wrapper's non-zero exit propagates as exit 126 in BOTH `mode=auto`
  and `mode=on` — there is no silent skip. To avoid this, operators on
  no-new-privs environments should set `mode=off` and use ptrace-pid
  mode (#269) instead.
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
