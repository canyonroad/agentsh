# Interception-Aware Opaque Shell-C Pre-Check — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the shell-shim policy pre-check from denying benign `bash -c`/`sh -c` scripts when runtime `execve` enforcement is active, while keeping the hard-deny when it is not.

**Architecture:** `policy.Engine.CheckCommand`'s opaque-script pre-deny becomes conditional on an `execveEnforcementActive` flag passed in by the caller. When true (seccomp-execve or ptrace active), the opaque script is allowed to run and its inner `execve` calls are policed at depth by the existing `CheckExecve` path; when false, behavior is byte-for-byte unchanged. The flag is computed by the `App` (`cfg.Sandbox.Seccomp.Execve.Enabled || a.ptraceTracer != nil`) and threaded only through the five command pre-check call sites.

**Tech Stack:** Go; existing `internal/policy` engine and `internal/api` server.

**Spec:** `docs/superpowers/specs/2026-05-23-issue-375-shellc-opaque-interception-aware-design.md`

---

## File Structure

- `internal/policy/engine.go` — split `CheckCommand` into an internal `checkCommand(command, args, execveEnforcementActive bool)`; keep `CheckCommand` as a `false` wrapper; add `CheckCommandWithExecve`. Gate the `shellc-opaque-script` branch on `!execveEnforcementActive`.
- `internal/policy/command_shellc_interception_test.go` (new) — interception-on/off behavior + reporter battery + inner-deny-still-enforced.
- `internal/api/session_policy.go` — add `App.execveEnforcementActive()` helper.
- `internal/api/exec_stream.go`, `internal/api/pty_core.go`, `internal/api/grpc.go`, `internal/api/core.go` (×2) — switch the command pre-check call to `CheckCommandWithExecve(..., <app>.execveEnforcementActive())`.
- `internal/api/session_policy_test.go` (new or existing) — unit test for `execveEnforcementActive()`.

---

## Task 1: Engine — interception-aware opaque gate

**Files:**
- Modify: `internal/policy/engine.go` (function `CheckCommand`, currently at `engine.go:583`; opaque branch at `engine.go:618`)
- Test: `internal/policy/command_shellc_interception_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `internal/policy/command_shellc_interception_test.go`:

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// newInterceptionTestEngine builds an engine whose policy has a restrictive
// command rule (deny-shutdown), so hasRestrictiveCommandRule is set and the
// opaque pre-deny gate is reachable. Mirrors command_shellc_test.go.
func newInterceptionTestEngine(t *testing.T) *Engine {
	t.Helper()
	p := &Policy{
		CommandRules: []CommandRule{
			{Name: "deny-shutdown", Commands: []string{"shutdown"}, Decision: "deny"},
			{Name: "allow-shells", Commands: []string{"sh", "bash", "dash", "zsh"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// Issue #375: with execve enforcement active, opaque shell-c scripts must NOT
// be statically pre-denied — inner execs are policed at runtime by CheckExecve.
func TestCheckCommand_OpaqueAllowedWhenExecveEnforced(t *testing.T) {
	e := newInterceptionTestEngine(t)

	battery := []string{
		"echo $HOME",
		"ls /tmp | head",
		"echo x > /tmp/a",
		"true && true",
		"echo $(date)",
		"for i in 1 2; do echo $i; done",
		"curl https://example.com",
	}
	for _, script := range battery {
		dec := e.CheckCommandWithExecve("/bin/sh", []string{"-c", script}, true)
		if dec.Rule == "shellc-opaque-script" {
			t.Errorf("script %q: pre-denied as opaque with execve enforcement active; want fall-through to allow", script)
		}
		if dec.PolicyDecision != types.DecisionAllow {
			t.Errorf("script %q: decision = %s (rule=%q), want allow", script, dec.PolicyDecision, dec.Rule)
		}
	}
}

// Without execve enforcement, the current hard-deny is preserved.
func TestCheckCommand_OpaqueDeniedWhenNoExecveEnforcement(t *testing.T) {
	e := newInterceptionTestEngine(t)

	dec := e.CheckCommandWithExecve("/bin/sh", []string{"-c", "echo $HOME | head"}, false)
	if dec.PolicyDecision != types.DecisionDeny || dec.Rule != "shellc-opaque-script" {
		t.Errorf("got %s rule=%q, want deny shellc-opaque-script", dec.PolicyDecision, dec.Rule)
	}

	// Plain CheckCommand (no execve param) must keep the legacy hard-deny too.
	dec2 := e.CheckCommand("/bin/sh", []string{"-c", "echo $HOME | head"})
	if dec2.PolicyDecision != types.DecisionDeny || dec2.Rule != "shellc-opaque-script" {
		t.Errorf("CheckCommand: got %s rule=%q, want deny shellc-opaque-script", dec2.PolicyDecision, dec2.Rule)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails to compile/fail**

Run: `go test ./internal/policy/ -run TestCheckCommand_Opaque -v`
Expected: FAIL — `e.CheckCommandWithExecve` undefined (method not yet added).

- [ ] **Step 3: Implement the engine change**

In `internal/policy/engine.go`, replace the `CheckCommand` signature line (`engine.go:583`):

```go
func (e *Engine) CheckCommand(command string, args []string) Decision {
```

with these three definitions (the body that followed `CheckCommand` now belongs to `checkCommand`):

```go
// CheckCommand evaluates a command against the policy with no assumption of
// runtime execve interception (opaque shell-c scripts are pre-denied when a
// restrictive command rule is present). See CheckCommandWithExecve for callers
// on an execve-policed execution path.
func (e *Engine) CheckCommand(command string, args []string) Decision {
	return e.checkCommand(command, args, false)
}

// CheckCommandWithExecve is CheckCommand for callers whose execution path has
// runtime execve interception active (seccomp USER_NOTIF or ptrace), so every
// inner execve is policed by CheckExecve. When execveEnforcementActive is true
// the opaque shell-c pre-deny is skipped — the script runs and its inner
// commands are enforced precisely at exec time. Issue #375.
func (e *Engine) CheckCommandWithExecve(command string, args []string, execveEnforcementActive bool) Decision {
	return e.checkCommand(command, args, execveEnforcementActive)
}

func (e *Engine) checkCommand(command string, args []string, execveEnforcementActive bool) Decision {
```

Then change the opaque-deny gate (currently `engine.go:618`) from:

```go
			} else if e.hasRestrictiveCommandRule && shellparse.IsOpaqueShellC(cur, curArgs) {
```

to:

```go
			} else if e.hasRestrictiveCommandRule && !execveEnforcementActive && shellparse.IsOpaqueShellC(cur, curArgs) {
```

Leave the body of the function (everything after the opening brace) unchanged.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/policy/ -run TestCheckCommand_Opaque -v`
Expected: PASS (both tests).

- [ ] **Step 5: Run the full policy package + the existing shellc test**

Run: `go test ./internal/policy/`
Expected: ok (existing `command_shellc_test.go` still passes — it uses `CheckCommand`, which now defaults `false`).

- [ ] **Step 6: Commit**

```bash
git add internal/policy/engine.go internal/policy/command_shellc_interception_test.go
git commit -m "fix(#375): make opaque shell-c pre-deny interception-aware in policy engine"
```

---

## Task 2: App — execveEnforcementActive() helper

**Files:**
- Modify: `internal/api/session_policy.go`
- Test: `internal/api/session_policy_test.go` (create if absent)

- [ ] **Step 1: Write the failing test**

Create `internal/api/session_policy_test.go` (or append if it exists):

```go
package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestExecveEnforcementActive(t *testing.T) {
	tests := []struct {
		name    string
		seccomp bool
		ptrace  bool // simulate a.ptraceTracer != nil
		want    bool
	}{
		{"none", false, false, false},
		{"seccomp execve", true, false, true},
		{"ptrace", false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Sandbox.Seccomp.Execve.Enabled = tt.seccomp
			a := &App{cfg: cfg}
			if tt.ptrace {
				a.ptraceTracer = struct{}{}
			}
			if got := a.execveEnforcementActive(); got != tt.want {
				t.Errorf("execveEnforcementActive() = %v, want %v", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/api/ -run TestExecveEnforcementActive -v`
Expected: FAIL — `a.execveEnforcementActive` undefined.

- [ ] **Step 3: Implement the helper**

In `internal/api/session_policy.go`, add at the end of the file:

```go
// execveEnforcementActive reports whether inner execve calls will be policed at
// runtime for sandboxed commands on this host: either seccomp execve
// interception is enabled, or a ptrace tracer is attached. Used to relax the
// opaque shell-c pre-deny (issue #375) — when true, CheckExecve enforces the
// command policy on every inner exec, so the static pre-deny is redundant.
func (a *App) execveEnforcementActive() bool {
	return a.cfg.Sandbox.Seccomp.Execve.Enabled || a.ptraceTracer != nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/api/ -run TestExecveEnforcementActive -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/session_policy.go internal/api/session_policy_test.go
git commit -m "feat(#375): add App.execveEnforcementActive helper"
```

---

## Task 3: Wire the command pre-check call sites

**Files (modify the single `CheckCommand` call on each listed line):**
- `internal/api/exec_stream.go:60`
- `internal/api/pty_core.go:60`
- `internal/api/grpc.go:293`
- `internal/api/core.go:861`
- `internal/api/core.go:1070`

- [ ] **Step 1: Update `exec_stream.go`**

Change:

```go
	pre := a.policyEngineFor(s).CheckCommand(req.Command, req.Args)
```

to:

```go
	pre := a.policyEngineFor(s).CheckCommandWithExecve(req.Command, req.Args, a.execveEnforcementActive())
```

- [ ] **Step 2: Update `pty_core.go`**

Change:

```go
	pre := a.policyEngineFor(sess).CheckCommand(req.Command, req.Args)
```

to:

```go
	pre := a.policyEngineFor(sess).CheckCommandWithExecve(req.Command, req.Args, a.execveEnforcementActive())
```

- [ ] **Step 3: Update `grpc.go`** (the App is `s.app` here)

Change:

```go
	pre := s.app.policyEngineFor(sess).CheckCommand(execReq.Command, execReq.Args)
```

to:

```go
	pre := s.app.policyEngineFor(sess).CheckCommandWithExecve(execReq.Command, execReq.Args, s.app.execveEnforcementActive())
```

- [ ] **Step 4: Update `core.go:861`**

Change:

```go
	pre := a.policyEngineFor(s).CheckCommand(req.Command, req.Args)
```

to:

```go
	pre := a.policyEngineFor(s).CheckCommandWithExecve(req.Command, req.Args, a.execveEnforcementActive())
```

- [ ] **Step 5: Update `core.go:1070`**

Change:

```go
	cmdDecision := a.policyEngineFor(s).CheckCommand(wrappedReq.Command, wrappedReq.Args)
```

to:

```go
	cmdDecision := a.policyEngineFor(s).CheckCommandWithExecve(wrappedReq.Command, wrappedReq.Args, a.execveEnforcementActive())
```

- [ ] **Step 6: Verify build and that no other intended call sites were missed**

Run: `go build ./... && grep -rn "policyEngineFor(.*)\.CheckCommand(" internal/api/*.go | grep -v _test.go`
Expected: build OK; the grep returns **no** results (all five execution-path sites now use `CheckCommandWithExecve`). Other `CheckCommand` callers (platform adapters, `context_eval`) intentionally remain.

- [ ] **Step 7: Commit**

```bash
git add internal/api/exec_stream.go internal/api/pty_core.go internal/api/grpc.go internal/api/core.go
git commit -m "fix(#375): pass execve-enforcement signal into command pre-check on exec paths"
```

---

## Task 4: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build + Windows cross-compile**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: both succeed (no output).

- [ ] **Step 2: Vet + gofmt**

Run: `go vet ./internal/policy/ ./internal/api/ && gofmt -l internal/policy/ internal/api/session_policy.go`
Expected: vet clean; `gofmt -l` prints nothing.

- [ ] **Step 3: Run affected unit tests**

Run: `go test ./internal/policy/ ./internal/api/`
Expected: ok for both.

- [ ] **Step 4: Confirm runtime execve enforcement is still intact (depth-1 denial)**

Run: `go test ./internal/integration/ -run TestExecve`
Expected: ok — nested/inner `execve` denial behavior is unchanged (this proves the security argument: inner commands are still blocked at exec time).

- [ ] **Step 5: Commit any formatting fixes (if Step 2 changed files)**

```bash
git add -A && git commit -m "chore(#375): gofmt" || echo "nothing to commit"
```

---

## Self-review notes

- **Spec coverage:** opaque gate change (Task 1), signal definition + helper (Task 2), call-site wiring at the five exec paths named in the spec (Task 3), tests for both interception states + reporter battery + inner-deny intact (Tasks 1 & 4). No-interception path unchanged (Task 1 Step 5 + `CheckCommand` default `false`). Non-goals (no config knob, no byte-set change, `shellc-wrapper-bypass`/`shellc-depth-exceeded` untouched) respected.
- **Type consistency:** `CheckCommandWithExecve(command string, args []string, execveEnforcementActive bool) Decision` and `App.execveEnforcementActive() bool` are used identically in Tasks 1–3.
- **No placeholders:** every code/command step shows concrete content and expected output.
