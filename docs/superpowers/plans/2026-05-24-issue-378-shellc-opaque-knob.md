# `sandbox.seccomp.shellc.opaque` knob (#378) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an operator knob `sandbox.seccomp.shellc.opaque: deny | enforce | allow` (default `enforce`) controlling how the policy engine handles opaque `sh -c` payloads, so sandbox-API platforms can run pipes/redirects/globs instead of a blanket exit-126.

**Architecture:** Config gains a `seccomp.shellc.opaque` string (defaulted + validated). The policy engine gains a `ShellCOpaqueMode` passed per-call to `CheckCommandWithExecve` (the same per-call pattern as `execveEnforcementActive`, #375); the App supplies it from config at every command-check site. The opaque-deny branch becomes mode-aware while preserving the `hasRestrictiveCommandRule` gate, with an enriched deny message and an `allow`-mode warning.

**Tech Stack:** Go; `internal/config`, `internal/policy`, `internal/api`.

**Spec:** `docs/superpowers/specs/2026-05-24-issue-378-shellc-opaque-knob-design.md`

**Verified facts (don't re-derive):**
- `SandboxSeccompConfig` is at `internal/config/config.go:490`; its `Execve ExecveConfig \`yaml:"execve"\`` field is at line 495. `applyDefaults`/`applyDefaultsWithSource` set seccomp defaults around `config.go:1686` (e.g. `cfg.Sandbox.Seccomp.Mode` default at 1686-1687). `validateConfig` is at `config.go:2140`; the #376-added `cfg.Sandbox.Validate()` block is at ~2446, just before the function's final `return nil`. Tests in `internal/config` are `package config` and call `applyDefaults(cfg)` then `validateConfig(cfg)` directly (see `validate_sandbox_signing_test.go`). `applyDefaults(&Config{})` then `validateConfig` returns nil (baseline valid).
- The opaque-deny lives in `internal/policy/engine.go` `checkCommand` (the `else if` at ~line 635):
  ```go
  } else if e.hasRestrictiveCommandRule && !execveEnforcementActive && shellparse.IsOpaqueShellC(cur, curArgs) {
      msg := "opaque shell script cannot be safely parsed for policy pre-check"
      if reason := shellparse.OpaqueReason(cur, curArgs); reason != "" {
          msg = "opaque shell script: contains " + reason
      }
      denyDec := e.wrapDecision(string(types.DecisionDeny), "shellc-opaque-script", msg, nil)
      if dec := denyDec; decisionStrictness(dec.PolicyDecision) > resultStrictness {
          result = dec
          resultStrictness = decisionStrictness(dec.PolicyDecision)
      }
  }
  ```
- `checkCommand(command string, args []string, execveEnforcementActive bool) Decision` is at engine.go:600. `CheckCommand(command, args)` calls `e.checkCommand(command, args, false)` (engine.go ~585-590). `CheckCommandWithExecve(command, args, execveEnforcementActive)` is at engine.go:596-597 and calls `e.checkCommand(...)`.
- `hasRestrictiveCommandRule` (engine.go:53) is set true by any command rule deciding deny/redirect/soft_delete/approve/audit.
- `wrapDecision(decision, rule, msg string, redirect *CommandRedirect) Decision` is at engine.go:1122. `decisionStrictness` and `types.DecisionDeny`/`DecisionAllow` exist and are already used in this function.
- The 6 production `CheckCommandWithExecve` call sites (all already pass `a.execveEnforcementActive()` / `s.app.execveEnforcementActive()`): `internal/api/core.go:861`, `core.go:1070`, `grpc.go:293` (receiver `s.app`), `exec_stream.go:60`, `pty_core.go:60`, `wrap.go:164` (receiver `a`, variable `engine`). The App field is `a.cfg` (`*config.Config`); `a.cfg.Sandbox.Seccomp.Execve.Enabled` is already read in `session_policy.go:73`.
- The 3 existing test call sites (3-arg) are in `internal/policy/command_shellc_interception_test.go:42,56,74`; helper `newInterceptionTestEngine(t)` builds an engine with a `deny-shutdown` restrictive rule + `allow-shells`. These must be updated to the new 4-arg form passing the enforce mode.
- `internal/policy/engine.go` does NOT currently import `log/slog`.

---

## File Structure

- `internal/config/config.go` — `SandboxSeccompShellcConfig` struct + `Shellc` field; default-to-enforce in `applyDefaults`; value check in `validateConfig`.
- `internal/config/shellc_opaque_test.go` (new) — config default + validation tests.
- `internal/policy/engine.go` — `ShellCOpaqueMode` type + `ParseShellCOpaqueMode`; thread the mode through `checkCommand`/`CheckCommand`/`CheckCommandWithExecve`; mode-aware opaque branch + enriched message + `allow` warning.
- `internal/policy/command_shellc_opaque_mode_test.go` (new) — engine matrix tests.
- `internal/policy/command_shellc_interception_test.go` — update 3 call sites to the new signature (mechanical).
- `internal/api/session_policy.go` — add `(a *App) shellCOpaqueMode()` helper.
- `internal/api/{core.go,grpc.go,exec_stream.go,pty_core.go,wrap.go}` — pass the mode at the 6 call sites.

---

## Task 1: Config schema — `seccomp.shellc.opaque` (default + validation)

**Files:**
- Create: `internal/config/shellc_opaque_test.go`
- Modify: `internal/config/config.go` (struct near line 490/495; applyDefaults near 1686; validateConfig near 2446)

- [ ] **Step 1: Write the failing tests**

Create `internal/config/shellc_opaque_test.go`:

```go
package config

import (
	"strings"
	"testing"
)

// Issue #378: sandbox.seccomp.shellc.opaque controls opaque shell-c handling.
// It defaults to "enforce" and validateConfig rejects unknown values.

func TestApplyDefaults_ShellcOpaqueDefaultsEnforce(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	if got := cfg.Sandbox.Seccomp.Shellc.Opaque; got != "enforce" {
		t.Errorf("default seccomp.shellc.opaque = %q, want \"enforce\"", got)
	}
}

func TestValidateConfig_ShellcOpaqueAcceptsValidValues(t *testing.T) {
	for _, v := range []string{"", "deny", "enforce", "allow"} {
		cfg := &Config{}
		applyDefaults(cfg)
		cfg.Sandbox.Seccomp.Shellc.Opaque = v
		if err := validateConfig(cfg); err != nil {
			t.Errorf("opaque=%q: unexpected validation error: %v", v, err)
		}
	}
}

func TestValidateConfig_ShellcOpaqueRejectsUnknown(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Sandbox.Seccomp.Shellc.Opaque = "bogus"
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("opaque=bogus must fail validation")
	}
	if !strings.Contains(err.Error(), "seccomp.shellc.opaque") {
		t.Errorf("error should name seccomp.shellc.opaque; got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'ShellcOpaque' -v`
Expected: FAIL — compile error `cfg.Sandbox.Seccomp.Shellc undefined` (field doesn't exist yet).

- [ ] **Step 3: Add the config struct + field**

In `internal/config/config.go`, add the struct immediately after the `SandboxSeccompConfig` struct definition (after its closing `}`):

```go
// SandboxSeccompShellcConfig controls how the shell-shim handles opaque
// `sh -c`/`bash -c` payloads that cannot be statically resolved to a single
// command for policy pre-check (issue #378).
type SandboxSeccompShellcConfig struct {
	// Opaque selects handling for opaque shell-c scripts when the policy has
	// a restrictive command rule:
	//   "enforce" (default) — run only when per-exec enforcement is active
	//                         (ptrace, or seccomp.execve + unix_sockets);
	//                         otherwise deny shellc-opaque-script.
	//   "allow"             — run even without per-exec enforcement (accepts
	//                         the bypass risk; emits a warning).
	//   "deny"              — always deny opaque scripts.
	Opaque string `yaml:"opaque"`
}
```

and add a field to `SandboxSeccompConfig` immediately after the `Execve ExecveConfig \`yaml:"execve"\`` line (config.go:495):

```go
	Shellc      SandboxSeccompShellcConfig      `yaml:"shellc"`
```

- [ ] **Step 4: Default to "enforce" in applyDefaults**

In `internal/config/config.go`, in `applyDefaultsWithSource`, immediately after the `cfg.Sandbox.Seccomp.Mode` default (the block at ~1686-1688 that sets Mode to "enforce"), add:

```go
	if cfg.Sandbox.Seccomp.Shellc.Opaque == "" {
		cfg.Sandbox.Seccomp.Shellc.Opaque = "enforce"
	}
```

- [ ] **Step 5: Validate the value**

In `internal/config/config.go`, in `validateConfig`, immediately before the `if err := cfg.Sandbox.Validate(); err != nil {` block (~line 2446), add:

```go
	// Issue #378: opaque shell-c handling mode. Empty is accepted because
	// applyDefaults normalizes it to "enforce" before the server runs.
	switch cfg.Sandbox.Seccomp.Shellc.Opaque {
	case "", "deny", "enforce", "allow":
	default:
		return fmt.Errorf("seccomp.shellc.opaque: invalid value %q (want deny, enforce, or allow)", cfg.Sandbox.Seccomp.Shellc.Opaque)
	}
```

(`fmt` is already imported in config.go.)

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/config/ -run 'ShellcOpaque' -v`
Expected: PASS (all three).

- [ ] **Step 7: Full config package + build**

Run: `go build ./... && go test ./internal/config/`
Expected: build OK; config package ok.

- [ ] **Step 8: Commit**

```bash
git add internal/config/config.go internal/config/shellc_opaque_test.go
git commit -m "feat(#378): add sandbox.seccomp.shellc.opaque config knob

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Engine mode-aware opaque handling + API wiring

This task changes `CheckCommandWithExecve`'s signature and updates all its callers in the **same commit**, so the tree always builds.

**Files:**
- Create: `internal/policy/command_shellc_opaque_mode_test.go`
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/command_shellc_interception_test.go` (3 call sites → 4-arg)
- Modify: `internal/api/session_policy.go` (+ helper)
- Modify: `internal/api/core.go`, `internal/api/grpc.go`, `internal/api/exec_stream.go`, `internal/api/pty_core.go`, `internal/api/wrap.go` (6 call sites)

- [ ] **Step 1: Write the failing engine matrix tests**

Create `internal/policy/command_shellc_opaque_mode_test.go`:

```go
package policy

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// Issue #378: sandbox.seccomp.shellc.opaque controls opaque shell-c handling.
// The hasRestrictiveCommandRule gate is preserved (allow-only policies are
// never tightened); within it the mode picks the outcome.

const opaqueScript = "echo $HOME | head" // opaque: pipe + var

func TestParseShellCOpaqueMode(t *testing.T) {
	cases := map[string]ShellCOpaqueMode{
		"":        ShellCOpaqueEnforce,
		"enforce": ShellCOpaqueEnforce,
		"allow":   ShellCOpaqueAllow,
		"deny":    ShellCOpaqueDeny,
		"bogus":   ShellCOpaqueEnforce, // defensive default
	}
	for in, want := range cases {
		if got := ParseShellCOpaqueMode(in); got != want {
			t.Errorf("ParseShellCOpaqueMode(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCheckCommand_OpaqueModeMatrix(t *testing.T) {
	type want struct {
		deny bool // true => denied as shellc-opaque-script
	}
	cases := []struct {
		name        string
		mode        ShellCOpaqueMode
		execveOn    bool
		want        want
	}{
		{"enforce+active=allow", ShellCOpaqueEnforce, true, want{deny: false}},
		{"enforce+inactive=deny", ShellCOpaqueEnforce, false, want{deny: true}},
		{"allow+active=allow", ShellCOpaqueAllow, true, want{deny: false}},
		{"allow+inactive=allow", ShellCOpaqueAllow, false, want{deny: false}},
		{"deny+active=deny", ShellCOpaqueDeny, true, want{deny: true}},
		{"deny+inactive=deny", ShellCOpaqueDeny, false, want{deny: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newInterceptionTestEngine(t) // has a restrictive rule
			dec := e.CheckCommandWithExecve("/bin/sh", []string{"-c", opaqueScript}, tc.execveOn, tc.mode)
			gotDeny := dec.PolicyDecision == types.DecisionDeny && dec.Rule == "shellc-opaque-script"
			if gotDeny != tc.want.deny {
				t.Fatalf("decision=%s rule=%q; want deny=%v", dec.PolicyDecision, dec.Rule, tc.want.deny)
			}
			if tc.want.deny && !strings.Contains(dec.Message, "shellc.opaque=allow") {
				t.Errorf("deny message should name the remedy; got %q", dec.Message)
			}
		})
	}
}

// With NO restrictive command rule, opaque scripts run regardless of mode.
func TestCheckCommand_OpaqueModeNoRestrictiveRuleAlwaysAllows(t *testing.T) {
	p := &Policy{
		CommandRules: []CommandRule{
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	for _, mode := range []ShellCOpaqueMode{ShellCOpaqueEnforce, ShellCOpaqueAllow, ShellCOpaqueDeny} {
		dec := e.CheckCommandWithExecve("/bin/sh", []string{"-c", opaqueScript}, false, mode)
		if dec.Rule == "shellc-opaque-script" {
			t.Errorf("mode=%v: opaque denied despite no restrictive rule", mode)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/policy/ -run 'OpaqueMode|ParseShellCOpaqueMode' 2>&1 | head`
Expected: FAIL — compile error (`ShellCOpaqueMode`/`ParseShellCOpaqueMode` undefined; `CheckCommandWithExecve` takes 3 args not 4).

- [ ] **Step 3: Add the mode type + parser**

In `internal/policy/engine.go`, add near the top-level type declarations (e.g. just above `func (e *Engine) checkCommand`):

```go
// ShellCOpaqueMode selects how opaque shell-c scripts are handled when the
// policy has a restrictive command rule. The zero value is Enforce, so engines
// constructed without explicit configuration keep the pre-#378 behavior.
type ShellCOpaqueMode int

const (
	ShellCOpaqueEnforce ShellCOpaqueMode = iota // run only under active per-exec enforcement; else deny
	ShellCOpaqueAllow                            // run even without per-exec enforcement
	ShellCOpaqueDeny                             // always deny opaque scripts
)

// ParseShellCOpaqueMode maps a config string to a mode. Unknown/empty values
// map to Enforce (the safe default); config validation rejects bad values
// before this is reached in production.
func ParseShellCOpaqueMode(s string) ShellCOpaqueMode {
	switch s {
	case "allow":
		return ShellCOpaqueAllow
	case "deny":
		return ShellCOpaqueDeny
	default:
		return ShellCOpaqueEnforce
	}
}
```

- [ ] **Step 4: Thread the mode through checkCommand / CheckCommand / CheckCommandWithExecve**

In `internal/policy/engine.go`:

Change `CheckCommand` (the 2-arg public method, ~line 585-590) to pass the default mode:

```go
func (e *Engine) CheckCommand(command string, args []string) Decision {
	return e.checkCommand(command, args, false, ShellCOpaqueEnforce)
}
```

Change `CheckCommandWithExecve` (engine.go:596-597) to accept and forward the mode:

```go
func (e *Engine) CheckCommandWithExecve(command string, args []string, execveEnforcementActive bool, opaqueMode ShellCOpaqueMode) Decision {
	return e.checkCommand(command, args, execveEnforcementActive, opaqueMode)
}
```

Change the `checkCommand` signature (engine.go:600):

```go
func (e *Engine) checkCommand(command string, args []string, execveEnforcementActive bool, opaqueMode ShellCOpaqueMode) Decision {
```

(Keep the existing `CheckCommand` doc comment; if `CheckCommand`'s current body differs, replace only the call to add the `, ShellCOpaqueEnforce` argument.)

- [ ] **Step 5: Make the opaque branch mode-aware (+ message + warning)**

In `internal/policy/engine.go`, add `"log/slog"` to the import block. Replace the opaque `else if` branch (the block at ~line 635 shown in Verified facts) with:

```go
			} else if e.hasRestrictiveCommandRule && shellparse.IsOpaqueShellC(cur, curArgs) {
				// Opaque scripts (metachars, pipes, subshells, globs, …) can
				// execute binaries we can't predict. The operator chooses how to
				// handle them via sandbox.seccomp.shellc.opaque (issue #378). The
				// hasRestrictiveCommandRule gate is preserved so allow-only
				// policies are never tightened.
				switch opaqueMode {
				case ShellCOpaqueAllow:
					if !execveEnforcementActive {
						slog.Warn("sandbox.seccomp.shellc.opaque=allow: running opaque shell script without per-exec enforcement",
							"reason", shellparse.OpaqueReason(cur, curArgs))
					}
					// fall through: no pre-deny.
				default: // ShellCOpaqueEnforce, ShellCOpaqueDeny
					deny := opaqueMode == ShellCOpaqueDeny || !execveEnforcementActive
					if deny {
						msg := "opaque shell script cannot be safely parsed for policy pre-check"
						if reason := shellparse.OpaqueReason(cur, curArgs); reason != "" {
							msg = "opaque shell script: contains " + reason
						}
						msg += "; set sandbox.seccomp.shellc.opaque=allow to run it without per-exec enforcement, or enable execve enforcement (seccomp.execve + unix_sockets, or ptrace) to run it under policy"
						denyDec := e.wrapDecision(string(types.DecisionDeny), "shellc-opaque-script", msg, nil)
						if dec := denyDec; decisionStrictness(dec.PolicyDecision) > resultStrictness {
							result = dec
							resultStrictness = decisionStrictness(dec.PolicyDecision)
						}
					}
				}
			}
```

- [ ] **Step 6: Update the 3 existing interception test call sites**

In `internal/policy/command_shellc_interception_test.go`, append `, ShellCOpaqueEnforce` to the three `CheckCommandWithExecve` calls (lines 42, 56, 74), preserving their existing assertions:
- line 42: `e.CheckCommandWithExecve("/bin/sh", []string{"-c", script}, true, ShellCOpaqueEnforce)`
- line 56: `e.CheckCommandWithExecve("/bin/sh", []string{"-c", "echo $HOME | head"}, false, ShellCOpaqueEnforce)`
- line 74: `e.CheckCommandWithExecve("/bin/sh", []string{"-c", "shutdown now"}, true, ShellCOpaqueEnforce)`

- [ ] **Step 7: Run the policy package tests**

Run: `go test ./internal/policy/ -run 'OpaqueMode|ParseShellCOpaqueMode|Opaque' -v && go test ./internal/policy/`
Expected: new matrix + parser tests PASS; the existing `TestCheckCommand_OpaqueAllowedWhenExecveEnforced` / `OpaqueDeniedWhenNoExecveEnforcement` / `DerivableDenyStillDeniedWhenExecveEnforced` still PASS; full policy package ok.

- [ ] **Step 8: Add the App helper**

In `internal/api/session_policy.go`, add:

```go
// shellCOpaqueMode resolves the operator's opaque shell-c handling mode from
// config (sandbox.seccomp.shellc.opaque) for command pre-checks. Issue #378.
func (a *App) shellCOpaqueMode() policy.ShellCOpaqueMode {
	return policy.ParseShellCOpaqueMode(a.cfg.Sandbox.Seccomp.Shellc.Opaque)
}
```

(`policy` is already imported in this file.)

- [ ] **Step 9: Update the 6 production call sites**

Append the mode argument to each `CheckCommandWithExecve` call:
- `internal/api/core.go:861`: `...CheckCommandWithExecve(req.Command, req.Args, a.execveEnforcementActive(), a.shellCOpaqueMode())`
- `internal/api/core.go:1070`: `...CheckCommandWithExecve(wrappedReq.Command, wrappedReq.Args, a.execveEnforcementActive(), a.shellCOpaqueMode())`
- `internal/api/grpc.go:293`: `...CheckCommandWithExecve(execReq.Command, execReq.Args, s.app.execveEnforcementActive(), s.app.shellCOpaqueMode())`
- `internal/api/exec_stream.go:60`: `...CheckCommandWithExecve(req.Command, req.Args, a.execveEnforcementActive(), a.shellCOpaqueMode())`
- `internal/api/pty_core.go:60`: `...CheckCommandWithExecve(req.Command, req.Args, a.execveEnforcementActive(), a.shellCOpaqueMode())`
- `internal/api/wrap.go:164`: `...CheckCommandWithExecve(req.AgentCommand, req.AgentArgs, a.execveEnforcementActive(), a.shellCOpaqueMode())`

- [ ] **Step 10: Build + affected tests**

Run: `go build ./... && go test ./internal/policy/ ./internal/api/`
Expected: build OK; both packages pass.

- [ ] **Step 11: Commit**

```bash
git add internal/policy/engine.go internal/policy/command_shellc_opaque_mode_test.go internal/policy/command_shellc_interception_test.go internal/api/session_policy.go internal/api/core.go internal/api/grpc.go internal/api/exec_stream.go internal/api/pty_core.go internal/api/wrap.go
git commit -m "feat(#378): mode-aware opaque shell-c handling wired from config

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build + Windows cross-compile**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: both succeed (no output).

- [ ] **Step 2: Vet + gofmt**

Run: `go vet ./internal/config/ ./internal/policy/ ./internal/api/ && gofmt -l internal/config/config.go internal/config/shellc_opaque_test.go internal/policy/engine.go internal/policy/command_shellc_opaque_mode_test.go internal/policy/command_shellc_interception_test.go internal/api/session_policy.go internal/api/core.go internal/api/grpc.go internal/api/exec_stream.go internal/api/pty_core.go internal/api/wrap.go`
Expected: vet clean; `gofmt -l` prints nothing.

- [ ] **Step 3: Affected package tests**

Run: `go test ./internal/config/ ./internal/policy/ ./internal/api/`
Expected: ok for all three.

- [ ] **Step 4: Commit any formatting fixes (only if Step 2 changed files)**

```bash
git add -A && git commit -m "chore(#378): gofmt" || echo "nothing to commit"
```

---

## Self-review notes

- **Spec coverage:** config schema + default + validation (Task 1) ← spec §Design.1; `ShellCOpaqueMode` + mode-aware branch + matrix (Task 2 Steps 3-5) ← spec §Design.2 + behavior matrix; enriched message + `allow` warning (Task 2 Step 5) ← spec §Design.3; API wiring (Task 2 Steps 8-9) ← spec §Design.2 "App sets the mode"; tests (Task 1 Step 1, Task 2 Step 1) ← spec §Testing. Non-goals respected: no auto-activation of interception; `hasRestrictiveCommandRule` gate preserved (matrix test with no rule); `enforce` reproduces today's behavior (existing interception tests unchanged in meaning).
- **Type/signature consistency:** `ShellCOpaqueMode`, `ShellCOpaqueEnforce/Allow/Deny`, `ParseShellCOpaqueMode`, `checkCommand(cmd, args, execveEnforcementActive, opaqueMode)`, `CheckCommandWithExecve(cmd, args, bool, ShellCOpaqueMode)`, `CheckCommand(cmd, args)` (unchanged arity), `a.shellCOpaqueMode()`, `cfg.Sandbox.Seccomp.Shellc.Opaque` — consistent across all tasks and call sites.
- **Build stays green per commit:** Task 1 is config-only. Task 2 changes the `CheckCommandWithExecve` signature and updates all 9 callers (3 tests + 6 prod) in one commit. Task 3 is verification only.
- **No placeholders:** every code/command step is concrete with expected output.
