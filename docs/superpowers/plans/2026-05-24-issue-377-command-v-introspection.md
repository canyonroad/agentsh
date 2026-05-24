# Allow `command -v` / `command -V` introspection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the shell-c pre-check from denying `bash -c 'command -v NAME'` / `command -V NAME` as `shellc-wrapper-bypass`, by treating those introspection forms as benign builtins.

**Architecture:** In `internal/shellparse/stripWrappers`, special-case `command -v`/`-V` to stop wrapper-stripping and leave `command` as the head token; `parseSimpleShellC`'s existing `isShellBuiltin("command")` check then returns `statusFallback`, so the engine applies the operator's allow-shell rule. `command -p` (executes) and `command NAME` (no flag, derives to NAME) are unchanged.

**Tech Stack:** Go; `internal/shellparse`, `internal/policy`.

**Spec:** `docs/superpowers/specs/2026-05-24-issue-377-command-v-introspection-design.md`

**Verified facts (don't re-derive):**
- `stripWrappers` is at `internal/shellparse/shellparse.go:819`. Its catch-all bypass `return nil, true` is the line to guard before. Current body:
  ```go
  func stripWrappers(tokens []string) ([]string, bool) {
  	for len(tokens) >= 2 && isTransparentWrapper(tokens[0]) {
  		wrapper := tokens[0]
  		next := tokens[1]
  		if !strings.HasPrefix(next, "-") {
  			tokens = tokens[1:]
  			continue
  		}
  		// nice -n INCREMENT CMD … : the one flag form we parse.
  		if wrapper == "nice" && next == "-n" && len(tokens) >= 3 && isNumericIncrement(tokens[2]) {
  			tokens = tokens[3:]
  			continue
  		}
  		return nil, true
  	}
  	return tokens, false
  }
  ```
- `isShellBuiltin("command")` returns `true` (confirmed). `parseSimpleShellC` calls `if isShellBuiltin(tokens[0]) { return "", nil, statusFallback }` after `stripWrappers`.
- Public API: `IsShellCBypassAttempt(command string, args []string) bool` and `DerivePolicyTarget(command string, args []string) (string, []string, bool)` (both in package `shellparse`).
- `internal/policy` tests are `package policy`; build a `&Policy{CommandRules: []CommandRule{...}}`, call `NewEngine(p, false, true)`, then `e.CheckCommand(cmd, args)` returning a `Decision` with `.PolicyDecision` (compare to `types.DecisionAllow`/`types.DecisionDeny`) and `.Rule`. Model: `internal/policy/command_shellc_test.go`.

---

## File Structure

- `internal/shellparse/shellparse.go` — add the `command -v`/`-V` guard in `stripWrappers` (the only behavioral change).
- `internal/shellparse/command_v_test.go` (new) — shellparse-level regression tests (bypass classification + derive behavior).
- `internal/policy/command_v_introspection_test.go` (new) — engine-level test proving `command -v ls` is allowed and `command shutdown` still denies.

---

## Task 1: Allow `command -v`/`-V` introspection in `stripWrappers`

**Files:**
- Create: `internal/shellparse/command_v_test.go`
- Create: `internal/policy/command_v_introspection_test.go`
- Modify: `internal/shellparse/shellparse.go` (inside `stripWrappers`, before `return nil, true`)

- [ ] **Step 1: Write the failing shellparse tests**

Create `internal/shellparse/command_v_test.go`:

```go
package shellparse

import "testing"

// Issue #377: `command -v`/`-V NAME` is read-only introspection (prints whether
// NAME exists / its type; never executes NAME). It must not be classified as a
// wrapper-bypass. `command -p` (executes NAME) and `command NAME` (no flag,
// forwards to NAME) keep their existing behavior.

func TestIsShellCBypassAttempt_CommandIntrospection(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"command -v is introspection, not bypass", []string{"-c", "command -v ls"}, false},
		{"command -V is introspection, not bypass", []string{"-c", "command -V ls"}, false},
		{"command -p executes, still bypass", []string{"-c", "command -p ls"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsShellCBypassAttempt("/bin/sh", tc.args); got != tc.want {
				t.Errorf("IsShellCBypassAttempt(sh, %v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestDerivePolicyTarget_CommandForms(t *testing.T) {
	// No-flag `command shutdown` still derives to the inner binary so command
	// rules (e.g. deny shutdown) fire.
	if cmd, _, ok := DerivePolicyTarget("/bin/sh", []string{"-c", "command shutdown"}); !ok || cmd != "shutdown" {
		t.Errorf("DerivePolicyTarget(command shutdown) = (%q, ok=%v), want (\"shutdown\", true)", cmd, ok)
	}
	// `command -v ls` is introspection: nothing to derive (falls back to the
	// outer shell rule), so ok must be false (and it must NOT be a bypass).
	if _, _, ok := DerivePolicyTarget("/bin/sh", []string{"-c", "command -v ls"}); ok {
		t.Error("DerivePolicyTarget(command -v ls) ok=true, want false (introspection)")
	}
}
```

- [ ] **Step 2: Write the failing engine test**

Create `internal/policy/command_v_introspection_test.go`:

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// Issue #377: `command -v NAME` must be allowed (it's introspection), not
// denied as shellc-wrapper-bypass, while `command shutdown` (no flag) still
// derives to shutdown so a deny rule fires.
func TestCheckCommand_CommandVAllowed(t *testing.T) {
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

	dec := e.CheckCommand("/bin/sh", []string{"-c", "command -v ls"})
	if dec.Rule == "shellc-wrapper-bypass" {
		t.Errorf("command -v ls denied as wrapper-bypass; want allow")
	}
	if dec.PolicyDecision != types.DecisionAllow {
		t.Errorf("command -v ls decision = %s (rule=%q), want allow", dec.PolicyDecision, dec.Rule)
	}

	denied := e.CheckCommand("/bin/sh", []string{"-c", "command shutdown"})
	if denied.PolicyDecision != types.DecisionDeny || denied.Rule != "deny-shutdown" {
		t.Errorf("command shutdown = %s rule=%q, want deny deny-shutdown", denied.PolicyDecision, denied.Rule)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/shellparse/ -run 'TestIsShellCBypassAttempt_CommandIntrospection|TestDerivePolicyTarget_CommandForms' -v && go test ./internal/policy/ -run TestCheckCommand_CommandVAllowed -v`
Expected: FAIL — the `command -v`/`-V` cases currently classify as bypass (`IsShellCBypassAttempt` returns true; `DerivePolicyTarget(command -v ls)` ok=false is actually already true today, but the engine test's first assertion fails because `command -v ls` is denied as `shellc-wrapper-bypass`). Specifically: `TestIsShellCBypassAttempt_CommandIntrospection` fails on the `-v`/`-V` rows, and `TestCheckCommand_CommandVAllowed` fails with `dec.Rule == "shellc-wrapper-bypass"`.

- [ ] **Step 4: Add the guard in `stripWrappers`**

In `internal/shellparse/shellparse.go`, inside `stripWrappers`, immediately before the catch-all `return nil, true`, insert:

```go
		// `command -v`/`-V NAME` is introspection: it prints whether NAME
		// exists / its type and does NOT execute it. Stop stripping so the
		// builtin classifier (isShellBuiltin("command")) hands this back to the
		// outer shell rule rather than flagging a wrapper-bypass. `command -p`
		// (which executes NAME under a default PATH) is intentionally excluded.
		// Issue #377.
		if wrapper == "command" && (next == "-v" || next == "-V") {
			return tokens, false
		}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/shellparse/ -run 'TestIsShellCBypassAttempt_CommandIntrospection|TestDerivePolicyTarget_CommandForms' -v && go test ./internal/policy/ -run TestCheckCommand_CommandVAllowed -v`
Expected: PASS.

- [ ] **Step 6: Run the full packages (no regressions)**

Run: `go test ./internal/shellparse/ ./internal/policy/`
Expected: ok for both (existing shellparse/policy suites still pass).

- [ ] **Step 7: Commit**

```bash
git add internal/shellparse/shellparse.go internal/shellparse/command_v_test.go internal/policy/command_v_introspection_test.go
git commit -m "fix(#377): allow command -v/-V introspection in shell-c pre-check"
```

---

## Task 2: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build + Windows cross-compile**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: both succeed (no output).

- [ ] **Step 2: Vet + gofmt**

Run: `go vet ./internal/shellparse/ ./internal/policy/ && gofmt -l internal/shellparse/shellparse.go internal/shellparse/command_v_test.go internal/policy/command_v_introspection_test.go`
Expected: vet clean; `gofmt -l` prints nothing.

- [ ] **Step 3: Affected package tests**

Run: `go test ./internal/shellparse/ ./internal/policy/`
Expected: ok for both.

- [ ] **Step 4: Commit any formatting fixes (only if Step 2 changed files)**

```bash
git add -A && git commit -m "chore(#377): gofmt" || echo "nothing to commit"
```

---

## Self-review notes

- **Spec coverage:** the `stripWrappers` guard (Task 1 Step 4) implements the only behavioral change; `-v`/`-V` allowed and `-p`/no-flag preserved are all covered by tests (Task 1 Steps 1-2). Non-goals respected (no other wrapper touched; `-p` stays bypass).
- **Type consistency:** `IsShellCBypassAttempt`, `DerivePolicyTarget`, `NewEngine(p, false, true)`, `Decision.PolicyDecision`, `Decision.Rule`, `types.DecisionAllow`/`DecisionDeny` all match the verified facts and `command_shellc_test.go`.
- **No placeholders:** every code/command step is concrete with expected output.
