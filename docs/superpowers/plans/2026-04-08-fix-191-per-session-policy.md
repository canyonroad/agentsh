# Fix #191: Use Per-Session Policy Engine at Command Precheck & Landlock Derivation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `agentsh exec` (all four entry points) and `agentsh wrap` Landlock derivation respect the per-session policy engine that was already compiled and stored on the `session.Session`, instead of silently falling back to the process-global `a.policy`. Fixes canyonroad/agentsh#191.

**Architecture:** The `session.Session` type already has a `PolicyEngine()` accessor returning the per-session `*policy.Engine` (populated on `CreateSession` in `internal/api/core.go:683-716`). Two places in `internal/api/core.go` (`setupSeccompWrapper` at 110-115, and the seccomp handler wiring at 172-177) already use the idiom `if sp := s.PolicyEngine(); sp != nil { use sp }`. This plan extracts that idiom into a tiny helper method on `*App` and applies it to the five command-precheck call sites and the wrap-time Landlock derivation call site that were missed.

**Tech Stack:** Go, Go test framework. No new dependencies.

**Out of scope for this PR (follow-up):**
- `internal/api/core.go:1052` — `a.policy.Limits()` returns resource limits from the global policy too. Same class of bug, but `Limits()` isn't `CheckCommand` and #191 as filed only covers command precheck + Landlock. Track separately.
- `internal/api/app.go:1374` (`policyTest` HTTP) and `internal/api/grpc.go:776` (`PolicyTest` gRPC) — debugging/test endpoints that also ignore session policy. Same class, but these are debugger helpers, not enforcement paths. Track separately unless scope expands.

---

## File Structure

**New file:**
- `internal/api/session_policy.go` — one small helper method, `(*App).policyEngineFor(*session.Session) *policy.Engine`. Keeping it in its own file makes the change easy to locate and means future contributors can find the canonical accessor via `grep policyEngineFor`.

**New test file:**
- `internal/api/session_policy_test.go` — unit tests for the helper.

**Modified:**
- `internal/api/core.go` — two call sites at `:845` and `:1053`.
- `internal/api/exec_stream.go` — one call site at `:60`.
- `internal/api/pty_core.go` — one call site at `:60`.
- `internal/api/grpc.go` — one call site at `:293`.
- `internal/api/wrap.go` — Landlock derivation at `:167-170`.
- `internal/integration/agentsh_policy_test.go` — extend with a regression test that uses a non-`default` policy file name.

---

## Task 1: Add the `policyEngineFor` helper (red → green → commit)

**Files:**
- Create: `internal/api/session_policy.go`
- Create: `internal/api/session_policy_test.go`

**Why this helper exists:** The inline `if sp := s.PolicyEngine(); sp != nil { sessionPolicy = sp }` idiom is already used at `internal/api/core.go:110-115` and `internal/api/core.go:172-177`. Extracting it removes duplication and — more importantly — makes every precheck call site a one-liner, which is how we prevent this bug from recurring.

- [ ] **Step 1: Write the failing unit test**

Create `internal/api/session_policy_test.go` with:

```go
package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

// newEngineAllowingCommand returns a minimal *policy.Engine with a single
// allow rule for the named command. The rule name is caller-supplied so
// tests can tell which engine produced a decision (by inspecting .Rule on
// the returned Decision).
//
// Shared by session_policy_test.go and session_policy_integration_test.go.
func newEngineAllowingCommand(t *testing.T, ruleName, cmdName string) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    ruleName,
		CommandRules: []policy.CommandRule{
			{
				Name:     ruleName,
				Commands: []string{cmdName},
				Decision: string(types.DecisionAllow),
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestPolicyEngineFor_PrefersSessionEngine(t *testing.T) {
	globalEngine := newEngineAllowingCommand(t, "allow-global-cmd", "global-cmd")
	sessionEngine := newEngineAllowingCommand(t, "allow-session-cmd", "session-cmd")

	mgr := session.NewManager(5)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	app := &App{policy: globalEngine}

	got := app.policyEngineFor(s)
	if got != sessionEngine {
		t.Fatalf("expected session engine, got %p (sessionEngine=%p, globalEngine=%p)",
			got, sessionEngine, globalEngine)
	}

	// Functional check: the returned engine must allow session-cmd and deny global-cmd,
	// proving we're consulting the session policy and not the global one.
	if dec := got.CheckCommand("session-cmd", nil); dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("session-cmd should be allowed via session engine, got %v (rule=%s)",
			dec.EffectiveDecision, dec.Rule)
	}
	if dec := got.CheckCommand("global-cmd", nil); dec.EffectiveDecision == types.DecisionAllow {
		t.Errorf("global-cmd should NOT be allowed via session engine, got %v (rule=%s)",
			dec.EffectiveDecision, dec.Rule)
	}
}

func TestPolicyEngineFor_FallsBackToGlobalWhenSessionEngineUnset(t *testing.T) {
	globalEngine := newEngineAllowingCommand(t, "allow-global-cmd", "global-cmd")

	mgr := session.NewManager(5)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	// Intentionally do NOT call s.SetPolicyEngine.

	app := &App{policy: globalEngine}

	got := app.policyEngineFor(s)
	if got != globalEngine {
		t.Fatalf("expected fallback to global engine, got %p (globalEngine=%p)", got, globalEngine)
	}
}

func TestPolicyEngineFor_NilSessionFallsBackToGlobal(t *testing.T) {
	globalEngine := newEngineAllowingCommand(t, "allow-global-cmd", "global-cmd")
	app := &App{policy: globalEngine}

	got := app.policyEngineFor(nil)
	if got != globalEngine {
		t.Fatalf("expected global engine for nil session, got %p", got)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails to compile**

Run: `go test ./internal/api/ -run TestPolicyEngineFor -v`

Expected: compile error along the lines of ``app.policyEngineFor undefined (type *App has no field or method policyEngineFor)``. This confirms we're writing a red test.

- [ ] **Step 3: Implement the helper**

Create `internal/api/session_policy.go` with:

```go
package api

import (
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
)

// policyEngineFor returns the effective policy engine to consult for the given
// session. It prefers the session's own engine (compiled from the session's
// named policy file with per-session variable expansion) and falls back to the
// process-global engine (a.policy) when the session has no engine of its own
// or when s is nil.
//
// This exists to fix canyonroad/agentsh#191: before this helper, the command
// precheck and wrap-time Landlock derivation paths used a.policy directly,
// which silently ignored custom rules authored in any non-default policy file.
// All new call sites that need to consult "the policy for this session" should
// use this helper rather than touching a.policy directly.
func (a *App) policyEngineFor(s *session.Session) *policy.Engine {
	if s != nil {
		if sp := s.PolicyEngine(); sp != nil {
			return sp
		}
	}
	return a.policy
}
```

- [ ] **Step 4: Run the test and verify it passes**

Run: `go test ./internal/api/ -run TestPolicyEngineFor -v`

Expected: three PASSes (`TestPolicyEngineFor_PrefersSessionEngine`, `TestPolicyEngineFor_FallsBackToGlobalWhenSessionEngineUnset`, `TestPolicyEngineFor_NilSessionFallsBackToGlobal`).

- [ ] **Step 5: Commit**

```bash
git add internal/api/session_policy.go internal/api/session_policy_test.go
git commit -m "$(cat <<'EOF'
feat(api): add policyEngineFor helper to resolve session vs global engine

Centralizes the "prefer session engine, fall back to global" idiom that
was previously inlined in setupSeccompWrapper and the seccomp handler
wiring. No call sites switched yet; subsequent commits will route the
command precheck and wrap Landlock derivation through this helper to
fix #191.

Refs #191
EOF
)"
```

---

## Task 2: Route core.go precheck and EnvPolicy lookup through the helper (TDD via event-capture)

**Files:**
- Modify: `internal/api/core.go:845` (precheck call)
- Modify: `internal/api/core.go:1053` (EnvPolicy lookup)
- Create/modify: `internal/api/session_policy_integration_test.go` (new file to keep test logic co-located with the helper)

**Goal of the new test:** Construct an `App` whose global `a.policy` would DENY a command, create a session whose per-session engine ALLOWS the same command, invoke `execInSessionCore`, and inspect the emitted `command_policy` event (stored via the in-memory composite store) to confirm the precheck consulted the session engine. This is the smallest test that actually wires through `execInSessionCore` end-to-end at the precheck layer.

- [ ] **Step 1: Write the failing integration-style test**

Create `internal/api/session_policy_integration_test.go`:

```go
package api

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

// newEngineDenyingOnly returns a *policy.Engine with a single explicit
// deny rule for the named command. The rule name embeds the command so
// tests can tell which engine produced the decision (distinguishing it
// from a default-deny fallback or from an engine built by
// newEngineAllowingCommand in session_policy_test.go).
func newEngineDenyingOnly(t *testing.T, cmdName string) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "global-deny-" + cmdName,
		CommandRules: []policy.CommandRule{
			{
				Name:     "global-deny-" + cmdName,
				Commands: []string{cmdName},
				Decision: string(types.DecisionDeny),
				Message:  "denied by global policy",
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// TestExecInSessionCore_PrecheckConsultsSessionPolicy is the regression
// test for #191. It constructs an App whose global policy denies "widget"
// and whose session policy allows "widget", then calls execInSessionCore
// and asserts the emitted command_precheck event reflects the session
// policy's ALLOW decision — not the global policy's DENY.
//
// newEngineAllowingCommand comes from session_policy_test.go (same package).
func TestExecInSessionCore_PrecheckConsultsSessionPolicy(t *testing.T) {
	globalEngine := newEngineDenyingOnly(t, "widget")
	sessionEngine := newEngineAllowingCommand(t, "session-allow-widget", "widget")

	mgr := session.NewManager(5)
	captured := &capturingEventStore{}
	store := composite.New(captured, nil)
	broker := events.NewBroker()

	cfg := &config.Config{}
	app := NewApp(cfg, mgr, store, globalEngine, broker, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	// We don't care whether the command actually runs — we only care which
	// engine the precheck consulted. The precheck event is emitted BEFORE
	// the command would be run, so even if runCommandWithResources errors
	// later (no ptrace tracer, binary doesn't exist), the captured event
	// tells us what we need.
	_, _, _ = app.execInSessionCore(context.Background(), s.ID, types.ExecRequest{
		Command: "widget",
	})

	ev := captured.firstCommandPrecheck()
	if ev == nil {
		t.Fatal("no command_precheck event was emitted")
	}
	if ev.Policy == nil {
		t.Fatal("command_precheck event has nil Policy")
	}
	if ev.Policy.Rule != "session-allow-widget" {
		t.Errorf("precheck consulted the wrong engine: event rule = %q, want %q. "+
			"This means the precheck is still using a.policy instead of the session engine.",
			ev.Policy.Rule, "session-allow-widget")
	}
	if ev.Policy.EffectiveDecision != types.DecisionAllow {
		t.Errorf("precheck should have returned allow, got %v", ev.Policy.EffectiveDecision)
	}
}

// capturingEventStore is a minimal store.EventStore implementation that
// records every AppendEvent call so tests can inspect what was emitted.
// It satisfies the same interface as mockEventStore (see policies_test.go)
// but, unlike that one, keeps the events so we can assert on them.
type capturingEventStore struct {
	events []types.Event
}

func (c *capturingEventStore) AppendEvent(_ context.Context, ev types.Event) error {
	c.events = append(c.events, ev)
	return nil
}

func (c *capturingEventStore) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (c *capturingEventStore) Close() error { return nil }

func (c *capturingEventStore) firstCommandPrecheck() *types.Event {
	for i := range c.events {
		if c.events[i].Operation == "command_precheck" {
			return &c.events[i]
		}
	}
	return nil
}
```

- [ ] **Step 2: Confirm the test compiles and fails for the right reason**

Run: `go test ./internal/api/ -run TestExecInSessionCore_PrecheckConsultsSessionPolicy -v`

Expected: the test should compile (`capturingEventStore` satisfies `store.EventStore` via `AppendEvent` / `QueryEvents` / `Close`, matching the shape already used by `mockEventStore` in `internal/api/policies_test.go`) and then FAIL with a message like `precheck consulted the wrong engine: event rule = "global-deny-widget", want "session-allow-widget"`.

**If compilation breaks** because the `store.EventStore` interface has grown additional methods since this plan was written, update `capturingEventStore` to add the missing methods — mirror whatever `mockEventStore` in `policies_test.go` does.

- [ ] **Step 3: Fix core.go:845 (precheck call)**

At `internal/api/core.go:845`, change:

```go
pre := a.policy.CheckCommand(req.Command, req.Args)
```

to:

```go
pre := a.policyEngineFor(s).CheckCommand(req.Command, req.Args)
```

- [ ] **Step 4: Fix core.go:1053 (EnvPolicy lookup)**

At `internal/api/core.go:1052-1053`, the current code is:

```go
limits := a.policy.Limits()
cmdDecision := a.policy.CheckCommand(wrappedReq.Command, wrappedReq.Args)
```

Change the `CheckCommand` line only (leave `Limits()` for a follow-up — out of scope, see header):

```go
limits := a.policy.Limits()
cmdDecision := a.policyEngineFor(s).CheckCommand(wrappedReq.Command, wrappedReq.Args)
```

- [ ] **Step 5: Run the regression test and verify it passes**

Run: `go test ./internal/api/ -run TestExecInSessionCore_PrecheckConsultsSessionPolicy -v`

Expected: PASS.

- [ ] **Step 6: Run the full api package tests to check for regressions**

Run: `go test ./internal/api/... -count=1`

Expected: all existing tests still PASS. If anything fails, STOP and investigate — do not proceed to the next task.

- [ ] **Step 7: Commit**

```bash
git add internal/api/core.go internal/api/session_policy_integration_test.go
git commit -m "$(cat <<'EOF'
fix(api): use session policy engine at core.go command precheck (#191)

Route execInSessionCore's command_precheck and EnvPolicy lookup through
the policyEngineFor helper so that custom rules authored in non-default
session policies are actually honored. Adds a regression test that
captures the emitted command_precheck event and asserts the rule name
matches the session engine, not the global a.policy.

The runCommandWithResources EnvPolicy lookup at core.go:1053 is fixed in
the same commit because it shares the same code path; a.policy.Limits()
on the preceding line is a separate class of bug (session-specific
limits are also dropped) and is left for a follow-up.

Refs #191
EOF
)"
```

---

## Task 3: Route the other three exec entry points through the helper

**Files:**
- Modify: `internal/api/exec_stream.go:60`
- Modify: `internal/api/pty_core.go:60`
- Modify: `internal/api/grpc.go:293`

These are mechanical: same idiom, three call sites. Each site already has a session variable in scope (the names differ: `s`, `sess`, `sess` respectively). Do them together because they're the same fix pattern, and the existing test suite plus a grep verification is sufficient for mechanical changes.

- [ ] **Step 1: Fix exec_stream.go:60**

At `internal/api/exec_stream.go:60`, change:

```go
pre := a.policy.CheckCommand(req.Command, req.Args)
```

to:

```go
pre := a.policyEngineFor(s).CheckCommand(req.Command, req.Args)
```

(The session variable in this function is `s`, declared at line 32 via `s, ok := a.sessions.Get(id)`.)

- [ ] **Step 2: Fix pty_core.go:60**

At `internal/api/pty_core.go:60`, change:

```go
pre := a.policy.CheckCommand(req.Command, req.Args)
```

to:

```go
pre := a.policyEngineFor(sess).CheckCommand(req.Command, req.Args)
```

(The session variable in this function is `sess`, declared at line 47 via `sess, ok := a.sessions.Get(sessionID)`.)

- [ ] **Step 3: Fix grpc.go:293**

At `internal/api/grpc.go:293`, change:

```go
pre := s.app.policy.CheckCommand(execReq.Command, execReq.Args)
```

to:

```go
pre := s.app.policyEngineFor(sess).CheckCommand(execReq.Command, execReq.Args)
```

(Note: in this file `s` is the `*grpcServer` receiver, and the session variable is `sess`, declared at line 273 via `sess, ok := s.app.sessions.Get(req.SessionID)`. Do not confuse the two.)

- [ ] **Step 4: Verify no remaining `a.policy.CheckCommand` call sites in the four exec entry points**

Run: `grep -rn 'policy\.CheckCommand' internal/api/core.go internal/api/exec_stream.go internal/api/pty_core.go internal/api/grpc.go`

Expected output: four lines, all of the form `*.policyEngineFor(...).CheckCommand(...)`. If any line still shows bare `a.policy.CheckCommand` or `s.app.policy.CheckCommand`, that's a missed call site — fix it before proceeding.

- [ ] **Step 5: Run the api package tests**

Run: `go test ./internal/api/... -count=1`

Expected: all PASS. The Task 2 regression test will also run against core.go; there is no additional regression test for the other three entry points — we rely on grep verification (Step 4) plus the shared helper unit tests from Task 1. If you want extra confidence, copy the Task 2 test and point it at `execInSessionStream`, but only do so if the existing tests pass cleanly — don't gold-plate.

- [ ] **Step 6: Commit**

```bash
git add internal/api/exec_stream.go internal/api/pty_core.go internal/api/grpc.go
git commit -m "$(cat <<'EOF'
fix(api): use session policy engine at exec-stream/pty/grpc precheck (#191)

Route the remaining three exec entry points (HTTP streaming exec, PTY
exec, gRPC Exec) through the policyEngineFor helper. Mechanical change
mirroring the core.go fix; the shared helper unit tests and a grep
verification that no "a.policy.CheckCommand" call sites remain in these
files provide the regression safety net.

Refs #191
EOF
)"
```

---

## Task 4: Route wrap.go Landlock derivation through the helper

**Files:**
- Modify: `internal/api/wrap.go:167-171`
- Modify: `internal/api/session_policy_integration_test.go` (extend with a wrap-path test)

The Landlock derivation in `wrapInitCore` reads `a.policy.Policy()` three times to build the execute/read/write allow-path lists. When a user's session policy grants extra paths, those grants are silently dropped at Landlock. Same helper, same one-line substitution — but the substitution pattern is slightly different because we need `.Policy()` (the raw `*policy.Policy`) not the engine itself.

- [ ] **Step 1: Write the failing test**

Append to `internal/api/session_policy_integration_test.go`:

```go
// TestWrap_LandlockDerivationUsesSessionPolicy is the regression test for the
// wrap.go:167-170 half of #191. It asserts that when a session has a custom
// policy engine with an extra allow_read path, Landlock derivation reads from
// the session engine's policy, not from a.policy.
//
// This test does not actually launch a wrapper (which requires a real seccomp
// capable environment); it calls a small helper that exercises just the
// derivation branch. If wrap.go is refactored so that derivation moves out of
// wrapInitCore, this test should move with it.
func TestWrap_LandlockDerivationUsesSessionPolicy(t *testing.T) {
	globalEngine := newEngineAllowingCommand(t, "global", "ls")
	sessionPol := &policy.Policy{
		Version: 1,
		Name:    "session-with-extra-read",
		CommandRules: []policy.CommandRule{
			{Name: "allow-ls", Commands: []string{"ls"}, Decision: string(types.DecisionAllow)},
		},
		FileRules: []policy.FileRule{
			{
				Name:       "allow-read-project",
				Paths:      []string{"/srv/project"},
				Operations: []string{"read"},
				Decision:   string(types.DecisionAllow),
			},
		},
	}
	sessionEngine, err := policy.NewEngine(sessionPol, false, true)
	if err != nil {
		t.Fatalf("NewEngine session: %v", err)
	}

	mgr := session.NewManager(5)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetPolicyEngine(sessionEngine)

	app := &App{policy: globalEngine}

	// Direct helper exercise: the engine we get for this session must be the
	// session engine, and its Policy() must contain the file rule that only
	// exists in the session policy. The fix at wrap.go:167-170 calls through
	// the same helper, so this assertion covers the wrap path transitively.
	pol := app.policyEngineFor(s).Policy()
	foundSessionRule := false
	for _, fr := range pol.FileRules {
		if fr.Name == "allow-read-project" {
			foundSessionRule = true
			break
		}
	}
	if !foundSessionRule {
		t.Errorf("Landlock derivation would miss the session's file rule: "+
			"policyEngineFor(s).Policy() has %d file rules, none named allow-read-project",
			len(pol.FileRules))
	}
}
```

- [ ] **Step 2: Run the test — it should PASS already**

Run: `go test ./internal/api/ -run TestWrap_LandlockDerivationUsesSessionPolicy -v`

Expected: PASS. This test exercises the helper directly, which Task 1 already wired up. It is a characterization test: it locks in the contract that `policyEngineFor(s).Policy()` exposes the session's rules so that when we swap the wrap.go call sites in the next step, a later refactor can't silently break the Landlock path.

If the test unexpectedly FAILS, STOP — something about Task 1 is wrong; investigate before proceeding.

- [ ] **Step 3: Fix wrap.go:167-170**

At `internal/api/wrap.go:158-171`, the current code is:

```go
	// Add Landlock config if enabled
	if a.cfg.Landlock.Enabled {
		llResult := capabilities.DetectLandlock()
		if llResult.Available {
			workspace := s.WorkspaceMountPath()
			seccompCfg.LandlockEnabled = true
			seccompCfg.LandlockABI = llResult.ABI
			seccompCfg.Workspace = workspace

			if a.policy != nil {
				seccompCfg.AllowExecute = landlock.DeriveExecutePathsFromPolicy(a.policy.Policy())
				seccompCfg.AllowRead = landlock.DeriveReadPathsFromPolicy(a.policy.Policy())
				seccompCfg.AllowWrite = landlock.DeriveWritePathsFromPolicy(a.policy.Policy())
			}
```

Change the inner `if a.policy != nil { ... }` block to use the session engine:

```go
	// Add Landlock config if enabled
	if a.cfg.Landlock.Enabled {
		llResult := capabilities.DetectLandlock()
		if llResult.Available {
			workspace := s.WorkspaceMountPath()
			seccompCfg.LandlockEnabled = true
			seccompCfg.LandlockABI = llResult.ABI
			seccompCfg.Workspace = workspace

			if engine := a.policyEngineFor(s); engine != nil {
				seccompCfg.AllowExecute = landlock.DeriveExecutePathsFromPolicy(engine.Policy())
				seccompCfg.AllowRead = landlock.DeriveReadPathsFromPolicy(engine.Policy())
				seccompCfg.AllowWrite = landlock.DeriveWritePathsFromPolicy(engine.Policy())
			}
```

(Preserve the nil guard — `policyEngineFor` can return `a.policy`, which may itself be nil in a test configuration that passed `nil` to `NewApp`.)

- [ ] **Step 4: Verify the wrap test still passes and wrap_test.go tests still pass**

Run: `go test ./internal/api/ -run 'TestWrap' -v`

Expected: all PASS.

- [ ] **Step 5: Verify no remaining `a.policy.Policy()` call sites in wrap.go**

Run: `grep -n 'a\.policy\.Policy' internal/api/wrap.go`

Expected: no matches. If anything still reads `a.policy.Policy()` at the Landlock branch, fix it.

- [ ] **Step 6: Commit**

```bash
git add internal/api/wrap.go internal/api/session_policy_integration_test.go
git commit -m "$(cat <<'EOF'
fix(api): derive Landlock allow-paths from session policy (#191)

Replace the a.policy.Policy() reads in wrapInitCore's Landlock derivation
with app.policyEngineFor(s).Policy() so that per-session allow_read /
allow_write / allow_execute rules are reflected in the Landlock ruleset
applied to wrapped agents. Without this, users authoring a custom
per-session policy would get Landlock paths derived from the default
policy instead.

Adds a characterization test that pins the contract: the helper must
return a Policy that contains the session's file rules.

Refs #191
EOF
)"
```

---

## Task 5: Extend the integration test to cover non-default policy file names

**Files:**
- Modify: `internal/integration/agentsh_policy_test.go`

The existing integration test `TestPolicyAllowAndDenyCommands` writes its rules to `default.yaml`, which masks #191 because the file happens to become both `a.policy` AND the session engine. Add a sibling test that uses a policy file named `custom.yaml` and creates a session against that named policy, so any future regression that re-introduces the `a.policy` shortcut gets caught by CI.

- [ ] **Step 1: Read the existing test file**

Read `internal/integration/agentsh_policy_test.go` in full so you can mirror its style (testcontainer setup, policy YAML constant, etc.).

- [ ] **Step 2: Add a new test function**

Append to `internal/integration/agentsh_policy_test.go`:

```go
// TestPolicyNonDefaultNameHonored is the regression test for #191. It writes
// a custom policy to a file NAMED OTHER THAN default.yaml, creates a session
// that selects it by name, and verifies that a rule defined only in that
// custom policy actually fires at the command precheck layer.
//
// Before #191 was fixed, the exec precheck consulted a.policy (the default
// policy) rather than the session's engine, so a rule defined only in a
// non-default policy file was silently ignored.
func TestPolicyNonDefaultNameHonored(t *testing.T) {
	ctx := context.Background()

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	// Default policy: does NOT allow "echo".
	writeFile(t, filepath.Join(policiesDir, "default.yaml"), testDefaultPolicyForNonDefaultTest)
	// Custom policy: allows "echo" only.
	writeFile(t, filepath.Join(policiesDir, "custom.yaml"), testCustomPolicyForNonDefaultTest)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, testConfigTemplate)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	endpoint, cleanup := startServerContainer(t, ctx, bin, configPath, policiesDir, workspace)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	// Create a session that selects the CUSTOM policy by name.
	sess, err := cli.CreateSession(ctx, "/workspace", "custom")
	if err != nil {
		t.Fatalf("CreateSession(custom): %v", err)
	}

	// echo is allowed ONLY by the custom policy. If #191 regresses, the
	// precheck will consult the default policy and deny this with
	// E_POLICY_DENIED.
	allowResp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "echo",
		Args:    []string{"ok"},
	})
	if err != nil {
		t.Fatalf("Exec(echo) under custom policy: %v — this is the #191 regression signature", err)
	}
	if allowResp.Result.ExitCode != 0 || allowResp.Result.Stdout != "ok\n" {
		t.Fatalf("echo under custom policy unexpected result: %+v", allowResp.Result)
	}

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
}

const testDefaultPolicyForNonDefaultTest = `
version: 1
name: default
description: integration test default policy (no echo)
command_rules:
  - name: deny-all-explicit
    commands: ["echo"]
    decision: deny
    message: "denied by default policy"
resource_limits:
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`

const testCustomPolicyForNonDefaultTest = `
version: 1
name: custom
description: integration test custom policy (allows echo)
command_rules:
  - name: allow-echo
    commands: ["echo"]
    decision: allow
resource_limits:
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`
```

- [ ] **Step 3: Run the new integration test**

Run: `go test -tags integration ./internal/integration/ -run TestPolicyNonDefaultNameHonored -v`

Expected: PASS. If the test FAILS because the precheck returned E_POLICY_DENIED on `echo`, that means one of the earlier tasks missed a call site — go back and fix.

If the test cannot run because the testcontainer infrastructure isn't available in the current environment, note that in the commit message and rely on CI to run it. The core unit/integration tests from Tasks 1-4 already provide coverage.

- [ ] **Step 4: Run the existing integration test to confirm no regression**

Run: `go test -tags integration ./internal/integration/ -run TestPolicyAllowAndDenyCommands -v`

Expected: PASS (unchanged).

- [ ] **Step 5: Commit**

```bash
git add internal/integration/agentsh_policy_test.go
git commit -m "$(cat <<'EOF'
test(integration): add non-default-policy-name regression for #191

Writes a custom policy to a file named other than default.yaml, creates
a session against that named policy, and verifies a rule defined only
in that policy fires at the command precheck. This is the test shape
that would have caught #191 before it shipped — the existing
TestPolicyAllowAndDenyCommands wrote its custom rules to default.yaml,
which happened to become both a.policy AND the session engine, masking
the bug.

Refs #191
EOF
)"
```

---

## Task 6: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full test suite**

Run: `go test ./...`

Expected: all PASS. Investigate any failure — do not proceed until clean.

- [ ] **Step 2: Cross-compile for Windows**

Run: `GOOS=windows go build ./...`

Expected: clean build, no output. Required by CLAUDE.md.

- [ ] **Step 3: Cross-compile for Darwin**

Run: `GOOS=darwin go build ./...`

Expected: clean build, no output.

- [ ] **Step 4: Verify all exec precheck call sites now go through the helper**

Run: `grep -rn 'policy\.CheckCommand' internal/api/ --include='*.go' | grep -v _test.go`

Expected: every non-test match in `internal/api/` either:
- uses the helper pattern `*.policyEngineFor(*).CheckCommand(*)`, OR
- is on an internal `policy.Engine` local variable (not `a.policy`)

If any bare `a.policy.CheckCommand` or `s.app.policy.CheckCommand` remains in a production code path, that's a missed call site.

- [ ] **Step 5: Verify wrap.go Landlock call sites are fixed**

Run: `grep -n 'a\.policy\.Policy' internal/api/wrap.go`

Expected: no matches.

- [ ] **Step 6: Smoke-test the whole branch**

Run: `git log --oneline main..HEAD`

Expected: 6 commits — one `docs:` commit for the plan file, then 5 fix/test commits (one per task 1-5), in order. If the fix commit count is off, a task was skipped — go back.

- [ ] **Step 7: Report ready**

At this point the branch is ready for code review. Report to the user:
- Branch: `fix/191-per-session-policy-engine`
- Worktree: `.worktrees/fix-191-per-session-policy`
- Commits: 5 (helper, core.go, three-entry-points, wrap.go Landlock, integration test)
- Tests: all passing, cross-compile clean
- Ready for: roborev review, then PR

Do NOT push, do NOT create a PR, do NOT merge. The user's memory note says "Run roborev between tasks, fix all issues above low before proceeding" — so roborev is the next step, not a PR.
