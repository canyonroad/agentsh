# Enforce env_policy on the wrap path (#379) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce env `allow`/`deny`/`max_*` on the client-spawned wrap path (shell shim / kernel-install / `agentsh wrap`) by plumbing the resolved policy through `WrapInitResponse` and applying a subtractive `policy.BuildEnv` filter client-side — gated behind `sandbox.wrap_env_policy.enabled` (default off), fail-open.

**Architecture:** Server resolves the env policy for the wrapped command and (only when the flag is on) sends it as a new `EnvPolicyWire` field on `WrapInitResponse`. A new `internal/wrapenv.Filter` helper maps the wire type to `policy.ResolvedEnvPolicy` and runs `policy.BuildEnv` over the **inherited** launcher env (subtractive), fail-open. Both client launch sites filter the inherited base *before* adding agentsh markers / `env_inject`, so those always survive.

**Tech Stack:** Go; `pkg/types`, `internal/config`, `internal/policy`, `internal/wrapenv` (new), `internal/api`, `internal/cli`, `internal/shim/kernelinstall`.

**Spec:** `docs/superpowers/specs/2026-05-24-issue-379-wrap-env-policy-design.md`

**Verified facts (don't re-derive):**
- `WrapInitResponse` is in `pkg/types/sessions.go`; it currently ends with `EnvInject map[string]string `json:"env_inject,omitempty"``. `pkg/types` must NOT import `internal/policy` (so the wire type is primitive).
- `policy.ResolvedEnvPolicy{Allow []string; Deny []string; MaxBytes int; MaxKeys int; BlockIteration bool}` (`internal/policy/env_policy.go:13`). `policy.BuildEnv(pol ResolvedEnvPolicy, baseEnv []string, addKeys map[string]string) ([]string, error)` (env_policy.go:55): no allow patterns ⇒ keep all except `deny` + `defaultSecretDeny`; allow patterns ⇒ keep only allowed; then `max_bytes`/`max_keys`. `AWS_SECRET_ACCESS_KEY` is in `defaultSecretDeny`.
- `internal/policy` already imports `pkg/types`, so `internal/wrapenv` importing both `pkg/types` and `internal/policy` creates no cycle.
- `SandboxConfig` (`internal/config/config.go:~345`) holds sub-structs like `UnixSockets`, `Seccomp`, `Ptrace`. `internal/config` imports `gopkg.in/yaml.v3` as `yaml`. Config tests are `package config`.
- The wrap handler `wrapInitCore` (`internal/api/wrap.go:124`) sets `EnvInject: mergeEnvInject(a.cfg, a.policyEngineFor(s))` at two response sites: ptrace (`wrap.go:283`) and seccomp (`wrap.go:519`, the final `return types.WrapInitResponse{`). `dec` at `wrap.go:164` is scoped to the `req.Mode == "shim"` block — NOT in scope at those sites; resolve via a helper instead.
- `a.policyEngineFor(s)` returns `*policy.Engine` (or nil). `engine.CheckCommandWithExecve(cmd, args, a.execveEnforcementActive(), a.shellCOpaqueMode()).EnvPolicy` yields the resolved `policy.ResolvedEnvPolicy`. `App` (package `api`) has unexported fields `cfg *config.Config` and `policy *policy.Engine` (settable in-package tests); `policyEngineFor(nil)` falls back to `a.policy`.
- `internal/cli/wrap_linux.go` imports `internal/envinject`, `pkg/types`. Both env builds are `env := buildWrapEnv(os.Environ(), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)` — ptrace branch (~L33) and seccomp branch (~L138).
- `internal/shim/kernelinstall/install_linux.go` imports `internal/envinject`, `pkg/types`. Site (L200): `env := assembleWrapperEnv(filterShimInternalEnv(p.Env), p.Argv0, resp.WrapperEnv, resp.EnvInject)`. `assembleWrapperEnv(base []string, argv0 string, wrapperEnv, envInject map[string]string) []string` (L388) is a pure function that overlays `envInject` then appends `AGENTSH_*` markers.

---

## File Structure

- `pkg/types/sessions.go` — `EnvPolicyWire` type + `EnvPolicy *EnvPolicyWire` field on `WrapInitResponse`.
- `internal/config/config.go` — `SandboxWrapEnvPolicyConfig{Enabled bool}` + `WrapEnvPolicy` field on `SandboxConfig`.
- `internal/wrapenv/wrapenv.go` (new) + `wrapenv_test.go` — the `Filter` helper (the only logic unit).
- `internal/api/wrap.go` — `wrapEnvPolicyWire` helper; populate `EnvPolicy` at both response sites.
- `internal/cli/wrap_linux.go`, `internal/shim/kernelinstall/install_linux.go` — filter the inherited base.

---

## Task 1: Wire type + opt-in config flag

**Files:**
- Modify: `pkg/types/sessions.go`
- Modify: `internal/config/config.go`
- Create: `internal/config/wrap_env_policy_test.go`

- [ ] **Step 1: Write the failing config test**

Create `internal/config/wrap_env_policy_test.go`:

```go
package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// Issue #379: sandbox.wrap_env_policy.enabled is an opt-in flag, default false.

func TestWrapEnvPolicy_DefaultsOff(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	if cfg.Sandbox.WrapEnvPolicy.Enabled {
		t.Error("sandbox.wrap_env_policy.enabled must default to false")
	}
}

func TestWrapEnvPolicy_UnmarshalsTrue(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("sandbox:\n  wrap_env_policy:\n    enabled: true\n"), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !cfg.Sandbox.WrapEnvPolicy.Enabled {
		t.Error("sandbox.wrap_env_policy.enabled should be true after unmarshal")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/config/ -run TestWrapEnvPolicy -v`
Expected: FAIL — compile error `cfg.Sandbox.WrapEnvPolicy undefined`.

- [ ] **Step 3: Add the wire type to pkg/types**

In `pkg/types/sessions.go`, add (above `WrapInitResponse`):

```go
// EnvPolicyWire carries the resolved env allow/deny/limits for the client
// (shell shim / CLI wrap) to filter the executed command's inherited
// environment. Nil/omitted means "no filtering" — the field is only populated
// when sandbox.wrap_env_policy.enabled is true, which also makes mixed-version
// deployments degrade safely. block_iteration is intentionally not carried: it
// is not enforceable on the wrap path (shells read environ directly). Issue #379.
type EnvPolicyWire struct {
	Allow    []string `json:"allow,omitempty"`
	Deny     []string `json:"deny,omitempty"`
	MaxBytes int      `json:"max_bytes,omitempty"`
	MaxKeys  int      `json:"max_keys,omitempty"`
}
```

and add a field at the end of the `WrapInitResponse` struct (after `EnvInject`):

```go
	// EnvPolicy carries the resolved env allow/deny/limits for the client to
	// filter the executed command's inherited environment, when
	// sandbox.wrap_env_policy.enabled is set. Nil ⇒ no filtering. Issue #379.
	EnvPolicy *EnvPolicyWire `json:"env_policy,omitempty"`
```

- [ ] **Step 4: Add the config flag**

In `internal/config/config.go`, add the struct (near the other `Sandbox*` sub-structs):

```go
// SandboxWrapEnvPolicyConfig opts into enforcing env_policy (allow/deny/max_*)
// on the client-spawned wrap path (shell shim / kernel-install / agentsh wrap).
// Default off; fail-open. Issue #379.
type SandboxWrapEnvPolicyConfig struct {
	Enabled bool `yaml:"enabled"`
}
```

and add a field to `SandboxConfig` (next to `Ptrace`/`Seccomp`):

```go
	WrapEnvPolicy SandboxWrapEnvPolicyConfig `yaml:"wrap_env_policy"`
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/config/ -run TestWrapEnvPolicy -v && go build ./...`
Expected: both tests PASS; build OK.

- [ ] **Step 6: Commit**

```bash
git add pkg/types/sessions.go internal/config/config.go internal/config/wrap_env_policy_test.go
git commit -m "feat(#379): WrapInitResponse.EnvPolicy wire + sandbox.wrap_env_policy flag

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `internal/wrapenv.Filter` helper

**Files:**
- Create: `internal/wrapenv/wrapenv.go`
- Create: `internal/wrapenv/wrapenv_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/wrapenv/wrapenv_test.go`:

```go
package wrapenv

import (
	"slices"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func has(env []string, kv string) bool { return slices.Contains(env, kv) }

func TestFilter_NilWireIsIdentity(t *testing.T) {
	base := []string{"PATH=/bin", "FOO=bar"}
	got := Filter(base, nil)
	if !slices.Equal(got, base) {
		t.Errorf("nil wire must return base unchanged; got %v", got)
	}
}

func TestFilter_DenyStripsMatchKeepsRest(t *testing.T) {
	base := []string{"PATH=/bin", "SECRET_TOKEN=x", "HOME=/h"}
	got := Filter(base, &types.EnvPolicyWire{Deny: []string{"SECRET_*"}})
	if has(got, "SECRET_TOKEN=x") {
		t.Error("denied var must be stripped")
	}
	if !has(got, "PATH=/bin") || !has(got, "HOME=/h") {
		t.Error("non-denied vars must be kept")
	}
}

func TestFilter_DefaultSecretDenyWhenNoAllow(t *testing.T) {
	base := []string{"PATH=/bin", "AWS_SECRET_ACCESS_KEY=zzz"}
	got := Filter(base, &types.EnvPolicyWire{}) // empty policy, no allow
	if has(got, "AWS_SECRET_ACCESS_KEY=zzz") {
		t.Error("default-secret-deny var must be stripped when no allow patterns")
	}
	if !has(got, "PATH=/bin") {
		t.Error("ordinary var must be kept")
	}
}

func TestFilter_AllowIsAllowlist(t *testing.T) {
	base := []string{"PATH=/bin", "HOME=/h", "OTHER=1"}
	got := Filter(base, &types.EnvPolicyWire{Allow: []string{"PATH", "HOME"}})
	if has(got, "OTHER=1") {
		t.Error("non-allowed var must be dropped under allowlist")
	}
	if !has(got, "PATH=/bin") || !has(got, "HOME=/h") {
		t.Error("allowed vars must be kept")
	}
}

func TestFilter_MaxKeys(t *testing.T) {
	base := []string{"A=1", "B=2", "C=3", "D=4"}
	got := Filter(base, &types.EnvPolicyWire{MaxKeys: 2})
	if len(got) > 2 {
		t.Errorf("max_keys=2 must cap key count; got %d", len(got))
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/wrapenv/ -v`
Expected: FAIL — package/`Filter` does not exist.

- [ ] **Step 3: Implement Filter**

Create `internal/wrapenv/wrapenv.go`:

```go
// Package wrapenv applies env_policy filtering to the inherited environment on
// the client-spawned wrap path (shell shim / kernel-install / agentsh wrap),
// the counterpart to server-side buildPolicyEnv. Issue #379.
package wrapenv

import (
	"log/slog"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// Filter applies the wrapped command's env policy subtractively over the
// inherited base environment. A nil wire returns base unchanged (fail-open for
// the default-off and mixed-version cases). On a BuildEnv error it returns base
// unchanged with a warning — env filtering must never block a command.
func Filter(base []string, wire *types.EnvPolicyWire) []string {
	if wire == nil {
		return base
	}
	pol := policy.ResolvedEnvPolicy{
		Allow:    wire.Allow,
		Deny:     wire.Deny,
		MaxBytes: wire.MaxBytes,
		MaxKeys:  wire.MaxKeys,
	}
	out, err := policy.BuildEnv(pol, base, nil)
	if err != nil {
		slog.Warn("wrap env policy filter failed; passing inherited env unfiltered", "error", err)
		return base
	}
	return out
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/wrapenv/ -v`
Expected: PASS (all 5).

- [ ] **Step 5: Commit**

```bash
git add internal/wrapenv/wrapenv.go internal/wrapenv/wrapenv_test.go
git commit -m "feat(#379): wrapenv.Filter subtractive env-policy filter

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Server — resolve + populate `EnvPolicy`

**Files:**
- Modify: `internal/api/wrap.go` (helper + two response sites)
- Create: `internal/api/wrap_env_policy_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/api/wrap_env_policy_test.go`:

```go
package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

func newWrapEnvTestApp(t *testing.T, enabled bool, p *policy.Policy) *App {
	t.Helper()
	eng, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cfg := &config.Config{}
	cfg.Sandbox.WrapEnvPolicy.Enabled = enabled
	return &App{cfg: cfg, policy: eng}
}

func TestWrapEnvPolicyWire_NilWhenDisabled(t *testing.T) {
	p := &policy.Policy{
		EnvPolicy:    policy.EnvPolicy{Deny: []string{"FOO"}},
		CommandRules: []policy.CommandRule{{Name: "allow-sh", Commands: []string{"sh"}, Decision: "allow"}},
	}
	a := newWrapEnvTestApp(t, false, p)
	if w := a.wrapEnvPolicyWire(nil, types.WrapInitRequest{AgentCommand: "/bin/sh", AgentArgs: []string{"-c", "echo hi"}}); w != nil {
		t.Errorf("flag off must yield nil wire; got %+v", w)
	}
}

func TestWrapEnvPolicyWire_PopulatedWhenEnabled(t *testing.T) {
	p := &policy.Policy{
		EnvPolicy:    policy.EnvPolicy{Deny: []string{"FOO"}},
		CommandRules: []policy.CommandRule{{Name: "allow-sh", Commands: []string{"sh"}, Decision: "allow"}},
	}
	a := newWrapEnvTestApp(t, true, p)
	w := a.wrapEnvPolicyWire(nil, types.WrapInitRequest{AgentCommand: "/bin/sh", AgentArgs: []string{"-c", "echo hi"}})
	if w == nil {
		t.Fatal("flag on must yield a non-nil wire")
	}
	found := false
	for _, d := range w.Deny {
		if d == "FOO" {
			found = true
		}
	}
	if !found {
		t.Errorf("wire.Deny should contain FOO from the resolved policy; got %v", w.Deny)
	}
}
```

(If `policy.Policy`/`policy.EnvPolicy` field names differ, adjust to the actual exported fields — the resolved `Deny` must surface `FOO`.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/api/ -run TestWrapEnvPolicyWire -v`
Expected: FAIL — `a.wrapEnvPolicyWire` undefined.

- [ ] **Step 3: Add the helper**

In `internal/api/wrap.go`, add:

```go
// wrapEnvPolicyWire resolves the env policy for the wrapped command and returns
// it as a wire value for the client to filter the inherited environment, when
// sandbox.wrap_env_policy.enabled is set. Returns nil when disabled or when no
// engine is available (fail-open). Even an empty (no allow/deny/max) policy
// yields a non-nil wire so the client still applies the default-secret-deny
// baseline. Issue #379.
func (a *App) wrapEnvPolicyWire(s *session.Session, req types.WrapInitRequest) *types.EnvPolicyWire {
	if !a.cfg.Sandbox.WrapEnvPolicy.Enabled {
		return nil
	}
	engine := a.policyEngineFor(s)
	if engine == nil {
		return nil
	}
	pol := engine.CheckCommandWithExecve(req.AgentCommand, req.AgentArgs, a.execveEnforcementActive(), a.shellCOpaqueMode()).EnvPolicy
	return &types.EnvPolicyWire{
		Allow:    pol.Allow,
		Deny:     pol.Deny,
		MaxBytes: pol.MaxBytes,
		MaxKeys:  pol.MaxKeys,
	}
}
```

(Confirm `session` is already imported in `wrap.go`; it is used throughout the file.)

- [ ] **Step 4: Populate the two response sites**

In `internal/api/wrap.go`, in the ptrace response (the `return types.WrapInitResponse{` at ~L279, which sets `EnvInject:`), add a field:

```go
			EnvPolicy:             a.wrapEnvPolicyWire(s, req),
```

and in the seccomp response (the final `return types.WrapInitResponse{` at ~L507, which sets `EnvInject:`), add:

```go
		EnvPolicy: a.wrapEnvPolicyWire(s, req),
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/api/ -run TestWrapEnvPolicyWire -v && go build ./...`
Expected: both tests PASS; build OK.

- [ ] **Step 6: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_env_policy_test.go
git commit -m "feat(#379): server resolves + sends wrap EnvPolicy when flag enabled

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Client — filter the inherited base

**Files:**
- Modify: `internal/cli/wrap_linux.go` (two sites + import)
- Modify: `internal/shim/kernelinstall/install_linux.go` (one site + import)
- Create: `internal/shim/kernelinstall/wrap_env_policy_test.go`

- [ ] **Step 1: Write the failing ordering test**

Create `internal/shim/kernelinstall/wrap_env_policy_test.go`:

```go
package kernelinstall

import (
	"slices"
	"testing"

	"github.com/agentsh/agentsh/internal/wrapenv"
	"github.com/agentsh/agentsh/pkg/types"
)

// Issue #379: filtering applies to the inherited base BEFORE agentsh markers and
// env_inject are added, so a denied var is dropped while markers and injected
// values survive.
func TestAssembleWrapperEnv_FiltersBaseKeepsMarkersAndInject(t *testing.T) {
	base := []string{"PATH=/bin", "SECRET_TOKEN=x"}
	wire := &types.EnvPolicyWire{Deny: []string{"SECRET_*"}}

	filtered := wrapenv.Filter(base, wire)
	env := assembleWrapperEnv(filtered, "", map[string]string{}, map[string]string{"INJECTED": "1"})

	for _, kv := range env {
		if kv == "SECRET_TOKEN=x" {
			t.Error("denied var must not survive filtering")
		}
	}
	if !slices.Contains(env, "INJECTED=1") {
		t.Error("env_inject value must survive (applied after filter)")
	}
	if !slices.Contains(env, "AGENTSH_NOTIFY_SOCK_FD=3") {
		t.Error("agentsh marker must survive (appended after filter)")
	}
	if !slices.Contains(env, "PATH=/bin") {
		t.Error("non-denied inherited var must survive")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/shim/kernelinstall/ -run TestAssembleWrapperEnv_FiltersBase -v`
Expected: FAIL — `internal/wrapenv` not yet imported here / test references compile but the production call isn't wired (this test exercises the composition directly, so it will actually PASS once Step 1 compiles — if it already passes, that's fine: it locks in the ordering contract. The real production wiring is Steps 3-4, verified by build.)

(Note: this test validates the helper composition; the production change in Steps 3-4 is verified by `go build` + the full suite. If the test passes immediately, proceed — it is a guard, not red-green for new logic, which lives in `wrapenv` Task 2.)

- [ ] **Step 3: Wire kernelinstall**

In `internal/shim/kernelinstall/install_linux.go`, add `"github.com/agentsh/agentsh/internal/wrapenv"` to the import block, and change the base at L200 from:

```go
	env := assembleWrapperEnv(filterShimInternalEnv(p.Env), p.Argv0, resp.WrapperEnv, resp.EnvInject)
```

to:

```go
	env := assembleWrapperEnv(wrapenv.Filter(filterShimInternalEnv(p.Env), resp.EnvPolicy), p.Argv0, resp.WrapperEnv, resp.EnvInject)
```

- [ ] **Step 4: Wire cli/wrap_linux.go (both branches)**

In `internal/cli/wrap_linux.go`, add `"github.com/agentsh/agentsh/internal/wrapenv"` to the import block. In BOTH the ptrace branch (~L33) and seccomp branch (~L138), change:

```go
	env := buildWrapEnv(os.Environ(), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
```

to:

```go
	env := buildWrapEnv(wrapenv.Filter(os.Environ(), wrapResp.EnvPolicy), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
```

- [ ] **Step 5: Run tests + build**

Run: `go test ./internal/shim/kernelinstall/ -run TestAssembleWrapperEnv_FiltersBase -v && go build ./... && GOOS=windows go build ./...`
Expected: test PASS; both builds OK.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/wrap_linux.go internal/shim/kernelinstall/install_linux.go internal/shim/kernelinstall/wrap_env_policy_test.go
git commit -m "feat(#379): filter inherited env on wrap launch paths

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build + Windows cross-compile**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: both succeed.

- [ ] **Step 2: Vet + gofmt**

Run: `go vet ./pkg/types/ ./internal/config/ ./internal/wrapenv/ ./internal/api/ ./internal/cli/ ./internal/shim/kernelinstall/ && gofmt -l pkg/types/sessions.go internal/config/config.go internal/config/wrap_env_policy_test.go internal/wrapenv/wrapenv.go internal/wrapenv/wrapenv_test.go internal/api/wrap.go internal/api/wrap_env_policy_test.go internal/cli/wrap_linux.go internal/shim/kernelinstall/install_linux.go internal/shim/kernelinstall/wrap_env_policy_test.go`
Expected: vet clean; `gofmt -l` prints nothing.

- [ ] **Step 3: Affected package tests**

Run: `go test ./pkg/types/ ./internal/config/ ./internal/wrapenv/ ./internal/api/ ./internal/cli/ ./internal/shim/kernelinstall/ ./internal/policy/`
Expected: ok for all.

- [ ] **Step 4: Commit any formatting fixes (only if Step 2 changed files)**

```bash
git add -A && git commit -m "chore(#379): gofmt" || echo "nothing to commit"
```

---

## Self-review notes

- **Spec coverage:** wire type + flag (Task 1) ← spec §1,§2; `wrapenv.Filter` subtractive fail-open (Task 2) ← spec §3; server resolve+populate when enabled (Task 3) ← spec §2; client apply-before-markers in all 3 sites (Task 4) ← spec §4; verification incl. Windows (Task 5). Non-goals respected: no minimal-rebuild, `block_iteration` not carried (wire omits it), no exec-path change, default-off (flag), fail-open (Filter returns base on nil/error).
- **Type/name consistency:** `types.EnvPolicyWire{Allow,Deny,MaxBytes,MaxKeys}`, `WrapInitResponse.EnvPolicy *EnvPolicyWire`, `config.SandboxWrapEnvPolicyConfig{Enabled}` at `cfg.Sandbox.WrapEnvPolicy.Enabled`, `wrapenv.Filter(base, wire)`, `(a *App) wrapEnvPolicyWire(s, req)`, `policy.ResolvedEnvPolicy`/`policy.BuildEnv` — consistent across tasks.
- **Build stays green per commit:** Task 1 pure additions; Task 2 new package; Task 3 uses Task 1's type; Task 4 uses Task 1+2. Each compiles independently.
- **No placeholders:** every step has concrete code/commands. (Task 3 test notes a fallback if `policy.Policy` field names differ; Task 4 Step 2 notes the guard-test may pass immediately by design.)
