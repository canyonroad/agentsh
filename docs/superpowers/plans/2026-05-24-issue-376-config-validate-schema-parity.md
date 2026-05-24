# config validate / startup schema-validation parity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `agentsh config validate` reject the configs the server rejects at startup, by wiring the two config-schema cross-field validators (`cfg.Sandbox.Validate()`, `cfg.Policies.Signing.Validate()`) into `config.validateConfig`.

**Architecture:** `config.Load`/`LoadWithSource` (used by `config validate`, the server, and shim auto-start) run `validateConfig`. Append the two validators — currently called only at `server.New` — to the end of `validateConfig`, with error prefixes copied verbatim from `server.go` so messages are identical. Keep the startup calls as defense-in-depth with a guardrail comment. Host/environment checks stay at startup.

**Tech Stack:** Go; `internal/config`, `internal/server`.

**Spec:** `docs/superpowers/specs/2026-05-24-issue-376-config-validate-schema-parity-design.md`

**Verified facts (don't re-derive):**
- `validateConfig(cfg *Config) error` is at `internal/config/config.go:2140`; its final `return nil` is at `config.go:2441`. Insert the new calls immediately before that `return nil`.
- `applyDefaults(&Config{})` followed by `validateConfig` returns `nil` (baseline is fully valid) — confirmed empirically. So tests build `&Config{}`, call `applyDefaults(cfg)`, override the field under test, then call `validateConfig(cfg)`.
- `applyDefaults` does NOT populate `Sandbox.Ptrace`; tests that enable ptrace must set `cfg.Sandbox.Ptrace = DefaultPtraceConfig()` first (gives valid `attach_mode`/`on_attach_failure`/`mask_tracer_pid`/`max_hold_ms`). `DefaultPtraceConfig()` has `Enabled:false` and `Trace{Execve,File,Network,Signal}` all `true` (i.e. NOT execve-only — matches the issue repro).
- `SandboxConfig.Validate()` checks, in order: (1) `Ptrace.Enabled && Seccomp.Execve.Enabled` → `"…mutually exclusive…"`; (2) `Ptrace.Enabled && *UnixSockets.Enabled && !Ptrace.IsExecveOnly()` → `"…requires execve-only tracing…"`; (3) `Ptrace.Validate()` (returns nil when ptrace disabled).
- `SigningConfig.Validate()` errors with `"signing.trust_store is required when signing.mode is \"enforce\""` when `Mode` is `enforce`/`warn` and `TrustStore == ""`. Field path: `cfg.Policies.Signing.{Mode,TrustStore}`.
- `server.go:143-149` wraps these as `fmt.Errorf("sandbox config: %w", err)` and `fmt.Errorf("signing config: %w", err)`.
- Test files in `internal/config` are `package config` and call the unexported `applyDefaults`/`validateConfig` directly (see `internal/config/pkgcheck_test.go`).

---

## File Structure

- `internal/config/config.go` — append two validator calls to the end of `validateConfig` (the only behavioral change).
- `internal/config/validate_sandbox_signing_test.go` (new) — regression tests proving the validators are wired into `validateConfig`.
- `internal/server/server.go` — guardrail comment above the existing startup validation calls (no behavior change).

---

## Task 1: Wire schema validators into `validateConfig` (+ tests + guardrail comment)

**Files:**
- Create: `internal/config/validate_sandbox_signing_test.go`
- Modify: `internal/config/config.go` (before the `return nil` at line 2441)
- Modify: `internal/server/server.go` (comment above line 143)

- [ ] **Step 1: Write the failing tests**

Create `internal/config/validate_sandbox_signing_test.go`:

```go
package config

import (
	"strings"
	"testing"
)

// Issue #376: validateConfig (run by config.Load and `agentsh config validate`)
// must enforce the config-schema cross-field invariants the server also checks
// at startup, with the same messages, so misconfig is caught pre-deploy.

func TestValidateConfig_RejectsPtraceUnixSocketsNonExecveOnly(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	enabled := true
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.Seccomp.Execve.Enabled = false // isolate the unix_sockets path (else mutual-exclusion fires first)
	cfg.Sandbox.Ptrace = DefaultPtraceConfig()  // valid sub-fields; Trace.* all true => NOT execve-only
	cfg.Sandbox.Ptrace.Enabled = true

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("ptrace + unix_sockets with non-execve-only tracing must fail validation")
	}
	if !strings.Contains(err.Error(), "sandbox config:") || !strings.Contains(err.Error(), "requires execve-only tracing") {
		t.Errorf("error should match the startup message; got: %v", err)
	}
}

func TestValidateConfig_RejectsPtraceWithSeccompExecve(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Sandbox.Ptrace = DefaultPtraceConfig()
	cfg.Sandbox.Ptrace.Enabled = true
	cfg.Sandbox.Seccomp.Execve.Enabled = true

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("ptrace + seccomp.execve must fail validation (mutually exclusive)")
	}
	if !strings.Contains(err.Error(), "sandbox config:") || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should match the startup message; got: %v", err)
	}
}

func TestValidateConfig_RejectsSigningEnforceWithoutTrustStore(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	cfg.Policies.Signing.Mode = "enforce"
	cfg.Policies.Signing.TrustStore = ""

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("signing mode=enforce without trust_store must fail validation")
	}
	if !strings.Contains(err.Error(), "signing config:") || !strings.Contains(err.Error(), "trust_store is required") {
		t.Errorf("error should match the startup message; got: %v", err)
	}
}

func TestValidateConfig_AcceptsDefaultBaseline(t *testing.T) {
	// Regression guard: the newly-wired validators must NOT reject a normal
	// default config. (Also confirms validateConfig still reaches its tail.)
	cfg := &Config{}
	applyDefaults(cfg)
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("default config must validate cleanly; got: %v", err)
	}
}

func TestValidateConfig_AcceptsExecveOnlyPtraceWithUnixSockets(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	enabled := true
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.Seccomp.Execve.Enabled = false
	cfg.Sandbox.Ptrace = DefaultPtraceConfig()
	cfg.Sandbox.Ptrace.Enabled = true
	cfg.Sandbox.Ptrace.Trace.File = false
	cfg.Sandbox.Ptrace.Trace.Network = false
	cfg.Sandbox.Ptrace.Trace.Signal = false // now execve-only

	if err := validateConfig(cfg); err != nil {
		t.Fatalf("execve-only ptrace + unix_sockets must validate cleanly; got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestValidateConfig_Rejects(PtraceUnixSocketsNonExecveOnly|PtraceWithSeccompExecve|SigningEnforceWithoutTrustStore)' -v`
Expected: all three **reject** tests FAIL (`validateConfig` returns nil today, so each hits its `t.Fatal("…must fail validation")`). The two `Accepts*` tests already PASS.

- [ ] **Step 3: Wire the validators into `validateConfig`**

In `internal/config/config.go`, immediately before the final `return nil` of `validateConfig` (line 2441), insert:

```go
	// Config-schema cross-field invariants that the server also enforces at
	// startup. Validated here so `agentsh config validate` (and the shim's
	// auto-start path) catch them before deploy rather than surfacing as a
	// generic "server unreachable" at runtime (issue #376). Host/environment
	// checks (capabilities, etc.) intentionally stay at server startup.
	if err := cfg.Sandbox.Validate(); err != nil {
		return fmt.Errorf("sandbox config: %w", err)
	}
	if err := cfg.Policies.Signing.Validate(); err != nil {
		return fmt.Errorf("signing config: %w", err)
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -run TestValidateConfig_ -v`
Expected: all five tests PASS (three reject, two accept).

- [ ] **Step 5: Add the guardrail comment in `server.go`**

In `internal/server/server.go`, directly above the `if err := cfg.Sandbox.Validate(); err != nil {` line (currently line 143), insert:

```go
	// These config-schema invariants are also enforced by config.validateConfig
	// (run by config.Load), so `agentsh config validate` catches them pre-deploy
	// (issue #376). The calls here are defense-in-depth for any server built from
	// a config that did not pass through config.Load. New config-schema invariants
	// belong in config.validateConfig, not here.
```

- [ ] **Step 6: Build and commit**

Run: `go build ./... && go test ./internal/config/ ./internal/server/`
Expected: build OK; both packages pass.

```bash
git add internal/config/config.go internal/config/validate_sandbox_signing_test.go internal/server/server.go
git commit -m "fix(#376): enforce sandbox+signing schema invariants in config validate"
```

---

## Task 2: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build + Windows cross-compile**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: both succeed (no output).

- [ ] **Step 2: Vet + gofmt**

Run: `go vet ./internal/config/ ./internal/server/ && gofmt -l internal/config/config.go internal/config/validate_sandbox_signing_test.go internal/server/server.go`
Expected: vet clean; `gofmt -l` prints nothing.

- [ ] **Step 3: Affected package tests**

Run: `go test ./internal/config/ ./internal/server/`
Expected: ok for both (no existing fixture relied on loading an invalid config successfully).

- [ ] **Step 4: Commit any formatting fixes (only if Step 2 changed files)**

```bash
git add -A && git commit -m "chore(#376): gofmt" || echo "nothing to commit"
```

---

## Self-review notes

- **Spec coverage:** validator wiring (Task 1 Step 3) covers Sandbox + Signing; message parity via verbatim prefixes; guardrail comment (Task 1 Step 5); env checks untouched (no task touches `capabilities.CheckAll`); tests for both reject and accept paths (Task 1 Step 1), including the default-baseline regression guard. Non-goals respected (no env checks moved, no startup calls removed, no other startup checks relocated).
- **Type consistency:** `validateConfig`, `applyDefaults`, `DefaultPtraceConfig`, `SandboxConfig.Validate`, `SigningConfig.Validate`, field paths `cfg.Sandbox.Ptrace.Trace.{Execve,File,Network,Signal}`, `cfg.Sandbox.UnixSockets.Enabled (*bool)`, `cfg.Sandbox.Seccomp.Execve.Enabled`, `cfg.Policies.Signing.{Mode,TrustStore}` all match the verified facts.
- **No placeholders:** every code/command step is concrete with expected output.
