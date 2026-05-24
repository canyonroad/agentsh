# `symlink_escape: deny` cwd-subtree fix (#377 part 2) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In `symlink_escape: deny` mode, stop blanket-denying every command run from a symlinked-escaping cwd by evaluating the cwd subtree against `file_rules` (like `evaluate` mode), while keeping escapes outside the cwd subtree blanket-denied.

**Architecture:** Add two lightweight `Session` accessors (`GetCwd`, `FirstCwdEscapeWarn`). In `internal/fsmonitor/fuse.go` `checkWithExist`'s symlink-escape branch, when in deny mode compute whether the checked path is under the process cwd (`pathutil.IsUnderRoot`); if so, fall through to `evalEscapedSymlink` + `file_rules` and emit a one-time-per-session diagnostic. Escapes outside the cwd subtree, `..`-escapes, and broken links remain `workspace-escape` denies.

**Tech Stack:** Go; `internal/session`, `internal/fsmonitor`, `internal/pathutil`, `log/slog`.

**Spec:** `docs/superpowers/specs/2026-05-24-issue-377-symlink-cwd-deny-design.md`

**Verified facts (don't re-derive):**
- `internal/fsmonitor/fuse.go` `checkWithExist` is at L471; its symlink-escape branch is L501-515. The gate to change:
  ```go
  escapeDeny := n.hooks != nil && n.hooks.SymlinkEscapeDeny
  var escaped string
  if !escapeDeny {
      escaped = evalEscapedSymlink(realRoot, virtPath, n.vroot())
  }
  if escaped != "" {
      policyPath = escaped
  } else {
      return policy.Decision{
          PolicyDecision:    types.DecisionDeny,
          EffectiveDecision: types.DecisionDeny,
          Rule:              "workspace-escape",
          Message:           err.Error(),
      }
  }
  ```
- `Hooks` (fuse.go:30) has fields `SessionID string`, `Session *session.Session`, `SymlinkEscapeDeny bool`. fuse.go already imports `internal/session`. fuse.go does **NOT** import `log/slog` or `internal/pathutil` — both must be added.
- `pathutil.IsUnderRoot(path, root)` returns `path == root || strings.HasPrefix(path, root+"/")` and returns `false` for empty `root` (fail-closed). It subsumes the `virtPath == cwd` equality case.
- `evalEscapedSymlink(realRoot, virtPath, virtualRoot string) string` (path.go:88) returns `""` for `..`-escapes (its `pathutil.IsRealPathUnder` guard) and for broken links / missing parents (`EvalSymlinks` error), and the cleaned resolved real path otherwise.
- `internal/session/manager.go`: `Session` struct at L29, `mu sync.Mutex` at L30, `Cwd string` at L40. `sync` is already imported (L12). Existing accessor `GetCwdEnvHistory()` at L954 also copies env+history (the reason for adding the lightweight `GetCwd`).
- `n.check(ctx, virtPath, op)` is unit-testable without a real FUSE mount and returns a `policy.Decision` with `.EffectiveDecision` (compare to `types.DecisionDeny`/`types.DecisionAllow`) and `.Rule` (string). Test model: `internal/fsmonitor/check_symlink_test.go` `TestCheck_SymlinkEscapeDenyRestoresBlanketDeny` (L176) and the existing helper `newCheckTestNodeWithEscape(t, workspace, pol, escapeDeny)` (L25), which builds a node but does **not** set `hooks.Session`.
- `&session.Session{Cwd: cwd}` is a valid composite literal from package `fsmonitor` (only the exported `Cwd` field is set; the unexported `mu` is zero-value usable).
- `internal/fsmonitor` tests are `package fsmonitor`; they import `context`, `os`, `path/filepath`, `testing`, `internal/policy`, `pkg/types`. The new Session-aware helper additionally needs `internal/session`.

---

## File Structure

- `internal/session/manager.go` — add `cwdEscapeWarnOnce sync.Once` field + `GetCwd()` and `FirstCwdEscapeWarn()` accessors (the session-side change).
- `internal/session/manager_cwd_test.go` (new) — unit tests for the two accessors.
- `internal/fsmonitor/fuse.go` — the cwd-subtree gate in `checkWithExist`'s escape branch + two new imports (`log/slog`, `internal/pathutil`).
- `internal/fsmonitor/check_symlink_test.go` — add a Session-aware node helper + four deny-mode regression tests.

---

## Task 1: Session accessors (`GetCwd`, `FirstCwdEscapeWarn`)

**Files:**
- Create: `internal/session/manager_cwd_test.go`
- Modify: `internal/session/manager.go` (struct field after L30; new methods near `GetCwdEnvHistory` at L954)

- [ ] **Step 1: Write the failing tests**

Create `internal/session/manager_cwd_test.go`:

```go
package session

import "testing"

// Issue #377 (part 2): the FUSE symlink-escape check needs a lightweight cwd
// accessor (no env/history copy) and a once-per-session diagnostic latch.

func TestGetCwd_ReturnsCurrentCwd(t *testing.T) {
	s := &Session{Cwd: "/workspace/proj"}
	if got := s.GetCwd(); got != "/workspace/proj" {
		t.Errorf("GetCwd() = %q, want %q", got, "/workspace/proj")
	}
}

func TestFirstCwdEscapeWarn_TrueExactlyOnce(t *testing.T) {
	s := &Session{}
	if !s.FirstCwdEscapeWarn() {
		t.Fatal("first FirstCwdEscapeWarn() = false, want true")
	}
	for i := 0; i < 3; i++ {
		if s.FirstCwdEscapeWarn() {
			t.Fatalf("FirstCwdEscapeWarn() returned true on subsequent call %d, want false", i+2)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/session/ -run 'TestGetCwd_ReturnsCurrentCwd|TestFirstCwdEscapeWarn_TrueExactlyOnce' -v`
Expected: FAIL — compile error `s.GetCwd undefined` / `s.FirstCwdEscapeWarn undefined` (methods don't exist yet).

- [ ] **Step 3: Add the struct field**

In `internal/session/manager.go`, add a field to the `Session` struct immediately after `mu sync.Mutex` (L30):

```go
	mu                sync.Mutex
	cwdEscapeWarnOnce sync.Once // #377: latches the one-time symlink-cwd-escape diagnostic
```

- [ ] **Step 4: Add the two accessors**

In `internal/session/manager.go`, immediately above `func (s *Session) GetCwdEnvHistory()` (L954), insert:

```go
// GetCwd returns the session's current virtual working directory. It is a
// lightweight accessor (no env/history copy) for hot-path callers such as the
// FUSE symlink-escape check (#377).
func (s *Session) GetCwd() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Cwd
}

// FirstCwdEscapeWarn reports true exactly once per session. The FUSE layer uses
// it to emit a single diagnostic when the process cwd is a symlink whose target
// escapes the workspace mount under symlink_escape="deny" (#377), so the
// otherwise-opaque "everything denied" failure is self-describing.
func (s *Session) FirstCwdEscapeWarn() bool {
	first := false
	s.cwdEscapeWarnOnce.Do(func() { first = true })
	return first
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/session/ -run 'TestGetCwd_ReturnsCurrentCwd|TestFirstCwdEscapeWarn_TrueExactlyOnce' -v`
Expected: PASS (both).

- [ ] **Step 6: Run the full session package (no regressions)**

Run: `go test ./internal/session/`
Expected: ok.

- [ ] **Step 7: Commit**

```bash
git add internal/session/manager.go internal/session/manager_cwd_test.go
git commit -m "feat(#377): add Session.GetCwd + FirstCwdEscapeWarn accessors

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: cwd-subtree gate in `checkWithExist`

**Files:**
- Modify: `internal/fsmonitor/check_symlink_test.go` (add helper + 4 tests)
- Modify: `internal/fsmonitor/fuse.go` (escape branch L501-515; imports)

- [ ] **Step 1: Add the Session-aware test helper**

In `internal/fsmonitor/check_symlink_test.go`, add the `internal/session` import to the import block, then add this helper directly below `newCheckTestNodeWithEscape` (after L40):

```go
// newCheckTestNodeWithEscapeCwd is newCheckTestNodeWithEscape plus a session
// whose Cwd is set, so deny-mode cwd-subtree behavior (#377) is testable.
func newCheckTestNodeWithEscapeCwd(t *testing.T, workspace string, pol *policy.Policy, escapeDeny bool, cwd string) *node {
	t.Helper()
	n := newCheckTestNodeWithEscape(t, workspace, pol, escapeDeny)
	n.hooks.Session = &session.Session{Cwd: cwd}
	return n
}
```

- [ ] **Step 2: Write the four failing tests**

In `internal/fsmonitor/check_symlink_test.go`, append:

```go
// Issue #377 (part 2): in symlink_escape="deny" mode, a symlink whose target
// escapes the mount but resolves THROUGH the process cwd subtree must be
// evaluated against file_rules (like evaluate mode), not blanket-denied as
// workspace-escape. Escapes outside the cwd subtree, ".."-escapes, and broken
// links stay workspace-escape denies.

func TestCheck_DenyCwdSubtreeEscapeIsEvaluatedAndAllowed(t *testing.T) {
	workspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "system-binary")
	if err := os.WriteFile(outsideTarget, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideTarget, filepath.Join(workspace, "venv", "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-outside",
		FileRules: []policy.FileRule{
			{Name: "allow-outside", Paths: []string{realRoot(t, outsideDir) + "/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	// cwd is the venv subtree; the escaping symlink is under it.
	n := newCheckTestNodeWithEscapeCwd(t, workspace, pol, true, "/workspace/venv")
	dec := n.check(context.Background(), "/workspace/venv/bin/python", "read")
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("deny mode + cwd-subtree escape must evaluate file_rules; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule == "workspace-escape" {
		t.Errorf("rule=%q; want a file_rule (not blanket workspace-escape)", dec.Rule)
	}
}

func TestCheck_DenyCwdSubtreeEscapeIsEvaluatedAndDeniedByFileRule(t *testing.T) {
	workspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "system-binary")
	if err := os.WriteFile(outsideTarget, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideTarget, filepath.Join(workspace, "venv", "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	pol := &policy.Policy{
		Version: 1,
		Name:    "deny-outside",
		FileRules: []policy.FileRule{
			{Name: "deny-outside", Paths: []string{realRoot(t, outsideDir) + "/**"}, Operations: []string{"*"}, Decision: "deny"},
		},
	}
	n := newCheckTestNodeWithEscapeCwd(t, workspace, pol, true, "/workspace/venv")
	dec := n.check(context.Background(), "/workspace/venv/bin/python", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("file_rule deny must deny; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule != "deny-outside" {
		t.Errorf("rule=%q; want deny-outside (evaluated, not blanket workspace-escape)", dec.Rule)
	}
}

func TestCheck_DenyEscapeOutsideCwdSubtreeStillBlanketDenies(t *testing.T) {
	workspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "system-binary")
	if err := os.WriteFile(outsideTarget, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideTarget, filepath.Join(workspace, "venv", "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-outside",
		FileRules: []policy.FileRule{
			{Name: "allow-outside", Paths: []string{realRoot(t, outsideDir) + "/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	// cwd is a DIFFERENT subtree; the escaping symlink is NOT under it.
	n := newCheckTestNodeWithEscapeCwd(t, workspace, pol, true, "/workspace/proj")
	dec := n.check(context.Background(), "/workspace/venv/bin/python", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("escape outside cwd subtree must deny; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule != "workspace-escape" {
		t.Errorf("rule=%q; want workspace-escape (deny mode, outside cwd subtree)", dec.Rule)
	}
}

func TestCheck_DenyDotDotEscapeUnderCwdStillBlanketDenies(t *testing.T) {
	workspace := t.TempDir()
	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	// cwd is the whole workspace, so the path is "in the cwd subtree", forcing
	// the cwd-subtree branch; a ".."-escape must STILL deny because
	// evalEscapedSymlink returns "" for it.
	n := newCheckTestNodeWithEscapeCwd(t, workspace, pol, true, "/workspace")
	dec := n.check(context.Background(), "/workspace/../etc/hostname", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("..-escape under cwd must deny; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule != "workspace-escape" {
		t.Errorf("rule=%q; want workspace-escape (..-escape always denies)", dec.Rule)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/fsmonitor/ -run 'TestCheck_DenyCwdSubtree|TestCheck_DenyEscapeOutsideCwdSubtreeStillBlanketDenies|TestCheck_DenyDotDotEscapeUnderCwdStillBlanketDenies' -v`
Expected: FAIL — the two `DenyCwdSubtree*` tests fail (today deny mode blanket-denies, so the allow test gets `workspace-escape` and the file-rule-deny test gets rule `workspace-escape` not `deny-outside`). The `OutsideCwdSubtree` and `DotDotEscapeUnderCwd` tests already pass (deny mode already blanket-denies both) — that's fine; they guard against the new code over-reaching.

- [ ] **Step 4: Add the imports to `fuse.go`**

In `internal/fsmonitor/fuse.go`, add to the import block (L5-19): `"log/slog"` in the stdlib group and `"github.com/agentsh/agentsh/internal/pathutil"` in the agentsh group:

```go
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/pathutil"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
```

- [ ] **Step 5: Replace the escape-branch gate**

In `internal/fsmonitor/fuse.go` `checkWithExist`, replace the gate block (currently L501-505):

```go
			escapeDeny := n.hooks != nil && n.hooks.SymlinkEscapeDeny
			var escaped string
			if !escapeDeny {
				escaped = evalEscapedSymlink(realRoot, virtPath, n.vroot())
			}
```

with:

```go
			// In symlink_escape="deny" mode we normally blanket-deny any symlink
			// whose target escapes the workspace mount. But when the process cwd is
			// itself such a symlink (common in Daytona/devcontainer layouts where
			// /workspace is a symlink), that blanket deny rejects EVERY command run
			// from the cwd. Treat the cwd and its subtree like evaluate mode:
			// resolve the escaped target and let file_rules decide. Escapes OUTSIDE
			// the cwd subtree stay blanket-denied, so deny mode's core protection is
			// preserved. (#377)
			escapeDeny := n.hooks != nil && n.hooks.SymlinkEscapeDeny
			inCwdSubtree := false
			if escapeDeny && n.hooks.Session != nil {
				if cwd := n.hooks.Session.GetCwd(); pathutil.IsUnderRoot(virtPath, cwd) {
					inCwdSubtree = true
					if n.hooks.Session.FirstCwdEscapeWarn() {
						slog.Warn("symlink_escape=deny: process cwd is a symlink escaping the workspace mount; evaluating its subtree against file_rules instead of blanket-denying",
							"session", n.hooks.SessionID, "cwd", cwd)
					}
				}
			}
			var escaped string
			if !escapeDeny || inCwdSubtree {
				escaped = evalEscapedSymlink(realRoot, virtPath, n.vroot())
			}
```

(The `if escaped != "" { ... } else { ...workspace-escape... }` block below is unchanged.)

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/fsmonitor/ -run 'TestCheck_DenyCwdSubtree|TestCheck_DenyEscapeOutsideCwdSubtreeStillBlanketDenies|TestCheck_DenyDotDotEscapeUnderCwdStillBlanketDenies' -v`
Expected: PASS (all four).

- [ ] **Step 7: Run the full fsmonitor package (no regressions)**

Run: `go test ./internal/fsmonitor/`
Expected: ok — in particular the existing `TestCheck_SymlinkEscapeDenyRestoresBlanketDeny` (no session set → `n.hooks.Session == nil` → `inCwdSubtree` stays false → unchanged blanket deny) and the `evaluate`-mode tests still pass.

- [ ] **Step 8: Commit**

```bash
git add internal/fsmonitor/fuse.go internal/fsmonitor/check_symlink_test.go
git commit -m "fix(#377): evaluate cwd-subtree symlink escapes in deny mode

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build + Windows cross-compile**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: both succeed (no output). (`pathutil.IsUnderRoot` and `log/slog` are cross-platform.)

- [ ] **Step 2: Vet + gofmt**

Run: `go vet ./internal/session/ ./internal/fsmonitor/ && gofmt -l internal/session/manager.go internal/session/manager_cwd_test.go internal/fsmonitor/fuse.go internal/fsmonitor/check_symlink_test.go`
Expected: vet clean; `gofmt -l` prints nothing.

- [ ] **Step 3: Affected package tests**

Run: `go test ./internal/session/ ./internal/fsmonitor/ ./internal/policy/`
Expected: ok for all three.

- [ ] **Step 4: Commit any formatting fixes (only if Step 2 changed files)**

```bash
git add -A && git commit -m "chore(#377): gofmt" || echo "nothing to commit"
```

---

## Self-review notes

- **Spec coverage:** Session accessors (Task 1) ← spec §Design.1; cwd-subtree gate + diagnostic (Task 2 Steps 4-5) ← spec §Design.2; the four deny-mode tests (Task 2 Step 2) ← spec §Testing cases 1-4; accessor tests (Task 1 Step 1) ← spec §Testing case 6; evaluate-mode-unchanged (spec §Testing case 5) is covered by Task 2 Step 7 running the existing suite. Non-goals respected: no `evaluate`-mode code touched, no `resolveWorkingDir` change, `..`/broken-link denies preserved (Task 2 test 4).
- **Type consistency:** `GetCwd() string`, `FirstCwdEscapeWarn() bool`, `cwdEscapeWarnOnce sync.Once`, `pathutil.IsUnderRoot(virtPath, cwd)`, `n.hooks.Session`, `n.hooks.SessionID`, `evalEscapedSymlink(realRoot, virtPath, n.vroot())`, `policy.Decision{...}`, `types.DecisionAllow/DecisionDeny`, helper `newCheckTestNodeWithEscapeCwd(t, workspace, pol, escapeDeny, cwd)` are consistent across all tasks and match the verified facts.
- **No placeholders:** every code/command step is concrete with expected output.
