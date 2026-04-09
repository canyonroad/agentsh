# `agentsh wrap` Server Auto-Start Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `agentsh wrap` auto-start the local agentsh server on connection-refused, matching what `agentsh exec` already does, so users no longer need to start the server manually.

**Architecture:** Extract the session-fetch portion of `runWrap` into a small unexported helper `fetchSessionForWrap` that wraps the existing if/else around `c.GetSession` / `c.CreateSessionWithRequest` with the same auto-start-and-retry block already used in `internal/cli/exec.go`. Add one package-level seam (`ensureServerRunningFn`) so the retry path can be unit-tested without forking a real `agentsh server` subprocess. `runWrap` collapses to a one-line caller of the helper.

**Tech Stack:** Go 1.x, cobra (CLI), testify (`require`/`assert`), existing `internal/cli/auto.go` helpers (`autoDisabled`, `isConnectionError`, `ensureServerRunning`), existing `mockWrapClient` test double.

**Spec:** `docs/superpowers/specs/2026-04-08-agentsh-wrap-autostart-design.md`

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `internal/cli/wrap.go` | Modify | Add `ensureServerRunningFn` package var. Add `fetchSessionForWrap` helper. Replace the if/else session-fetch block in `runWrap` (current lines 92–116) with a one-line call to the helper. |
| `internal/cli/wrap_test.go` | Modify | Extend `mockWrapClient` with two stub function fields (`getSessionFn`, `createSessionFn`). Add one new test (`TestFetchSessionForWrap_AutoStartsServerOnConnRefused`). |

No other files are touched. No new exports. No new dependencies.

---

## Background for the Implementer

You are implementing one focused change to a Go CLI command. Read these first so the rest of the plan makes sense:

1. **`agentsh wrap`** is a subcommand that launches an "AI agent" (like `claude-code` or `codex`) as a child process with all its `exec` syscalls intercepted via seccomp / Endpoint Security / a Windows driver. The intercepted commands are routed through an `agentsh server` for policy checks, approvals, and audit logging. The full implementation is in `internal/cli/wrap.go`.

2. **The `agentsh server`** is a separate process — typically the same `agentsh` binary invoked as `agentsh server --config <path>`. It listens on `http://127.0.0.1:18080` by default. `wrap` (and `exec`) talk to it via an HTTP/gRPC client (`internal/client/cli_client.go`).

3. **Auto-start already exists for `exec`.** Look at `internal/cli/auto.go` (~170 lines) — the helpers `autoDisabled`, `isConnectionError`, `shouldAutoStartServer`, `ensureServerRunning`, `waitForHealth` are all there. `agentsh exec` and `agentsh exec --pty` already use them (`exec.go:147–154`, `exec.go:225–229`, `exec_pty.go:139–142`). `wrap.go` does not. This plan adds the same wiring to `wrap.go`.

4. **The pattern.** On the FIRST server call:
   - Try the call.
   - If `err != nil && !autoDisabled() && isConnectionError(err)`, call `ensureServerRunning(ctx, cfg.serverAddr, log)`.
   - If auto-start succeeds, retry the original call.
   - If auto-start fails, return `fmt.Errorf("server unreachable (%v); auto-start failed: %w", err, startErr)`.

5. **`ensureServerRunning`** is gated by `shouldAutoStartServer` — only loopback hosts on the default port (`18080`) are eligible. Remote / non-default-port servers are not auto-started; `ensureServerRunning` returns `"server not reachable at %s"` for them. This is fine and inherited unchanged.

6. **`AGENTSH_NO_AUTO=1`** in the environment makes `autoDisabled()` return true, which short-circuits the retry. Inherited unchanged.

7. **The test seam.** `runWrap` itself is hard to unit-test end-to-end (it calls `exec.LookPath`, sets up seccomp/ES/driver interception, launches a child process, runs a ptrace handshake on Linux, and waits for the child). So we extract the auto-start-wrapped session fetch into `fetchSessionForWrap` and unit-test that helper directly. To avoid the test forking a real `agentsh server` subprocess, we add a package-level var `ensureServerRunningFn = ensureServerRunning` that the test swaps with a stub.

8. **The existing test file** `internal/cli/wrap_test.go` already has a `mockWrapClient` that implements `client.CLIClient` and is used by `TestSetupWrapInterception_*`. We extend it (without breaking those tests) by adding two optional stub function fields.

9. **Build & test commands** for this repo:
   - `go build ./...`
   - `go test ./...`
   - `GOOS=windows go build ./...` (cross-compile sanity check, required by `CLAUDE.md`)

10. **Commit style.** The repo uses Conventional Commits-ish prefixes (`feat:`, `fix:`, `docs:`, `refactor:`). Each task ends with a small focused commit. Co-author trailer per repo convention.

---

## Task 1: Extend `mockWrapClient` with stub function fields

This task adds plumbing to the test double so that future tests (Task 2) can inject per-call behavior. It does NOT add any new test cases yet — this commit is pure test-infrastructure plumbing and existing tests (`TestSetupWrapInterception_*`, `TestWrapCmd_*`) must still pass unchanged.

**Files:**
- Modify: `internal/cli/wrap_test.go:128-167` (the `mockWrapClient` struct and its `GetSession` / `CreateSessionWithRequest` methods)

- [ ] **Step 1.1: Open `internal/cli/wrap_test.go` and read the existing mock**

Read lines 128–217 to understand the existing `mockWrapClient` struct and method shapes. Confirm `GetSession` is at lines 161–164 and `CreateSessionWithRequest` is at lines 155–157. The existing implementations return static values (`types.Session{ID: id}` and `types.Session{}` respectively).

- [ ] **Step 1.2: Add two stub function fields to the struct**

In `internal/cli/wrap_test.go`, modify the `mockWrapClient` struct (currently at lines 128–136). Add two new fields at the bottom of the struct. The full struct after the change should look like:

```go
// mockWrapClient implements CLIClient for testing wrap interception setup.
type mockWrapClient struct {
	wrapInitCalled   bool
	wrapInitReq      types.WrapInitRequest
	wrapInitResp     types.WrapInitResponse
	wrapInitErr      error
	createSessCalled bool
	getSessionCalled bool
	getSessionFn     func(ctx context.Context, id string) (types.Session, error)
	createSessionFn  func(ctx context.Context, req types.CreateSessionRequest) (types.Session, error)
}
```

(The new fields are `getSessionFn` and `createSessionFn`. Leave existing fields untouched.)

- [ ] **Step 1.3: Update `GetSession` to consult the stub when set**

Replace the existing `GetSession` method (lines 161–164) with:

```go
func (m *mockWrapClient) GetSession(ctx context.Context, id string) (types.Session, error) {
	m.getSessionCalled = true
	if m.getSessionFn != nil {
		return m.getSessionFn(ctx, id)
	}
	return types.Session{ID: id}, nil
}
```

The default behavior (no stub set → return `types.Session{ID: id}`) is unchanged, so existing tests are unaffected.

- [ ] **Step 1.4: Update `CreateSessionWithRequest` to consult the stub when set**

Replace the existing `CreateSessionWithRequest` method (lines 155–157) with:

```go
func (m *mockWrapClient) CreateSessionWithRequest(ctx context.Context, req types.CreateSessionRequest) (types.Session, error) {
	m.createSessCalled = true
	if m.createSessionFn != nil {
		return m.createSessionFn(ctx, req)
	}
	return types.Session{}, nil
}
```

(I also added `m.createSessCalled = true` to mirror the pattern in `GetSession` and `CreateSession`. The field already exists on the struct.)

- [ ] **Step 1.5: Run existing tests in the cli package to verify nothing is broken**

Run:
```bash
go test ./internal/cli/...
```

Expected: PASS. All existing tests (`TestWrapCmd_*`, `TestSetupWrapInterception_*`, `TestAutoDisabled_*`, `TestShouldAutoStartServer_*`, etc.) should still pass. If any fail, stop and investigate — the change in this task is purely additive and should not break anything.

- [ ] **Step 1.6: Verify cross-compile**

Run:
```bash
GOOS=windows go build ./...
```

Expected: success, no output. Required by `CLAUDE.md` before committing any change in this repo.

- [ ] **Step 1.7: Commit**

```bash
git add internal/cli/wrap_test.go
git commit -m "$(cat <<'EOF'
test(cli/wrap): add stub function fields to mockWrapClient

Adds optional getSessionFn and createSessionFn fields so individual
tests can inject per-call behavior for the session-fetch path.
Default behavior (when stubs are nil) is unchanged so existing
TestSetupWrapInterception_* tests still pass.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Write the failing test for `fetchSessionForWrap`

Strict TDD: this test references symbols (`fetchSessionForWrap` and `ensureServerRunningFn`) that do not exist yet, so the package will fail to compile. That is the expected failure for this step. We do not implement either symbol until Task 3.

**Files:**
- Modify: `internal/cli/wrap_test.go` (add a new test function at the bottom of the file)

- [ ] **Step 2.1: Add the test function at the end of `internal/cli/wrap_test.go`**

Append the following to the end of the file. Make sure `syscall` and `context` are in the import block (you may need to add `syscall`).

```go
func TestFetchSessionForWrap_AutoStartsServerOnConnRefused(t *testing.T) {
	// Mock client: first GetSession returns ECONNREFUSED, second succeeds.
	var calls int
	mc := &mockWrapClient{
		getSessionFn: func(ctx context.Context, id string) (types.Session, error) {
			calls++
			if calls == 1 {
				return types.Session{}, syscall.ECONNREFUSED
			}
			return types.Session{ID: id}, nil
		},
	}

	// Stub the auto-start hook so no real subprocess is forked.
	var autoStartCalls int
	var autoStartAddr string

	origEnsureFn := ensureServerRunningFn
	t.Cleanup(func() { ensureServerRunningFn = origEnsureFn })
	ensureServerRunningFn = func(ctx context.Context, addr string, log io.Writer) error {
		autoStartCalls++
		autoStartAddr = addr
		return nil
	}

	cfg := &clientConfig{serverAddr: "http://127.0.0.1:18080"}
	opts := wrapOptions{sessionID: "existing-sess"}

	sess, err := fetchSessionForWrap(context.Background(), mc, cfg, opts, "/tmp/work")

	require.NoError(t, err)
	assert.Equal(t, "existing-sess", sess.ID)
	assert.Equal(t, 2, calls, "GetSession should be retried after auto-start")
	assert.Equal(t, 1, autoStartCalls, "ensureServerRunningFn should be called exactly once")
	assert.Equal(t, "http://127.0.0.1:18080", autoStartAddr)
}
```

- [ ] **Step 2.2: Add `syscall` to the import block if missing**

Check the import block at the top of `internal/cli/wrap_test.go` (lines 3–15). If `"syscall"` is not present, add it. The block should look like (alphabetical order — testify comes after stdlib):

```go
import (
	"bytes"
	"context"
	"io"
	"net/url"
	"runtime"
	"syscall"
	"testing"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)
```

(`io`, `context`, `assert`, `require` should already be there from existing tests. `syscall` is the only addition.)

- [ ] **Step 2.3: Run the test to verify it fails to compile**

Run:
```bash
go test ./internal/cli/ -run TestFetchSessionForWrap_AutoStartsServerOnConnRefused
```

Expected: FAIL with a compile error mentioning `undefined: fetchSessionForWrap` and `undefined: ensureServerRunningFn`. Both symbols will be defined in Task 3.

If the failure is anything other than these two undefined-symbol errors (e.g., a typo, wrong import, etc.), fix the test before moving on.

- [ ] **Step 2.4: Do NOT commit yet**

Task 2 leaves the package in a broken-build state on purpose. Task 3 makes it green and the combined commit lands together. Move directly to Task 3 without committing.

---

## Task 3: Add `ensureServerRunningFn` seam and implement `fetchSessionForWrap`

This task makes the test from Task 2 pass. It adds the package-level seam var and the helper function. It does NOT yet wire the helper into `runWrap` — `runWrap` continues to use its existing if/else session-fetch block. That swap is Task 4. Keeping these two tasks separate means Task 3 introduces the new helper and proves it works (test passes), and Task 4 is a pure refactor at the call site.

**Files:**
- Modify: `internal/cli/wrap.go` (add seam var; add helper function)

- [ ] **Step 3.1: Open `internal/cli/wrap.go` and locate the import block**

The current imports are at lines 3–16. They include `context`, `fmt`, `io`, `os`, `os/exec`, `os/signal`, `runtime`, `syscall`, plus internal packages `client` and `types`. No new imports are needed for this task — `os.Stderr`, `context`, `fmt`, the `client` and `types` packages, and the existing helpers from `internal/cli/auto.go` are all already in scope (same package).

- [ ] **Step 3.2: Add the seam var immediately after the import block**

Insert this block at line 17 (the blank line right after the closing `)` of the import block, before `func newWrapCmd()`):

```go
// ensureServerRunningFn is the auto-start hook used by fetchSessionForWrap.
// Defaults to the real ensureServerRunning helper from auto.go; tests
// override it to avoid forking a real agentsh server subprocess.
var ensureServerRunningFn = ensureServerRunning
```

- [ ] **Step 3.3: Add the `fetchSessionForWrap` helper at the end of the file**

Append the following helper after the existing `setupWrapInterception` function (current end of file is around line 325 — append after the closing brace of `setupWrapInterception`):

```go
// fetchSessionForWrap resolves the session for runWrap, either by reusing
// opts.sessionID (GetSession) or by creating a new session
// (CreateSessionWithRequest). If the first server call fails with a
// connection error and auto-start is enabled, it forks the local agentsh
// server via ensureServerRunningFn and retries once. The behaviour mirrors
// the auto-start blocks already present in exec.go and exec_pty.go.
func fetchSessionForWrap(
	ctx context.Context,
	c client.CLIClient,
	cfg *clientConfig,
	opts wrapOptions,
	workspace string,
) (types.Session, error) {
	fetch := func() (types.Session, error) {
		if opts.sessionID != "" {
			return c.GetSession(ctx, opts.sessionID)
		}
		return c.CreateSessionWithRequest(ctx, types.CreateSessionRequest{
			Workspace: workspace,
			Policy:    opts.policy,
			Home:      userHomeDir(),
		})
	}

	sess, err := fetch()
	if err != nil && !autoDisabled() && isConnectionError(err) {
		if startErr := ensureServerRunningFn(ctx, cfg.serverAddr, os.Stderr); startErr == nil {
			sess, err = fetch()
		} else {
			return types.Session{}, fmt.Errorf("server unreachable (%v); auto-start failed: %w", err, startErr)
		}
	}
	if err != nil {
		if opts.sessionID != "" {
			return types.Session{}, fmt.Errorf("get session %s: %w", opts.sessionID, err)
		}
		return types.Session{}, fmt.Errorf("create session: %w", err)
	}
	return sess, nil
}
```

A few things to confirm while you're writing this:
- `autoDisabled` and `isConnectionError` come from `internal/cli/auto.go` — same package, no import needed.
- `ensureServerRunningFn` is the var you just added in Step 3.2 — same file.
- `userHomeDir` comes from `internal/cli/root.go:98` — same package.
- `client.CLIClient`, `client.CLIOptions`, `types.Session`, `types.CreateSessionRequest` are already imported at the top of `wrap.go`.
- `clientConfig`, `wrapOptions` are defined in the same package (`internal/cli/root.go:58`, `internal/cli/wrap.go:62`).

- [ ] **Step 3.4: Run the new test to verify it now passes**

Run:
```bash
go test ./internal/cli/ -run TestFetchSessionForWrap_AutoStartsServerOnConnRefused -v
```

Expected: PASS.

If it fails, the most likely causes are:
- Typo in the helper signature (compile error).
- Forgot the `m.createSessCalled = true` in Task 1 Step 1.4 (not actually a problem for THIS test, since the test uses `getSessionFn`, but worth a sanity check).
- The `fetch` closure returning the wrong branch — verify `opts.sessionID` is `"existing-sess"` (so `GetSession` is called, not `CreateSessionWithRequest`).

- [ ] **Step 3.5: Run the full cli package test suite**

Run:
```bash
go test ./internal/cli/...
```

Expected: PASS for everything. The seam var and the new helper should be invisible to existing tests.

- [ ] **Step 3.6: Cross-compile sanity check**

Run:
```bash
GOOS=windows go build ./...
```

Expected: success. The helper is platform-independent, but `wrap.go` is built on all platforms (it has `runtime.GOOS` switches inside `runWrap`), so the new helper has to compile on Windows too.

- [ ] **Step 3.7: Commit Task 2 + Task 3 together**

```bash
git add internal/cli/wrap.go internal/cli/wrap_test.go
git commit -m "$(cat <<'EOF'
feat(cli/wrap): add fetchSessionForWrap with server auto-start

Introduces fetchSessionForWrap, an unexported helper that wraps the
session GetSession / CreateSessionWithRequest call sites with the same
auto-start-and-retry pattern already used by agentsh exec. On a
connection-refused error from the first server call, the helper invokes
ensureServerRunningFn (a new package-level seam defaulting to
ensureServerRunning) to fork a local agentsh server, then retries
the original call once.

The seam var lets the new unit test exercise the retry path without
forking a real subprocess. runWrap is not yet wired through the helper;
that swap follows in the next commit.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Wire `fetchSessionForWrap` into `runWrap`

This is a pure refactor at the call site. The behavior change (auto-start) was added in Task 3 but is dormant until the call site switches over. After this task, `agentsh wrap` actually auto-starts the server.

**Files:**
- Modify: `internal/cli/wrap.go:92-116` (the existing if/else session-fetch block inside `runWrap`)

- [ ] **Step 4.1: Re-read the existing block in `runWrap`**

Open `internal/cli/wrap.go` and read lines 92–116. The current block looks like:

```go
	var sessID string
	var workspaceMount string
	var llmProxyURL string
	if opts.sessionID != "" {
		sess, err := c.GetSession(ctx, opts.sessionID)
		if err != nil {
			return fmt.Errorf("get session %s: %w", opts.sessionID, err)
		}
		sessID = sess.ID
		workspaceMount = sess.WorkspaceMount
		llmProxyURL = sess.LLMProxyURL
	} else {
		sess, err := c.CreateSessionWithRequest(ctx, types.CreateSessionRequest{
			Workspace: workspace,
			Policy:    opts.policy,
			Home:      userHomeDir(),
		})
		if err != nil {
			return fmt.Errorf("create session: %w", err)
		}
		sessID = sess.ID
		workspaceMount = sess.WorkspaceMount
		llmProxyURL = sess.LLMProxyURL
		fmt.Fprintf(os.Stderr, "agentsh: session %s created (policy: %s)\n", sessID, opts.policy)
	}
```

The vars `sessID`, `workspaceMount`, `llmProxyURL` are used later in `runWrap` (lines 121, 122, 123, 175, 178, 277) for FUSE mount setup, the LLM proxy env vars, and the report. They MUST remain in scope after the block.

- [ ] **Step 4.2: Replace lines 92–116 with the helper call**

Replace the entire 25-line block with this 9-line block:

```go
	sess, err := fetchSessionForWrap(ctx, c, cfg, opts, workspace)
	if err != nil {
		return err
	}
	sessID := sess.ID
	workspaceMount := sess.WorkspaceMount
	llmProxyURL := sess.LLMProxyURL
	if opts.sessionID == "" {
		fmt.Fprintf(os.Stderr, "agentsh: session %s created (policy: %s)\n", sessID, opts.policy)
	}
```

Notes:
- The three vars switch from `var sessID string` (separate declaration) to `sessID := sess.ID` (declared and assigned together). Both forms are equivalent for downstream usage.
- The "session created" log line is preserved but moved to a single conditional after the helper call. It still only fires on the create path.
- `sess, err :=` reuses the function-scoped `err` declared at line 79 (from `c, err := client.NewForCLI(...)`). Go's `:=` reuses an existing var when at least one var on the LHS is new (`sess` here). This is reuse, not shadowing — `go vet` is happy. (If you accidentally trigger a shadow warning under `go vet -vettool=shadow`, the outer `err` is at function scope and you can leave it; the repo's default `go vet` does not enable shadow checking.)
- Line 117 of the modified file should be the `// If FUSE is active...` comment that currently sits at line 118. After your edit, the file is shorter by ~16 lines.

- [ ] **Step 4.3: Build the package to catch any compile errors**

Run:
```bash
go build ./internal/cli/...
```

Expected: success, no output. If it fails:
- "sessID declared but not used" / "workspaceMount declared but not used" / "llmProxyURL declared but not used" → unlikely (they ARE used later in the function), but if it appears, check that you didn't accidentally delete the downstream usage at lines ~121 (workspaceMount), ~169 (workspaceMount), ~175 (llmProxyURL), ~277 (sessID).
- "fetchSessionForWrap undefined" → Task 3 wasn't committed properly; re-run Task 3.
- Anything else → read the error carefully and fix locally before continuing.

- [ ] **Step 4.4: Run the full cli package test suite**

Run:
```bash
go test ./internal/cli/...
```

Expected: PASS. The new test from Task 2/3 still passes. The existing `TestWrapCmd_*` and `TestSetupWrapInterception_*` tests still pass. No test should reference the removed if/else structure.

- [ ] **Step 4.5: Run the entire test suite**

Run:
```bash
go test ./...
```

Expected: PASS. This catches any side effects in other packages — there shouldn't be any, but agentsh has many packages and a full run is required by `CLAUDE.md` before commit.

- [ ] **Step 4.6: Cross-compile sanity check**

Run:
```bash
GOOS=windows go build ./...
```

Expected: success. `wrap.go` is built on all platforms.

- [ ] **Step 4.7: Commit**

```bash
git add internal/cli/wrap.go
git commit -m "$(cat <<'EOF'
feat(cli/wrap): auto-start agentsh server when running wrap

runWrap now delegates session reuse / creation to fetchSessionForWrap,
which auto-starts a local agentsh server on connection-refused. Users
no longer need to start the server manually before running
'agentsh wrap -- <agent>' on a default loopback config.

Behaviour matches 'agentsh exec' today: only loopback hosts on the
default port (18080) are eligible for auto-start, AGENTSH_NO_AUTO=1
disables it, and remote-server connection errors surface with the same
"server unreachable; auto-start failed" wrap.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Manual smoke test

Confirm the change works end-to-end on a real binary. This is a manual checklist, not committed code.

**Files:**
- None (run-time verification only)

- [ ] **Step 5.1: Build the binary**

Run:
```bash
go build -o ./bin/agentsh ./cmd/agentsh
```

Expected: success, `./bin/agentsh` exists and is executable.

- [ ] **Step 5.2: Ensure no agentsh server is running**

Run:
```bash
pkill -f 'agentsh server' || true
curl -fsS http://127.0.0.1:18080/health || echo "server is down (expected)"
```

Expected: `pkill` exits 0 or 1 (1 = no process matched, both are fine). `curl` fails and prints `server is down (expected)`.

- [ ] **Step 5.3: Run wrap with a trivial agent and observe auto-start**

Run:
```bash
./bin/agentsh wrap -- bash -c 'echo hello from wrapped'
```

Expected stderr lines (in order, exact wording may vary slightly):
```
agentsh: auto-starting server (config <some path>)
agentsh: session <id> created (policy: agent-default)
agentsh: agent bash started with <mechanism> interception (pid: <n>)
agentsh: session <id> complete (agent exit code: 0)
```

Expected stdout:
```
hello from wrapped
```

If no `auto-starting server` line appears, something is wrong with the wiring — the helper isn't being called, or auto-start is gated off. Check the call site (Task 4 Step 4.2) and re-read `internal/cli/auto.go:34` (`shouldAutoStartServer`) to confirm `127.0.0.1:18080` is eligible.

- [ ] **Step 5.4: Run a second wrap and confirm no auto-start fires**

Run:
```bash
./bin/agentsh wrap -- bash -c 'echo second run'
```

Expected: no `auto-starting server` line on stderr. The server forked in Step 5.3 is still running (it was detached via `cmd.Process.Release()`), so the first call succeeds and the retry block is never entered. This is the "zero overhead when server is already up" row of the spec's behavior matrix.

- [ ] **Step 5.5: Verify `AGENTSH_NO_AUTO=1` disables auto-start**

Kill the running server and try again with auto-start disabled:
```bash
pkill -f 'agentsh server'
sleep 0.5
AGENTSH_NO_AUTO=1 ./bin/agentsh wrap -- bash -c 'echo this should fail' || echo "wrap exited with non-zero (expected)"
```

Expected: `wrap` fails with a connection-refused error wrapped as `create session: ... connection refused` (or similar). No `auto-starting server` line appears. The final line is `wrap exited with non-zero (expected)`.

- [ ] **Step 5.6: Restart server cleanly for the next user**

Run:
```bash
./bin/agentsh server --config configs/server-config.yaml &
disown
```

(Optional — only if you want to leave the system in a runnable state. The user may have their own way of running the server.)

- [ ] **Step 5.7: No commit**

Smoke test produces no code. Move on to Task 6.

---

## Task 6: Final verification and PR-readiness

**Files:**
- None (verification only)

- [ ] **Step 6.1: Full test suite**

Run:
```bash
go test ./...
```

Expected: PASS across the whole repo.

- [ ] **Step 6.2: Cross-compile to Windows**

Run:
```bash
GOOS=windows go build ./...
```

Expected: success. Required by `CLAUDE.md`.

- [ ] **Step 6.3: Check `go vet`**

Run:
```bash
go vet ./internal/cli/...
```

Expected: no output (clean). If anything appears (e.g., shadow warnings on `err`), address it before declaring done.

- [ ] **Step 6.4: Review your diff**

Run:
```bash
git log --oneline main..HEAD
git diff main..HEAD -- internal/cli/wrap.go internal/cli/wrap_test.go
```

Read the diff. Confirm:
- Three commits on the branch (Task 1, Task 3 [combined with 2], Task 4).
- `wrap.go` net change: +~50 lines (one var, one helper), -~16 lines (the inline if/else collapsed).
- `wrap_test.go` net change: +~30 lines (struct fields + new test).
- No unrelated changes (no formatting drift in untouched parts of the file, no other files modified).

- [ ] **Step 6.5: Done**

The branch is ready. If you're using subagent-driven-development, hand back to the parent for review. If you're working solo, push and open a PR per the repo's normal workflow.

---

## Summary of Changes

| Commit | Files | Net Lines | Purpose |
|---|---|---|---|
| 1 | `wrap_test.go` | +12 | Add stub fields to `mockWrapClient` |
| 2 (combined w/ 3) | `wrap.go`, `wrap_test.go` | +~80 | Add `ensureServerRunningFn` seam, `fetchSessionForWrap` helper, and the failing-then-passing unit test |
| 3 | `wrap.go` | -7 net | Wire `runWrap` to call the helper |

Total: ~3 commits, ~85 added lines, ~16 removed lines, 2 files touched.
