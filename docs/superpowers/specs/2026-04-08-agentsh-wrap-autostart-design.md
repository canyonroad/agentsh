# `agentsh wrap` Server Auto-Start — Design Spec

**Date:** 2026-04-08
**Status:** Draft
**Problem:** `agentsh wrap` requires the user to have already started the agentsh server (`agentsh server` or a systemd/launchd unit). If the server is down, `wrap` fails immediately on its first network call. `agentsh exec` and `agentsh exec --pty` already auto-start the local server in this situation; `wrap` should match.

## Background

`agentsh exec` (`internal/cli/exec.go:147–154` and `:225–229`) and `agentsh exec --pty` (`internal/cli/exec_pty.go:139–142`) already implement lazy auto-start. The pattern:

1. Try the server call.
2. If `err != nil && !autoDisabled() && isConnectionError(err)`, call `ensureServerRunning(ctx, cfg.serverAddr, log)` (`internal/cli/auto.go:80`).
3. If auto-start succeeds, retry the original call. If auto-start fails, wrap as `"server unreachable (%v); auto-start failed: %w"`.

`ensureServerRunning` is gated by `shouldAutoStartServer` (`internal/cli/auto.go:34`) — only loopback hosts on the default port (`18080`) are eligible — and by `AGENTSH_NO_AUTO` via `autoDisabled` (`internal/cli/auto.go:21`). When eligible, it forks `os.Args[0] server --config <path>` with stdio detached and stderr captured to a temp file, then polls `/health` for up to 5 seconds before returning. The forked server detaches via `cmd.Process.Release()` and persists for the rest of the session.

The same machinery should be wired into `runWrap`. No new helpers, no behavioral changes to `ensureServerRunning` itself.

## Approach

Mirror the `exec.go` auto-start pattern (`internal/cli/exec.go:147–154`, `:225–229`) inside `runWrap` (`internal/cli/wrap.go:71`). `runWrap` makes its first network call at one of two sites depending on whether `--session` was provided:

- `c.GetSession(ctx, opts.sessionID)` at line 96 (reuse path)
- `c.CreateSessionWithRequest(ctx, ...)` at line 104 (create path)

Both call sites are folded into one unexported helper, `fetchSessionForWrap`, so the auto-start-and-retry block is written once and the helper can be unit-tested in isolation without exercising the rest of `runWrap` (which continues into `exec.LookPath`, `setupWrapInterception`, child process launch, etc., and is not unit-testable). `runWrap` becomes a one-line caller of `fetchSessionForWrap`.

Extracting a shared helper across `exec.go`, `exec_pty.go`, and `wrap.go` (so all three CLI commands share one auto-start wrapper) is explicitly out of scope and noted as a follow-up. The helper added here lives in `wrap.go` and is wrap-specific.

To make `fetchSessionForWrap` testable without spawning a real `agentsh server` subprocess, one narrow seam is added: an overridable package-level var `ensureServerRunningFn` in `wrap.go` that defaults to the real `ensureServerRunning`. Tests swap it with a stub.

## Detailed Design

### 1. Test Seam in `wrap.go`

Add one package-level var near the top of `internal/cli/wrap.go`, immediately after the imports:

```go
// Overridable for tests. Production wiring uses ensureServerRunning.
var ensureServerRunningFn = ensureServerRunning
```

It has the same signature as `ensureServerRunning`, so the swap is trivial. `fetchSessionForWrap` calls `ensureServerRunningFn` instead of the symbol directly.

### 2. Auto-Start Wiring in `runWrap`

**File:** `internal/cli/wrap.go`, function `runWrap`.

**2a. Client construction (line 73).** Unchanged. `runWrap` continues to call `client.NewForCLI` directly. The test bypasses this by calling `fetchSessionForWrap` directly with a mock `client.CLIClient`.

**2b. New helper `fetchSessionForWrap`.** Encapsulates the entire if/else session-fetch block (current lines 92–116 of `wrap.go`) and the auto-start-and-retry pattern. Returns the resolved session, plus the session ID / mount / proxy URL fields that `runWrap` currently extracts.

```go
// fetchSessionForWrap resolves the session for runWrap, either by reusing
// opts.sessionID or by creating a new session. If the first server call fails
// with a connection error and auto-start is enabled, it forks the local
// agentsh server via ensureServerRunningFn and retries once.
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

**2c. `runWrap` becomes a one-line caller.** The current if/else block at lines 92–116 collapses to:

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

Everything after this in `runWrap` (FUSE mount handling at line 118 onward, `exec.LookPath`, `setupWrapInterception`, child launch, signal forwarding, ptrace handshake, wait, report) is unchanged.

**Logging destination.** `os.Stderr`. This matches `exec_pty.go:140` and the existing `runWrap` style — `runWrap` is a free function and writes status messages to `os.Stderr` throughout. (`exec.go` uses `cmd.ErrOrStderr()` because its retry sits inside the cobra `RunE` closure with direct access to `cmd`; threading `cmd` into `runWrap` just for this would be a needless refactor.)

### 3. Behavior Matrix

| Scenario | Result |
|---|---|
| `127.0.0.1:18080` + server already up | First call succeeds. Zero overhead. |
| `127.0.0.1:18080` + server down | First call returns conn-refused → `ensureServerRunningFn` forks `agentsh server --config <path>`, polls `/health` (5s deadline) → retry succeeds. One auto-start log line on stderr. |
| `127.0.0.1:18080` + server down + `AGENTSH_NO_AUTO=1` | `autoDisabled()` short-circuits the retry. Original conn-refused error bubbles up via the existing `fmt.Errorf("get session %s: %w", ...)` / `fmt.Errorf("create session: %w", ...)` wrap. |
| Remote host or non-default port + server down | `shouldAutoStartServer` returns false → `ensureServerRunningFn` returns `"server not reachable at %s"` → `runWrap` returns `"server unreachable (...); auto-start failed: server not reachable at ..."`. Same UX as `exec` today. |
| Remote host + server up | First call succeeds. Auto-start path never entered. |

The matrix is identical to what `agentsh exec` produces today, by construction.

### 4. Test

**File:** `internal/cli/wrap_test.go`.

The unit under test is `fetchSessionForWrap`. Testing it directly avoids the rest of `runWrap` (which is not unit-testable: it calls `exec.LookPath`, sets up seccomp/ES interception, launches a child process, runs a ptrace handshake on Linux, and waits for the child).

**Test mock extensions.** Extend the existing `mockWrapClient` in `wrap_test.go` so its `GetSession` and `CreateSessionWithRequest` methods consult per-test stub functions. The current static returns are kept as defaults so the existing tests in this file are not disturbed.

```go
type mockWrapClient struct {
    // ... existing fields ...
    getSessionFn    func(ctx context.Context, id string) (types.Session, error)
    createSessionFn func(ctx context.Context, req types.CreateSessionRequest) (types.Session, error)
}

func (m *mockWrapClient) GetSession(ctx context.Context, id string) (types.Session, error) {
    m.getSessionCalled = true
    if m.getSessionFn != nil {
        return m.getSessionFn(ctx, id)
    }
    return types.Session{ID: id}, nil
}

func (m *mockWrapClient) CreateSessionWithRequest(ctx context.Context, req types.CreateSessionRequest) (types.Session, error) {
    if m.createSessionFn != nil {
        return m.createSessionFn(ctx, req)
    }
    return types.Session{}, nil
}
```

**The retry test.**

```go
func TestFetchSessionForWrap_AutoStartsServerOnConnRefused(t *testing.T) {
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

This test exercises:
- The conn-error gate (`isConnectionError(syscall.ECONNREFUSED)` is true).
- The auto-start hook (`ensureServerRunningFn` is called with `cfg.serverAddr`).
- The retry path (second `GetSession` call returns success).
- The reuse-session branch (`opts.sessionID != ""` → `GetSession`, not `CreateSessionWithRequest`).

The create-session branch is symmetric to the reuse-session branch — both go through the same `fetch` closure inside `fetchSessionForWrap`. A second test for the create branch is optional and not required by the user's ask. If added later, it would mirror this test with `getSessionFn → createSessionFn` and `opts.sessionID = ""`.

### 5. Files Changed

| File | Change |
|---|---|
| `internal/cli/wrap.go` | Add `ensureServerRunningFn` package var. Add `fetchSessionForWrap` helper containing the auto-start-and-retry logic. Replace the existing if/else session-fetch block in `runWrap` with a one-line call to the helper. |
| `internal/cli/wrap_test.go` | Extend `mockWrapClient` with `getSessionFn`/`createSessionFn` stub fields. Add `TestFetchSessionForWrap_AutoStartsServerOnConnRefused`. |

No other files are touched. No new exports. No new dependencies.

### 6. What This Does NOT Change

- `ensureServerRunning`, `shouldAutoStartServer`, `autoDisabled`, `isConnectionError` — existing helpers, used as-is.
- `exec.go` and `exec_pty.go` — their existing auto-start blocks are not refactored. The duplication grows from two sites to three; extracting a shared helper is a separate follow-up.
- `setupWrapInterception` and the post-session-fetch flow (`exec.LookPath`, child launch, signal forwarding, ptrace handshake, FUSE mount handling, LLM proxy env) — unchanged.
- The systemd/launchd `agentsh daemon install` path — unrelated, not touched.
- `client.NewForCLI` — call site in `runWrap` is unchanged.
- `AGENTSH_NO_AUTO` semantics — same gate as `exec` today.
- Remote-server behavior — same gate as `exec` today; no auto-start attempted, error message format unchanged.

### 7. Manual Smoke Test

```bash
# 1. Ensure no agentsh server is running.
pkill -f 'agentsh server' || true
curl -s http://127.0.0.1:18080/health  # should fail

# 2. Run wrap with a trivial agent.
./bin/agentsh wrap -- bash -c true

# Expected stderr (in order):
#   agentsh: auto-starting server (config <path>)
#   agentsh: session <id> created (policy: agent-default)
#   agentsh: agent bash started ...
#   agentsh: session <id> complete (agent exit code: 0)

# 3. Run again — server should already be up, no auto-start log line.
./bin/agentsh wrap -- bash -c true

# 4. Disable auto-start and verify failure mode.
pkill -f 'agentsh server'
AGENTSH_NO_AUTO=1 ./bin/agentsh wrap -- bash -c true
# Expected: connection-refused error from the session create call, no auto-start attempted.
```
