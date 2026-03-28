# Fix file_monitor Write Denials Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix two bugs causing the seccomp file_monitor to deny all writes in the `agentsh wrap` path (63/73 → 73/73).

**Architecture:** Two independent fixes: (1) add `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` in the wrapper before exec so the server can read tracee memory under Yama ptrace_scope=1, and (2) thread the session-specific policy engine (with expanded `${PROJECT_ROOT}`) through to the wrap path's notify handler.

**Tech Stack:** Go, Linux seccomp user-notify, prctl/Yama LSM, testcontainers (Docker integration tests)

---

### Task 1: Add PR_SET_PTRACER_ANY to wrapper

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go:142-153`

- [ ] **Step 1: Add the prctl call before exec**

After `unix.Close(sockFD)` at line 143 and before the `// Exec the real command` comment at line 145, add:

```go
	// Allow the server process to read our memory via ProcessVMReadv.
	// Under Yama ptrace_scope=1 (Ubuntu/Debian default), only ancestor
	// processes can use ProcessVMReadv. In the wrap path the server is NOT
	// our ancestor, so this prctl authorizes any process to read us.
	// Security: the child is already sandboxed via seccomp BPF.
	if err := unix.Prctl(unix.PR_SET_PTRACER, uintptr(unix.PR_SET_PTRACER_ANY), 0, 0, 0); err != nil {
		log.Printf("PR_SET_PTRACER_ANY: %v (ProcessVMReadv may fail under Yama)", err)
	}
```

Reference: `golang.org/x/sys/unix` provides both `Prctl`, `PR_SET_PTRACER`, and `PR_SET_PTRACER_ANY` constants.

- [ ] **Step 2: Verify it compiles**

Run: `go build ./cmd/agentsh-unixwrap/`
Expected: success, no errors

- [ ] **Step 3: Verify cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: success (wrapper is linux-only, build-tagged)

- [ ] **Step 4: Commit**

```bash
git add cmd/agentsh-unixwrap/main.go
git commit -m "fix: add PR_SET_PTRACER_ANY to wrapper for Yama ptrace_scope=1

Under Yama ptrace_scope=1 (Ubuntu/Debian default), the server cannot use
ProcessVMReadv on the sandboxed child in the wrap path because the server
is not an ancestor. This caused all file writes to be denied (EACCES)
before policy evaluation.

prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) authorizes any process to read
the child's memory. The child is already sandboxed via seccomp BPF, so
this is a minimal security relaxation."
```

---

### Task 2: Thread session policy engine to wrap path

**Files:**
- Modify: `internal/api/wrap.go:345` (pass session to startNotifyHandlerForWrap)
- Modify: `internal/api/wrap_linux.go:61` (accept session, use session policy)
- Modify: `internal/api/wrap_windows.go:38` (update stub signature)
- Modify: `internal/api/wrap_other.go:25` (update stub signature)

- [ ] **Step 1: Update `startNotifyHandlerForWrap` signature in wrap_linux.go**

At line 61, change the function signature to accept `s *session.Session`:

```go
func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session) {
```

At the top of the function body (after the emitter line 62), add the session policy resolution:

```go
	// Prefer session-specific policy engine (has expanded ${PROJECT_ROOT} etc.)
	// over app-level engine, matching the exec path pattern in core.go.
	sessionPolicy := a.policy
	if s != nil {
		if sp := s.PolicyEngine(); sp != nil {
			sessionPolicy = sp
		}
	}
```

Then replace the three uses of `a.policy` with `sessionPolicy`:
- Line 68: `createExecveHandler(a.cfg.Sandbox.Seccomp.Execve, sessionPolicy, a.approvals)`
- Line 109: `createFileHandler(a.cfg.Sandbox.Seccomp.FileMonitor, sessionPolicy, emitter, a.cfg.Landlock.Enabled)`
- Line 117: `unixmon.ServeNotifyWithExecve(ctx, notifyFD, sessionID, sessionPolicy, emitter, execveHandler, fileHandler)`

- [ ] **Step 2: Update stub in wrap_windows.go**

At line 38, update the signature to match:

```go
func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session) {
```

The function body stays empty (no-op on Windows).

- [ ] **Step 3: Update stub in wrap_other.go**

At line 25, update the signature to match:

```go
func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session) {
```

The function body stays a no-op comment.

- [ ] **Step 4: Update callsite in wrap.go**

At line 345, pass the session `s`:

```go
	startNotifyHandlerForWrap(ctx, notifyFD, sessionID, a, execveEnabled, wrapperPID, s)
```

Note: `acceptNotifyFD` already receives `s *session.Session` as a parameter (line 293).

- [ ] **Step 5: Verify it compiles on all platforms**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: success

- [ ] **Step 6: Run existing tests**

Run: `go test ./internal/api/...`
Expected: all pass (existing tests use nil sessions or test infrastructure that doesn't exercise this path directly)

- [ ] **Step 7: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_linux.go internal/api/wrap_windows.go internal/api/wrap_other.go
git commit -m "fix: use session-specific policy engine in wrap path

The wrap path was using a.policy (app-level engine, no variable expansion)
instead of the session-specific engine. Policy rules with \${PROJECT_ROOT}
were never expanded, so workspace write-allow rules never matched.

Thread the session through acceptNotifyFD → startNotifyHandlerForWrap and
prefer s.PolicyEngine() with fallback to a.policy, matching the exec path."
```

---

### Task 3: Integration test for write operations

**Files:**
- Modify: `internal/integration/file_monitor_test.go`

- [ ] **Step 1: Add write test cases to TestFileMonitor_ReadAllowed**

After the existing `write_denied_path` subtest (around line 160), add these subtests inside `TestFileMonitor_ReadAllowed`:

```go
	// Write to workspace: should succeed (allowed by allow-workspace rule)
	t.Run("write_workspace_file", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command:    "sh",
			Args:       []string{"-c", "echo test_content > /workspace/write_test.txt && cat /workspace/write_test.txt"},
			WorkingDir: "/workspace",
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout")
			}
			t.Fatalf("Exec write workspace: %v", err)
		}
		if result.Result.ExitCode != 0 {
			t.Errorf("write to /workspace should succeed: exit=%d stderr=%q",
				result.Result.ExitCode, result.Result.Stderr)
		} else {
			stdout := strings.TrimSpace(result.Result.Stdout)
			if stdout != "test_content" {
				t.Errorf("expected 'test_content', got %q", stdout)
			}
		}
	})

	// Write to /tmp: should succeed (allowed by allow-tmp rule)
	t.Run("write_tmp_file", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command:    "sh",
			Args:       []string{"-c", "echo tmp_content > /tmp/write_test.txt && cat /tmp/write_test.txt"},
			WorkingDir: "/workspace",
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout")
			}
			t.Fatalf("Exec write tmp: %v", err)
		}
		if result.Result.ExitCode != 0 {
			t.Errorf("write to /tmp should succeed: exit=%d stderr=%q",
				result.Result.ExitCode, result.Result.Stderr)
		} else {
			stdout := strings.TrimSpace(result.Result.Stdout)
			if stdout != "tmp_content" {
				t.Errorf("expected 'tmp_content', got %q", stdout)
			}
		}
	})
```

- [ ] **Step 2: Verify test compiles**

Run: `go test -c -tags integration ./internal/integration/`
Expected: compiles without errors

- [ ] **Step 3: Commit**

```bash
git add internal/integration/file_monitor_test.go
git commit -m "test: add write-allowed integration tests for file_monitor

Adds subtests verifying that writes to /workspace and /tmp succeed when
policy allows them. These would have caught the wrap path write denial bug."
```

---

### Task 4: Verify full build and existing tests

**Files:** None (verification only)

- [ ] **Step 1: Build all targets**

Run: `go build ./...`
Expected: success

- [ ] **Step 2: Cross-compile for Windows**

Run: `GOOS=windows go build ./...`
Expected: success

- [ ] **Step 3: Run all unit tests**

Run: `go test ./...`
Expected: all pass

- [ ] **Step 4: Run integration tests (if Docker available)**

Run: `go test -tags integration -run TestFileMonitor -v ./internal/integration/ -timeout 300s`
Expected: all file_monitor tests pass including the new write tests

**Note on PR_SET_PTRACER exec survival:** The integration tests validate this implicitly. The Docker containers run with Yama ptrace_scope=1. If `PR_SET_PTRACER_ANY` did NOT survive exec, the write tests would fail with the same EACCES errors as before. If the integration tests pass with writes succeeding, exec survival is confirmed. If they fail, the contingency `/proc/PID/mem` fallback from the spec would be needed as a follow-up.
