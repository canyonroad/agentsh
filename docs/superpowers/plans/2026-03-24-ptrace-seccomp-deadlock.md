# Ptrace + Seccomp Deadlock Fix Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the immediate deadlock when both ptrace and seccomp file_monitor are enabled in hybrid mode by delaying ptrace attachment until after the wrapper completes seccomp setup.

**Architecture:** Add a READY/GO handshake to the wrapper-server protocol. The wrapper sends READY after all initialization (seccomp, signal filter, Landlock). The server attaches ptrace, then sends GO. The wrapper exec's only after receiving GO. This separates seccomp setup (untraced) from command execution (ptrace-traced).

**Tech Stack:** Go stdlib (unix sockets, ptrace). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-03-24-ptrace-seccomp-deadlock-design.md`

**Task dependencies:** Tasks 1, 2, 3 are independent and can be done in any order. Task 4 depends on all three. Task 5 depends on Task 4.

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `cmd/agentsh-unixwrap/main.go` | Modify | Add READY/GO handshake when `AGENTSH_PTRACE_SYNC=1` |
| `internal/api/core.go` | Modify | Set `AGENTSH_PTRACE_SYNC=1` in wrapper env when ptrace is active |
| `internal/api/notify_linux.go` | Modify | Read READY byte after ACK, signal `ptraceReady` channel |
| `internal/api/notify_stub.go` | Modify | Update signature to match `notify_linux.go` (cross-compile) |
| `internal/api/exec.go` | Modify | Reorder hybrid mode + update `startWrapperHandlers` signature |
| `internal/api/exec_stream.go` | Modify | Same reordering as exec.go (parallel hybrid mode block) |

---

### Task 1: Wrapper READY/GO handshake

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go:77-118`

- [ ] **Step 1: Add READY/GO handshake and move socket close**

Replace lines 88-118 in `cmd/agentsh-unixwrap/main.go` (from the `}` closing the `if notifFD >= 0` block through the end of Landlock setup). The current code closes `sockFD` at line 91 before signal filter and Landlock. The new code moves the close to after all initialization + READY/GO handshake.

Current lines 89-118:
```go
	// Close notify socket - we're done with it
	_ = unix.Close(sockFD)

	// Install signal filter if enabled...
	// ... (signal filter + Landlock code)
```

Replace with:
```go
	// Install signal filter if enabled and we have a signal socket
	sigSockFD, _ := signalSockFD()
	if cfg.SignalFilterEnabled && sigSockFD >= 0 {
		sigCfg := signal.DefaultSignalFilterConfig()
		sigFilter, err := signal.InstallSignalFilter(sigCfg)
		if err != nil {
			log.Printf("signal filter: %v (continuing without)", err)
		} else {
			defer sigFilter.Close()
			sigFD := sigFilter.NotifFD()
			if sigFD >= 0 {
				if err := sendFD(sigSockFD, sigFD); err != nil {
					log.Fatalf("send signal fd: %v", err)
				}
			}
		}
		_ = unix.Close(sigSockFD)
	}

	// Apply Landlock filesystem restrictions before exec.
	if cfg.LandlockEnabled && cfg.LandlockABI > 0 {
		if err := applyLandlock(cfg); err != nil {
			log.Printf("landlock: %v (continuing without)", err)
		}
	}

	// Ptrace sync handshake: when the server will attach ptrace after our
	// seccomp setup, we signal READY and wait for GO before exec. This
	// prevents ptrace from interfering with seccomp filter installation.
	// Only runs when notifFD >= 0 (seccomp is active) and AGENTSH_PTRACE_SYNC=1.
	if notifFD >= 0 && os.Getenv("AGENTSH_PTRACE_SYNC") == "1" {
		if _, err := unix.Write(sockFD, []byte{'R'}); err != nil {
			log.Fatalf("send READY byte: %v", err)
		}
		// Wait for GO byte, retrying on EINTR.
		if err := waitForACK(func(b []byte) (int, error) { return unix.Read(sockFD, b) }); err != nil {
			log.Fatalf("wait for GO byte: %v", err)
		}
	}

	// Close notify socket - done with all handshakes
	_ = unix.Close(sockFD)
```

Note: the existing `_ = unix.Close(sockFD)` at line 91 is removed. The signal filter and Landlock code is unchanged — just moved before the new READY/GO block. The READY/GO block is guarded by both `notifFD >= 0` (seccomp is active) and `AGENTSH_PTRACE_SYNC=1`. The `waitForACK` helper is reused for the GO byte read (same 1-byte read with EINTR retry).

- [ ] **Step 2: Verify build**

Run: `go build ./cmd/agentsh-unixwrap/`
Expected: success.

- [ ] **Step 3: Commit**

```bash
git add cmd/agentsh-unixwrap/main.go
git commit -m "feat: wrapper READY/GO handshake for ptrace sync"
```

---

### Task 2: Server sets `AGENTSH_PTRACE_SYNC=1` in hybrid mode

**Files:**
- Modify: `internal/api/core.go:256`

- [ ] **Step 1: Add env var in the `extraEnv` map**

In `internal/api/core.go`, find the `extraEnv` map construction at line 256:

```go
	extraEnv := map[string]string{"AGENTSH_NOTIFY_SOCK_FD": strconv.Itoa(envFD)}
```

Add the ptrace sync flag immediately after:

```go
	extraEnv := map[string]string{"AGENTSH_NOTIFY_SOCK_FD": strconv.Itoa(envFD)}
	if a.ptraceTracer != nil {
		extraEnv["AGENTSH_PTRACE_SYNC"] = "1"
	}
```

This is only reachable in hybrid mode because `setupSeccompWrapper` returns early for full ptrace mode at line 128.

- [ ] **Step 2: Verify build**

Run: `go build ./...`
Expected: success.

- [ ] **Step 3: Commit**

```bash
git add internal/api/core.go
git commit -m "feat: set AGENTSH_PTRACE_SYNC=1 in wrapper env for hybrid mode"
```

---

### Task 3: Notify handler reads READY byte and signals ptraceReady

**Files:**
- Modify: `internal/api/notify_linux.go:180` (signature + goroutine body)
- Modify: `internal/api/notify_stub.go:21` (matching signature)
- Modify: `internal/api/exec.go:681` (`startWrapperHandlers` signature)

- [ ] **Step 1: Update `startNotifyHandler` signature in `notify_linux.go`**

At line 180, add `ptraceReady chan<- error` parameter:

```go
func startNotifyHandler(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker, execveHandler any, fileMonitorCfg config.SandboxSeccompFileMonitorConfig, landlockEnabled bool, ptraceReady chan<- error) {
```

- [ ] **Step 2: Update `startNotifyHandler` signature in `notify_stub.go`**

At line 21, update to match:

```go
func startNotifyHandler(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker, execveHandler any, fileMonitorCfg config.SandboxSeccompFileMonitorConfig, landlockEnabled bool, ptraceReady chan<- error) {
```

The stub body stays the same (close parentSock, return). The `ptraceReady` parameter is unused on non-Linux.

- [ ] **Step 3: Replace ServeNotifyWithExecve call with new flow**

In the goroutine inside `startNotifyHandler` (`notify_linux.go`), replace lines 279-286 (from the ACK comment through the `ServeNotifyWithExecve returned` log):

Current:
```go
		// Send ACK to wrapper...
		if _, err := parentSock.Write([]byte{1}); err != nil {
			slog.Debug("notify: ACK write to wrapper failed", ...)
		}
		slog.Debug("starting ServeNotifyWithExecve", ...)
		unixmon.ServeNotifyWithExecve(ctx, notifyFD, sessID, pol, emitter, h, fileHandler)
		slog.Debug("ServeNotifyWithExecve returned", ...)
```

Replace with:
```go
		// Send ACK to wrapper so it knows the notify handler is ready before exec.
		if _, err := parentSock.Write([]byte{1}); err != nil {
			slog.Debug("notify: ACK write to wrapper failed", "error", err, "session_id", sessID)
		}

		// Start ServeNotifyWithExecve BEFORE reading READY to ensure notifications
		// can be processed by the time the wrapper exec's after receiving GO.
		serveDone := make(chan struct{})
		go func() {
			defer close(serveDone)
			slog.Debug("starting ServeNotifyWithExecve", "session_id", sessID, "has_execve_handler", h != nil, "has_file_handler", fileHandler != nil, "has_policy", pol != nil)
			unixmon.ServeNotifyWithExecve(ctx, notifyFD, sessID, pol, emitter, h, fileHandler)
			slog.Debug("ServeNotifyWithExecve returned", "session_id", sessID)
		}()

		// If ptrace sync is enabled, read the READY byte from the wrapper
		// and signal the main goroutine that ptrace can now be attached.
		if ptraceReady != nil {
			_ = parentSock.SetReadDeadline(time.Time{}) // clear FD-receive deadline
			_ = parentSock.SetReadDeadline(time.Now().Add(recvFDTimeout))
			readyBuf := make([]byte, 1)
			_, readyErr := parentSock.Read(readyBuf)
			if readyErr != nil {
				ptraceReady <- fmt.Errorf("read READY byte: %w", readyErr)
			} else {
				ptraceReady <- nil
			}
			_ = parentSock.SetReadDeadline(time.Time{}) // clear for GO byte
		}

		<-serveDone // wait for ServeNotifyWithExecve to finish
```

- [ ] **Step 4: Update `startWrapperHandlers` signature**

In `internal/api/exec.go` at line 681:

```go
func startWrapperHandlers(ctx context.Context, extra *extraProcConfig, pid, pgid int, ptraceReady chan<- error) {
```

Update the `startNotifyHandler` call inside to pass `ptraceReady`:

```go
	if extra.notifyParentSock != nil {
		startNotifyHandler(ctx, extra.notifyParentSock, extra.notifySessionID, extra.notifyPolicy, extra.notifyStore, extra.notifyBroker, extra.execveHandler, extra.fileMonitorCfg, extra.landlockEnabled, ptraceReady)
	}
```

- [ ] **Step 5: Update all non-hybrid callers to pass `nil`**

In `exec.go`, the non-hybrid wrapper call (search for `startWrapperHandlers` outside the hybrid block, around line 447):
```go
startWrapperHandlers(handlerCtx, extra, cmd.Process.Pid, pgid, nil)
```

In `exec_stream.go`, the non-hybrid wrapper call (around line 543):
```go
startWrapperHandlers(handlerCtx, extra, cmd.Process.Pid, pgid, nil)
```

- [ ] **Step 6: Verify build (including cross-compile)**

Run: `go build ./... && GOOS=windows go build ./... && GOOS=darwin go build ./...`
Expected: success.

- [ ] **Step 7: Commit**

```bash
git add internal/api/notify_linux.go internal/api/notify_stub.go internal/api/exec.go internal/api/exec_stream.go
git commit -m "feat: notify handler reads READY byte and signals ptraceReady"
```

---

### Task 4: Reorder hybrid mode in exec.go and exec_stream.go

**Files:**
- Modify: `internal/api/exec.go:283-362`
- Modify: `internal/api/exec_stream.go:387-464`

**Depends on:** Tasks 1, 2, 3

- [ ] **Step 1: Reorder exec.go hybrid mode block**

Replace the hybrid mode block in `internal/api/exec.go` (lines 283-362). Current order: ptrace attach → start handlers → hook → resume → waitExit. New order: start handlers → wait READY → ptrace attach → hook → resume → GO byte → waitExit.

```go
		if tracer != nil && hasWrapperHandlers {
			// HYBRID MODE: ptrace for execve interception + seccomp wrapper for sockets/files/Landlock.
			// The wrapper must complete seccomp setup BEFORE ptrace attaches to prevent deadlock.
			// Protocol: wrapper does seccomp init → READY byte → server attaches ptrace → GO byte → wrapper exec's.
			ptraceDone := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = killProcessGroup(pgid)
					_ = killProcess(cmd.Process.Pid)
				case <-ptraceDone:
				}
			}()

			// 1. Start wrapper handlers — notify handler receives FD, sends ACK,
			// starts ServeNotifyWithExecve, then reads READY byte from wrapper.
			handlerCtx, handlerCancel := context.WithCancel(ctx)
			ptraceReady := make(chan error, 1)
			startWrapperHandlers(handlerCtx, extra, cmd.Process.Pid, pgid, ptraceReady)

			// 2. Wait for wrapper to signal READY (seccomp setup complete).
			if readyErr := <-ptraceReady; readyErr != nil {
				close(ptraceDone)
				handlerCancel()
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
				pipeWG.Wait()
				cmd.Process.Release()
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("hybrid wrapper ready: %w", readyErr)
			}

			// 3. Attach ptrace NOW — wrapper is idle, waiting for GO byte.
			waitExit, resume, attachErr := ptraceExecAttach(tracer, cmd.Process.Pid, sessionID, cmdID, hook != nil)
			if attachErr != nil {
				close(ptraceDone)
				handlerCancel()
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
				pipeWG.Wait()
				cmd.Process.Release()
				return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("hybrid ptrace attach: %w", attachErr)
			}

			// 4. Run hook while process stopped (cgroup/eBPF setup)
			if hook != nil {
				if cleanup, hookErr := hook(cmd.Process.Pid); hookErr != nil {
					slog.Warn("hybrid mode: cgroup/eBPF hook failed (continuing without resource controls)",
						"error", hookErr, "pid", cmd.Process.Pid)
				} else if cleanup != nil {
					defer func() { _ = cleanup() }()
				}
			}

			// 5. Resume wrapper and send GO byte.
			if resume != nil {
				if resumeErr := resume(); resumeErr != nil {
					close(ptraceDone)
					handlerCancel()
					_ = killProcess(cmd.Process.Pid)
					_ = killProcessGroup(pgid)
					pipeWG.Wait()
					cmd.Process.Release()
					return 127, nil, nil, 0, 0, false, false, types.ExecResources{}, fmt.Errorf("ptrace resume: %w", resumeErr)
				}
			}

			// 6. Send GO byte — wrapper reads it and calls exec.
			// Socket access is safe: main goroutine blocked on <-ptraceReady before this,
			// so notify goroutine's READY read is complete. No concurrent socket access.
			if _, err := extra.notifyParentSock.Write([]byte{'G'}); err != nil {
				slog.Warn("hybrid mode: GO byte write failed", "error", err, "pid", cmd.Process.Pid)
			}

			// 7. Wait for exit via ptrace exit channel
			waitStart := time.Now()
			slog.Debug("exec waiting for command (hybrid)", "command", req.Command, "pid", cmd.Process.Pid)
			result := waitExit()
			close(ptraceDone)
			handlerCancel()
			if result.err != nil {
				_ = killProcess(cmd.Process.Pid)
				_ = killProcessGroup(pgid)
			}
			waitDuration := time.Since(waitStart)
			slog.Debug("exec command finished (hybrid)", "command", req.Command, "pid", cmd.Process.Pid, "exit_code", result.exitCode, "wait_duration_ms", waitDuration.Milliseconds())
			pipeWG.Wait()
			stdout, stderr = stdoutW.Bytes(), stderrW.Bytes()
			stdoutTotal, stderrTotal = stdoutW.total, stderrW.total
			stdoutTrunc, stderrTrunc = stdoutW.truncated, stderrW.truncated
			resources = result.resources
			cmd.Process.Release()

			if ctx.Err() != nil {
				_ = killProcessGroup(pgid)
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return 124, stdout, append(stderr, []byte("command timed out\n")...), stdoutTotal, stderrTotal + int64(len("command timed out\n")), true, true, resources, ctx.Err()
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				return 127, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, ctx.Err()
			}
			return result.exitCode, stdout, stderr, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, result.err
		}
```

- [ ] **Step 2: Apply identical reordering to exec_stream.go**

Replace the hybrid mode block in `internal/api/exec_stream.go` (lines 387-464) with the same pattern. The differences from exec.go:
- Log `"exec_stream waiting for command (hybrid)"` instead of `"exec waiting for command (hybrid)"`
- Log `"exec_stream command finished (hybrid)"` instead of `"exec command finished (hybrid)"`

All other code is identical.

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: success.

- [ ] **Step 4: Run existing tests**

Run: `go test ./internal/api/ -v -count=1 -timeout 120s 2>&1 | tail -20`
Expected: all existing tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/api/exec.go internal/api/exec_stream.go
git commit -m "fix: reorder hybrid mode to prevent ptrace+seccomp deadlock"
```

---

### Task 5: Final verification

**Depends on:** Tasks 1-4

- [ ] **Step 1: Run full test suite**

Run: `go test ./...`
Expected: all PASS.

- [ ] **Step 2: Verify cross-compilation**

Run: `GOOS=windows go build ./... && GOOS=darwin go build ./...`
Expected: success.
