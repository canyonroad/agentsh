# Fix: Ptrace + Seccomp Deadlock in Hybrid Mode

## Problem

When both `ptrace.enabled: true` and `seccomp.file_monitor.enabled: true` are configured, the shell shim with `force=true` causes an immediate deadlock on the first command. The agentsh server stops responding to HTTP requests.

The deadlock occurs because ptrace attaches to the wrapper process (`agentsh-unixwrap`) BEFORE the wrapper sets up seccomp. Ptrace intercepts the wrapper's own syscalls during seccomp setup, preventing the wrapper from completing its initialization. The seccomp notify handler in the server can't receive the notify FD, and the system hangs.

**What works:**
- Ptrace alone + `force=true`: works perfectly (execve interception, blocking)
- Seccomp file_monitor alone: works perfectly
- Both together: immediate deadlock on first command

## Root Cause

In hybrid mode (`exec.go:283-362`), the current execution order is:

```
spawn wrapper → ptrace attach + prefilter injection → start notify handlers → resume → waitExit
```

Ptrace attaches to the wrapper PID and injects a seccomp prefilter. The wrapper is then resumed. But the wrapper needs to install its own seccomp filter, send the notify FD to the server, and receive an ACK — all while being ptrace-traced. The interaction between ptrace tracing and seccomp filter installation/operation on the same process creates a deadlock.

## Solution

Delay ptrace attachment until after the wrapper has completed all seccomp setup and is about to exec. The wrapper and server coordinate via the existing unix socketpair with two additional bytes.

### New execution order

```
spawn wrapper → start notify handlers → [wrapper: seccomp setup, send FD, ACK] →
[wrapper: READY byte] → ptrace attach + prefilter → resume → [server: GO byte] →
wrapper exec's → ptrace intercepts exec → waitExit
```

At exec time, ptrace is attached but the wrapper has already finished all seccomp setup. After exec, both filters are active on the actual command: prefilter (execve → TRACE) + wrapper's filter (file ops → USER_NOTIF). These handle different syscalls and don't interfere.

### Protocol change

Existing protocol (unchanged for non-hybrid mode):
```
wrapper → server: notify FD (SCM_RIGHTS)
server → wrapper: ACK byte
wrapper: closes socket, exec's
```

New protocol (hybrid mode only, when `AGENTSH_PTRACE_SYNC=1` is set):
```
wrapper → server: notify FD (SCM_RIGHTS)
server → wrapper: ACK byte
wrapper → server: READY byte ('R')
server: attaches ptrace, injects prefilter
server → wrapper: GO byte ('G')
wrapper: closes socket, exec's → ptrace intercepts exec
```

The wrapper detects hybrid mode via `AGENTSH_PTRACE_SYNC=1` in its environment, set by the server in `setupSeccompWrapper` when ptrace is active.

### Server-side changes (`internal/api/exec.go`)

The hybrid mode block reorders operations:

```
1. startWrapperHandlers(ctx, extra)  ← starts notify handler
   └─ receives FD, sends ACK
   └─ reads READY byte from wrapper
   └─ signals ptraceReady channel
2. <-ptraceReady                     ← wait for wrapper ready
3. ptraceExecAttach(tracer, pid)     ← attach ptrace NOW
4. hook (cgroup/eBPF)
5. resume()                          ← resume ptrace-stopped wrapper
6. write GO byte to socket           ← wrapper can now exec
7. waitExit()                        ← wrapper exec's, ptrace intercepts
```

A `ptraceReady chan struct{}` is passed to `startNotifyHandler` via a new field on `extraProcConfig`. The notify handler closes it after reading the READY byte.

The GO byte is sent by the main goroutine after `resume()`, not by the notify handler (avoids goroutine coordination).

### Wrapper-side changes (`cmd/agentsh-unixwrap/main.go`)

After the existing ACK wait, when `AGENTSH_PTRACE_SYNC=1`:

```go
sendFD(sockFD, notifyFD)
waitForACK(sockFD)         // server has the notify FD

if os.Getenv("AGENTSH_PTRACE_SYNC") == "1" {
    sendReadyByte(sockFD)  // seccomp done, about to exec
    waitForGO(sockFD)      // server attached ptrace
}

close(sockFD)
syscall.Exec(...)
```

Without `AGENTSH_PTRACE_SYNC=1`, the wrapper behaves exactly as before.

## Files to modify

1. `internal/api/exec.go` — Reorder hybrid mode: move ptrace attach after wrapper ready signal
2. `internal/api/notify_linux.go` — Read READY byte after ACK, signal ptraceReady channel
3. `internal/api/core.go` — Set `AGENTSH_PTRACE_SYNC=1` in wrapper env when ptrace is active
4. `cmd/agentsh-unixwrap/main.go` — Send READY byte, wait for GO byte when sync enabled

## Test plan

**Unit tests:**
- Wrapper with `AGENTSH_PTRACE_SYNC=1`: sends READY after ACK, waits for GO before exec
- Wrapper without `AGENTSH_PTRACE_SYNC`: existing protocol unchanged

**Integration tests:**
- Hybrid mode (ptrace + seccomp file_monitor): command completes without deadlock
- Execve interception works (blocked command denied)
- File monitoring works (file operations intercepted)

**Regression tests:**
- Ptrace-only mode: unchanged behavior
- Seccomp-only mode: unchanged behavior
- Wrapper without ptrace: ACK protocol unchanged

**Manual smoke test (exe.dev):**
- `echo hello` → completes instantly
- `sudo whoami` → blocked by ptrace execve interception
- `cat /etc/shadow` → blocked by seccomp file monitor
