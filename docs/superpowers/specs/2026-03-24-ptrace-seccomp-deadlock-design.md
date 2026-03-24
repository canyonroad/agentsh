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
spawn wrapper → start notify handlers + ServeNotifyWithExecve →
[wrapper: seccomp setup, signal filter, Landlock, send FD, ACK] →
[wrapper: READY byte] → ptrace attach (SEIZE + INTERRUPT) →
hook (cgroup/eBPF while stopped) → resume → [server: GO byte] →
wrapper exec's → first syscall exit → prefilter injected → waitExit
```

Note: the prefilter is NOT injected at attach time. It is injected at the first syscall exit after resume (when the wrapper calls `exec`). This is the existing ptrace prefilter injection mechanism — attach just does SEIZE + INTERRUPT.

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

### Server-side changes (`internal/api/exec.go` and `internal/api/exec_stream.go`)

Both `exec.go` (lines 283-362) and `exec_stream.go` (lines 386-464) have identical hybrid mode blocks. Both must be updated with the same reordering.

The hybrid mode block reorders operations:

```
1. startWrapperHandlers(ctx, extra)  ← starts notify handler goroutine
   └─ receives FD, sends ACK
   └─ starts ServeNotifyWithExecve (before reading READY, so it's ready for notifications)
   └─ reads READY byte from wrapper (with 10s timeout)
   └─ sends nil on ptraceReady channel (or error on failure)
2. <-ptraceReady                     ← wait for wrapper ready (check error)
3. ptraceExecAttach(tracer, pid)     ← PTRACE_SEIZE + INTERRUPT (no prefilter yet)
4. hook (cgroup/eBPF while stopped)
5. resume()                          ← resume wrapper (still blocked on read for GO)
6. write GO byte to notifyParentSock ← wrapper reads GO, calls exec
7. waitExit()                        ← exec triggers prefilter injection at first syscall exit
```

The `ptraceReady` channel is `chan error` (not `chan struct{}`), so the notify handler can communicate failure (e.g., wrapper crash, socket error, timeout). The main goroutine checks the error after receiving from the channel.

**Socket FD ownership:** The notify handler goroutine receives `parentSock` but defers its close until `ServeNotifyWithExecve` returns (after exec/process exit). The main goroutine writes the GO byte to `extra.notifyParentSock` after `resume()`. This is safe because the defer close only fires when the goroutine returns, which is after the process exits. The main goroutine's GO write happens long before that. **Sequencing guarantee:** The main goroutine blocks on `<-ptraceReady` before writing GO. Since the READY read in the notify goroutine completes before sending on `ptraceReady`, the socket is never accessed concurrently by both goroutines.

**Signature change:** `startNotifyHandler` (or `startWrapperHandlers`) gains a new `ptraceReady chan<- error` parameter. In hybrid mode, the caller creates and passes the channel; in non-hybrid mode (and in `exec.go`/`exec_stream.go` non-hybrid call sites), it passes `nil` and the handler skips the READY/GO handshake.

**Notify handler ordering within the goroutine:**
```go
go func() {
    defer parentSock.Close()
    notifyFD := recvFD(parentSock)     // receive notify FD
    sendACK(parentSock)                // wrapper unblocked
    go ServeNotifyWithExecve(notifyFD) // start handling notifications NOW
    readREADY(parentSock, 10s timeout) // wait for wrapper to signal ready
    ptraceReady <- err                 // signal main goroutine
    // goroutine continues handling notifications until ctx cancelled
}()
```

`ServeNotifyWithExecve` is started in a nested goroutine BEFORE reading the READY byte. This eliminates the race between notification handling startup and wrapper exec after GO. By the time the server sends GO and the wrapper calls exec, `ServeNotifyWithExecve` is already running and ready to handle seccomp notifications.

### Wrapper-side changes (`cmd/agentsh-unixwrap/main.go`)

After ALL existing wrapper initialization (seccomp filter, signal filter, Landlock), when `AGENTSH_PTRACE_SYNC=1`:

```go
// Existing initialization (unchanged):
installSeccompFilter()           // install BPF with USER_NOTIF
sendFD(sockFD, notifyFD)        // send notify FD to server
waitForACK(sockFD)               // server has the notify FD
installSignalFilter()            // if signal filter enabled
sendFD(signalSockFD, signalFD)  // send signal FD
waitForACK(signalSockFD)
applyLandlock()                  // if Landlock enabled

// NEW: ptrace sync handshake (only when AGENTSH_PTRACE_SYNC=1)
if os.Getenv("AGENTSH_PTRACE_SYNC") == "1" {
    sendReadyByte(sockFD)        // all init done, about to exec
    waitForGO(sockFD, 30s)       // server attached ptrace, safe to exec (30s timeout, fatal on timeout)
}

// NOTE: unix.Close(sockFD) must be moved here (after READY/GO exchange)
// when AGENTSH_PTRACE_SYNC=1. Currently it's at line 91 before exec.
unix.Close(sockFD)
syscall.Exec(...)
```

The READY byte is sent AFTER all initialization (seccomp, signals, Landlock) to ensure the wrapper is fully set up before ptrace attaches. Without `AGENTSH_PTRACE_SYNC=1`, the wrapper behaves exactly as before.

## Files to modify

1. `internal/api/exec.go` — Reorder hybrid mode: move ptrace attach after wrapper ready signal
2. `internal/api/exec_stream.go` — Identical hybrid mode reordering (parallel copy of exec.go hybrid block)
3. `internal/api/notify_linux.go` — Start ServeNotifyWithExecve before READY read, read READY byte with timeout, signal ptraceReady channel with error
4. `internal/api/core.go` — Set `AGENTSH_PTRACE_SYNC=1` in wrapper env when ptrace is active. This is only reachable in hybrid mode because `setupSeccompWrapper` returns early for full ptrace mode (when no wrapper is needed). The env var is set in the existing `if a.ptraceTracer != nil` block.
5. `cmd/agentsh-unixwrap/main.go` — Send READY byte after all init, wait for GO byte, move socket close after handshake

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
