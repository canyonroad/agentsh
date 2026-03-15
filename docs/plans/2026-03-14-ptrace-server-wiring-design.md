# Design: Wire ptrace Tracer into Server Exec and Wrap Paths

**Date:** 2026-03-14
**Status:** Draft

---

## 1. Overview

Wire the existing `ptrace.Tracer` into the agentsh server so that when `sandbox.ptrace.enabled: true`, all processes spawned via `exec` and `wrap` are traced via ptrace instead of seccomp user-notify.

**Architecture**: One `ptrace.Tracer` per server process, started at boot, runs for the server's lifetime. Processes are attached via `tracer.AttachPID(pid)` as they're spawned. The tracer dispatches syscall events to the session's policy engine through thin adapter handlers that reuse the existing policy evaluation and audit emission code.

**Key decisions**:
- Ptrace mode and seccomp mode are mutually exclusive — when ptrace is on, `agentsh-unixwrap` is not used
- The tracer owns the process pause/resume lifecycle, replacing the existing `getSysProcAttrStopped()` / `resumeTracedProcess()` mechanism
- For `wrap`, the CLI skips the seccomp wrapper and reports the shell PID to the server for attachment
- Cleanup follows the server context — tracer stops when the server shuts down, individual tracee cleanup happens through natural exit events

**Files touched**:
- `internal/api/app.go` — add tracer field, init at boot
- `internal/api/core.go` — conditional exec path (ptrace vs seccomp)
- `internal/api/exec.go` — attach tracer instead of seccomp wrapper
- `internal/api/wrap.go` — ptrace-mode wrap handshake
- `internal/api/wrap_linux.go` — accept PID instead of notify fd
- `internal/api/ptrace_handlers.go` — new file, adapter handlers
- `internal/api/process_linux.go` — tracer-aware pause/resume
- `internal/ptrace/tracer.go` — `WaitAttached`, `ResumePID`, `AttachOption`
- `pkg/types/wrap.go` — add `PtraceMode` flag to `WrapInitResponse`

---

## 2. Server Boot — Tracer Initialization

Add a tracer field to the `App` struct and initialize it in `NewApp()`.

```go
// app.go
type App struct {
    // ... existing fields ...
    ptraceTracer *ptrace.Tracer
    ptraceCancel context.CancelFunc
}
```

During `NewApp()`, after config validation:

```go
if cfg.Sandbox.Ptrace.Enabled {
    router := &ptraceHandlerRouter{
        sessions: app.sessions,
        store:    app.store,
        broker:   app.broker,
    }
    tr := ptrace.NewTracer(ptrace.TracerConfig{
        AttachMode:       cfg.Sandbox.Ptrace.AttachMode,
        TraceExecve:      cfg.Sandbox.Ptrace.Trace.Execve,
        TraceFile:        cfg.Sandbox.Ptrace.Trace.File,
        TraceNetwork:     cfg.Sandbox.Ptrace.Trace.Network,
        TraceSignal:      cfg.Sandbox.Ptrace.Trace.Signal,
        MaskTracerPid:    cfg.Sandbox.Ptrace.MaskTracerPid == "on",
        SeccompPrefilter: cfg.Sandbox.Ptrace.Performance.SeccompPrefilter,
        MaxTracees:       cfg.Sandbox.Ptrace.Performance.MaxTracees,
        MaxHoldMs:        cfg.Sandbox.Ptrace.Performance.MaxHoldMs,
        ExecHandler:      router,
        FileHandler:      router,
        NetworkHandler:   router,
        SignalHandler:    router,
    })
    ctx, cancel := context.WithCancel(context.Background())
    app.ptraceTracer = tr
    app.ptraceCancel = cancel
    go tr.Run(ctx)
}
```

A `Close()` method on App calls `ptraceCancel()` during shutdown.

---

## 3. Handler Adapters — Routing Syscalls to Policy

The tracer is singleton but policy engines are per-session. A handler router looks up the right session for each syscall event.

New file `internal/api/ptrace_handlers.go`:

```go
type ptraceHandlerRouter struct {
    sessions *session.Manager
    store    *composite.Store
    broker   *events.Broker
}
```

This struct implements all four ptrace handler interfaces. On each syscall event, it:

1. Reads `SessionID` from the event context (set during `AttachPID`)
2. Looks up the session via `sessions.Get(sessionID)`
3. Gets the session's policy engine
4. Evaluates the policy (same `EvaluateCommand()` / `EvaluateFile()` / `EvaluateNetwork()` calls the seccomp path uses)
5. Emits an audit event to the store
6. Returns allow/deny/redirect to the tracer

Example for exec:

```go
func (r *ptraceHandlerRouter) HandleExecve(ctx context.Context, ec ptrace.ExecContext) ptrace.ExecResult {
    s, _ := r.sessions.Get(ec.SessionID)
    pe := s.PolicyEngine()
    decision := pe.EvaluateCommand(ec.Filename, ec.Argv)
    r.store.Record(audit.ExecEvent{...})
    if decision.Action == policy.Deny {
        return ptrace.ExecResult{Action: ptrace.Deny}
    }
    return ptrace.ExecResult{Action: ptrace.Allow}
}
```

Same pattern for `HandleFile`, `HandleNetwork`, `HandleSignal`. The redirect case maps `policy.Redirect` to ptrace's syscall injection (Phase 4a).

---

## 4. Exec Path — Tracer Attachment

In `core.go`, `execInSessionCore()` conditionally skips the seccomp wrapper:

```go
if a.ptraceTracer != nil {
    wrappedReq = req  // no wrapper, run command directly
} else {
    result := a.setupSeccompWrapper(req, id, s)
    // ... existing seccomp path
}
```

In `exec.go`, `runCommandWithResources()` uses the tracer for pause/resume when active:

```go
if tracer != nil {
    tracer.AttachPID(cmd.Process.Pid,
        ptrace.WithSessionID(sessionID),
        ptrace.WithCommandID(cmdID))
    tracer.WaitAttached(cmd.Process.Pid)

    // Cgroup hook runs while process is stopped
    if hook != nil {
        cleanup, _ := hook(cmd.Process.Pid)
        if cleanup != nil {
            defer cleanup()
        }
    }

    // Resume — tracer stays attached for ongoing tracing
    tracer.ResumePID(cmd.Process.Pid)
} else {
    // Existing seccomp path unchanged
}
```

The tracer's `PTRACE_SEIZE` + `PTRACE_INTERRUPT` replaces the existing `getSysProcAttrStopped()` / `resumeTracedProcess()` mechanism. One ptrace owner, no conflicts.

New methods on tracer:
- `WaitAttached(pid)` — blocks until the tracee is seized and stopped
- `ResumePID(pid)` — resumes the tracee while keeping tracer attached

---

## 5. Wrap Path — Ptrace Mode Handshake

When ptrace is active, the server tells the CLI to skip `agentsh-unixwrap` entirely.

**Server side** — `wrapInitCore()`:

```go
if a.ptraceTracer != nil {
    return types.WrapInitResponse{
        PtraceMode:   true,
        NotifySocket: notifySocketPath,  // reused for PID handshake
    }, http.StatusOK, nil
}
```

The server creates a Unix socket listener. Instead of receiving a seccomp notify fd, it receives the shell's PID via `SO_PEERCRED`.

**Server accept** — new `acceptPtracePID()` in `wrap_linux.go`:

```go
func (a *App) acceptPtracePID(ctx context.Context, listener net.Listener, sessionID string) {
    conn, _ := listener.Accept()
    pid := getPeerPID(conn)
    a.ptraceTracer.AttachPID(pid, ptrace.WithSessionID(sessionID))
    a.ptraceTracer.WaitAttached(pid)
    a.ptraceTracer.ResumePID(pid)
}
```

**CLI side** — when `WrapInitResponse.PtraceMode` is true:

```go
if resp.PtraceMode {
    conn, _ := net.Dial("unix", resp.NotifySocket)
    defer conn.Close()
    syscall.Exec(shellPath, shellArgs, env)
}
```

The socket connection transmits the PID via credentials and serves as a keepalive — when the shell exits, the connection closes.

---

## 6. Session ID Propagation

Extend `AttachPID` to accept metadata via functional options:

```go
func (t *Tracer) AttachPID(pid int, opts ...AttachOption) error

type AttachOption func(*attachOpts)
type attachOpts struct {
    sessionID string
    commandID string
}

func WithSessionID(id string) AttachOption {
    return func(o *attachOpts) { o.sessionID = id }
}

func WithCommandID(id string) AttachOption {
    return func(o *attachOpts) { o.commandID = id }
}
```

The tracer propagates these to `TraceeState` when the attach completes. All child processes forked from this PID inherit the same session ID via the existing process tree tracking.

The handler router reads `ec.SessionID` on every syscall event and routes to the correct policy engine.

This keeps the tracer package decoupled from the API layer — it stores and propagates opaque string IDs without importing `session` or `policy`.

---

## 7. Testing and Validation

**Unit tests** — `internal/api/ptrace_handlers_test.go`:
- Handler router with mock session manager and policy engine
- Verify allow/deny/redirect decisions route correctly
- Verify audit events emitted for each decision

**Integration tests** — extend `internal/ptrace/integration_test.go`:
- End-to-end: process spawn → tracer attach → syscall trap → policy evaluate → allow/deny
- Behind `//go:build integration && linux` (existing pattern)

**Benchmark** — re-run `make bench` after wiring:
- Results will show real ptrace overhead (currently shows 0% because tracer wasn't engaged)
- Update `docs/security-modes.md` with new numbers

**Smoke test** — extend `scripts/smoke.sh`:
- Ptrace-mode test: server with `sandbox.ptrace.enabled: true`, basic exec
- Skipped when `SYS_PTRACE` capability unavailable
