# Design: Wire ptrace Tracer into Server Exec and Wrap Paths

**Date:** 2026-03-14
**Status:** Draft

---

## 1. Overview

Wire the existing `ptrace.Tracer` into the agentsh server so that when `sandbox.ptrace.enabled: true`, all processes spawned via `exec` and `wrap` are traced via ptrace instead of seccomp user-notify.

**Architecture**: One `ptrace.Tracer` per server process, started at boot, runs for the server's lifetime. Processes are attached via `tracer.AttachPID(pid)` as they're spawned. The tracer dispatches syscall events to the session's policy engine through thin adapter handlers that reuse the existing policy evaluation and audit emission code.

**Key decisions**:
- Ptrace mode and seccomp mode are mutually exclusive — when ptrace is on, `agentsh-unixwrap` is not used. Enforced by config validation.
- The tracer owns the process pause/resume lifecycle, replacing the existing `getSysProcAttrStopped()` / `resumeTracedProcess()` mechanism. Processes start normally (no `PTRACE_TRACEME`); the tracer's `PTRACE_SEIZE` + `PTRACE_INTERRUPT` stops them.
- For `wrap`, the CLI skips the seccomp wrapper and reports the shell PID to the server for attachment
- Cleanup follows the server context — tracer stops when the server shuts down, individual tracee cleanup happens through natural exit events

**Files touched**:
- `internal/api/app.go` — add tracer field, `Close()` method, init at boot
- `internal/api/core.go` — conditional exec path (ptrace vs seccomp)
- `internal/api/exec.go` — attach tracer instead of seccomp wrapper
- `internal/api/wrap.go` — ptrace-mode wrap handshake
- `internal/api/wrap_linux.go` — accept PID instead of notify fd
- `internal/api/ptrace_handlers.go` — new file, adapter handlers
- `internal/api/process_linux.go` — tracer-aware pause/resume
- `internal/ptrace/tracer.go` — `WaitAttached`, `ResumePID`, `AttachOption`
- `internal/ptrace/attach.go` — propagate `attachOpts` to `TraceeState`
- `internal/config/ptrace.go` — mutual exclusion validation
- `internal/server/server.go` — plumb `App.Close()` into server shutdown
- `internal/cli/wrap_linux.go` — ptrace-mode branch in `platformSetupWrap`
- `pkg/types/sessions.go` — add `PtraceMode` field to `WrapInitResponse`

---

## 2. Config Validation

Add mutual exclusion validation in `internal/config/ptrace.go`:

```go
// In SandboxConfig.Validate() or a new cross-field validator:
if c.Ptrace.Enabled && c.Seccomp.Execve.Enabled {
    return fmt.Errorf("sandbox.ptrace and sandbox.seccomp.execve are mutually exclusive")
}
if c.Ptrace.Enabled && c.UnixSockets.Enabled {
    return fmt.Errorf("sandbox.ptrace and sandbox.unix_sockets are mutually exclusive")
}
```

This prevents both interception mechanisms from being active simultaneously, which would cause `PTRACE_TRACEME` / `PTRACE_SEIZE` conflicts and duplicate syscall handling.

Note: `MaskTracerPid` config validation currently rejects any value other than `"off"`. The tracer's `MaskTracerPid` field should be set to `false` unconditionally until that validation is relaxed in a future change.

---

## 3. Server Boot — Tracer Initialization

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
        MaskTracerPid:    false,  // validation rejects non-"off" values for now
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

### Shutdown

Add a `Close()` method to `App`:

```go
func (a *App) Close() {
    if a.ptraceCancel != nil {
        a.ptraceCancel()
    }
}
```

Plumb this into the server lifecycle. `Server` currently does not hold a reference to `App` — it only calls `app.Router()` to get an `http.Handler`. To fix this:

```go
// server.go — add App reference
type Server struct {
    // ... existing fields ...
    app *api.App  // for lifecycle management
}

// In Server.Close():
func (s *Server) Close() error {
    // ... existing shutdown ...
    if s.app != nil {
        s.app.Close()
    }
    return nil
}
```

When the tracer's context is cancelled, its `Run()` method exits, which detaches all tracees gracefully (existing cleanup path in the tracer).

---

## 4. Handler Adapters — Routing Syscalls to Policy

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
3. Gets the session's policy engine via `s.PolicyEngine()` (returns `*policy.Engine`)
4. Evaluates the policy using the real API: `pe.CheckCommand()`, `pe.CheckFile()`, `pe.CheckNetwork()`
5. Emits an audit event to the store
6. Returns allow/deny/redirect to the tracer

Example for exec:

```go
func (r *ptraceHandlerRouter) HandleExecve(ctx context.Context, ec ptrace.ExecContext) ptrace.ExecResult {
    s, ok := r.sessions.Get(ec.SessionID)
    if !ok {
        return ptrace.ExecResult{Action: ptrace.Deny}  // unknown session = deny
    }
    pe := s.PolicyEngine()
    result := pe.CheckCommand(ec.Filename, ec.Argv)
    // Emit audit event
    r.store.Record(...)
    switch result.Decision {
    case policy.Deny:
        return ptrace.ExecResult{Action: ptrace.Deny}
    case policy.Redirect:
        return ptrace.ExecResult{Action: ptrace.Redirect, RedirectTo: result.RedirectTo}
    default:
        return ptrace.ExecResult{Action: ptrace.Allow}
    }
}
```

Same pattern for `HandleFile`, `HandleNetwork`, `HandleSignal`. The redirect case maps to ptrace's syscall injection engine (Phase 4a).

---

## 5. Ptrace API Extensions

### 5.1 AttachPID with Options

Current signature: `func (t *Tracer) AttachPID(pid int) error`

Extend to accept metadata:

```go
func (t *Tracer) AttachPID(pid int, opts ...AttachOption) error

type AttachOption func(*attachOpts)
type attachOpts struct {
    sessionID   string
    commandID   string
    keepStopped bool  // if true, leave tracee stopped after attach
}

func WithSessionID(id string) AttachOption {
    return func(o *attachOpts) { o.sessionID = id }
}

func WithCommandID(id string) AttachOption {
    return func(o *attachOpts) { o.commandID = id }
}

func WithKeepStopped() AttachOption {
    return func(o *attachOpts) { o.keepStopped = true }
}
```

The `attachOpts` are sent through `attachQueue` alongside the PID. In `attachThread()` (`attach.go`), propagate to `TraceeState`:

```go
t.tracees[tid] = &TraceeState{
    TID:       tid,
    TGID:      tgid,
    SessionID: opts.sessionID,   // NEW
    CommandID: opts.commandID,   // NEW
    Attached:  time.Now(),
    // ... existing fields ...
}
```

Add `CommandID string` field to `TraceeState`.

When `keepStopped` is true, `attachThread` skips the final `PtraceSyscall`/`PtraceCont` call, leaving the tracee stopped after `PTRACE_SETOPTIONS`. This is needed for the cgroup hook window.

All child processes forked from this PID inherit the same session/command IDs via existing process tree tracking.

### 5.2 WaitAttached

```go
func (t *Tracer) WaitAttached(pid int) error
```

Implementation: `AttachPID` creates a per-PID channel stored in a `sync.Map` on the tracer. When `attachThread` completes (after seize + interrupt + set options), it signals this channel. `WaitAttached` blocks on the channel. This is safe because `WaitAttached` runs on the API goroutine, not the tracer's locked OS thread.

### 5.3 ResumePID

```go
func (t *Tracer) ResumePID(pid int) error
```

Implementation: sends a resume request through a channel to the tracer's event loop. The event loop calls `PtraceSyscall` (or `PtraceCont`) on the tracee. This must happen on the tracer's locked OS thread, not the caller's goroutine, because ptrace operations must be performed by the thread that owns the tracee.

---

## 6. Exec Path — Tracer Attachment

In `core.go`, `execInSessionCore()` conditionally skips the seccomp wrapper:

```go
if a.ptraceTracer != nil {
    wrappedReq = req  // no wrapper, run command directly
} else {
    result := a.setupSeccompWrapper(req, id, s)
    // ... existing seccomp path
}
```

In `exec.go`, `runCommandWithResources()` uses the tracer for pause/resume when active. The process is started **without** `Ptrace: true` in `SysProcAttr` — no `PTRACE_TRACEME`. Instead, the tracer uses `PTRACE_SEIZE` externally:

```go
if tracer != nil {
    // Start process normally (no PTRACE_TRACEME — incompatible with PTRACE_SEIZE)
    cmd.SysProcAttr = getSysProcAttr()  // just Setpgid: true

    if err := cmd.Start(); err != nil { ... }

    // Tracer attaches via PTRACE_SEIZE + PTRACE_INTERRUPT (stops the process)
    tracer.AttachPID(cmd.Process.Pid,
        ptrace.WithSessionID(sessionID),
        ptrace.WithCommandID(cmdID),
        ptrace.WithKeepStopped())
    tracer.WaitAttached(cmd.Process.Pid)

    // Cgroup hook runs while process is stopped by tracer
    if hook != nil {
        cleanup, _ := hook(cmd.Process.Pid)
        if cleanup != nil {
            defer cleanup()
        }
    }

    // Resume — tracer stays attached for ongoing tracing
    tracer.ResumePID(cmd.Process.Pid)
} else {
    // Existing seccomp path unchanged (PTRACE_TRACEME for cgroup hook)
}
```

**Race window note**: Between `cmd.Start()` and `PTRACE_SEIZE`, the process runs briefly untraced. With seccomp prefilter in `children` mode, the tracer auto-attaches to fork children via `PTRACE_O_TRACECLONE`. For the initial `exec` call, this window is typically <1ms and the process hasn't reached `main()` yet. If this proves insufficient, a pipe-based barrier can be added in a follow-up.

---

## 7. Wrap Path — Ptrace Mode Handshake

When ptrace is active, the server tells the CLI to skip `agentsh-unixwrap` entirely.

**Types change** — in `pkg/types/sessions.go`, add field to `WrapInitResponse`:

```go
type WrapInitResponse struct {
    PtraceMode    bool              `json:"ptrace_mode,omitempty"`
    WrapperBinary string            `json:"wrapper_binary,omitempty"`
    // ... existing fields ...
}
```

**Server side** — `wrapInitCore()` in `wrap.go`:

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
    // Keep conn open — when shell exits, connection closes for detection
}
```

**CLI side** — in `internal/cli/wrap_linux.go`, `platformSetupWrap()` branches on ptrace mode:

```go
func platformSetupWrap(...) {
    if wrapResp.PtraceMode {
        // Skip agentsh-unixwrap wrapper, socket pair creation, ACK handshake.
        // Connect to server socket for PID handshake via SO_PEERCRED.
        conn, _ := net.Dial("unix", wrapResp.NotifySocket)
        defer conn.Close()
        // Exec the agent shell directly — no wrapper
        syscall.Exec(shellPath, shellArgs, env)
        return
    }
    // ... existing seccomp wrapper path (unchanged) ...
}
```

The existing `runWrap()` in `internal/cli/wrap.go` checks `WrapperBinary == ""` on Linux and errors. With ptrace mode, this check must be guarded:

```go
if !resp.PtraceMode && runtime.GOOS == "linux" && resp.WrapperBinary == "" {
    return fmt.Errorf("server did not provide wrapper binary")
}
```

---

## 8. Testing and Validation

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

**Config validation tests** — `internal/config/ptrace_test.go`:
- Verify mutual exclusion: ptrace + seccomp.execve → error
- Verify mutual exclusion: ptrace + unix_sockets → error
