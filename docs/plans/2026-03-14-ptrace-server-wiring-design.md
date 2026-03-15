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
- `internal/ptrace/tracer.go` — `attachQueue` type change, `WaitAttached`, `ResumePID`, `AttachOption`
- `internal/ptrace/attach.go` — propagate `attachOpts` to `TraceeState`, `keepStopped` support
- `internal/config/config.go` — mutual exclusion validation in `ApplyDefaults` / validation path
- `internal/server/server.go` — store `App` reference, plumb `App.Close()` into both `Run()` shutdown and `Close()`
- `internal/cli/wrap.go` — guard `WrapperBinary == ""` check in `setupWrapInterception()`
- `internal/cli/wrap_linux.go` — ptrace-mode branch in `platformSetupWrap`, return `wrapLaunchConfig`
- `pkg/types/sessions.go` — add `PtraceMode` field to `WrapInitResponse`

---

## 2. Config Validation

Add mutual exclusion validation. No `SandboxConfig.Validate()` exists, so add cross-field validation in `internal/config/config.go` in the `ApplyDefaults()` path or a new `ValidateSandbox()` function:

```go
func (c *SandboxConfig) Validate() error {
    if c.Ptrace.Enabled && c.Seccomp.Execve.Enabled {
        return fmt.Errorf("sandbox.ptrace and sandbox.seccomp.execve are mutually exclusive")
    }
    if c.Ptrace.Enabled && c.UnixSockets.Enabled != nil && *c.UnixSockets.Enabled {
        return fmt.Errorf("sandbox.ptrace and sandbox.unix_sockets are mutually exclusive")
    }
    return c.Ptrace.Validate()
}
```

Note: `UnixSockets.Enabled` is `*bool` (pointer), so it must be dereferenced.

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

Plumb this into the server lifecycle. `Server` currently does not hold a reference to `App` — `New()` creates `App` locally and only calls `app.Router()`. To fix:

1. Store the `App` on the `Server` struct:

```go
// server.go
type Server struct {
    // ... existing fields ...
    app *api.App  // for lifecycle management
}
```

2. Call `App.Close()` in **both** the `Run()` graceful shutdown path (select-based SIGTERM handler, lines ~706-743) **and** the `Server.Close()` method (line ~746). The `Run()` shutdown path calls `httpServer.Shutdown()` directly without going through `Server.Close()`, so both paths need coverage:

```go
// In Run() shutdown path:
s.httpServer.Shutdown(shutdownCtx)
if s.app != nil {
    s.app.Close()
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
4. Evaluates the policy using `pe.CheckExecve(filename, argv, depth)` which returns `policy.Decision`. Uses `CheckExecve` (not `CheckCommand`) because ptrace intercepts execve at arbitrary process tree depths — `CheckCommand` hardcodes depth=0
5. Emits an audit event to the store
6. Returns allow/deny/redirect to the tracer

Example for exec — translating between `policy.Decision` and `ptrace.ExecResult`:

```go
func (r *ptraceHandlerRouter) HandleExecve(ctx context.Context, ec ptrace.ExecContext) ptrace.ExecResult {
    s, ok := r.sessions.Get(ec.SessionID)
    if !ok {
        // Unknown session — deny with EACCES
        return ptrace.ExecResult{Allow: false, Errno: int32(syscall.EACCES)}
    }
    pe := s.PolicyEngine()
    decision := pe.CheckExecve(ec.Filename, ec.Argv, ec.Depth)
    // Emit audit event
    r.store.Record(...)

    // Translate policy decision to ptrace result.
    // ExecResult fields (from tracer.go lines 35-42):
    //   Action string    — "allow", "deny", "redirect"
    //   Allow  bool      — legacy allow flag
    //   Errno  int32     — errno to return on deny (e.g. EACCES)
    //   StubPath string  — path to stub binary for redirect
    //   Rule   string    — matched rule name for audit
    //
    // policy.Decision fields:
    //   EffectiveDecision types.Decision — "allow", "deny", "approve", "redirect", etc.
    //   Redirect          *types.RedirectInfo — has .Command field for redirect target
    //   Rule              string
    switch decision.EffectiveDecision {
    case types.DecisionDeny:
        return ptrace.ExecResult{
            Action: "deny",
            Allow:  false,
            Errno:  int32(syscall.EACCES),
            Rule:   decision.Rule,
        }
    case types.DecisionRedirect:
        return ptrace.ExecResult{
            Action:   "redirect",
            StubPath: decision.Redirect.Command,
            Rule:     decision.Rule,
        }
    case types.DecisionApprove:
        // Approval-required decisions cannot be handled via ptrace's synchronous
        // handler path (no HTTP request context to block on). Deny with a
        // descriptive rule name so operators can see what happened in audit logs.
        // Future: wire into ParkTracee for async approval flow.
        return ptrace.ExecResult{
            Action: "deny",
            Allow:  false,
            Errno:  int32(syscall.EACCES),
            Rule:   decision.Rule + " (approval required, denied in ptrace mode)",
        }
    default:
        return ptrace.ExecResult{
            Action: "allow",
            Allow:  true,
            Rule:   decision.Rule,
        }
    }
}
```

Same pattern for `HandleFile`, `HandleNetwork`, `HandleSignal` — each translates from the policy engine's result type to the corresponding ptrace result type. The redirect case uses ptrace's syscall injection engine (Phase 4a) via the `StubPath` mechanism.

---

## 5. Ptrace API Extensions

### 5.1 AttachPID with Options

Current signature: `func (t *Tracer) AttachPID(pid int) error`
Current `attachQueue`: `chan int`

Both must change. Introduce an `attachRequest` struct and change the channel type:

```go
type attachRequest struct {
    pid  int
    opts attachOpts
}

type attachOpts struct {
    sessionID   string
    commandID   string
    keepStopped bool
}

type AttachOption func(*attachOpts)

func WithSessionID(id string) AttachOption { ... }
func WithCommandID(id string) AttachOption { ... }
func WithKeepStopped() AttachOption { ... }
```

Change `attachQueue` from `chan int` to `chan attachRequest`:

```go
// tracer.go — field change
attachQueue chan attachRequest  // was: chan int
```

This requires updating all receive sites:
- `drainQueues()` in `Run()` — receives `attachRequest` instead of `int`
- `Run()` ECHILD fallback path (tracer.go ~line 1101) — `case req := <-t.attachQueue`
- `Run()` tid==0 idle path (tracer.go ~line 1119) — `case req := <-t.attachQueue`
- `attachProcess()` — accepts `attachOpts`, passes to `attachThread()`
- `attachThread()` — uses `opts` to set `TraceeState` fields and honor `keepStopped`

In `attachThread()` (`attach.go`), propagate metadata to `TraceeState`:

```go
t.tracees[tid] = &TraceeState{
    TID:       tid,
    TGID:      tgid,
    SessionID: opts.sessionID,   // already exists on TraceeState, currently unused at attach time
    CommandID: opts.commandID,   // NEW field to add
    Attached:  time.Now(),
    // ... existing fields ...
}
```

Note: `TraceeState` already has a `SessionID` field (set during child inheritance in `handleNewChild`). Only `CommandID` needs to be added.

When `keepStopped` is true, `attachThread` skips the final `PtraceSyscall`/`PtraceCont` call (lines 106-115 of attach.go), leaving the tracee in ptrace-stop state after `PTRACE_SETOPTIONS`. The tracee is still registered in `t.tracees` so the event loop knows about it, but no events will arrive from it until `ResumePID` is called. The tracee is also registered in `t.parkedTracees` so that `handleResumeRequest` can find and resume it. The event loop's `Wait4(-1, WNOHANG)` will simply not see this PID — it's stopped, not delivering events, which is correct. The `WaitAttached` channel signals completion so the caller knows the tracee is ready.

**Multi-thread note**: `attachProcess` iterates all threads in `/proc/<pid>/task/` and calls `attachThread` for each. With `keepStopped`, all threads get stopped and registered in `parkedTracees`. `ResumePID` must resume all threads of the TGID, not just the leader. Implementation: `ResumePID(pid)` sends a resume request for each TID that shares the TGID with `pid`. For the exec path, freshly-started processes are single-threaded, so this is a non-issue. For the wrap path, `keepStopped` is not used (see Section 7), avoiding the multi-thread complexity entirely.

### 5.2 WaitAttached

```go
func (t *Tracer) WaitAttached(pid int) error
```

Implementation: `AttachPID` creates a per-PID channel stored in a `sync.Map` on the tracer (`t.attachDone sync.Map`). When `attachThread` completes (after seize + interrupt + set options + tracee state registration), it loads and signals this channel. `WaitAttached` blocks on the channel, then deletes the entry from the map (cleanup). This is safe because `WaitAttached` runs on the API goroutine, not the tracer's locked OS thread.

Error cases: if `attachThread` fails (e.g., process exited before seize), it signals the channel with an error. `WaitAttached` returns this error. If `WaitAttached` is never called, a background sweep (or GC finalizer) cleans up orphaned channels after a timeout.

### 5.3 ResumePID

```go
func (t *Tracer) ResumePID(pid int) error
```

Implementation: sends a resume request through the existing `resumeQueue chan resumeRequest` to the tracer's event loop. The `resumeRequest` struct has `TID int, Allow bool, Errno int` — used by `ParkTracee`/`handleResumeRequest` for policy approval parks.

For `keepStopped` tracees, `attachThread` must register the tracee in `t.parkedTracees` (in addition to `t.tracees`) so that `handleResumeRequest` recognizes it. Without this, `handleResumeRequest` checks `t.parkedTracees[req.TID]`, finds nothing, logs a warning, and returns without resuming — leaving the tracee stopped forever. By adding the tracee to `parkedTracees` during `keepStopped` attach, the existing `handleResumeRequest` path works unchanged: it removes from `parkedTracees` and calls `PtraceSyscall` to resume.

---

## 6. Exec Path — Tracer Attachment

In `core.go`, `execInSessionCore()` conditionally skips the seccomp wrapper. `setupSeccompWrapper` always returns a `*wrapperSetupResult` (never nil). The simplest approach is to short-circuit inside `setupSeccompWrapper` when ptrace is active:

```go
// In setupSeccompWrapper(), add early return:
func (a *App) setupSeccompWrapper(req types.ExecRequest, sessionID string, s *session.Session) *wrapperSetupResult {
    if a.ptraceTracer != nil {
        // Ptrace mode: no wrapper, no seccomp notify sockets
        return &wrapperSetupResult{wrappedReq: req, extraCfg: nil}
    }
    // ... existing seccomp setup ...
}
```

This avoids rewriting the caller and keeps `extraCfg` nil, which suppresses all seccomp notify handler goroutines in `runCommandWithResources()`.

In `exec.go`, `runCommandWithResources()` currently has two paths controlled by `startStopped := hook != nil`. With ptrace, this must be refactored into three paths:

1. **Ptrace tracer active** — process starts normally (`getSysProcAttr()`), tracer attaches via `PTRACE_SEIZE`, cgroup hook runs while tracer holds process stopped, tracer resumes
2. **Seccomp stopped-start** (existing) — process starts with `PTRACE_TRACEME` via `getSysProcAttrStopped()`, cgroup hook runs, `resumeTracedProcess()` detaches
3. **No interception** — process starts normally, no hook

```go
if tracer != nil {
    // Path 1: Ptrace tracer active
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

**Race window note**: Between `cmd.Start()` and `PTRACE_SEIZE`, the process runs briefly untraced. Any pre-main file or network activity would be untraced during this window. On a loaded system this could exceed 1ms. Mitigation: a pipe-based barrier can be added in a follow-up — the child blocks on reading from a pipe, the parent seizes it, then closes the pipe to unblock. For Phase 1 wiring, the race is acceptable since the seccomp prefilter (in `children` mode) auto-attaches to fork children, and the initial exec target is typically a known-safe binary path.

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
func (a *App) acceptPtracePID(ctx context.Context, listener net.Listener, sessionID string) error {
    conn, err := listener.Accept()
    if err != nil {
        return fmt.Errorf("accept ptrace PID: %w", err)
    }
    unixConn, ok := conn.(*net.UnixConn)
    if !ok {
        conn.Close()
        return fmt.Errorf("expected Unix connection, got %T", conn)
    }
    pid := getConnPeerPID(unixConn)  // existing function in wrap_linux.go
    if pid <= 0 {
        conn.Close()
        return fmt.Errorf("getConnPeerPID returned invalid PID: %d", pid)
    }
    if err := a.ptraceTracer.AttachPID(pid, ptrace.WithSessionID(sessionID)); err != nil {
        conn.Close()
        return fmt.Errorf("attach PID %d: %w", pid, err)
    }
    if err := a.ptraceTracer.WaitAttached(pid); err != nil {
        conn.Close()
        return fmt.Errorf("wait attached PID %d: %w", pid, err)
    }
    // No WithKeepStopped() and no ResumePID() — the wrap path has no cgroup hook
    // to run while the process is stopped. attachThread resumes the tracee
    // automatically after PTRACE_SETOPTIONS when keepStopped is false (default).
    // Keep conn open — when shell exits, connection closes for detection
    return nil
}
```

**CLI side** — in `internal/cli/wrap_linux.go`, `platformSetupWrap()` branches on ptrace mode. Instead of calling `syscall.Exec` directly (which would replace the process and bypass `runWrap()`'s signal forwarding and exit code handling), return a `wrapLaunchConfig` that launches the shell without the wrapper:

```go
func platformSetupWrap(...) (*wrapLaunchConfig, error) {
    if wrapResp.PtraceMode {
        // Connect to server socket for PID handshake via SO_PEERCRED.
        conn, err := net.Dial("unix", wrapResp.NotifySocket)
        if err != nil {
            return nil, fmt.Errorf("ptrace handshake: %w", err)
        }
        // Return launch config that runs the shell directly (no wrapper).
        // runWrap() will Start() this, handle signals, and Wait().
        // The connection stays open as a keepalive.
        return &wrapLaunchConfig{
            command:    shellPath,
            args:       shellArgs,
            env:        env,
            keepAlive:  conn,  // closed when shell exits
        }, nil
    }
    // ... existing seccomp wrapper path (unchanged) ...
}
```

Note: `wrapLaunchConfig` (defined in `internal/cli/wrap.go` line ~262) may need a `keepAlive io.Closer` field for the handshake connection.

**WrapperBinary guard** — the existing check in `setupWrapInterception()` (`internal/cli/wrap.go` line ~289) errors if `WrapperBinary == ""` on Linux. This fires *before* `platformSetupWrap` is called. Guard it:

```go
// In setupWrapInterception(), before calling platformSetupWrap:
if !wrapResp.PtraceMode && runtime.GOOS == "linux" && wrapResp.WrapperBinary == "" {
    return nil, fmt.Errorf("server returned empty wrapper binary")
}
```

---

## 8. Testing and Validation

**Unit tests** — `internal/api/ptrace_handlers_test.go`:
- Handler router with mock session manager and policy engine
- Verify allow/deny/redirect decisions route correctly per actual `ExecResult`/`FileResult`/etc. field names
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
