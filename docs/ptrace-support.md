# Spec: ptrace Syscall Tracer Backend for agentsh

**Version:** 0.1 — Draft  
**Date:** 2026-03-11  
**Author:** Eran / Canyon Road  
**Status:** Phase 2 Complete

---

## 1. Motivation

agentsh's kernel-level enforcement (seccomp user-notify, eBPF, FUSE) requires Linux capabilities that are unavailable in restricted container runtimes — most notably **AWS Fargate**, where the Firecracker microVM blocks `SYS_ADMIN`, seccomp user-notify, eBPF, and `/dev/fuse`.

Fargate does, however, support exactly one additional capability: **`SYS_PTRACE`**, combined with `pidMode: "task"` (shared PID namespace across containers in an ECS task). This is the same mechanism used by Datadog CWS, Falco, Lacework, and Sysdig for runtime security on Fargate.

A ptrace-based tracer backend would allow agentsh to provide strong enforcement on Fargate and similar restricted environments — full allow/deny/audit for all four syscall planes (exec, file, network, signal), with steering/redirect support in Phase 4. Entirely opt-in and feature-flagged off by default.

### 1.1 Non-Goals

- Replacing seccomp/eBPF/FUSE on environments where they are available. ptrace is a fallback for restricted runtimes, not a preferred path.
- macOS or Windows support. ptrace semantics differ substantially; this spec covers Linux only.
- Transparent file path rewriting (FUSE redirect semantics). ptrace can deny/allow file operations but transparent path substitution is deferred to a future iteration.

---

## 2. Architecture Overview

### 2.1 How ptrace Differs from seccomp user-notify

seccomp user-notify installs a BPF filter **inside the child process**; notifications flow to the parent via an fd. The child inherits the filter atomically on `fork`/`clone`.

ptrace works in the opposite direction: the **tracer attaches to the tracee from the outside**. The tracer calls `ptrace(PTRACE_ATTACH, pid)` or, for new children, `ptrace(PTRACE_SEIZE, pid)`. Process tree inheritance is handled via ptrace options (`PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEVFORK`), which cause the kernel to auto-attach to new children before they run.

### 2.2 Deployment Model

The ptrace tracer runs as a **sidecar container** in the same ECS task (or Kubernetes pod), with:

- `SYS_PTRACE` capability added
- `pidMode: "task"` (ECS) or `shareProcessNamespace: true` (K8s)
- Shared PID namespace allows the sidecar to see and trace all processes in the workload container

The agentsh server process in the sidecar runs the ptrace tracer loop, which attaches to the root process of the workload container and automatically inherits tracing to all descendants.

### 2.3 Component Placement

```
internal/
  ptrace/                      ← NEW package
    tracer.go                  ← Core ptrace event loop
    tracer_test.go
    attach.go                  ← Process discovery and attachment
    attach_test.go
    syscall_handler.go         ← Syscall dispatch (exec, file, net, signal)
    syscall_handler_test.go
    seccomp_prefilter.go       ← Optional BPF pre-filter for performance
    seccomp_prefilter_test.go
    args.go                    ← Register/memory reading helpers
    args_test.go
    args_amd64.go              ← x86_64 register layout
    args_arm64.go              ← aarch64 register layout
    process_tree.go            ← Tracee process tree tracking
    process_tree_test.go
    integration_test.go        ← Integration tests requiring SYS_PTRACE
    doc.go
  capabilities/
    check.go                   ← Add ptrace availability check
    security_caps.go           ← Add ModePtrace, update SelectMode()
    detect_linux.go            ← Report ptrace in detection output
  platform/
    types.go                   ← Add HasPtrace to Capabilities struct
    interfaces.go              ← Add SyscallTracer interface
```

---

## 3. Configuration

### 3.1 Config Schema

New section under `sandbox` in `config.yml`:

```yaml
sandbox:
  ptrace:
    # Master switch. Default: false. Must be explicitly enabled.
    enabled: false

    # How to discover the initial tracee process.
    #   "children"  — agentsh forks the workload and traces from exec (recommended for Phase 1)
    #   "pid"       — attach to a specific PID (set via target_pid, target_pid_file, or AGENTSH_PTRACE_TARGET_PID)
    #   "sidecar"   — [Phase 3] auto-discover workload container's root process via /proc
    attach_mode: "children"

    # Explicit target PID (only used when attach_mode: "pid")
    # Can also be set via AGENTSH_PTRACE_TARGET_PID env var.
    target_pid: 0

    # Path to a file containing the target PID (only used when attach_mode: "pid").
    # agentsh polls this file on startup until it appears or a timeout is reached.
    # Useful for sidecar deployments where the workload writes its PID to a shared volume.
    target_pid_file: ""

    # Which syscall classes to trace. Each can be independently toggled.
    # Disabling a class means those syscalls pass through without stopping.
    trace:
      execve: true          # execve, execveat
      file: true            # openat, openat2, unlinkat, renameat2, mkdirat, linkat, symlinkat, fchmodat, fchmodat2, fchownat (+ legacy amd64: open, creat, unlink, rmdir, rename, mkdir, link, symlink, chmod, chown)
      network: true         # connect, bind — with sockaddr parsing for AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC
      signal: true          # kill, tgkill, tkill, rt_sigqueueinfo, rt_tgsigqueueinfo — with optional redirect via register rewrite (kill/tkill/tgkill only)

    # Performance tuning
    performance:
      # seccomp-BPF pre-filter to reduce ptrace stops.
      # In "children" mode: installed in the child before exec. Works reliably.
      # In "pid" mode: NOT available in Phase 1. Falls back to PTRACE_O_TRACESYSGOOD
      #   (traces all syscalls, handler discards uninteresting ones). Adds ~10-30% overhead.
      # Phase 3 may add pre-filter injection for pid/sidecar mode.
      seccomp_prefilter: true  # Only effective in children mode for Phase 1

      # Maximum concurrent tracees before warning. 0 = unlimited.
      max_tracees: 500

      # When a tracee is stopped, maximum time (ms) to hold it before force-allowing.
      # Prevents a hung policy decision from blocking the workload indefinitely.
      max_hold_ms: 5000

    # Anti-detection mitigation
    # Controls whether and how agentsh masks TracerPid in /proc/<pid>/status.
    #   "off"        — no masking (default)
    #   "ptrace"     — intercept /proc reads via ptrace (works everywhere, including Fargate)
    #   "ld_preload" — inject LD_PRELOAD library to hook read() (lower overhead, no static binaries)
    #   "mount"      — bind-mount modified /proc (requires mount namespace or CAP_SYS_ADMIN)
    mask_tracer_pid: "off"

    # Fail-open vs fail-closed when ptrace attachment fails.
    # "fail_open"   — log warning, let process run untraced
    # "fail_closed" — kill the untraced process (strict security)
    on_attach_failure: "fail_open"
```

### 3.2 Environment Variable Overrides

| Variable | Maps To | Notes |
|----------|---------|-------|
| `AGENTSH_PTRACE_ENABLED` | `sandbox.ptrace.enabled` | `"true"` / `"1"` enables |
| `AGENTSH_PTRACE_TARGET_PID` | `sandbox.ptrace.target_pid` | Integer PID |
| `AGENTSH_PTRACE_TARGET_PID_FILE` | `sandbox.ptrace.target_pid_file` | Path to file containing PID |
| `AGENTSH_PTRACE_ATTACH_MODE` | `sandbox.ptrace.attach_mode` | `"children"`, `"pid"` (Phase 1); `"sidecar"` (Phase 3) |
| `AGENTSH_PTRACE_PREFILTER` | `sandbox.ptrace.performance.seccomp_prefilter` | `"true"` / `"false"` (only effective in children mode) |

### 3.3 Security Mode Integration

In `internal/capabilities/security_caps.go`, add a new mode:

```go
const (
    ModeFull         = "full"          // 100%
    ModePtrace       = "ptrace"        // NEW — opt-in only
    ModeLandlock     = "landlock"      // 85%
    ModeLandlockOnly = "landlock-only" // 80%
    ModeMinimal      = "minimal"       // 50%
)
```

`SelectMode()` update:

```go
func (c *SecurityCapabilities) SelectMode() string {
    if c.Seccomp && c.EBPF && c.FUSE {
        return ModeFull
    }
    // ptrace mode: ptrace available + explicitly enabled in config
    // Note: ptrace is NOT auto-selected. It only activates when
    // sandbox.ptrace.enabled=true. This is a manual opt-in.
    if c.Ptrace && c.PtraceEnabled {
        return ModePtrace
    }
    if c.Landlock && c.FUSE {
        return ModeLandlock
    }
    if c.Landlock {
        return ModeLandlockOnly
    }
    return ModeMinimal
}
```

Key design decision: **ptrace mode is never auto-selected**. It requires `sandbox.ptrace.enabled: true` in config. Auto-detection only reports its availability; the operator must opt in.

---

## 4. Capability Detection

### 4.1 Probing ptrace Availability

In `internal/capabilities/security_caps.go`, add:

```go
type SecurityCapabilities struct {
    // ... existing fields ...
    Ptrace        bool // SYS_PTRACE capability available and functional
    PtraceEnabled bool // Explicitly enabled in config (not auto-detected)
}
```

Detection logic (new file `internal/capabilities/check_ptrace_linux.go`):

```go
func checkPtraceCapability() bool {
    // Step 1: Check effective capabilities by parsing /proc/self/status.
    //
    // WARNING: Do not use unix.Capget with a single CapUserData struct.
    // LINUX_CAPABILITY_VERSION_3 requires TWO CapUserData structs (the
    // capability set is 64 bits split across two 32-bit structs). Using
    // a single struct silently reads only the low 32 bits. CAP_SYS_PTRACE
    // is bit 19, so it happens to be in the low struct — but the single-struct
    // pattern is a known footgun (golang/go#44312) and should not be copied.
    //
    // Instead, parse CapEff from /proc/self/status, which is always correct.
    capEff, err := readCapEff()
    if err != nil {
        return false
    }
    const capSysPtrace = 19
    if capEff&(1<<capSysPtrace) == 0 {
        return false
    }

    // Step 2: Functional probe — actually try to ptrace a child.
    // Capability bits can be present but the syscall blocked by seccomp.
    // The only reliable test is a real attach.
    return probePtraceAttach()
}

// readCapEff reads the effective capability set from /proc/self/status.
func readCapEff() (uint64, error) {
    data, err := os.ReadFile("/proc/self/status")
    if err != nil {
        return 0, err
    }
    for _, line := range strings.Split(string(data), "\n") {
        if strings.HasPrefix(line, "CapEff:\t") {
            hex := strings.TrimPrefix(line, "CapEff:\t")
            return strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
        }
    }
    return 0, fmt.Errorf("CapEff not found in /proc/self/status")
}

// probePtraceAttach forks a short-lived child and attempts PTRACE_SEIZE.
// This is the only reliable way to confirm ptrace actually works, because
// seccomp filters or LSMs can block ptrace even when the capability is present.
func probePtraceAttach() bool {
    // Fork a child that just sleeps briefly
    cmd := exec.Command("/bin/sleep", "0.1")
    if err := cmd.Start(); err != nil {
        return false
    }

    pid := cmd.Process.Pid

    // Try PTRACE_SEIZE (non-stopping attach)
    err := unix.PtraceSeize(pid, 0)
    if err != nil {
        cmd.Process.Kill()
        cmd.Wait()
        return false // ptrace blocked
    }

    // Seize succeeded — ptrace works.
    // Clean up: PTRACE_DETACH requires the tracee to be in ptrace-stop.
    // PTRACE_SEIZE does not stop the tracee, so we must interrupt first.
    if err := unix.PtraceInterrupt(pid); err != nil {
        // Interrupt failed — just kill the child.
        cmd.Process.Kill()
        cmd.Wait()
        return true // seize worked, ptrace is available
    }

    var status unix.WaitStatus
    _, err = unix.Wait4(pid, &status, 0, nil)
    if err == nil && status.Stopped() {
        // Got a valid ptrace-stop — safe to detach.
        unix.PtraceDetach(pid)
    }
    // If wait failed or status was unexpected, the kill below cleans up.

    cmd.Process.Kill()
    cmd.Wait()
    return true
}
```

### 4.2 `agentsh detect` Output

```
CAPABILITIES
----------------------------------------
  capabilities_drop          ✓
  cgroups_v2                 -
  ebpf                       -
  fuse                       -
  landlock                   -
  ptrace                     ✓     ← NEW
  seccomp                    -
  seccomp_user_notify        -

TIPS
----------------------------------------
  ptrace: Enables syscall-level enforcement via ptrace
    -> Set 'sandbox.ptrace.enabled: true' in config to activate
    -> Recommended for Fargate and other restricted container runtimes
```

---

## 5. Core Tracer Implementation

### 5.1 `internal/ptrace/tracer.go` — Event Loop

The tracer uses a single-threaded `wait4` loop (ptrace requires all operations from the same OS thread):

```go
type Tracer struct {
    cfg           TracerConfig
    policyEngine  PolicyEngine       // reuse existing interface
    eventChannel  chan<- IOEvent     // reuse existing IOEvent
    execHandler   *ExecveHandler    // reuse from internal/netmonitor/unix
    fileHandler   *FileHandler      // reuse from internal/netmonitor/unix
    signalEngine  *signal.Engine    // reuse from internal/signal
    processTree   *ProcessTree      // local tracee tree
    prefilter     *SeccompPrefilter // optional BPF installer (children mode only)
    prefilterActive bool            // true if prefilter was successfully installed

    // attachQueue receives PIDs from external goroutines (e.g., AttachPID API).
    // The tracer loop drains this channel and performs PTRACE_SEIZE on its
    // locked OS thread. This is the only safe way to add tracees at runtime.
    attachQueue   chan int

    // resumeQueue receives approval decisions from external goroutines.
    // When policy evaluation requires async approval (human or LLM), the
    // tracee is "parked" — left in ptrace-stop without resuming — and its
    // TID is stored in parkedTracees. When the approval callback fires, it
    // sends a resumeRequest to this channel. The tracer loop drains it
    // alongside attachQueue and resumes the parked tracee.
    resumeQueue   chan resumeRequest

    // mu protects tracees map and all TraceeState fields. Both the tracer loop
    // (writer) and external goroutines (readers: metrics, API) must hold mu.
    // Go's memory model requires synchronization on both sides for visibility,
    // and the race detector will flag unsynchronized writes even from a sole writer.
    // Keep critical sections short: read/mutate state under lock, then unlock
    // before doing expensive work (ptrace calls, policy evaluation).
    mu            sync.Mutex
    tracees       map[int]*TraceeState
    parkedTracees map[int]struct{}     // TIDs awaiting async approval

    stopped       chan struct{}
}

// resumeRequest carries an async approval decision back to the tracer loop.
type resumeRequest struct {
    TID   int
    Allow bool
    Errno int  // used when !Allow (e.g., EACCES)
}

type TraceeState struct {
    TID       int             // Thread ID (ptrace attaches to threads, not processes)
    TGID      int             // Thread group ID (= PID of the thread group leader)
    ParentPID int
    SessionID string
    InSyscall bool            // true = at syscall-enter, false = at syscall-exit
    LastNr    int             // syscall number at enter
    Attached  time.Time
    PendingDenyErrno int      // Non-zero if this thread needs return-value fixup at syscall-exit
    PendingInterrupt bool     // true if PTRACE_INTERRUPT was issued; cleared on PTRACE_EVENT_STOP
    IsVforkChild     bool     // true between PTRACE_EVENT_VFORK and PTRACE_EVENT_EXEC
    MemFD            int      // cached /proc/<tid>/mem fd, opened at attach, closed at detach
}
```

The main loop:

```go
func (t *Tracer) Run(ctx context.Context) error {
    // Lock to OS thread — ptrace requires single-thread affinity
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()

    for {
        // Phase 1: drain all pending attach and resume requests, check context.
        // This runs before every wait4 call, guaranteeing that queued
        // attaches and approval results are processed even if no tracee
        // stops are arriving.
        if err := t.drainQueues(ctx); err != nil {
            return err // ctx.Err()
        }

        // Phase 2: non-blocking wait for any tracee stop.
        // WNOHANG returns immediately if no tracee is stopped.
        var status unix.WaitStatus
        tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOHANG, nil)

        if err != nil {
            if err == unix.EINTR {
                continue
            }
            if err == unix.ECHILD {
                // No tracees at all. Block on attachQueue/resumeQueue or ctx.
                select {
                case <-ctx.Done():
                    return ctx.Err()
                case pid := <-t.attachQueue:
                    if err := t.attachProcess(pid); err != nil {
                        slog.Error("attach from queue failed", "pid", pid, "error", err)
                    }
                    continue
                case req := <-t.resumeQueue:
                    t.handleResumeRequest(req)
                    continue
                }
            }
            return fmt.Errorf("wait4: %w", err)
        }

        if tid == 0 {
            // WNOHANG: no tracee stopped right now.
            // Block briefly on queues or ctx to avoid busy-spinning.
            select {
            case <-ctx.Done():
                return ctx.Err()
            case pid := <-t.attachQueue:
                if err := t.attachProcess(pid); err != nil {
                    slog.Error("attach from queue failed", "pid", pid, "error", err)
                }
            case req := <-t.resumeQueue:
                t.handleResumeRequest(req)
            case <-time.After(5 * time.Millisecond):
            }
            continue
        }

        // A tracee stopped — handle it.
        t.handleStop(ctx, tid, status)
    }
}

// drainQueues processes all immediately-available attach and resume requests.
func (t *Tracer) drainQueues(ctx context.Context) error {
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case pid := <-t.attachQueue:
            if err := t.attachProcess(pid); err != nil {
                slog.Error("attach from queue failed", "pid", pid, "error", err)
            }
        case req := <-t.resumeQueue:
            t.handleResumeRequest(req)
        default:
            return nil // Queues drained
        }
    }
}

// handleResumeRequest processes an async approval decision for a parked tracee.
func (t *Tracer) handleResumeRequest(req resumeRequest) {
    t.mu.Lock()
    _, parked := t.parkedTracees[req.TID]
    if parked {
        delete(t.parkedTracees, req.TID)
    }
    t.mu.Unlock()

    if !parked {
        slog.Warn("resume request for non-parked tracee", "tid", req.TID)
        return
    }

    if req.Allow {
        t.allowSyscall(req.TID)
    } else {
        t.denySyscall(req.TID, req.Errno)
    }
}
```

**Why WNOHANG + channels, not blocking wait4:**

A blocking `wait4(-1, ...)` holds the tracer thread hostage until some tracee stops. If `AttachPID` enqueues a request or an approval callback fires while `wait4` is blocked, the request sits unprocessed until an unrelated tracee event happens — which may be never (e.g., if the only tracee is sleeping). Worse, if there are zero tracees, `wait4` returns `ECHILD` immediately, and a naive loop would exit before any attach request could be processed.

The WNOHANG pattern processes tracee stops when available, drains both the attach and resume queues between iterations, and uses a short `select` on the channels to avoid busy-spinning. The channels are the wakeup mechanism — no eventfd or self-pipe needed. Go's channel select is sufficient since the tracer thread only needs to multiplex between "tracee stopped" (poll via WNOHANG), "new attach" (attachQueue), and "approval result" (resumeQueue).
```

### 5.2 Stop Event Dispatch

```go
func (t *Tracer) handleStop(ctx context.Context, tid int, status unix.WaitStatus) {
    switch {
    case status.Exited() || status.Signaled():
        t.handleExit(tid, status)
        // No resume — process/thread is gone.

    case status.Stopped():
        sig := status.StopSignal()

        switch {
        case sig == unix.SIGTRAP|0x80:
            // Syscall-stop (PTRACE_O_TRACESYSGOOD).
            // handleSyscallStop owns the resume decision.
            t.handleSyscallStop(ctx, tid)

        case sig == unix.SIGTRAP:
            event := status.TrapCause()
            switch event {
            case unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_CLONE:
                t.handleNewChild(tid, event)
                t.resumeTracee(tid, 0)
            case unix.PTRACE_EVENT_VFORK:
                t.handleNewChild(tid, event)
                t.markVforkChild(tid) // Mark child as vfork child (§12.7)
                t.resumeTracee(tid, 0)
            case unix.PTRACE_EVENT_EXEC:
                t.handleExecEvent(ctx, tid)
                t.resumeTracee(tid, 0)
            case unix.PTRACE_EVENT_SECCOMP:
                // handleSeccompStop owns the resume decision.
                // It calls allowSyscall/denySyscall internally, which resume the tracee.
                // The dispatcher MUST NOT resume after this returns.
                t.handleSeccompStop(ctx, tid)
            case unix.PTRACE_EVENT_EXIT:
                t.handlePreExit(tid)
                t.resumeTracee(tid, 0)
            case unix.PTRACE_EVENT_STOP:
                // PTRACE_EVENT_STOP occurs in two situations with PTRACE_SEIZE:
                // 1. As a response to PTRACE_INTERRUPT (during attach sequence)
                // 2. As a group-stop (SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU)
                t.handleEventStop(tid)
            default:
                // Unknown ptrace event — resume to avoid hanging the tracee.
                t.resumeTracee(tid, 0)
            }

        default:
            // Signal-delivery-stop: deliver the signal to the tracee.
            t.resumeTracee(tid, int(sig))
        }
    }
}

// handleEventStop distinguishes between PTRACE_INTERRUPT responses (during
// attach) and genuine group-stops (job control signals). With PTRACE_SEIZE,
// group-stops are reported as PTRACE_EVENT_STOP, not as signal-delivery-stops.
// The tracer must use PTRACE_LISTEN (not PTRACE_CONT) to maintain group-stop
// semantics — resuming with PTRACE_CONT would suppress the stop and break
// job control.
func (t *Tracer) handleEventStop(tid int) {
    t.mu.Lock()
    state := t.tracees[tid]
    if state != nil && state.PendingInterrupt {
        // This is our attach-time interrupt response — clear the flag.
        // The attach sequence (attachThread) handles its own wait4/restart,
        // so this path is defensive only. Resume normally.
        state.PendingInterrupt = false
        t.mu.Unlock()
        t.resumeTracee(tid, 0)
        return
    }
    t.mu.Unlock()

    // Genuine group-stop. Use PTRACE_LISTEN to keep the tracee in
    // group-stop while allowing it to be woken by SIGCONT. PTRACE_CONT
    // would cancel the group-stop and break job control.
    unix.PtraceListen(tid)
}
```

**Resume ownership rule:** Every code path through `handleStop` must resume the tracee exactly once. The rule is:

- **Ptrace-event stops** (fork, exec, exit): the dispatcher handles state, then resumes. These handlers never call `allowSyscall`/`denySyscall`.
- **Syscall-stops** (SIGTRAP|0x80): `handleSyscallStop` owns the resume. It calls `resumeTracee` at the end of every path (allow, deny fixup, or uninteresting-skip).
- **Seccomp-event stops** (PTRACE_EVENT_SECCOMP): `handleSeccompStop` owns the resume. It delegates to handlers that call `allowSyscall` or `denySyscall`, each of which resumes the tracee. The dispatcher must not resume afterward.
- **Group-stops** (PTRACE_EVENT_STOP): `handleEventStop` uses `PTRACE_LISTEN` — not a resume, but keeps the tracee in group-stop until SIGCONT.
- **Signal-delivery stops**: the dispatcher resumes with the signal number.

### 5.3 Syscall-Enter / Syscall-Exit Handling

When using `PTRACE_O_TRACESYSGOOD` (without seccomp prefilter), every traced syscall produces two stops: syscall-enter and syscall-exit. At enter, we inspect arguments and decide allow/deny. At exit, we can inspect return values for audit and apply deny fixups.

When using the seccomp prefilter (`PTRACE_EVENT_SECCOMP`), we get a single stop at syscall-enter for interesting syscalls only. This is the preferred mode.

**`PTRACE_GET_SYSCALL_INFO` (Linux 5.3+):** For reading syscall state at enter/exit, use `PTRACE_GET_SYSCALL_INFO` instead of manually reading registers and tracking `InSyscall`. This returns a `ptrace_syscall_info` struct containing: entry-or-exit flag, syscall number + all 6 args (at entry), and return value (at exit) — architecture-independent. This eliminates the `InSyscall` toggle and the bugs that come from it getting out of sync. The `Regs` interface is still needed for **writes** (deny fixup via `SetSyscallNr`, redirect via `SetArg`), but all **reads** should go through `PTRACE_GET_SYSCALL_INFO`. Fargate runs kernel 5.10+, so this is always available in the target environment.

**Per-thread state machine for TRACESYSGOOD mode:**

```
                  ┌─────────────────────┐
                  │    Running          │
                  └─────┬───────────────┘
                        │ syscall instruction
                        ▼
         ┌──────────────────────────────┐
         │   Syscall-Enter Stop         │
         │   InSyscall = true           │
         │   LastNr = regs.SyscallNr()  │
         └──────┬──────────────┬────────┘
                │              │
          allow/audit      deny (set nr=-1,
          (resume)         PendingDenyErrno=E)
                │              │
                ▼              ▼
         ┌──────────────────────────────┐
         │   Syscall-Exit Stop          │
         │   InSyscall = false          │
         │   if PendingDenyErrno != 0:  │
         │     applyDenyFixup()         │
         └──────┬───────────────────────┘
                │ resume
                ▼
         ┌──────────────────────────────┐
         │   Running                    │
         └──────────────────────────────┘
```

```go
// handleSyscallStop is called for SIGTRAP|0x80 stops (PTRACE_O_TRACESYSGOOD).
// It tracks per-thread enter/exit state and dispatches accordingly.
//
// Synchronization: ALL reads and writes to TraceeState are under mu.
// Although the tracer loop is the sole writer, Go's memory model requires
// synchronization for visibility to reader goroutines (metrics, API responses).
// The race detector will flag unsynchronized writes regardless of single-writer
// guarantees. Keep the critical section short: read/mutate state, unlock, then
// do the expensive work (getRegs, policy evaluation, resume).
func (t *Tracer) handleSyscallStop(ctx context.Context, tid int) {
    t.mu.Lock()
    state := t.tracees[tid]
    if state == nil {
        t.mu.Unlock()
        t.allowSyscall(tid)
        return
    }
    entering := !state.InSyscall
    state.InSyscall = entering // Flip: false→true on enter, true→false on exit
    pendingErrno := 0
    if !entering {
        pendingErrno = state.PendingDenyErrno
        state.PendingDenyErrno = 0
    }
    t.mu.Unlock()

    if entering {
        // === Syscall-enter ===
        regs, err := t.getRegs(tid)
        if err != nil {
            t.allowSyscall(tid)
            return
        }

        nr := regs.SyscallNr()

        t.mu.Lock()
        state.LastNr = nr
        t.mu.Unlock()

        // Dispatch to handler. Each MUST call allowSyscall or denySyscall exactly once.
        switch {
        case isExecveSyscall(nr):
            t.handleExecve(ctx, tid, regs)
        case isFileSyscall(nr):
            t.handleFile(ctx, tid, regs)
        case isNetworkSyscall(nr):
            t.handleNetwork(ctx, tid, regs)
        case isSignalSyscall(nr):
            t.handleSignal(ctx, tid, regs)
        default:
            t.allowSyscall(tid)
        }

    } else {
        // === Syscall-exit ===
        if pendingErrno != 0 {
            t.applyDenyFixup(tid, pendingErrno)
        }
        t.allowSyscall(tid)
    }
}
```

**`handleSeccompStop`** is used when the prefilter is active. `PTRACE_EVENT_SECCOMP` fires at syscall-enter only. There is no automatic paired syscall-exit stop — that is a `PTRACE_O_TRACESYSGOOD` behavior, not a seccomp-event behavior.

This creates a control-flow difference for deny:

- **Allow:** handler calls `allowSyscall`, which uses `PtraceCont`. The thread runs until the next seccomp event. No exit stop is generated.
- **Deny:** handler calls `denySyscall`, which sets `nr = -1`, stores `PendingDenyErrno`, sets `InSyscall = true` on the thread state, and resumes with `PtraceSyscall` (not `PtraceCont`). This one-off `PtraceSyscall` causes the kernel to produce a syscall-exit stop (SIGTRAP|0x80), which the main dispatcher routes to `handleSyscallStop`. `handleSyscallStop` sees `InSyscall = true`, applies the deny fixup, clears state, and resumes with `PtraceCont` — returning the thread to its normal seccomp-event tracing mode.

```
Seccomp-event mode deny flow:

  PTRACE_EVENT_SECCOMP        handleSeccompStop → denySyscall()
      │                            │  set nr=-1
      │                            │  PendingDenyErrno = EACCES
      │                            │  InSyscall = true
      │                            │  resume with PtraceSyscall (one-off)
      ▼
  SIGTRAP|0x80 (exit)         handleSyscallStop
      │                            │  sees InSyscall = true
      │                            │  applyDenyFixup (set retval = -EACCES)
      │                            │  InSyscall = false
      │                            │  resume with PtraceCont (back to normal)
      ▼
  Running (next seccomp event)
```

```go
func (t *Tracer) handleSeccompStop(ctx context.Context, tid int) {
    regs, err := t.getRegs(tid)
    if err != nil {
        t.allowSyscall(tid) // Resume to avoid hanging
        return
    }

    nr := regs.SyscallNr()

    // Dispatch to handler. Each handler MUST call exactly one of:
    //   allowSyscall(tid)  — resumes with PtraceCont, no exit stop
    //   denySyscall(tid, errno) — resumes with PtraceSyscall, produces exit stop for fixup
    // The dispatcher does NOT resume after this function returns.
    switch {
    case isExecveSyscall(nr):
        t.handleExecve(ctx, tid, regs)
    case isFileSyscall(nr):
        t.handleFile(ctx, tid, regs)
    case isNetworkSyscall(nr):
        t.handleNetwork(ctx, tid, regs)
    case isSignalSyscall(nr):
        t.handleSignal(ctx, tid, regs)
    default:
        t.allowSyscall(tid)
    }
}
```

And the updated `denySyscall` / `allowSyscall` to handle both modes:

```go
// denySyscall invalidates the current syscall and arranges for the return
// value to be overwritten with -errno at the next syscall-exit stop.
// Works in both TRACESYSGOOD and TRACESECCOMP modes.
//
// SAFETY: If setRegs fails, the tracee's original syscall is intact and would
// execute unmodified — a silent security bypass. In this case we kill the
// tracee. A failed deny must never silently become an allow.
func (t *Tracer) denySyscall(tid int, errno int) error {
    regs, err := t.getRegs(tid)
    if err != nil {
        return err
    }
    regs.SetSyscallNr(-1)
    if err := t.setRegs(tid, regs); err != nil {
        // Cannot deny — kill the tracee to prevent the syscall from executing.
        t.mu.Lock()
        state := t.tracees[tid]
        tgid := tid
        if state != nil {
            tgid = state.TGID
        }
        t.mu.Unlock()
        unix.Tgkill(tgid, tid, unix.SIGKILL)
        return fmt.Errorf("deny failed, killed tid %d: %w", tid, err)
    }

    // Mark for fixup at syscall-exit.
    // Set InSyscall = true so handleSyscallStop knows an exit stop is expected.
    // This is a no-op in TRACESYSGOOD mode (InSyscall is already true at enter),
    // but critical in TRACESECCOMP mode where InSyscall is not normally tracked.
    t.mu.Lock()
    if state, ok := t.tracees[tid]; ok {
        state.PendingDenyErrno = errno
        state.InSyscall = true
    }
    t.mu.Unlock()

    // Resume with PtraceSyscall to get the syscall-exit stop for fixup.
    return unix.PtraceSyscall(tid, 0)
}

// allowSyscall resumes the tracee, allowing the syscall to proceed normally.
// In TRACESYSGOOD mode, uses PtraceSyscall to continue tracing.
// In TRACESECCOMP mode, uses PtraceCont so we only stop at the next seccomp event.
func (t *Tracer) allowSyscall(tid int) {
    if t.prefilterActive {
        unix.PtraceCont(tid, 0)
    } else {
        unix.PtraceSyscall(tid, 0)
    }
}

// resumeTracee resumes a tracee with an optional signal to deliver.
// Used for non-syscall stops (ptrace events, signal-delivery stops).
func (t *Tracer) resumeTracee(tid int, sig int) {
    if t.prefilterActive {
        unix.PtraceCont(tid, sig)
    } else {
        unix.PtraceSyscall(tid, sig)
    }
}
```

### 5.4 Deny Fixup

The two-phase deny approach is defined in `denySyscall` (above). The fixup function is called by `handleSyscallStop` at syscall-exit:

```go
// applyDenyFixup overwrites the syscall return value with -errno.
// Called at syscall-exit after denySyscall set nr=-1 at syscall-enter.
func (t *Tracer) applyDenyFixup(tid int, errno int) {
    regs, err := t.getRegs(tid)
    if err != nil {
        return
    }
    regs.SetReturnValue(-int64(errno))
    t.setRegs(tid, regs)
}
```

---

## 6. Architecture-Specific Register Access

### 6.1 Interface

```go
// Regs abstracts architecture-specific register access.
type Regs interface {
    SyscallNr() int
    SetSyscallNr(nr int)
    Arg(n int) uint64          // n = 0..5
    SetArg(n int, val uint64)
    ReturnValue() int64
    SetReturnValue(val int64)
    InstructionPointer() uint64
}
```

### 6.2 amd64 (`args_amd64.go`)

```go
type amd64Regs struct {
    raw unix.PtraceRegsAmd64
}

func (r *amd64Regs) SyscallNr() int       { return int(r.raw.Orig_rax) }
func (r *amd64Regs) SetSyscallNr(nr int)  { r.raw.Orig_rax = uint64(nr) }
func (r *amd64Regs) ReturnValue() int64   { return int64(r.raw.Rax) }
func (r *amd64Regs) SetReturnValue(v int64) { r.raw.Rax = uint64(v) }

func (r *amd64Regs) Arg(n int) uint64 {
    switch n {
    case 0: return r.raw.Rdi
    case 1: return r.raw.Rsi
    case 2: return r.raw.Rdx
    case 3: return r.raw.R10
    case 4: return r.raw.R8
    case 5: return r.raw.R9
    default: return 0
    }
}
```

### 6.3 arm64 (`args_arm64.go`)

```go
type arm64Regs struct {
    raw unix.PtraceRegsArm64
}

func (r *arm64Regs) SyscallNr() int       { return int(r.raw.Regs[8]) }
func (r *arm64Regs) SetSyscallNr(nr int)  { r.raw.Regs[8] = uint64(nr) }
func (r *arm64Regs) ReturnValue() int64   { return int64(r.raw.Regs[0]) }
func (r *arm64Regs) SetReturnValue(v int64) { r.raw.Regs[0] = uint64(v) }

func (r *arm64Regs) Arg(n int) uint64 {
    if n < 0 || n > 5 { return 0 }
    return r.raw.Regs[n] // x0..x5
}
```

---

## 7. seccomp Pre-Filter (Performance)

### 7.1 Why It Matters

Without a pre-filter, `PTRACE_O_TRACESYSGOOD` stops on **every** syscall. A typical `npm install` makes millions of syscalls; stopping on all of them adds 50-100µs per syscall (two context switches), making the workload 5-20x slower.

With a seccomp-BPF pre-filter installed in the tracee, only interesting syscalls trigger `PTRACE_EVENT_SECCOMP`. All other syscalls execute at native speed with zero overhead.

### 7.2 Children Mode (Phase 1): Pre-exec Filter Installation

In `children` mode, agentsh forks the workload process. Before `exec`, the child installs the seccomp filter itself. This is the standard, well-understood pattern:

```go
// In the forked child, before exec:
func (child *ChildProcess) installPrefilter(tracedSyscalls []int) error {
    // Required: set no_new_privs so seccomp filter can be installed without root
    if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
        return fmt.Errorf("set no_new_privs: %w", err)
    }

    // Build BPF program: SECCOMP_RET_TRACE for interesting syscalls,
    // SECCOMP_RET_ALLOW for everything else
    prog := buildPrefilterBPF(tracedSyscalls)

    // Install the filter using the seccomp() syscall (preferred over prctl)
    if err := seccomp.SetModeFilter(prog); err != nil {
        return fmt.Errorf("seccomp set_mode_filter: %w", err)
    }

    return nil
}
```

The filter uses `SECCOMP_RET_TRACE` (not `SECCOMP_RET_TRAP` or `SECCOMP_RET_KILL`). When a traced syscall is hit, the kernel delivers a `PTRACE_EVENT_SECCOMP` stop to the tracer. Non-traced syscalls execute at native speed.

This is clean, reliable, and the approach used by Datadog CWS in "wrap mode."

### 7.3 PID Mode (Phase 1): No Pre-Filter, TRACESYSGOOD Fallback

When attaching to an already-running process (`pid` mode), the pre-filter cannot be installed in Phase 1. The reasons:

1. **`seccomp()` applies to the calling thread.** To filter an external process, you'd need to inject a `seccomp()` syscall into every thread of the tracee. That requires syscall injection (Phase 4 technique) plus iterating all threads in `/proc/<pid>/task/*`.
2. **`no_new_privs` requirement.** If the tracee hasn't called `prctl(PR_SET_NO_NEW_PRIVS)`, seccomp filter installation requires `CAP_SYS_ADMIN` *in the tracee's user namespace*, which the tracer doesn't have.
3. **Existing seccomp filters.** The tracee may already have a seccomp profile (common in Kubernetes). seccomp filters stack, so a new filter can be added on top — but interactions between SECCOMP_RET_TRACE and existing RET_KILL/RET_ERRNO rules need careful analysis per-deployment.

Instead, `pid` mode uses `PTRACE_O_TRACESYSGOOD`, which stops on every syscall. The handler loop checks the syscall number and immediately resumes uninteresting ones. Measured overhead is 10-30% on I/O-heavy workloads, which is acceptable for agent sandboxes.

**Phase 3 research spike:** Investigate sidecar pre-filter injection via syscall injection. This is feasible (CRIU does it) but complex enough to warrant its own design doc after Phase 2 overhead measurements prove it's actually needed.

### 7.4 Syscalls to Trace

The default set, matching agentsh's existing seccomp and file/network/signal interception:

**Exec:** `execve` (59), `execveat` (322)

**File:** `openat` (257), `openat2` (437), `unlinkat` (263), `mkdirat` (258), `renameat2` (316), `linkat` (265), `symlinkat` (266), `fchmodat` (268), `fchownat` (260)  
Legacy (amd64): `open` (2), `unlink` (87), `rename` (82), `mkdir` (83), `rmdir` (84), `link` (86), `symlink` (88), `chmod` (90), `chown` (92)

**Network:** `connect` (42), `socket` (41), `bind` (49), `sendto` (44), `listen` (50)

**Signal:** `kill` (62), `tgkill` (234), `tkill` (200), `rt_sigqueueinfo` (129), `rt_tgsigqueueinfo` (297)

---

## 8. Process Discovery and Attachment

### 8.1 Target Discovery

Phase 1 supports two discovery modes only. Automatic sidecar discovery is deferred to Phase 3 after real Fargate E2E testing.

**Why no auto-discovery in Phase 1:** On ECS Fargate with `pidMode: "task"`, PID 1 is the AWS `pause` container — not the workload. On EKS, PID 1 is the Kubernetes `pause` container. The tracer cannot assume that "find PID 1" or "find a non-self process with PPid ≤ 1" returns the workload. Getting this wrong means attaching to the pause container or to nothing.

**Mode: `children` (recommended for Phase 1)**

agentsh forks the workload process directly. The tracer attaches before `exec`. This is the simplest and most reliable path — no discovery needed, no race between process start and attach.

```go
func (t *Tracer) startAndTrace(ctx context.Context, cmd string, args []string) (int, error) {
    child, err := t.forkChild(cmd, args)
    if err != nil {
        return 0, err
    }
    // Child is stopped at PTRACE_EVENT_EXEC before its first instruction
    return child.PID, nil
}
```

**Mode: `pid` (for sidecar deployments)**

The operator provides an explicit PID via config or environment variable (`AGENTSH_PTRACE_TARGET_PID`). For Fargate sidecar deployments, the workload container's entrypoint writes its own PID to a shared volume, and agentsh reads it:

```bash
# Workload container entrypoint
echo $$ > /shared/workload.pid
exec "$@"
```

```yaml
# agentsh config
sandbox:
  ptrace:
    enabled: true
    attach_mode: "pid"
    target_pid_file: "/shared/workload.pid"  # polls until file appears
```

```go
func (t *Tracer) discoverTarget() (int, error) {
    // Explicit PID from config or env
    if t.cfg.TargetPID > 0 {
        return t.cfg.TargetPID, nil
    }

    // PID file (for sidecar deployments)
    if t.cfg.TargetPIDFile != "" {
        return t.pollPIDFile(t.cfg.TargetPIDFile, 30*time.Second)
    }

    return 0, fmt.Errorf("attach_mode 'pid' requires target_pid or target_pid_file")
}
```

**Mode: `sidecar` (Phase 3 — deferred)**

Automatic `/proc` enumeration and process identification. Requires real Fargate E2E testing to understand the actual process tree layout, handle the `pause` container correctly, and deal with multi-container tasks where multiple workload containers may be present. Not safe to ship without that testing.

### 8.2 Attachment Sequence

**Critical: ptrace attaches to threads, not processes.** The ptrace man page is explicit: "tracee" means one thread. A multithreaded target (Node.js with libuv, Go runtime, Python with threading) has threads that must each be individually attached. Missing a thread means that thread's syscalls are completely unmonitored — a security hole, not a degraded mode.

**Step 1: Attach all existing threads**

```go
func (t *Tracer) attachProcess(pid int) error {
    // Enumerate all threads in the thread group
    taskDir := fmt.Sprintf("/proc/%d/task", pid)
    entries, err := os.ReadDir(taskDir)
    if err != nil {
        // Single-threaded fallback: just attach the PID
        return t.attachThread(pid)
    }

    var firstErr error
    for _, e := range entries {
        tid, err := strconv.Atoi(e.Name())
        if err != nil {
            continue
        }
        if err := t.attachThread(tid); err != nil {
            if firstErr == nil {
                firstErr = err
            }
            slog.Warn("failed to attach thread", "tid", tid, "pid", pid, "error", err)
        }
    }
    return firstErr
}
```

**Step 2: Attach a single thread with PTRACE_SEIZE**

`PTRACE_SEIZE` does **not** stop the tracee. The man page is explicit: the tracee continues running after seize. To actually start tracing syscalls, the tracer must interrupt the thread and restart it in the tracing regime:

```
PTRACE_SEIZE → PTRACE_INTERRUPT → wait for PTRACE_EVENT_STOP → PTRACE_SYSCALL (or PTRACE_CONT)
```

Without this sequence, an already-running thread will never enter syscall-stop, and the tracer's `wait4` loop will never see events from it.

```go
func (t *Tracer) attachThread(tid int) error {
    // PTRACE_SEIZE is preferred over PTRACE_ATTACH:
    // - Does not send SIGSTOP to the tracee
    // - Supports PTRACE_EVENT_SECCOMP
    // - Tracee continues running until explicitly interrupted
    err := unix.PtraceSeize(tid, t.ptraceOptions())
    if err != nil {
        return fmt.Errorf("PTRACE_SEIZE tid %d: %w", tid, err)
    }

    // Read TGID before interrupting — we need this for every thread.
    // TGID is the thread group leader's PID (= the "process ID" in user-visible terms).
    // For the leader thread, TID == TGID. For non-leader threads, TID != TGID.
    tgid, err := readTGID(tid)
    if err != nil {
        t.safeDetach(tid) // Tracee is not stopped — use safe cleanup
        return fmt.Errorf("read TGID for tid %d: %w", tid, err)
    }

    // PTRACE_SEIZE does NOT stop the tracee. We must explicitly interrupt it
    // to bring it into ptrace-stop, then restart with PTRACE_SYSCALL so it
    // enters the tracing regime. Without this, wait4 will never see events.
    if err := unix.PtraceInterrupt(tid); err != nil {
        t.safeDetach(tid) // Interrupt failed — tracee is not stopped
        return fmt.Errorf("PTRACE_INTERRUPT tid %d: %w", tid, err)
    }

    // Wait for the PTRACE_EVENT_STOP that PTRACE_INTERRUPT produces.
    var status unix.WaitStatus
    _, err = unix.Wait4(tid, &status, 0, nil)
    if err != nil {
        // wait4 failed — tracee state is uncertain. Best effort: try interrupt+wait again,
        // then detach. If that also fails, the tracee may be stuck, but PTRACE_O_EXITKILL
        // will clean it up when the tracer exits.
        t.safeDetach(tid)
        return fmt.Errorf("wait4 after interrupt tid %d: %w", tid, err)
    }

    // Validate we got the expected stop. PTRACE_INTERRUPT on a seized tracee
    // produces a group-stop with PTRACE_EVENT_STOP. Verify this rather than
    // blindly restarting — a wrong stop kind here means we misunderstood the
    // tracee's state, which is a correctness hazard.
    if !status.Stopped() {
        // Not stopped — should not happen after wait4 succeeds. Detach and bail.
        // Tracee is in an unknown state; safeDetach will try to recover.
        t.safeDetach(tid)
        return fmt.Errorf("tid %d: expected ptrace-stop after interrupt, got status %v", tid, status)
    }
    // PTRACE_EVENT_STOP is signaled as (SIGTRAP | PTRACE_EVENT_STOP << 8).
    // Go's WaitStatus.TrapCause() extracts the event.
    if event := status.TrapCause(); event != unix.PTRACE_EVENT_STOP {
        // Not the expected group-stop. Could be a signal-delivery-stop if the
        // thread was already stopping for another reason. Log and proceed with
        // caution — the thread is stopped, just not via the path we expected.
        slog.Warn("unexpected stop kind after PTRACE_INTERRUPT",
            "tid", tid, "event", event, "signal", status.StopSignal())
    }

    // From this point, the tracee is in ptrace-stop. PTRACE_DETACH is safe
    // in error paths below (no need for safeDetach).

    // Restart in the appropriate tracing mode.
    if t.prefilterActive {
        err = unix.PtraceCont(tid, 0)
    } else {
        err = unix.PtraceSyscall(tid, 0)
    }
    if err != nil {
        unix.PtraceDetach(tid) // Safe: tracee is in ptrace-stop
        return fmt.Errorf("restart tid %d: %w", tid, err)
    }

    // Open /proc/<tid>/mem for memory reads/writes (§9.5).
    // Cached for the lifetime of the tracee — closed in handleExit.
    memFD, err := unix.Open(fmt.Sprintf("/proc/%d/mem", tid), unix.O_RDWR, 0)
    if err != nil {
        // Read-only fallback (some configurations restrict O_RDWR)
        memFD, _ = unix.Open(fmt.Sprintf("/proc/%d/mem", tid), unix.O_RDONLY, 0)
    }

    // Record tracee thread — TGID is populated from /proc, not left as zero.
    t.mu.Lock()
    t.tracees[tid] = &TraceeState{
        TID:      tid,
        TGID:     tgid,
        Attached: time.Now(),
        MemFD:    memFD,
    }
    t.mu.Unlock()

    return nil
}

// safeDetach detaches from a seized tracee that may not be in ptrace-stop.
// PTRACE_DETACH is a restarting operation that requires the tracee to be
// in ptrace-stop. If the tracee is running (e.g., we seized but haven't
// interrupted yet, or interrupt failed), we must stop it first.
func (t *Tracer) safeDetach(tid int) {
    // Try interrupt → wait → detach. If any step fails, PTRACE_O_EXITKILL
    // will clean up when the tracer exits.
    if err := unix.PtraceInterrupt(tid); err != nil {
        // Can't interrupt — the tracee may not be ours anymore, or it exited.
        // Nothing more we can do.
        return
    }
    var status unix.WaitStatus
    if _, err := unix.Wait4(tid, &status, 0, nil); err != nil {
        return
    }
    if status.Stopped() {
        unix.PtraceDetach(tid)
    }
}

// readTGID reads the thread group ID from /proc/<tid>/status.
// This is the canonical way to determine which process a thread belongs to.
func readTGID(tid int) (int, error) {
    data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
    if err != nil {
        return 0, err
    }
    for _, line := range strings.Split(string(data), "\n") {
        if strings.HasPrefix(line, "Tgid:\t") {
            return strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Tgid:\t")))
        }
    }
    return 0, fmt.Errorf("Tgid not found in /proc/%d/status", tid)
}
```

**Note on `children` mode:** When agentsh forks the child, the child is created with `PTRACE_TRACEME` (or the parent uses `PTRACE_SEIZE` before `exec`). In this case the child is already stopped at `PTRACE_EVENT_EXEC` before executing its first instruction — no interrupt/wait sequence is needed.

**Step 3: seccomp pre-filter (children mode only in Phase 1)**

In `children` mode, the pre-filter is installed in the child before `exec`, which is trivial — the child calls `prctl(PR_SET_NO_NEW_PRIVS, 1)` then `seccomp(SECCOMP_SET_MODE_FILTER, ...)` before exec'ing the workload. This is a standard and well-understood pattern.

In `pid`/`sidecar` mode (attaching to an already-running process), pre-filter injection requires syscall injection into the tracee to call `seccomp()` on the tracee's behalf. This has complex interactions with `no_new_privs`, existing seccomp filters, and per-thread filter semantics (`seccomp()` applies to the calling thread, not the whole process — every thread must be individually filtered). **This is deferred to Phase 3** as a research spike.

Without the pre-filter in `pid` mode, the tracer uses `PTRACE_O_TRACESYSGOOD`, which stops on every syscall. The handler immediately resumes uninteresting syscalls. Overhead is higher (~10-30% on I/O-heavy workloads) but functional.

```go
func (t *Tracer) ptraceOptions() int {
    opts := unix.PTRACE_O_TRACECLONE |
        unix.PTRACE_O_TRACEFORK |
        unix.PTRACE_O_TRACEVFORK |
        unix.PTRACE_O_TRACEEXEC |
        unix.PTRACE_O_TRACEEXIT |
        unix.PTRACE_O_EXITKILL   // Kill all tracees if tracer dies. Non-negotiable for security.

    if t.prefilterActive {
        opts |= unix.PTRACE_O_TRACESECCOMP
    } else {
        opts |= unix.PTRACE_O_TRACESYSGOOD
    }

    return opts
}
```

**`PTRACE_O_EXITKILL`:** This ensures all tracees receive `SIGKILL` if the tracer exits unexpectedly (crash, OOM, etc.). Without it, a tracee that was stopped mid-syscall stays frozen forever, or worse, resumes running unmonitored. This is mandatory for a security product and must be set on every attachment.

**Non-leader-thread exec:** When a non-leader thread calls `execve`, the kernel replaces the entire thread group. The thread leader's TID is preserved, but the calling thread's TID disappears. The tracer receives `PTRACE_EVENT_EXEC` for the thread that called `execve`, and must update its internal state to reflect that the thread group now has a single thread with the leader's TID. The old non-leader TID entries should be removed from the tracee map.

```go
func (t *Tracer) handleExecEvent(ctx context.Context, tid int) {
    // On exec, the kernel collapses the thread group to a single thread.
    // The surviving thread takes the thread group leader's TID.
    // All other threads in the group are destroyed.
    t.mu.Lock()
    state := t.tracees[tid]
    if state == nil {
        t.mu.Unlock()
        return
    }

    // Clear vfork flag — exec completes the vfork contract.
    state.IsVforkChild = false

    // Get the former thread group leader's TID from ptrace
    formerTID, err := unix.PtraceGetEventMsg(tid)
    if err == nil && int(formerTID) != tid {
        // This thread took over the leader's TID. The old leader TID
        // may still be in our map — remove it and replace.
        delete(t.tracees, int(formerTID))
    }

    // Remove all other threads from this thread group
    // (they were killed by the exec)
    tgid := state.TGID
    for otherTID, otherState := range t.tracees {
        if otherState.TGID == tgid && otherTID != tid {
            delete(t.tracees, otherTID)
        }
    }
    t.mu.Unlock()

    // Invalidate per-tracee caches. After exec the entire address space is
    // remapped — VDSO base changes (ASLR), scratch pages are gone.
    delete(t.gadgetCache, tid)
    delete(t.scratchPages, tid)
}
```

### 8.3 Automatic Child Inheritance

When a tracee forks/clones, the kernel automatically attaches ptrace to the child (due to `PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE`). The child is stopped with a `PTRACE_EVENT_FORK`/`PTRACE_EVENT_CLONE` event before it executes any instructions.

**Identity model:** The tracer map is keyed by **TID** (thread ID), because ptrace operates on individual threads. The process tree is built from **TGID** (thread group ID), because policy, audit, and steering operate at the process level. The projection is:

- `t.tracees[tid]` → per-thread state (registers, syscall enter/exit, deny fixup)
- `t.processTree` → TGID-to-TGID parent/child relationships (process-level)
- Emitted events carry both: `ProcessID` = TGID (for policy attribution and UI), `Metadata["tid"]` = TID (for debugging)

This means `processTree.AddChild()` always takes TGID arguments, never raw TIDs. A new thread within the same process does not create a process tree edge. Thread-vs-process identity is determined by reading `/proc/<childTid>/status` for the actual TGID, not by inferring from the ptrace event type (which the man page documents as unreliable for this purpose).

```go
func (t *Tracer) handleNewChild(parentTID int, event int) {
    childTID, err := unix.PtraceGetEventMsg(parentTID)
    if err != nil {
        return
    }
    tid := int(childTID)

    // Read the child's actual TGID from /proc. Do NOT infer identity from
    // the ptrace event type. The man page documents that clone() with CLONE_VFORK
    // may surface as PTRACE_EVENT_VFORK, and clone() with exit signal SIGCHLD
    // may surface as PTRACE_EVENT_FORK. The event type does not reliably
    // distinguish "new thread" from "new process." /proc is the source of truth.
    childTGID, err := readTGID(tid)
    if err != nil {
        // Child may have already exited. Log and skip.
        slog.Warn("handleNewChild: cannot read TGID, skipping", "tid", tid, "error", err)
        return
    }

    t.mu.Lock()
    parent := t.tracees[parentTID]

    // Determine relationship by comparing TGIDs, not event types.
    // Same TGID as parent → new thread within the same process.
    // Different TGID → new process (child is its own thread group leader).
    isNewProcess := childTGID != parent.TGID

    t.tracees[tid] = &TraceeState{
        TID:       tid,
        TGID:      childTGID,
        ParentPID: parent.TGID,
        SessionID: parent.SessionID,
        Attached:  time.Now(),
    }
    t.mu.Unlock()

    // Process tree tracks TGID-to-TGID relationships only.
    // New thread within same process does not create a tree edge.
    if isNewProcess {
        t.processTree.AddChild(parent.TGID, childTGID)
    }

    // Emit event.
    // ProcessID = TGID for policy attribution. TID in metadata for debugging.
    eventType := EventType("process_fork")
    if !isNewProcess {
        eventType = EventType("thread_clone")
    }
    t.emitEvent(IOEvent{
        Type:      eventType,
        ProcessID: childTGID,
        Metadata: map[string]any{
            "tid":         tid,
            "parent_tgid": parent.TGID,
            "parent_tid":  parentTID,
            "new_process": isNewProcess,
        },
        Platform: "ptrace",
    })
}
```

---

## 9. Handler Reuse

### 9.1 ExecveHandler

The ptrace tracer reuses `internal/netmonitor/unix.ExecveHandler` directly. The handler's `Handle(ctx, ExecveContext) ExecveResult` method is policy-engine-agnostic; it doesn't know whether the caller is seccomp or ptrace.

The ptrace layer is responsible for:
1. Reading filename and argv from tracee memory (see §9.5 Memory Access below)
2. Building an `ExecveContext`
3. Calling `handler.Handle()`
4. Translating the `ExecveResult` into ptrace actions (allow/deny/redirect)

For redirect, ptrace rewrites the filename pointer in the tracee's registers to point to the agentsh-stub path, analogous to how the seccomp handler uses `handleRedirect`.

### 9.2 FileHandler

Reuses `internal/netmonitor/unix.FileHandler`. The ptrace layer reads file args from registers, resolves paths via `resolvePathAt` (already uses `/proc/<pid>/cwd` and `/proc/<pid>/fd/`), and calls the handler.

**Reuse caveat:** `FileHandler.Handle()` currently treats paths under a FUSE mount as audit-only (because FUSE handles enforcement). In ptrace mode, there is no FUSE mount, so the handler must always take the full enforcement path. This requires either passing a nil `MountRegistry` (which the handler already handles correctly — it skips the FUSE check) or adding a flag to force enforcement mode. The `Source` field in emitted events should be `"ptrace"` not `"seccomp"`. Expect some surgery around these FUSE/seccomp assumptions in the existing Linux path.

### 9.3 Signal Engine

Reuses `internal/signal.Engine`. The ptrace layer extracts signal context (target PID, signal number) from registers and calls the engine's policy evaluation. For redirect (e.g., SIGKILL → SIGTERM), ptrace modifies the signal argument register before resuming.

### 9.4 Network

For `connect` syscalls, the ptrace layer reads the `sockaddr` from tracee memory (same `ReadSockaddr` + `ParseSockaddr` helpers), checks network policy, and allows/denies. This provides connection-level visibility without eBPF.

DNS inspection works by intercepting `connect` to port 53 and `sendto` to port 53, then reading the DNS query from the tracee's buffer. This is less complete than eBPF's in-kernel inspection but covers the common case.

### 9.5 Memory Access

All reads and writes to tracee memory use `/proc/<tid>/mem` with `pread`/`pwrite`. This is preferred over `process_vm_readv` because:

1. **Portability:** Works across any namespace configuration as long as the tracer has ptrace access. `process_vm_readv` fails across some user namespace boundaries.
2. **Simplicity:** `pread` is a single syscall with no scatter-gather setup.
3. **Reliability:** `/proc/<pid>/mem` access is gated by the same ptrace permissions the tracer already holds — no additional capability requirements.

The fd is opened once at attach time and cached in `TraceeState.MemFD`. Closed at detach or tracee exit.

```go
// readBytes reads len(buf) bytes from the tracee's address space.
func (t *Tracer) readBytes(tid int, addr uint64, buf []byte) error {
    t.mu.Lock()
    state := t.tracees[tid]
    memFD := -1
    if state != nil {
        memFD = state.MemFD
    }
    t.mu.Unlock()

    if memFD < 0 {
        return fmt.Errorf("no memfd for tid %d", tid)
    }
    _, err := unix.Pread(memFD, buf, int64(addr))
    return err
}

// writeBytes writes buf into the tracee's address space.
func (t *Tracer) writeBytes(tid int, addr uint64, buf []byte) error {
    t.mu.Lock()
    state := t.tracees[tid]
    memFD := -1
    if state != nil {
        memFD = state.MemFD
    }
    t.mu.Unlock()

    if memFD < 0 {
        return fmt.Errorf("no memfd for tid %d", tid)
    }
    _, err := unix.Pwrite(memFD, buf, int64(addr))
    return err
}

// readString reads a NUL-terminated string from the tracee's address space.
// Reads in 256-byte chunks to avoid over-reading. Returns at most maxLen bytes.
func (t *Tracer) readString(tid int, addr uint64, maxLen int) (string, error) {
    var result []byte
    chunk := make([]byte, 256)
    for len(result) < maxLen {
        n := min(256, maxLen-len(result))
        if err := t.readBytes(tid, addr+uint64(len(result)), chunk[:n]); err != nil {
            return "", err
        }
        if idx := bytes.IndexByte(chunk[:n], 0); idx >= 0 {
            result = append(result, chunk[:idx]...)
            return string(result), nil
        }
        result = append(result, chunk[:n]...)
    }
    return string(result), nil
}
```

`process_vm_readv` may be revisited as a future optimization if profiling shows `/proc/<pid>/mem` reads are a bottleneck on high-throughput workloads.

---

## 10. Platform Interface Integration

### 10.1 New Interface

Add to `internal/platform/interfaces.go`:

```go
// SyscallTracer provides syscall-level interception via ptrace or equivalent.
// This is an alternative to seccomp user-notify for restricted environments.
type SyscallTracer interface {
    // Start begins tracing. Blocks until ctx is cancelled or all tracees exit.
    // Runs the tracer event loop on a locked OS thread. All ptrace operations
    // happen on this thread.
    Start(ctx context.Context) error

    // AttachPID enqueues attachment to an additional process's threads.
    // Safe to call from any goroutine. Sends the PID to the tracer loop's
    // attachQueue channel, which the loop drains between wait4 calls.
    // The channel send also unblocks the loop if it's in the idle select.
    AttachPID(pid int) error

    // TraceeCount returns the number of currently traced threads.
    TraceeCount() int

    // Available returns whether ptrace-based tracing is available.
    Available() bool

    // Implementation returns "ptrace".
    Implementation() string
}
```

### 10.2 Capabilities Update

In `internal/platform/types.go`:

```go
type Capabilities struct {
    // ... existing fields ...

    // Ptrace
    HasPtrace bool `json:"has_ptrace"`
}
```

### 10.3 Platform Registration

The Linux platform's `detectCapabilities()` adds ptrace detection. Uses the same `readCapEff()` + `probePtraceAttach()` helpers defined in §4.1 — do not duplicate the broken single-struct `Capget` pattern that exists elsewhere in the repo.

```go
caps.HasPtrace = checkPtraceCapability() // from internal/capabilities/check_ptrace_linux.go
```

**Repo-wide note:** The existing `internal/capabilities/security_caps.go` and `internal/platform/linux/platform.go` use a single `unix.CapUserData{}` struct with `LINUX_CAPABILITY_VERSION_3`. This is a known Go issue (golang/go#44312) — v3 requires two structs. CAP_SYS_PTRACE (bit 19) happens to be in the low 32 bits so the bug doesn't manifest here, but `readCapEff()` should become the standard helper for all capability checks across the repo.

---

## 11. Fargate Task Definition

Reference ECS task definition for the sidecar deployment. Uses `pid` mode with a shared volume for target PID discovery:

```json
{
  "family": "agentsh-fargate",
  "cpu": "512",
  "memory": "1024",
  "networkMode": "awsvpc",
  "pidMode": "task",
  "requiresCompatibilities": ["FARGATE"],
  "volumes": [
    {
      "name": "agentsh-shared"
    }
  ],
  "containerDefinitions": [
    {
      "name": "agentsh",
      "image": "ghcr.io/canyonroad/agentsh:latest",
      "essential": true,
      "linuxParameters": {
        "capabilities": {
          "add": ["SYS_PTRACE"]
        }
      },
      "environment": [
        { "name": "AGENTSH_PTRACE_ENABLED", "value": "true" },
        { "name": "AGENTSH_PTRACE_ATTACH_MODE", "value": "pid" },
        { "name": "AGENTSH_PTRACE_TARGET_PID_FILE", "value": "/shared/workload.pid" },
        { "name": "AGENTSH_HTTP_ADDR", "value": "0.0.0.0:18080" },
        { "name": "AGENTSH_LOG_LEVEL", "value": "info" }
      ],
      "mountPoints": [
        { "sourceVolume": "agentsh-shared", "containerPath": "/shared", "readOnly": false }
      ],
      "portMappings": [
        { "containerPort": 18080, "protocol": "tcp" }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:18080/health"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 10
      }
    },
    {
      "name": "agent-workload",
      "image": "your-agent-image:latest",
      "essential": true,
      "entryPoint": ["/usr/local/bin/agentsh-pid-writer", "/shared/workload.pid"],
      "environment": [
        { "name": "AGENTSH_SERVER", "value": "http://127.0.0.1:18080" }
      ],
      "mountPoints": [
        { "sourceVolume": "agentsh-shared", "containerPath": "/shared", "readOnly": false }
      ],
      "dependsOn": [
        { "containerName": "agentsh", "condition": "HEALTHY" }
      ]
    }
  ]
}
```

**How it works:** The workload container's entrypoint uses a small wrapper script (`agentsh-pid-writer`) that writes `$$` to the shared volume, then `exec`s the real command. This is cleaner than inlining `sh -c` in the task definition. A minimal implementation:

```bash
#!/bin/sh
# /usr/local/bin/agentsh-pid-writer — bake into your workload image
echo $$ > "$1"
shift
exec "$@"
```

The agentsh sidecar polls the PID file on startup and attaches once it appears. The `pidMode: "task"` shared PID namespace ensures the PID is valid across containers.

---

## 12. Known Limitations and Mitigations

### 12.1 Tracee Detection

**Issue:** Any process can read `/proc/self/status` and see `TracerPid: <nonzero>`.

**Mitigation:** For the AI agent security use case, this is low risk — supply chain attacks in npm/pip packages are not writing anti-ptrace checks today. Phase 4 adds TracerPid masking (§19) which raises the bar further, but is not a complete defense against a determined adversary targeting ptrace specifically.

### 12.2 TOCTOU on Pointer Arguments

**Issue:** In multithreaded tracees, another thread can overwrite the memory pointed to by a syscall argument between ptrace's read and the kernel's execution.

**Mitigation:** seccomp user-notify has the identical TOCTOU issue (documented in the kernel). FUSE does not. For file operations, the risk is a path swap between policy check and actual open. For most agent workloads (single-threaded scripts), this is not exploitable. For hardened deployments, combine ptrace with Landlock (if available) for defense-in-depth. This is a shared limitation with full mode's seccomp path — not a ptrace-specific gap.

### 12.3 Thread Spawn Race

**Issue:** Brief window between `clone()` and ptrace auto-attach where the new thread could execute a syscall.

**Mitigation:** With `PTRACE_O_TRACECLONE`, the kernel stops the new thread before it runs. The window is effectively zero in practice. seccomp's atomic inheritance is technically tighter, but no real-world exploit of this ptrace race has been documented.

### 12.4 Performance Overhead

**Issue:** Each traced syscall adds ~50-100µs (two context switches + register read/write).

**Mitigation:** In `children` mode, the seccomp pre-filter (§7.2) reduces traced syscalls to only the ~25 we care about (out of 400+). With the pre-filter, overhead is <5% on typical agent workloads (Datadog CWS benchmarks report similar). In `pid` mode (no pre-filter in Phase 1), overhead can reach 10-30% on I/O-heavy workloads.

**Configuration:**
- `attach_mode: children` — enables pre-filter, lowest overhead
- `performance.max_hold_ms: 5000` — prevents hung policy from blocking workload
- `trace.file: false` — disable file tracing if file policy is not needed, reducing overhead further

### 12.5 Single-Threaded Tracer Constraint

**Issue:** ptrace operations must come from the same OS thread that performed the attach. This means the tracer loop is single-threaded.

**Mitigation:** Policy evaluation and event emission are done asynchronously (channel-based), so only the register read/write and wait4 calls are on the hot thread. For workloads with <500 concurrent threads (typical for agent sandboxes), this is not a bottleneck. Multi-thread tracer partitioning is a potential future optimization but requires a separate design due to `wait4` cross-thread semantics (see §18).

### 12.6 Existing seccomp Filters

**Issue:** If the workload container already has a seccomp profile (common in Kubernetes), interactions with ptrace tracing need care.

**Mitigation:** In `pid` mode (Phase 1), no pre-filter is installed, so existing filters are irrelevant — the tracer uses `PTRACE_O_TRACESYSGOOD` only. In `children` mode, the pre-filter is installed in the child process before `exec`, under conditions agentsh controls. seccomp filters stack (most restrictive wins), so agentsh's `SECCOMP_RET_TRACE` rules cannot weaken any existing or subsequently-applied `RET_KILL` or `RET_ERRNO` rules. If a container runtime applies its own seccomp profile after exec (e.g., via the OCI runtime spec), that profile stacks on top of ours.

### 12.7 vfork Deadlock Hazard

**Issue:** When a tracee calls `vfork()`, the parent is suspended by the kernel until the child calls `exec` or `_exit`. If the ptrace tracer holds the vforked child at a syscall-stop (e.g., for async approval of the child's `execve`), the parent is also frozen. If the tracer then needs information from the parent (e.g., process tree context), it is waiting on a frozen process — deadlock.

This is a real scenario: shell scripts commonly use `vfork+exec` for subcommand execution.

**Mitigation:** The tracer tracks vfork children via the `IsVforkChild` flag on `TraceeState`, set on `PTRACE_EVENT_VFORK` and cleared on `PTRACE_EVENT_EXEC`. For vfork children, the tracer **must not park the tracee for async approval**. Instead, it uses synchronous-only policy evaluation, falling back to the `max_hold_ms` timeout and the configured timeout action (deny or allow) rather than waiting for interactive approval.

```go
// markVforkChild sets IsVforkChild on the child created by the vfork.
func (t *Tracer) markVforkChild(parentTID int) {
    childTID, err := unix.PtraceGetEventMsg(parentTID)
    if err != nil {
        return
    }
    t.mu.Lock()
    if state, ok := t.tracees[int(childTID)]; ok {
        state.IsVforkChild = true
    }
    t.mu.Unlock()
}
```

Policy dispatch code must check `IsVforkChild` before attempting to park:

```go
if state.IsVforkChild {
    // Synchronous policy only — parking would deadlock the vfork parent.
    decision := t.policyEngine.CheckExecveSync(ctx, execCtx)
    // ... apply decision immediately ...
} else {
    // May park for async approval.
    decision := t.policyEngine.CheckExecve(ctx, execCtx)
    // ...
}
```

---

## 13. Testing Strategy

### 13.1 Unit Tests

- `args_amd64_test.go`, `args_arm64_test.go` — register layout correctness
- `process_tree_test.go` — tree tracking, parent lookup, depth calculation
- `seccomp_prefilter_test.go` — BPF program generation for traced syscall sets
- `syscall_handler_test.go` — dispatch routing by syscall number

### 13.2 Integration Tests

All integration tests require `SYS_PTRACE` capability and are guarded by build tag `//go:build integration && ptrace`:

- **exec_test.go:** Trace a child that calls `execve`, verify policy allow/deny
- **file_test.go:** Trace file operations, verify events and deny enforcement
- **signal_test.go:** Trace `kill()`, verify signal redirect (SIGKILL → SIGTERM)
- **network_test.go:** Trace `connect()`, verify connection audit events
- **tree_test.go:** Fork bomb (controlled), verify all descendants are traced
- **prefilter_test.go:** Verify only interesting syscalls cause stops
- **sidecar_test.go:** Two-process test simulating sidecar PID namespace sharing

### 13.3 Dockerfile for CI

```dockerfile
FROM debian:bookworm-slim
# Tests need SYS_PTRACE — run with:
#   docker run --cap-add SYS_PTRACE --security-opt seccomp=unconfined
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates gcc libc6-dev make curl
COPY . /src
WORKDIR /src
RUN go test -tags "integration,ptrace" -v ./internal/ptrace/...
```

### 13.4 Fargate E2E Test

A separate integration test deploys the full sidecar task definition to Fargate and validates:
1. agentsh detects ptrace mode
2. Workload process is traced
3. Policy deny on blocked command works
4. Audit events are emitted
5. LLM proxy functions

---

## 14. Implementation Phases

### Phase 1: Core Tracer (MVP)

- `internal/ptrace/tracer.go` — event loop with `wait4`, single OS thread
- `internal/ptrace/args.go` — amd64 + arm64 register access
- `internal/ptrace/attach.go` — `PTRACE_SEIZE` with `PTRACE_O_EXITKILL`, per-thread attachment via `/proc/<pid>/task/*`
- `internal/ptrace/process_tree.go` — tracee tree tracking (thread-aware, handles non-leader exec)
- Two attach modes only: `children` (with pre-exec seccomp prefilter) and `pid` (TRACESYSGOOD fallback)
- Config parsing for `sandbox.ptrace`
- Capability detection (`HasPtrace` via CapEff parsing + real attach probe)
- Security mode `ptrace` (opt-in only, never auto-selected)
- Integration with `ExecveHandler` for command allow/deny
- Basic integration tests (require `SYS_PTRACE`)
- No redirect/steering, no sidecar auto-discovery, no percentage scores

**Deliverable:** agentsh can trace a workload process, enforce command allow/deny via ptrace, and emit execve audit events. `children` mode has seccomp prefilter for low overhead. `pid` mode works on Fargate with explicit target PID.

### Phase 2: Full Syscall Coverage ✓

- File syscall handling via `FileHandler` — allow/deny/audit for openat, openat2, unlinkat, renameat2, mkdirat, linkat, symlinkat, fchmodat, fchmodat2, fchownat, plus legacy amd64 equivalents (open, creat, unlink, rmdir, rename, mkdir, link, symlink, chmod, chown)
- Full path resolution with symlink handling: `resolvePath` (follows final symlink), `resolvePathNoFollow` (preserves leaf), dangling symlink detection, ELOOP/ENOTDIR fail-closed
- Network syscall handling (connect/bind) with sockaddr parsing for AF_INET, AF_INET6 (with scope_id), AF_UNIX (path + abstract with preserved NUL bytes), AF_UNSPEC
- Signal syscall handling (kill, tkill, tgkill, rt_sigqueueinfo, rt_tgsigqueueinfo) with optional redirect via register rewrite for kill/tkill/tgkill
- openat2 support with `open_how` struct parsing and fail-closed on resolve flags
- Fail-closed error handling: all extraction/parse errors deny with EACCES
- Unit tests for operation mapping, path resolution, sockaddr parsing, signal extraction
- Integration tests for file deny, network deny, signal deny, signal redirect

**Deliverable:** Full allow/deny/audit parity with seccomp user-notify for file, network, and signal. Signal redirect for kill/tkill/tgkill via register rewrite. No file/network steering yet.

### Phase 3: Production Hardening + Sidecar Discovery

- Sidecar auto-discovery (`sidecar` attach mode) based on real Fargate E2E testing
- Research spike: seccomp prefilter injection for `pid`/`sidecar` mode (via syscall injection)
- Graceful degradation when tracee exits unexpectedly
- Metrics: traced syscalls/sec, overhead latency per attach mode, tracee/thread count
- `max_hold_ms` timeout enforcement
- Fargate E2E test in CI (ECS task definition, end-to-end policy enforcement)
- Measured overhead comparison: children (with prefilter) vs pid (without) vs full mode
- Documentation: `docs/ptrace.md`, `docs/cross-platform.md`, `docs/security-modes.md`

**Deliverable:** Production-ready ptrace backend suitable for Fargate deployments. Measured overhead data to guide when prefilter injection is worth pursuing.

### Phase 4: Steering, Anti-Detection, and EKS Fargate

Phase 4 brings ptrace mode to full feature parity with seccomp+FUSE for redirect/steering behaviors, plus detection resistance and EKS support.

- Exec redirect via syscall injection and memory rewrite (§15)
- File path redirect via register + memory rewrite (§16)
- Soft-delete via injected `renameat2` (§16.5)
- Network connect redirect via sockaddr rewrite (§17.1)
- DNS redirect — basic UDP sendto/recvfrom rewrite (§17.2) — **best-effort, see fragility notes**
- SNI rewrite — single-write ClientHello case (§17.3) — **best-effort, see fragility notes**
- TracerPid masking via ptrace-intercepted /proc reads (§19) — **raises bar for casual detection, not a security boundary**
- EKS Fargate support (pending AWS `SYS_PTRACE` for EKS) (§20)

**Deliverable:** Complete steering support for the common cases. Honest about coverage gaps in DNS and TLS interception.

---

## 15. Phase 4 Design: Exec Redirect via ptrace

### 15.1 The Problem

The seccomp redirect path (Phases 1-3) uses `SECCOMP_IOCTL_NOTIF_ADDFD` to inject a socketpair fd into the tracee, then overwrites the filename pointer to point at the agentsh-stub symlink. The tracee executes agentsh-stub, which discovers the injected fd at well-known fd 100 and connects back to the server.

ptrace has no equivalent of `SECCOMP_ADDFD`. We need a different mechanism to inject the socketpair fd and redirect the exec.

### 15.2 Approach: Syscall Injection

ptrace can **inject arbitrary syscalls** into a stopped tracee by:

1. Saving the tracee's current register state
2. Writing new register values (syscall nr + args)
3. Resuming with `PTRACE_SYSCALL` to execute the injected syscall
4. Waiting for the syscall-exit stop
5. Reading the return value
6. Restoring the original register state

This is the same technique used by `strace -e inject`, `CRIU` (checkpoint/restore), and Datadog's process injection. It is well-established and works on both amd64 and arm64.

### 15.3 Exec Redirect Sequence

When `ExecveHandler.Handle()` returns `ActionRedirect`:

```
Tracee                          Tracer (ptrace)
───────                         ─────────────────
execve("/usr/bin/curl", ...)
  ↓ PTRACE_EVENT_SECCOMP
  │ [stopped]                   1. Read original registers (save)
  │                             2. Read filename, argv from tracee memory
  │                             3. ExecveHandler.Handle() → ActionRedirect
  │                             4. Create socketpair in tracer process
  │                             5. Inject dup2() syscall → places stub fd at fd 100
  │                             6. Overwrite filename in tracee memory → stub symlink path
  │                             7. Overwrite AGENTSH_STUB_FD in tracee environ (optional)
  │                             8. Restore original registers with modified filename ptr
  │                             9. Resume tracee
  ↓
execve("/tmp/as-xxxxx/s", ...)  ← kernel re-reads modified filename
  ↓ agentsh-stub runs
  ↓ discovers fd 100 → connects back to tracer
  ↓ tracer runs original command, proxies I/O
```

### 15.4 Syscall Injection Implementation

```go
// injectSyscall executes an arbitrary syscall in the stopped tracee.
// The tracee must be in a ptrace-stop (syscall-enter or PTRACE_EVENT_*).
// Returns the syscall return value.
//
// Uses the two-phase PtraceSyscall approach (not PtraceSingleStep):
//   1. Resume with PtraceSyscall → wait for syscall-enter stop
//   2. Resume with PtraceSyscall → wait for syscall-exit stop → read return value
//
// This is immune to seccomp prefilter interactions (PtraceSingleStep can
// collide with PTRACE_EVENT_SECCOMP) and signal delivery races (a pending
// signal can fire between a single-step return and our register read).
// This is the approach used by CRIU and strace for syscall injection.
func (t *Tracer) injectSyscall(pid int, nr int, args [6]uint64) (int64, error) {
    // 1. Save current registers
    savedRegs, err := t.getRegs(pid)
    if err != nil {
        return 0, fmt.Errorf("save regs: %w", err)
    }

    // 2. Build injected registers
    injRegs := savedRegs.Clone()
    injRegs.SetSyscallNr(nr)
    for i := 0; i < 6; i++ {
        injRegs.SetArg(i, args[i])
    }
    // Set IP to a known syscall instruction in the tracee's address space.
    // See §15.7 for gadget discovery (VDSO scan or stack stub).
    injRegs.SetInstructionPointer(t.syscallGadgetAddr(pid))

    if err := t.setRegs(pid, injRegs); err != nil {
        return 0, fmt.Errorf("set injected regs: %w", err)
    }

    // 3. Resume with PtraceSyscall — tracee hits the syscall instruction
    //    and stops at syscall-enter.
    if err := unix.PtraceSyscall(pid, 0); err != nil {
        t.setRegs(pid, savedRegs) // best-effort restore
        return 0, fmt.Errorf("resume for syscall-enter: %w", err)
    }

    // 4. Wait for syscall-enter stop
    var status unix.WaitStatus
    if _, err := unix.Wait4(pid, &status, 0, nil); err != nil {
        return 0, fmt.Errorf("wait for syscall-enter: %w", err)
    }

    // 5. Resume with PtraceSyscall again — kernel executes the syscall,
    //    tracee stops at syscall-exit.
    if err := unix.PtraceSyscall(pid, 0); err != nil {
        t.setRegs(pid, savedRegs)
        return 0, fmt.Errorf("resume for syscall-exit: %w", err)
    }

    // 6. Wait for syscall-exit stop
    if _, err := unix.Wait4(pid, &status, 0, nil); err != nil {
        return 0, fmt.Errorf("wait for syscall-exit: %w", err)
    }

    // 7. Read return value from the exit-stop registers
    resultRegs, err := t.getRegs(pid)
    if err != nil {
        return 0, fmt.Errorf("read result: %w", err)
    }
    retval := resultRegs.ReturnValue()

    // 8. Restore original registers
    if err := t.setRegs(pid, savedRegs); err != nil {
        return 0, fmt.Errorf("restore regs: %w", err)
    }

    return retval, nil
}
```

### 15.5 FD Injection via dup3 Injection

To inject the stub socketpair fd into the tracee at fd 100:

```go
func (t *Tracer) injectFD(tracee int, srcFD int, targetFD int) error {
    // Step 1: Send our fd to the tracee via /proc/<pid>/fd pidfd_getfd,
    // or use the SCM_RIGHTS trick via an abstract unix socket.
    //
    // Preferred approach: pidfd_getfd (kernel 5.6+)
    // This copies an fd from one process to another without a socket.

    // Open a pidfd for the tracee
    pidfd, err := t.injectSyscall(tracee, unix.SYS_PIDFD_OPEN, [6]uint64{
        uint64(os.Getpid()), // our PID
        0,                   // flags
    })
    if err != nil || pidfd < 0 {
        return fmt.Errorf("inject pidfd_open: %w (ret=%d)", err, pidfd)
    }

    // Use pidfd_getfd to copy srcFD from our process into the tracee
    gotFD, err := t.injectSyscall(tracee, unix.SYS_PIDFD_GETFD, [6]uint64{
        uint64(pidfd),  // pidfd (in tracee's fd table, pointing to our process)
        uint64(srcFD),  // fd to copy from our process
        0,              // flags
    })
    if err != nil || gotFD < 0 {
        // Fall back to SCM_RIGHTS approach if pidfd_getfd unavailable
        return t.injectFDViaSCMRights(tracee, srcFD, targetFD)
    }

    // dup3 to the target fd number
    if int(gotFD) != targetFD {
        _, err = t.injectSyscall(tracee, unix.SYS_DUP3, [6]uint64{
            uint64(gotFD),
            uint64(targetFD),
            uint64(unix.O_CLOEXEC),
        })
        if err != nil {
            return fmt.Errorf("inject dup3: %w", err)
        }
        // Close the intermediate fd
        t.injectSyscall(tracee, unix.SYS_CLOSE, [6]uint64{uint64(gotFD)})
    }

    // Close the pidfd
    t.injectSyscall(tracee, unix.SYS_CLOSE, [6]uint64{uint64(pidfd)})

    return nil
}
```

### 15.6 Fallback: SCM_RIGHTS FD Passing

If `pidfd_getfd` is unavailable (kernel < 5.6, or Fargate's kernel doesn't expose it), fall back to the classic Unix fd-passing mechanism:

1. Tracer creates an abstract Unix socket pair
2. Inject `socket(AF_UNIX, SOCK_STREAM, 0)` in tracee
3. Inject `connect()` to the abstract address in tracee
4. Tracer sends the target fd via `SCM_RIGHTS` on the accepted connection
5. Inject `recvmsg()` in tracee to receive the fd
6. Inject `dup3()` to place it at fd 100
7. Clean up injected socket fds

This is more complex (5-6 injected syscalls vs 3) but works on any Linux kernel. The tracee is frozen during the entire sequence, so there is no race.

```go
func (t *Tracer) injectFDViaSCMRights(tracee int, srcFD int, targetFD int) error {
    // Create abstract socket with random name
    name := fmt.Sprintf("\x00agentsh-inject-%d-%d", tracee, time.Now().UnixNano())

    // Tracer side: create listening socket
    srvFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
    if err != nil {
        return err
    }
    defer unix.Close(srvFD)

    addr := &unix.SockaddrUnix{Name: name}
    unix.Bind(srvFD, addr)
    unix.Listen(srvFD, 1)

    // Write sockaddr bytes into tracee memory at a scratch location
    // (we can use the stack area below SP, or allocate via mmap injection)
    scratchAddr := t.findScratchMemory(tracee)
    t.writeBytes(tracee, scratchAddr, encodeSockaddrUnix(name))

    // Inject socket() in tracee
    cliResult, _ := t.injectSyscall(tracee, unix.SYS_SOCKET, [6]uint64{
        unix.AF_UNIX, unix.SOCK_STREAM, 0,
    })
    cliFD := int(cliResult)

    // Inject connect() in tracee
    t.injectSyscall(tracee, unix.SYS_CONNECT, [6]uint64{
        uint64(cliFD),
        scratchAddr,
        uint64(len(encodeSockaddrUnix(name))),
    })

    // Tracer: accept and send fd via SCM_RIGHTS
    connFD, _, _ := unix.Accept(srvFD)
    defer unix.Close(connFD)
    rights := unix.UnixRights(srcFD)
    unix.Sendmsg(connFD, []byte{0}, rights, nil, 0)

    // Inject recvmsg() in tracee to receive the fd
    // (requires writing a msghdr + cmsg buffer into tracee memory)
    receivedFD := t.injectRecvmsg(tracee, cliFD, scratchAddr)

    // dup3 to target
    if receivedFD != targetFD {
        t.injectSyscall(tracee, unix.SYS_DUP3, [6]uint64{
            uint64(receivedFD), uint64(targetFD), uint64(unix.O_CLOEXEC),
        })
        t.injectSyscall(tracee, unix.SYS_CLOSE, [6]uint64{uint64(receivedFD)})
    }

    // Close injected client socket
    t.injectSyscall(tracee, unix.SYS_CLOSE, [6]uint64{uint64(cliFD)})

    return nil
}
```

### 15.7 Syscall Gadget Discovery

To inject a syscall, we need the tracee's instruction pointer to be at a `syscall` instruction. Options:

**Option A: VDSO scanning (preferred).** Every Linux process has a VDSO mapped that contains `syscall` / `svc #0` instructions. Parse `/proc/<pid>/maps` to find the VDSO, then scan for the instruction:

```go
func (t *Tracer) syscallGadgetAddr(pid int) uint64 {
    if cached, ok := t.gadgetCache[pid]; ok {
        return cached
    }

    maps, _ := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
    for _, line := range strings.Split(string(maps), "\n") {
        if strings.Contains(line, "[vdso]") {
            // Parse start address, scan for syscall/svc instruction
            addr := parseStartAddr(line)
            gadget := scanForSyscallInsn(pid, addr)
            t.gadgetCache[pid] = gadget
            return gadget
        }
    }

    // Fallback: write a tiny stub into tracee memory
    return t.writeSyscallStub(pid)
}
```

**IMPORTANT:** The gadget cache must be invalidated on `PTRACE_EVENT_EXEC`. After exec, the entire address space is remapped (ASLR assigns a new VDSO base). A stale cached address points to unmapped memory and would SIGSEGV the tracee during syscall injection. `handleExecEvent` must call `delete(t.gadgetCache, tid)`. Scratch pages (`t.scratchPages[tid]`) must also be invalidated on exec for the same reason.

**Option B: Stack stub injection.** Write `syscall; int3` (2 bytes on x86_64: `0f 05 cc`) below the current stack pointer, execute it, then restore. This is simpler but modifies tracee memory.

**Option C: Use the instruction pointer from the current stop.** If the tracee is stopped at a `PTRACE_EVENT_SECCOMP` triggered by an interesting syscall, the IP is already right after a `syscall` instruction. We can compute IP-2 (the `syscall` itself) and reuse it. This is the simplest and avoids any memory writes.

---

## 16. Phase 4 Design: File Path Redirect via ptrace

### 16.1 How FUSE Does It

FUSE intercepts every VFS operation and can silently substitute paths. When a tracee opens `/workspace/foo.txt`, FUSE can serve content from `/actual/storage/foo.txt` or `/workspace/.scratch/foo.txt`. The tracee never knows.

### 16.2 ptrace Equivalent: Argument Rewriting

When ptrace intercepts `openat(dirfd, "/home/agent/secrets/key.pem", O_RDONLY)` and policy says `redirect → /workspace/.scratch/key.pem`, the tracer:

1. Reads the path from tracee memory at the pointer in arg1
2. Evaluates policy → redirect
3. Writes the replacement path into tracee memory (overwriting the original, or at a scratch location)
4. Updates the arg1 register to point at the new path
5. Resumes the tracee — the kernel executes `openat` with the redirected path

```go
func (t *Tracer) redirectFile(pid int, regs Regs, originalPath string, redirectPath string) error {
    pathPtr := regs.Arg(1) // arg1 for openat

    if len(redirectPath) <= len(originalPath) {
        // Fits in place — overwrite
        return writeString(pid, pathPtr, redirectPath)
    }

    // Doesn't fit — write to scratch memory and update register
    scratchAddr, err := t.allocScratch(pid, len(redirectPath)+1)
    if err != nil {
        return err
    }
    if err := writeString(pid, scratchAddr, redirectPath); err != nil {
        return err
    }
    regs.SetArg(1, scratchAddr)
    return t.setRegs(pid, regs)
}
```

### 16.3 Scratch Memory Allocation

For paths that are longer than the original (common for redirect-to-scratch scenarios), we need writable memory in the tracee. Three strategies:

**Strategy A: Stack-relative.** Write below the current stack pointer (SP - N). The area below SP is technically unused. This is fragile if the tracee uses red zones (x86_64 ABI reserves 128 bytes below SP). Write at `SP - 256` to be safe.

**Strategy B: Injected mmap (recommended).** Call `mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` via syscall injection to allocate a scratch page. Cache it per-tracee. **Reset `used = 0` at each new syscall-enter stop** — the kernel has consumed the scratch data during the previous syscall, so the page is safe to reuse. This makes the scratch page an arena that serves all redirects for the tracee's lifetime.

```go
func (t *Tracer) allocScratch(pid int, size int) (uint64, error) {
    // Check if we already have a scratch page for this tracee
    if scratch, ok := t.scratchPages[pid]; ok && scratch.used+size <= scratch.size {
        addr := scratch.base + uint64(scratch.used)
        scratch.used += size
        return addr, nil
    }

    // Inject mmap syscall
    pageSize := uint64(4096)
    if uint64(size) > pageSize {
        pageSize = uint64(size+4095) &^ 4095
    }
    result, err := t.injectSyscall(pid, unix.SYS_MMAP, [6]uint64{
        0,                                // addr (NULL = kernel chooses)
        pageSize,                         // length
        unix.PROT_READ | unix.PROT_WRITE, // prot
        unix.MAP_PRIVATE | unix.MAP_ANONYMOUS, // flags
        ^uint64(0),                       // fd = -1
        0,                                // offset
    })
    if err != nil || int64(result) < 0 {
        return 0, fmt.Errorf("inject mmap failed: %w (ret=%d)", err, result)
    }

    t.scratchPages[pid] = &scratchPage{base: uint64(result), size: int(pageSize), used: size}
    return uint64(result), nil
}
```

**Strategy C (preferred for short strings): In-place with null terminator.** If the redirect path is only a few bytes longer, extend into the memory that follows (which is typically the next argv entry or environment string). This is the riskiest option and should only be used when the delta is small.

**Recommendation:** Use Strategy B (mmap injection) as the default. It's clean, doesn't corrupt the stack, and the allocation is reusable across multiple redirects in the same tracee's lifetime. The mmap injection costs one extra round-trip at first use per tracee, then zero cost for subsequent redirects. The `used` counter is reset at each syscall-enter in `handleSyscallStop` / `handleSeccompStop`:

```go
// Reset scratch page for this tracee — previous contents consumed by kernel.
if sp, ok := t.scratchPages[tid]; ok {
    sp.used = 0
}
```

### 16.4 File Redirect Policy Integration

File redirect rules already exist in agentsh policy:

```yaml
file_rules:
  - name: redirect-outside-writes
    paths: ["/home/**", "/tmp/**"]
    operations: [write, create]
    decision: redirect
    redirect_to: "/workspace/.scratch"
    message: "Writes outside workspace redirected"
```

The ptrace file handler adds a new code path for `DecisionRedirect`:

```go
func (t *Tracer) handleFileWithRedirect(ctx context.Context, pid int, regs Regs) {
    path := t.readPathArg(pid, regs)
    operation := syscallToOperation(regs.SyscallNr(), regs.Arg(2))

    decision := t.policyEngine.CheckFileWithRedirect(path, operation)

    switch decision.Decision {
    case "redirect":
        redirectPath := decision.RedirectTo
        if err := t.redirectFile(pid, regs, path, redirectPath); err != nil {
            // Redirect failed — deny for safety
            t.denySyscall(pid, int(unix.EACCES))
            return
        }
        t.emitEvent(IOEvent{
            Type:           EventFileOpen,
            Path:           path,
            Decision:       DecisionRedirect,
            Redirected:     true,
            RedirectTarget: redirectPath,
            OriginalTarget: path,
            Platform:       "ptrace",
        })
        t.allowSyscall(pid)

    case "deny":
        t.denySyscall(pid, int(unix.EACCES))

    default:
        t.allowSyscall(pid)
    }
}
```

### 16.5 Soft-Delete via ptrace

When policy returns `DecisionSoftDelete` for an `unlinkat` syscall, the ptrace handler:

1. Denies the original `unlinkat` (set syscall nr to -1)
2. Injects a `renameat2` syscall to move the file to the trash directory
3. Emits a `file_soft_delete` event with the restore token

```go
func (t *Tracer) handleSoftDelete(pid int, regs Regs, path string) error {
    // Generate trash path
    trashPath := t.trashPath(path)

    // Ensure trash directory exists (inject mkdir if needed)
    trashDir := filepath.Dir(trashPath)
    t.ensureDir(pid, trashDir)

    // Write both paths to scratch memory
    scratch, _ := t.allocScratch(pid, len(path)+len(trashPath)+2)
    writeString(pid, scratch, path)
    newPathAddr := scratch + uint64(len(path)) + 1
    writeString(pid, newPathAddr, trashPath)

    // Deny original unlinkat
    t.denySyscall(pid, 0) // returns 0 (success) to the tracee

    // Inject renameat2(AT_FDCWD, path, AT_FDCWD, trashPath, 0)
    const AT_FDCWD = ^uint64(0) - 99 // -100 as unsigned
    t.injectSyscall(pid, unix.SYS_RENAMEAT2, [6]uint64{
        AT_FDCWD, scratch,
        AT_FDCWD, newPathAddr,
        0, 0,
    })

    // Emit soft-delete event
    t.emitEvent(IOEvent{
        Type:     EventFileDelete,
        Path:     path,
        Decision: DecisionSoftDelete,
        Metadata: map[string]any{
            "trash_path":    trashPath,
            "restore_token": trashPath,
        },
        Platform: "ptrace",
    })

    return nil
}
```

The key insight: from the tracee's perspective, the `unlink()` call succeeds (returns 0). But under the hood, the file was moved to trash instead of deleted. The agent sees a successful delete; the operator can restore it. This is identical to the FUSE soft-delete behavior.

---

## 17. Phase 4 Design: Network Redirect via ptrace

### 17.1 Connect Redirect

When policy says `redirect connect api.anthropic.com:443 → vertex-proxy.internal:8443`:

1. ptrace intercepts `connect(fd, sockaddr{api.anthropic.com:443}, len)`
2. Reads the `sockaddr_in`/`sockaddr_in6` from tracee memory
3. Policy evaluates → redirect to `vertex-proxy.internal:8443`
4. Resolves the redirect target to an IP address
5. Writes the new `sockaddr` into tracee memory (same location — `sockaddr_in` is fixed size: 16 bytes for IPv4, 28 bytes for IPv6)
6. Resumes — kernel executes `connect()` to the redirected destination

```go
func (t *Tracer) redirectConnect(pid int, regs Regs, originalAddr *unix.SockaddrInet4, redirectHost string, redirectPort int) error {
    // Resolve redirect target
    ips, err := net.LookupIP(redirectHost)
    if err != nil {
        return err
    }

    // Build new sockaddr_in
    var newAddr unix.SockaddrInet4
    copy(newAddr.Addr[:], ips[0].To4())
    newAddr.Port = redirectPort

    // Write new sockaddr into tracee memory at the original pointer
    addrPtr := regs.Arg(1) // arg1 of connect()
    return writeBytes(pid, addrPtr, encodeSockaddrInet4(&newAddr))
}
```

Because `sockaddr_in` is 16 bytes and `sockaddr_in6` is 28 bytes, the overwrite always fits in place — no scratch allocation needed. This is a significant advantage over file path redirect.

### 17.2 DNS Redirect

> **Fragility: best-effort.** This covers the common case of `getaddrinfo` → `sendto` on UDP port 53 → `recvfrom`. It does NOT cover: DNS-over-HTTPS (bypasses port 53 entirely), DNS-over-TLS (port 853), TCP DNS (responses split across multiple `recv` calls), `recvmmsg` scatter-gather, or applications that use their own DNS resolver libraries that don't go through libc. For comprehensive DNS visibility, the LLM proxy (which already works on Fargate) or network-level DNS inspection at the VPC/security group layer are more reliable. This ptrace-based DNS redirect is an opportunistic enhancement, not a complete solution.

DNS redirect intercepts `sendto()` calls targeting port 53. The tracer:

1. Reads the DNS query from the tracee's send buffer
2. Parses the query to extract the domain name
3. Checks DNS redirect policy
4. If redirected: overwrites the `sockaddr` in arg4 (destination) to point to the redirect IP, or overwrites the DNS response in the receive buffer after the `recvfrom()` returns

For the simpler case (redirect DNS server IP), the approach is identical to connect redirect — just rewrite the destination `sockaddr`.

For the advanced case (rewrite DNS response to return a different IP), the tracer:
1. Allows the `sendto` to the original DNS server
2. Intercepts the subsequent `recvfrom` at syscall-exit
3. Reads the DNS response from tracee memory
4. Modifies the answer section to contain the redirect IP
5. Writes the modified response back into tracee memory

```go
func (t *Tracer) handleDNSResponse(pid int, regs Regs, queryDomain string, redirectIP net.IP) error {
    // At recvfrom syscall-exit, the buffer contains the DNS response
    bufPtr := regs.Arg(1) // recvfrom arg1 = buf
    bufLen := int(regs.ReturnValue())
    if bufLen <= 0 {
        return nil // Empty or error
    }

    // Read response from tracee
    response := make([]byte, bufLen)
    readBytes(pid, bufPtr, response)

    // Parse and modify DNS response
    modified := rewriteDNSAnswer(response, queryDomain, redirectIP)
    if modified == nil {
        return nil // Couldn't parse, pass through
    }

    // Write modified response back
    return writeBytes(pid, bufPtr, modified)
}
```

### 17.3 SNI Rewrite

> **Fragility: best-effort.** This covers the common case where the TLS ClientHello is sent in a single `write`/`sendto` call. It does NOT cover: `writev` scatter-gather sends (common in OpenSSL), `sendmsg` with multiple iovecs, partial writes where the ClientHello spans two `write` calls, or TLS 1.3 Encrypted Client Hello (ECH) which encrypts the SNI. For production API gateway routing, the LLM proxy's explicit routing is more reliable than transparent SNI rewriting.

For connect redirect with `tls_mode: rewrite_sni`, the tracer intercepts the first `sendto`/`write` after a redirected `connect()` succeeds, parses the TLS ClientHello from the tracee's send buffer, rewrites the SNI extension using the existing `findSNI` / `rewriteSNI` functions from `internal/netmonitor/sni.go`, and writes the modified ClientHello back.

```go
func (t *Tracer) handleTLSWrite(pid int, regs Regs, connState *redirectedConn) error {
    if !connState.needsSNIRewrite || connState.sniRewritten {
        return nil
    }

    bufPtr := regs.Arg(1)
    bufLen := int(regs.Arg(2))

    // Read the outgoing data
    data := make([]byte, bufLen)
    readBytes(pid, bufPtr, data)

    // Check if this is a TLS ClientHello
    loc, err := findSNI(data)
    if err != nil {
        return nil // Not TLS or no SNI — pass through
    }

    // Rewrite SNI
    modified, err := rewriteSNI(data, loc, connState.rewriteSNI)
    if err != nil {
        return nil
    }

    // Write back (may be different length)
    if len(modified) == len(data) {
        writeBytes(pid, bufPtr, modified)
    } else {
        // Different length: need to allocate scratch and update len register
        scratch, _ := t.allocScratch(pid, len(modified))
        writeBytes(pid, scratch, modified)
        regs.SetArg(1, scratch)
        regs.SetArg(2, uint64(len(modified)))
        t.setRegs(pid, regs)
    }

    connState.sniRewritten = true
    return nil
}
```

---

## 18. Future: Multi-Thread Tracer Scaling

### 18.1 The Problem

The Phase 1-4 tracer is single-threaded: one OS thread calls `wait4(-1, ...)` and handles all tracees. This works for typical agent workloads (<500 threads), but large build workloads (`npm install` with hundreds of parallel tasks, or Bazel with thousands of actions) can saturate the single thread.

At ~50µs per ptrace stop (with seccomp prefilter), a single thread handles ~20,000 stops/sec. A busy build might generate 5,000-10,000 traced syscalls/sec, which is within budget. Without the prefilter, throughput drops and a single thread may become a bottleneck.

### 18.2 Why This Needs a Separate Design

Multi-threaded ptrace is feasible but has subtle semantics that the current spec does not adequately address:

1. **`wait4` is thread-group-wide.** Since Linux 2.4, `wait4(-1, ...)` in one thread can collect children waited-for by other threads in the same thread group. For ptraced children, `__WALL` is automatically implied. This means "each thread runs its own independent `wait4` loop" does not work as naively described — threads can steal each other's events.

2. **Attachment is per-thread.** A ptrace command (e.g., `PTRACE_GETREGS`) must be issued from the thread that owns the tracee. But `wait4` can report stops from any tracee in the thread group. This creates a mismatch: Thread A receives a stop for a tracee owned by Thread B, but cannot call `PTRACE_GETREGS` on it.

3. **Workarounds exist but are complex.** Options include: using `waitid` with `P_PID` to wait for specific tracees per-thread; using separate processes (not threads) as tracer workers; or using a coordinator thread that dispatches events. Each has trade-offs. CRIU uses a multi-process model. Datadog CWS uses a single-threaded tracer with a channel-based offload for policy evaluation.

### 18.3 Recommendation

Single-threaded tracer is the shipping implementation through Phase 4. Policy evaluation and event emission already happen asynchronously (channel-based), so the hot path is only register read/write and `wait4`.

If Phase 3 overhead measurements show the single thread is a bottleneck for real workloads, write a separate multi-thread tracer design doc that addresses the `wait4` semantics correctly. Until then, do not commit to a multi-thread architecture.

---

## 19. Phase 4 Design: TracerPid Masking

> **This is not a security boundary.** TracerPid masking raises the bar for casual detection (e.g., a pip package checking `TracerPid` in a post-install script). It does NOT defeat a determined adversary who can check timing differences, use `prctl(PR_SET_PTRACER)` behavior probes, observe ptrace-induced scheduling artifacts, or read other `/proc` indicators. Describe this capability as "reduces casual anti-analysis" — not "prevents detection."

### 19.1 The Problem

Any traced process can read `/proc/self/status` and see `TracerPid: <nonzero>`, revealing that it is being monitored. A supply chain attack could check for this and behave differently.

### 19.2 Approach A: LD_PRELOAD Interposition (Primary)

Inject an `LD_PRELOAD` library that hooks `fopen` and `read` to mask `TracerPid` in `/proc/self/status` and `/proc/<own-pid>/status`.

```c
// libagentsh-mask.so
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>

static ssize_t (*real_read)(int fd, void *buf, size_t count);

ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    ssize_t n = real_read(fd, buf, count);

    if (n > 0) {
        // Check if this fd is /proc/self/status or /proc/<pid>/status
        char fdpath[64];
        char target[256];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
        ssize_t linklen = readlink(fdpath, target, sizeof(target)-1);
        if (linklen > 0) {
            target[linklen] = '\0';
            if (strstr(target, "/status")) {
                // Replace "TracerPid:\t<digits>" with "TracerPid:\t0"
                char *pos = memmem(buf, n, "TracerPid:\t", 11);
                if (pos) {
                    char *end = memchr(pos + 11, '\n', n - (pos + 11 - (char*)buf));
                    if (end) {
                        // Overwrite PID digits with "0" padded with spaces
                        memset(pos + 11, ' ', end - pos - 11);
                        pos[11] = '0';
                    }
                }
            }
        }
    }
    return n;
}
```

The library is compiled as part of agentsh's build and injected via `env_inject`:

```yaml
sandbox:
  ptrace:
    mask_tracer_pid: true
  env_inject:
    LD_PRELOAD: "/usr/lib/agentsh/libagentsh-mask.so"
```

**Limitations:**
- Statically-linked binaries bypass LD_PRELOAD (rare in agent workloads — Go binaries are the main exception, but Go's `os.ReadFile` uses raw syscalls)
- Process can use raw `syscall(SYS_READ)` to bypass the hook
- Not available if the tracee sets `AT_SECURE` (setuid)

### 19.3 Approach B: /proc Bind-Mount Override

If mount namespace is available (not on Fargate, but on EC2 or non-Fargate K8s), mount a FUSE filesystem over `/proc/<pid>/status` that serves a modified version.

This is more robust than LD_PRELOAD but requires `SYS_ADMIN` or mount namespace, which aren't available on Fargate. Documented as an option for non-Fargate deployments.

### 19.4 Approach C: ptrace-based Interception of /proc/self/status Reads

The ptrace tracer already intercepts `openat` syscalls. When it sees `openat(AT_FDCWD, "/proc/self/status", O_RDONLY)`:

1. Allow the `openat` to succeed
2. Track the returned fd in a per-tracee map: `maskedFDs[pid][fd] = "/proc/self/status"`
3. When a subsequent `read(fd, ...)` is intercepted at syscall-exit:
   - Check if `fd` is in `maskedFDs`
   - If yes, read the buffer from tracee memory, replace `TracerPid:\t<N>` with `TracerPid:\t0`, write it back

This is the most robust approach for ptrace mode because it works for all binaries (static, dynamic, Go) and doesn't require mount namespaces. The overhead is minimal — only `read()` calls on the tracked fds are intercepted at exit, and `/proc/self/status` is rarely read in hot loops.

```go
func (t *Tracer) handleReadExit(pid int, regs Regs) {
    fd := int(regs.Arg(0))
    maskedFDs := t.maskedFDs[pid]
    if maskedFDs == nil || maskedFDs[fd] == "" {
        return // Not a masked fd
    }

    n := regs.ReturnValue()
    if n <= 0 {
        return
    }

    bufPtr := regs.Arg(1)
    buf := make([]byte, n)
    readBytes(pid, bufPtr, buf)

    // Find and replace TracerPid
    needle := []byte("TracerPid:\t")
    idx := bytes.Index(buf, needle)
    if idx < 0 {
        return
    }

    // Find the end of the PID number
    start := idx + len(needle)
    end := bytes.IndexByte(buf[start:], '\n')
    if end < 0 {
        return
    }
    end += start

    // Replace with "0" padded with spaces (preserve buffer length)
    replacement := make([]byte, end-start)
    replacement[0] = '0'
    for i := 1; i < len(replacement); i++ {
        replacement[i] = ' '
    }
    copy(buf[start:end], replacement)

    writeBytes(pid, bufPtr, buf)
}
```

**Configuration:**

```yaml
sandbox:
  ptrace:
    # See §3.1 for the unified mask_tracer_pid field.
    # "off", "ptrace", "ld_preload", or "mount"
    mask_tracer_pid: "ptrace"
```

**Recommendation:** Use `"ptrace"` as the default when masking is desired. It works everywhere ptrace works, including Fargate. Fall back to `"ld_preload"` if the operator prefers lower overhead (no extra syscall-exit interception). `"mount"` is only for environments with mount capabilities.

---

## 20. Phase 4 Design: EKS Fargate Support

### 20.1 Current State

As of March 2026, `SYS_PTRACE` is supported on ECS Fargate but **not** on EKS Fargate. The EKS Fargate feature is tracked on the AWS containers roadmap (issue #1102) and has been a top-voted request since 2020.

### 20.2 Preparation

The ptrace tracer is architecturally compatible with EKS Fargate — the only missing piece is the capability grant. When AWS ships `SYS_PTRACE` for EKS Fargate, agentsh needs:

1. **Helm chart update:** Add `securityContext.capabilities.add: ["SYS_PTRACE"]` to the sidecar container spec and `shareProcessNamespace: true` to the pod spec.

2. **Sidecar discovery update:** On EKS, the pod's init process is the Kubernetes `pause` container (not the workload). The sidecar discovery logic needs to identify the workload container's root process by excluding `pause` and the agentsh container:

```go
func (t *Tracer) discoverTargetEKS() (int, error) {
    myPID := os.Getpid()
    entries, _ := os.ReadDir("/proc")

    for _, e := range entries {
        pid, err := strconv.Atoi(e.Name())
        if err != nil || pid == myPID || pid == 1 {
            continue
        }
        comm := readComm(pid)
        // Skip pause container and agentsh processes
        if comm == "pause" || strings.HasPrefix(comm, "agentsh") {
            continue
        }
        ppid := readPPID(pid)
        if ppid == 1 { // Direct child of pause container
            return pid, nil
        }
    }
    return 0, fmt.Errorf("no workload process found in EKS pod")
}
```

3. **K8s sidecar integration:** Extend `pkg/k8s/sidecar.go` to support ptrace mode sidecars with the correct security context and shared PID namespace.

4. **Admission controller:** For EKS deployments using the Datadog-style admission controller pattern, provide a mutating webhook that automatically injects the agentsh sidecar with ptrace configuration into pods matching a label selector.

### 20.3 Configuration

```yaml
sandbox:
  ptrace:
    enabled: true
    attach_mode: "sidecar"
    # Kubernetes-specific: how to identify the workload container
    kubernetes:
      # Skip these process names when discovering the target
      skip_processes: ["pause", "agentsh", "agentsh-server"]
      # Or specify the workload container name explicitly
      # container_name: "agent-workload"
```

### 20.4 Reference Pod Spec

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-workload
spec:
  template:
    spec:
      shareProcessNamespace: true
      containers:
        - name: agentsh
          image: ghcr.io/canyonroad/agentsh:latest
          securityContext:
            capabilities:
              add: ["SYS_PTRACE"]
          env:
            - name: AGENTSH_PTRACE_ENABLED
              value: "true"
            - name: AGENTSH_PTRACE_ATTACH_MODE
              value: "sidecar"
          ports:
            - containerPort: 18080
          readinessProbe:
            httpGet:
              path: /health
              port: 18080
        - name: agent-workload
          image: your-agent-image:latest
          env:
            - name: AGENTSH_SERVER
              value: "http://127.0.0.1:18080"
```

---

## 21. Feature Coverage Matrix

The following matrix describes what ptrace mode can and cannot do at each phase, compared to full mode. No percentage scores — those require a defined threat model and measured attack coverage, neither of which exist yet.

### 21.1 Allow / Deny / Audit (Core Enforcement)

| Capability | full mode | ptrace Phase 1 | ptrace Phase 2-3 | Notes |
|---|---|---|---|---|
| Command allow/deny | ✓ | ✓ | ✓ | Full parity from Phase 1 |
| File allow/deny | ✓ | — | ✓ | Phase 2 |
| Network allow/deny | ✓ | — | ✓ | Phase 2 |
| Signal allow/deny | ✓ | — | ✓ | Phase 2 |
| Structured audit events | ✓ | ✓ | ✓ | Full parity from Phase 1 |
| Process tree tracking | ✓ (atomic) | ✓ (auto-attach) | ✓ | Functionally equivalent; tiny theoretical race |
| LLM proxy + DLP | ✓ | ✓ | ✓ | Userspace, unaffected by enforcement backend |

### 21.2 Steering / Redirect (Phase 4)

| Capability | full mode | ptrace Phase 4 | Coverage | Notes |
|---|---|---|---|---|
| Exec redirect | ✓ (SECCOMP_ADDFD) | ✓ (syscall injection) | Full | Proven technique (CRIU, strace) |
| File path redirect | ✓ (FUSE remap) | ✓ (register rewrite) | Full | mmap scratch for long paths |
| Soft-delete | ✓ (FUSE rename) | ✓ (injected renameat2) | Mostly | Edge cases: cross-device, hardlinks |
| Connect redirect | ✓ (eBPF/proxy) | ✓ (sockaddr rewrite) | Full | Fixed-size struct, always fits in-place |
| DNS redirect | ✓ (eBPF/proxy) | ✓ (response rewrite) | **Partial** | UDP port 53 only. No DoH, DoT, TCP DNS, recvmmsg |
| SNI rewrite | ✓ (proxy intercept) | ✓ (buffer rewrite) | **Partial** | Single write() only. No writev, sendmsg, partial sends |
| Signal redirect | ✓ (seccomp) | ✓ (register rewrite) | Full | Phase 2 |

### 21.3 Evasion Resistance

| Property | full mode | ptrace mode | Notes |
|---|---|---|---|
| Detectable by tracee | No (seccomp is invisible) | Yes (TracerPid in /proc) | Masking (§19) raises bar for casual checks, not determined adversaries |
| TOCTOU (multithreaded pointer args) | Vulnerable (seccomp) | Vulnerable (same) | Shared limitation. FUSE is immune |
| Thread spawn race window | None (atomic seccomp inherit) | Tiny (PTRACE_O_TRACECLONE) | No known real-world exploit |
| Static binary anti-analysis | N/A | TracerPid masking ineffective | LD_PRELOAD doesn't work on static binaries |

### 21.4 Qualitative Assessment

**Phase 1-3 (allow/deny/audit):** Strong fallback mode for restricted runtimes. Full enforcement coverage for command, file, network, and signal policy. Good audit trail. No steering.

**Phase 4 (with steering):** Near-complete feature parity with full mode for the common cases that matter to AI agent security: exec redirect, file redirect, connect redirect. DNS and SNI rewriting are best-effort and should not be relied on as primary controls — use the LLM proxy for API routing instead.

**For the target use case** (AI agents running untrusted code from packages, repos, and MCP tools on Fargate): ptrace mode provides equivalent practical protection to full mode. The evasion gap (TracerPid, timing) requires a targeted adversary who knows agentsh is running and has built anti-ptrace checks — this is not the threat model agentsh is designed for. Supply chain attacks, MCP exfiltration, and agent prompt injection do not check for ptrace.

