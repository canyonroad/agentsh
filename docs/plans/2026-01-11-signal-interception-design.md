# Signal Interception Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add comprehensive signal interception to agentsh, allowing policies to control which signals processes can send to each other.

**Architecture:** Intercept signal-related syscalls via seccomp (Linux), audit via Endpoint Security (macOS), and use ETW + Job Objects + Restricted Tokens (Windows). Unified policy model with platform-specific enforcement and fallback to audit when blocking isn't possible.

**Tech Stack:** seccomp user notify (Linux), Endpoint Security Framework (macOS), ETW/Job Objects (Windows), existing policy engine

---

## Goals

1. **Prevent processes from killing agentsh** - Supervisor protection
2. **Prevent processes from killing each other** - Child A can't kill child B
3. **Prevent killing external processes** - Child can't kill processes outside agentsh
4. **Audit/log all signal attempts** - Complete visibility
5. **Config reload interception** - Control SIGHUP and similar signals

## Policy Schema

New top-level `signal_rules` section alongside existing `file_rules`, `network_rules`, etc.

### Full Example

```yaml
signal_rules:
  # Rule 1: Block fatal signals to anything outside session
  - name: block-external-kill
    signals: ["@fatal"]                    # Group: SIGKILL, SIGTERM, SIGQUIT, SIGABRT
    target:
      type: external                       # Any PID outside agentsh session
    decision: deny
    fallback: audit                        # If platform can't block, audit instead

  # Rule 2: Downgrade SIGKILL to SIGTERM for children
  - name: graceful-child-kill
    signals: [SIGKILL, 9]                  # Name or number
    target:
      type: children
    decision: redirect
    redirect_to: SIGTERM

  # Rule 3: Audit all signals to system processes
  - name: audit-system-signals
    signals: ["@all"]
    target:
      type: system                         # PID 1, kernel threads
    decision: audit

  # Rule 4: Block signals to specific process patterns
  - name: protect-database
    signals: ["@fatal", "@job"]
    target:
      type: process
      pattern: "postgres*"
    decision: deny

  # Rule 5: Require approval for SIGHUP to parent
  - name: approve-reload
    signals: [SIGHUP, SIGUSR1, SIGUSR2]
    target:
      type: parent
    decision: approve
```

### Signal Specification

Signals can be specified as:
- **Name:** `SIGKILL`, `SIGTERM`, `SIGHUP`, etc.
- **Number:** `9`, `15`, `1`, etc.
- **Group:** `@fatal`, `@job`, `@reload`, `@ignore`, `@all`

**Predefined groups:**

| Group | Signals |
|-------|---------|
| `@fatal` | SIGKILL, SIGTERM, SIGQUIT, SIGABRT |
| `@job` | SIGSTOP, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU |
| `@reload` | SIGHUP, SIGUSR1, SIGUSR2 |
| `@ignore` | SIGCHLD, SIGURG, SIGWINCH |
| `@all` | All signals |

### Target Specification

**Simple target types:**

| Type | Description |
|------|-------------|
| `self` | Process sending signal to itself |
| `children` | Direct children of sender |
| `descendants` | Children, grandchildren, etc. |
| `siblings` | Other processes at same level in session |
| `session` | Any process in the agentsh session |
| `parent` | The agentsh supervisor |
| `external` | Any PID outside the session |
| `system` | PID 1, kernel threads (PID < 100) |
| `user` | Other processes owned by same user but outside session |

**Advanced target types:**

```yaml
# Match by process name pattern
target:
  type: process
  pattern: "postgres*"

# Match by PID range
target:
  type: pid_range
  min: 1
  max: 100
```

### Decision Types

| Decision | Behavior |
|----------|----------|
| `allow` | Let signal through |
| `deny` | Block signal, return EPERM to sender |
| `audit` | Allow + enhanced logging |
| `approve` | Require manual approval before signal is sent |
| `redirect` | Change signal (e.g., SIGKILL → SIGTERM) |
| `absorb` | Silently drop, no error to sender |

**Redirect example:**

```yaml
- signals: [SIGKILL]
  target:
    type: children
  decision: redirect
  redirect_to: SIGTERM   # Downgrade SIGKILL to SIGTERM
```

**Fallback for platform limitations:**

```yaml
- signals: ["@fatal"]
  target:
    type: external
  decision: deny
  fallback: audit   # Used when platform can't block (macOS, Windows)
```

## Platform Implementations

### Linux (Full Support)

**Mechanism:** seccomp `SECCOMP_RET_USER_NOTIF` (Linux 5.0+)

**Syscalls intercepted:**

| Syscall | Purpose |
|---------|---------|
| `kill(pid, sig)` | Standard signal |
| `tgkill(tgid, tid, sig)` | Thread-specific signal |
| `tkill(tid, sig)` | Legacy thread signal |
| `rt_sigqueueinfo(pid, sig, info)` | Signal with data |
| `rt_tgsigqueueinfo(tgid, tid, sig, info)` | Thread + data |
| `pidfd_send_signal(pidfd, sig, ...)` | Modern pidfd-based (Linux 5.1+) |
| `ptrace(PTRACE_KILL, pid, ...)` | Debugger kill |

**Architecture:**

```
┌─────────────────────────────────────────────────────┐
│                 agentsh supervisor                  │
│  ┌─────────────────────────────────────────────┐   │
│  │         Signal Policy Engine                │   │
│  │  - Evaluate signal_rules                    │   │
│  │  - Track session PIDs (who's "inside")      │   │
│  │  - Resolve target type from PID             │   │
│  └──────────────────┬──────────────────────────┘   │
│                     │                               │
│  ┌──────────────────▼──────────────────────────┐   │
│  │      seccomp notify handler                 │   │
│  │  - Receive syscall notifications            │   │
│  │  - Read syscall args (pid, signal)          │   │
│  │  - Query policy engine                      │   │
│  │  - Respond: allow / EPERM / modify args     │   │
│  └──────────────────┬──────────────────────────┘   │
│                     │                               │
└─────────────────────┼───────────────────────────────┘
                      │ seccomp_unotify fd
┌─────────────────────▼───────────────────────────────┐
│              Child process (sandboxed)              │
│  - seccomp filter installed at start               │
│  - kill() syscall trapped → supervisor notified    │
└─────────────────────────────────────────────────────┘
```

**Capabilities:**
- Full blocking (deny returns EPERM)
- Signal redirection (modify syscall args)
- Signal absorption (return success without executing)
- Complete audit trail

### macOS (Audit + Best-Effort Isolation)

**Mechanism:** Endpoint Security Framework (audit) + Process Isolation (containment)

**ES events monitored:**

| Event | Purpose |
|-------|---------|
| `ES_EVENT_TYPE_NOTIFY_SIGNAL` | Signal sent between processes |
| `ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME` | SIGSTOP/SIGCONT equivalent |
| `ES_EVENT_TYPE_NOTIFY_EXIT` | Process termination (detect kills) |

**Architecture:**

```
┌─────────────────────────────────────────────────────┐
│                 agentsh supervisor                  │
│  ┌─────────────────────────────────────────────┐   │
│  │      Endpoint Security Client               │   │
│  │  - Subscribe to signal events               │   │
│  │  - NOTIFY only (cannot block)               │   │
│  │  - Full audit trail                         │   │
│  └──────────────────┬──────────────────────────┘   │
│                     │                               │
│  ┌──────────────────▼──────────────────────────┐   │
│  │      Signal Audit Logger                    │   │
│  │  - Log: source PID, target PID, signal      │   │
│  │  - Evaluate policy (for audit events)       │   │
│  │  - Emit "would_deny" events for violations  │   │
│  └─────────────────────────────────────────────┘   │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │      Process Isolation (containment)        │   │
│  │  - Run children as separate user (optional) │   │
│  │  - Sandbox profile with signal restrictions │   │
│  │  - Limits who can signal whom               │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

**Containment strategies:**

1. **User isolation** - Run child processes as unprivileged user
2. **Sandbox profile** - `(deny signal (target others))` (undocumented API)
3. **Process group isolation** - Separate pgid per task

**Limitations:**
- Cannot block signals like Linux seccomp
- ES Framework is notify-only for signals
- Sandbox profiles are unsupported API
- SIP prevents tracing Apple binaries

### Windows (Audit + Limited Control)

**Mechanism:** ETW + Job Objects + Console Control + Restricted Tokens

**Architecture:**

```
┌─────────────────────────────────────────────────────────┐
│                   agentsh supervisor                    │
│  ┌───────────────────────────────────────────────────┐ │
│  │              ETW Consumer                         │ │
│  │  - Microsoft-Windows-Kernel-Process provider      │ │
│  │  - Event ID 2: Process terminated                 │ │
│  │  - Event ID 11: Thread terminated                 │ │
│  │  - Captures: source PID, target PID, exit code    │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  ┌───────────────────────────────────────────────────┐ │
│  │              Job Object Manager                   │ │
│  │  - Create job per session                         │ │
│  │  - JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE            │ │
│  │  - JOB_OBJECT_LIMIT_BREAKAWAY_OK = false         │ │
│  │  - Track all PIDs in job                          │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  ┌───────────────────────────────────────────────────┐ │
│  │         Console Control Handler                   │ │
│  │  - SetConsoleCtrlHandler() for child processes    │ │
│  │  - Intercept: CTRL_C, CTRL_BREAK, CTRL_CLOSE     │ │
│  │  - Can BLOCK these (return TRUE)                  │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  ┌───────────────────────────────────────────────────┐ │
│  │          Restricted Token Manager                 │ │
│  │  - CreateRestrictedToken() for child processes    │ │
│  │  - Remove SeDebugPrivilege                        │ │
│  │  - Remove SeAssignPrimaryTokenPrivilege           │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**What CAN be blocked on Windows:**

| Signal Type | Windows Equivalent | Can Block? |
|-------------|-------------------|------------|
| SIGINT | `CTRL_C_EVENT` | Yes |
| SIGBREAK | `CTRL_BREAK_EVENT` | Yes |
| SIGTERM (graceful) | `WM_CLOSE` message | Yes (GUI apps) |
| SIGKILL | `TerminateProcess` | **No** |

**What Restricted Tokens prevent:**
- Killing other users' processes
- Killing elevated processes
- Killing system processes

**Limitations:**
- `TerminateProcess` cannot be intercepted by design
- A process can always kill its own children
- ETW is audit-only, not preventive

## Platform Capability Summary

| Capability | Linux | macOS | Windows |
|------------|-------|-------|---------|
| Block signals | Yes (seccomp) | No | Partial (console only) |
| Redirect signals | Yes | No | No |
| Absorb signals | Yes | No | No |
| Audit signals | Yes | Yes (ES) | Yes (ETW) |
| Process isolation | Yes (namespaces) | Yes (sandbox) | Yes (tokens) |

## Error Handling

### Syscall Interception Errors (Linux)

| Scenario | Handling |
|----------|----------|
| seccomp notify fd closed unexpectedly | Log error, kill process tree (fail-secure) |
| PID lookup fails (process exited) | Allow syscall (target already gone) |
| Policy evaluation timeout | Deny with EPERM (fail-secure) |
| Invalid signal number | Pass through (let kernel reject) |
| pidfd resolution fails | Deny with EPERM + audit |

### Target Classification Edge Cases

| Scenario | Classification | Rationale |
|----------|---------------|-----------|
| PID 0 (current process group) | `session` or `external` | Expand to actual PIDs, evaluate each |
| PID -1 (all processes) | `deny` always | Too dangerous, never allow |
| PID < 0 (process group) | Resolve group members | Evaluate each member separately |
| PID reuse race | Use pidfd where available | Linux 5.1+ prevents race |
| Zombie process | `external` | No longer in session |

### Platform Capability Detection

```go
type SignalCapabilities struct {
    CanBlock       bool   // Can prevent signals (Linux only)
    CanRedirect    bool   // Can modify signal (Linux only)
    CanAudit       bool   // Can log signal events (all platforms)
    CanIsolate     bool   // Can limit who signals whom (all platforms)
}
```

### Fallback Behavior

When a policy specifies `decision: deny` but the platform cannot block:

1. Check for `fallback` field in rule
2. If present, use fallback action (typically `audit`)
3. Emit `signal_would_deny` event indicating platform limitation
4. Log what would have been blocked for visibility

## Session PID Tracking

```go
type SessionPIDRegistry struct {
    session  map[int]string     // PID → session ID
    children map[int][]int      // PID → child PIDs
    parents  map[int]int        // PID → parent PID
}

func (r *SessionPIDRegistry) ClassifyTarget(sourcePID, targetPID int) TargetType {
    // Returns: self, children, descendants, siblings, session,
    //          parent, external, system, user
}
```

**PID tracking sources:**
- Linux: cgroup membership, fork/exec tracing
- macOS: ES process events
- Windows: Job Object membership

## Audit Events

### Event Types

| Event Type | Description |
|------------|-------------|
| `signal_sent` | Signal allowed through |
| `signal_blocked` | Signal denied |
| `signal_redirected` | Signal transformed |
| `signal_absorbed` | Signal silently dropped |
| `signal_approved` | Signal after manual approval |
| `signal_would_deny` | Audit mode: would have blocked |

### Event Payload

```go
type SignalEvent struct {
    Timestamp      time.Time
    SessionID      string
    EventType      EventType

    // Signal-specific
    Signal         int       // Signal number
    SignalName     string    // "SIGKILL", "SIGTERM", etc.
    SourcePID      int
    SourceCmd      string
    TargetPID      int
    TargetCmd      string
    TargetType     string    // "external", "children", etc.

    // Decision
    Decision       string
    RuleName       string
    Fallback       bool

    // Redirect-specific
    OriginalSignal int       // Before redirect

    // Platform
    Platform       string
    Syscall        string    // "kill", "tgkill", etc.
}
```

### Example Log Entries

```jsonl
{"timestamp":"2026-01-11T10:30:00Z","session_id":"sess_abc123","event_type":"signal_blocked","signal":9,"signal_name":"SIGKILL","source_pid":1234,"source_cmd":"python3","target_pid":1,"target_cmd":"systemd","target_type":"system","decision":"deny","rule_name":"block-system-signals","platform":"linux","syscall":"kill"}

{"timestamp":"2026-01-11T10:30:01Z","session_id":"sess_abc123","event_type":"signal_redirected","signal":15,"signal_name":"SIGTERM","source_pid":1234,"source_cmd":"bash","target_pid":1235,"target_cmd":"node","target_type":"children","decision":"redirect","rule_name":"graceful-child-kill","original_signal":9,"platform":"linux","syscall":"kill"}

{"timestamp":"2026-01-11T10:30:02Z","session_id":"sess_abc123","event_type":"signal_would_deny","signal":9,"signal_name":"SIGKILL","source_pid":1234,"source_cmd":"python3","target_pid":500,"target_cmd":"postgres","target_type":"external","decision":"deny","rule_name":"block-external-kill","fallback":true,"platform":"darwin","syscall":"kill"}
```

## Metrics

```go
var (
    signalTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "agentsh_signals_total",
            Help: "Total signal operations",
        },
        []string{"signal", "target_type", "decision", "platform"},
    )

    signalLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "agentsh_signal_evaluation_seconds",
            Help:    "Signal policy evaluation latency",
            Buckets: []float64{.0001, .0005, .001, .005, .01},
        },
        []string{"platform"},
    )
)
```

## Testing Strategy

### Unit Tests

- Policy evaluation logic
- Signal group expansion
- Target type classification
- PID registry operations

### Integration Tests (Linux)

- seccomp filter installation
- Syscall interception and blocking
- Signal redirection verification
- High-volume stress tests

### Platform Capability Tests

- Detect available features per platform
- Verify fallback behavior
- Test isolation mechanisms

### End-to-End Tests

```bash
# Block external kill
agentsh exec test-session -- python3 -c "
import os, signal
try:
    os.kill(1, signal.SIGTERM)
    print('FAIL: should have been blocked')
except PermissionError:
    print('PASS: blocked as expected')
"

# Verify redirect
agentsh exec test-session -- bash -c '
    python3 -c "import signal,time; signal.signal(signal.SIGTERM, lambda s,f: print(\"GOT SIGTERM\")); time.sleep(10)" &
    PID=$!
    sleep 1
    kill -KILL $PID  # Should be redirected to SIGTERM
    wait
'
```

## File Structure

```
internal/
├── signal/
│   ├── engine.go           # Signal policy evaluation
│   ├── groups.go           # Signal group definitions
│   ├── registry.go         # Session PID tracking
│   ├── types.go            # SignalRule, SignalEvent, etc.
│   ├── linux.go            # seccomp implementation
│   ├── darwin.go           # ES + isolation implementation
│   └── windows.go          # ETW + Job Objects implementation
├── policy/
│   └── model.go            # Add SignalRule to Policy struct
├── seccomp/
│   └── filter.go           # Add signal syscalls to filter
└── events/
    └── types.go            # Add signal event types
```

## References

- [seccomp user notification](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)
- [Endpoint Security Framework](https://developer.apple.com/documentation/endpointsecurity)
- [Windows ETW](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
- [TerminateProcess limitations](https://devblogs.microsoft.com/oldnewthing/20040722-00/?p=38373)
