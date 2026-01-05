# Seccomp-BPF Enforcement Design

## Overview

This design extends agentsh's existing Unix socket monitoring infrastructure to provide general syscall blocking with seccomp-bpf. The implementation uses `SECCOMP_RET_USER_NOTIF` for socket monitoring (allowing policy decisions) and `SECCOMP_RET_KILL_PROCESS` for blocked syscalls (immediate termination with logging).

## Goals

1. **Unix Socket Enforcement**: Monitor and control Unix socket `connect()` calls via user-notify
2. **Syscall Blocking**: Block dangerous syscalls with configurable blocklist/allowlist
3. **Audit Trail**: Log all blocked syscall attempts before process termination
4. **Configurability**: Policy-driven syscall rules, not hardcoded lists

## Configuration Schema

```yaml
sandbox:
  seccomp:
    enabled: true
    mode: enforce  # enforce | audit | disabled

    # Unix socket monitoring (existing behavior)
    unix_socket:
      enabled: true
      action: enforce  # enforce | audit

    # General syscall blocking
    syscalls:
      # Default action for syscalls not in any list
      default_action: allow  # allow | block

      # Syscalls to explicitly block (when default is allow)
      block:
        - ptrace
        - process_vm_readv
        - process_vm_writev
        - personality
        - mount
        - umount2
        - pivot_root
        - reboot
        - kexec_load
        - init_module
        - finit_module
        - delete_module

      # Syscalls to explicitly allow (when default is block)
      allow: []

      # Action when blocked syscall is attempted
      on_block: kill  # kill | log_and_kill
```

### Recommended Defaults

```yaml
# Dangerous syscalls blocked by default
block:
  - ptrace           # Process debugging/injection
  - process_vm_readv # Cross-process memory read
  - process_vm_writev # Cross-process memory write
  - personality      # Execution domain changes
  - mount            # Filesystem mounting
  - umount2          # Filesystem unmounting
  - pivot_root       # Root filesystem changes
  - reboot           # System reboot
  - kexec_load       # Kernel replacement
  - init_module      # Kernel module loading
  - finit_module     # Kernel module loading (fd)
  - delete_module    # Kernel module unloading
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        agentsh server                                │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    Session Manager                           │    │
│  │  ┌─────────────┐  ┌─────────────────────────────────────┐   │    │
│  │  │ Policy      │  │ Seccomp Handler                      │   │    │
│  │  │ Engine      │  │ (user-notify for unix sockets)      │   │    │
│  │  └─────────────┘  └─────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              ▲                                       │
│                              │ notify fd (SCM_RIGHTS)               │
│                              │                                       │
└──────────────────────────────┼───────────────────────────────────────┘
                               │
┌──────────────────────────────┼───────────────────────────────────────┐
│  agentsh-unixwrap            │                                       │
│  ┌───────────────────────────┴─────────────────────────────────┐    │
│  │ 1. Parse config from env (AGENTSH_SECCOMP_CONFIG)           │    │
│  │ 2. Build combined filter:                                    │    │
│  │    - connect() → SECCOMP_RET_USER_NOTIF                     │    │
│  │    - blocked syscalls → SECCOMP_RET_KILL_PROCESS            │    │
│  │ 3. Install filter with SECCOMP_FILTER_FLAG_NEW_LISTENER     │    │
│  │ 4. Send notify fd to parent via socketpair                   │    │
│  │ 5. exec() the target command                                 │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    Target Process                            │    │
│  │  connect(unix_socket) → user-notify → policy decision       │    │
│  │  ptrace() → SIGKILL (after audit log)                       │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

1. **agentsh-unixwrap**: Extended to read seccomp config from environment and build combined filter
2. **Seccomp Handler**: Existing handler continues processing unix socket notifications
3. **Audit Logger**: New component logs blocked syscall events before process termination
4. **Config Parser**: Parses YAML config and resolves syscall names to numbers

## Filter Installation

The filter installation in `agentsh-unixwrap` builds a combined BPF program:

```go
// internal/seccomp/filter.go

type Config struct {
    UnixSocketEnabled bool
    BlockedSyscalls   []string
    OnBlock           string // "kill" or "log_and_kill"
}

func BuildFilter(cfg Config) (*libseccomp.ScmpFilter, error) {
    // Default action: allow
    filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
    if err != nil {
        return nil, err
    }

    // Unix socket monitoring: connect() → user-notify
    if cfg.UnixSocketEnabled {
        connectNr, _ := libseccomp.GetSyscallFromName("connect")
        filter.AddRule(connectNr, libseccomp.ActNotify)
    }

    // Blocked syscalls → kill
    for _, name := range cfg.BlockedSyscalls {
        nr, err := libseccomp.GetSyscallFromName(name)
        if err != nil {
            continue // Skip unknown syscalls (cross-arch compat)
        }
        filter.AddRule(nr, libseccomp.ActKillProcess)
    }

    return filter, nil
}
```

### Installation Flow

1. `agentsh-unixwrap` reads `AGENTSH_SECCOMP_CONFIG` env var (JSON-encoded config)
2. Builds combined filter using libseccomp
3. Installs filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`
4. Sends notify fd to parent via pre-established socketpair
5. Calls `exec()` to run target command

## Handler Logic

### Unix Socket Handler (Existing)

```go
// internal/netmonitor/unix/handler.go
func (h *Handler) handleNotification(req *seccomp.NotifReq) {
    // Extract socket path from connect() args
    path := extractSocketPath(req)

    // Check policy
    allowed := h.policy.AllowUnixSocket(path)

    if allowed {
        seccomp.NotifSend(h.fd, &seccomp.NotifResp{
            ID:    req.ID,
            Flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        })
    } else {
        seccomp.NotifSend(h.fd, &seccomp.NotifResp{
            ID:    req.ID,
            Error: -int32(syscall.EACCES),
        })
    }
}
```

### Blocked Syscall Handling

For blocked syscalls, the kernel immediately terminates the process with `SIGKILL`. The handler doesn't receive notifications for `SECCOMP_RET_KILL_PROCESS` actions.

**Audit logging strategy**: Use `SECCOMP_RET_TRACE` with ptrace to log before kill, OR accept that blocked syscalls are logged via process termination signal.

**Recommended approach**: Use `SECCOMP_RET_KILL_PROCESS` and log via:
1. Process termination monitoring (parent receives SIGCHLD with specific exit status)
2. The exit status encodes the syscall number that triggered termination

```go
// internal/session/exec.go
func (s *Session) handleChildExit(status syscall.WaitStatus) {
    if status.Signaled() && status.Signal() == syscall.SIGSYS {
        // Seccomp killed the process
        syscallNr := extractSyscallFromSeccomp(status)
        s.audit.LogSeccompBlocked(syscallNr)
    }
}
```

### Extracting Syscall Info from SIGSYS

When `SECCOMP_RET_KILL_PROCESS` triggers, the process receives `SIGSYS`. The `si_syscall` field in `siginfo_t` contains the syscall number:

```go
// Use signalfd or ptrace to capture siginfo
func extractBlockedSyscall(pid int) (int, error) {
    var info unix.Siginfo
    _, err := unix.Ptrace(unix.PTRACE_GETSIGINFO, pid, 0, uintptr(unsafe.Pointer(&info)))
    if err != nil {
        return 0, err
    }
    // info.Syscall contains the blocked syscall number
    return int(info.Syscall), nil
}
```

## Event Schema

```go
// internal/audit/events.go

type SeccompBlockedEvent struct {
    Type      string    `json:"type"`       // "seccomp_blocked"
    Timestamp time.Time `json:"timestamp"`
    SessionID string    `json:"session_id"`

    // Process info
    PID       int    `json:"pid"`
    Command   string `json:"command"`

    // Syscall info
    Syscall   string `json:"syscall"`      // Human-readable name
    SyscallNr int    `json:"syscall_nr"`   // Numeric value

    // Policy info
    Reason    string `json:"reason"`       // "blocked_by_policy"
    Action    string `json:"action"`       // "killed"
}
```

Example JSON event:

```json
{
  "type": "seccomp_blocked",
  "timestamp": "2026-01-04T10:30:00Z",
  "session_id": "sess_abc123",
  "pid": 12345,
  "command": "malicious-tool",
  "syscall": "ptrace",
  "syscall_nr": 101,
  "reason": "blocked_by_policy",
  "action": "killed"
}
```

## Testing Approach

### Unit Tests

```go
// internal/seccomp/filter_test.go

func TestBuildFilter_BlockedSyscalls(t *testing.T) {
    cfg := Config{
        BlockedSyscalls: []string{"ptrace", "mount"},
    }
    filter, err := BuildFilter(cfg)
    require.NoError(t, err)

    // Verify filter contains expected rules
    // (libseccomp provides introspection APIs)
}

func TestBuildFilter_UnknownSyscall(t *testing.T) {
    cfg := Config{
        BlockedSyscalls: []string{"not_a_real_syscall"},
    }
    filter, err := BuildFilter(cfg)
    require.NoError(t, err) // Should skip unknown, not error
}
```

### Integration Tests

```go
// internal/seccomp/integration_test.go

func TestSeccompBlocks_Ptrace(t *testing.T) {
    if os.Getuid() != 0 {
        t.Skip("requires root for seccomp")
    }

    // Start wrapper with ptrace blocked
    cmd := exec.Command("agentsh-unixwrap", "strace", "-p", "1")
    cmd.Env = append(os.Environ(),
        `AGENTSH_SECCOMP_CONFIG={"blocked_syscalls":["ptrace"]}`)

    err := cmd.Run()
    require.Error(t, err)

    // Verify exit was due to SIGSYS
    exitErr := err.(*exec.ExitError)
    require.True(t, exitErr.Sys().(syscall.WaitStatus).Signaled())
}
```

### Smoke Test Extension

```bash
# scripts/smoke.sh addition

# Test seccomp blocking
seccomp_test_cmd="./bin/agentsh exec $sid -- sh -c 'strace -p 1 2>&1 || echo blocked'"
seccomp_out="$(eval "$seccomp_test_cmd" | tail -n 1)"
if [[ "$seccomp_out" != "blocked" ]]; then
    # If strace worked, seccomp isn't blocking ptrace
    if [[ "$seccomp_out" != *"Operation not permitted"* ]]; then
        echo "smoke: seccomp should block ptrace: got=$seccomp_out" >&2
        exit 1
    fi
fi
```

## Implementation Phases

### Phase 1: Configuration
- Add `sandbox.seccomp.syscalls` to config schema
- Parse and validate syscall names
- Pass config to wrapper via environment

### Phase 2: Filter Extension
- Extend `BuildFilter()` to include blocked syscalls
- Add `SECCOMP_RET_KILL_PROCESS` rules
- Unit test filter generation

### Phase 3: Audit Logging
- Capture SIGSYS from child processes
- Extract syscall number from siginfo
- Log `seccomp_blocked` events

### Phase 4: Testing
- Integration tests with real seccomp
- Smoke test extension
- CI/CD verification

## Security Considerations

1. **Filter ordering**: `SECCOMP_RET_KILL_PROCESS` takes precedence over `SECCOMP_RET_USER_NOTIF` for the same syscall
2. **Arch compatibility**: Use `libseccomp.GetSyscallFromName()` which handles arch-specific syscall numbers
3. **No bypass**: Once filter is installed, it cannot be removed (inherited by children)
4. **Privilege required**: Installing seccomp filters requires `CAP_SYS_ADMIN` or `no_new_privs`
