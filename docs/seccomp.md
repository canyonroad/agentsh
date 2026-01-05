# Seccomp-BPF Syscall Filtering

agentsh uses seccomp-bpf to enforce syscall-level security controls on agent processes.

## Overview

When enabled, seccomp filtering provides two types of protection:

1. **Unix Socket Monitoring**: Intercepts socket operations for policy-based access control
2. **Syscall Blocking**: Immediately terminates processes that attempt blocked syscalls

## Configuration

```yaml
sandbox:
  seccomp:
    enabled: true
    mode: enforce  # enforce | audit | disabled

    unix_socket:
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
