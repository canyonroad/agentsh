# Security Modes

agentsh supports multiple security modes depending on available kernel features. The system automatically detects available primitives and selects the best mode, or you can explicitly configure a specific mode.

## Overview

Security enforcement is provided through a combination of:
- **Landlock** - Kernel-enforced filesystem and network sandboxing
- **Seccomp** - Syscall filtering with user-notify support
- **FUSE** - Filesystem interception for fine-grained control
- **eBPF** - Network monitoring and policy enforcement
- **Capability dropping** - Linux capability restrictions

## Available Modes

| Mode | Requirements | Protection Level | Description |
|------|--------------|------------------|-------------|
| `full` | seccomp + eBPF + FUSE | 100% | Full security with all features |
| `landlock` | Landlock + FUSE | ~85% | Kernel-enforced execution and FS control |
| `landlock-only` | Landlock | ~80% | Landlock without FUSE granularity |
| `minimal` | (none) | ~50% | Capability dropping and shim policy only |

### Mode Selection

By default, agentsh auto-detects the best available mode at startup:

```
┌─────────────────────────────────────────────┐
│ Seccomp + eBPF + FUSE available?            │
│   Yes → full mode                           │
│   No ↓                                      │
├─────────────────────────────────────────────┤
│ Landlock + FUSE available?                  │
│   Yes → landlock mode                       │
│   No ↓                                      │
├─────────────────────────────────────────────┤
│ Landlock available?                         │
│   Yes → landlock-only mode                  │
│   No → minimal mode                         │
└─────────────────────────────────────────────┘
```

## Configuration

### Security Mode Settings

```yaml
security:
  mode: auto              # auto | full | landlock | landlock-only | minimal
  strict: false           # Fail if mode requirements not met
  minimum_mode: ""        # Fail if auto-detect picks worse than this
  warn_degraded: true     # Log warnings when running in degraded mode
```

### Landlock Configuration

When Landlock is available, configure filesystem and network restrictions:

```yaml
landlock:
  enabled: true

  # Directories where command execution is allowed
  allow_execute:
    - /usr/bin
    - /bin
    - /usr/local/bin

  # Directories where reading is allowed
  allow_read:
    - /etc/ssl/certs
    - /etc/resolv.conf
    - /lib
    - /lib64
    - /usr/lib

  # Directories where writing is allowed (beyond workspace)
  allow_write: []

  # Paths explicitly denied (applied by omission from ruleset)
  deny_paths:
    - /var/run/docker.sock
    - /run/docker.sock
    - /run/containerd/containerd.sock
    - /run/crio/crio.sock
    - /var/run/secrets/kubernetes.io
    - /run/systemd/private

  # Network restrictions (requires kernel 6.7+ / Landlock ABI v4)
  network:
    allow_connect_tcp: true   # Allow outbound TCP connections
    allow_bind_tcp: false     # Allow listening on TCP ports
    bind_ports: []            # Specific ports if bind allowed
```

### Capability Configuration

Control which Linux capabilities are available to sandboxed processes:

```yaml
capabilities:
  allow: []   # Capabilities to keep (empty = drop all droppable)

  # Example: agent that needs to ping
  # allow:
  #   - CAP_NET_RAW
```

## Feature Matrix

### By Security Mode

| Feature | full | landlock | landlock-only | minimal |
|---------|------|----------|---------------|---------|
| Execution control (shim) | Yes | Yes | Yes | Yes |
| Execution control (kernel) | seccomp | Landlock | Landlock | No |
| Filesystem (fine-grained) | FUSE | FUSE | Landlock | No |
| Unix sockets (path-based) | seccomp | Landlock | Landlock | No |
| Unix sockets (abstract) | seccomp | No | No | No |
| Signal interception | seccomp | No* | No* | No* |
| Network (kernel) | eBPF | Landlock** | Landlock** | No |
| Resource limits | cgroups | cgroups | cgroups | cgroups |

*Relies on PID namespace isolation + dropped CAP_KILL
**Requires kernel 6.7+ (Landlock ABI v4)

### Landlock ABI Versions

| ABI | Kernel | Features Added |
|-----|--------|----------------|
| v1 | 5.13+ | Basic filesystem sandboxing |
| v2 | 5.19+ | File reparenting (REFER) |
| v3 | 6.2+ | File truncation control |
| v4 | 6.7+ | Network TCP restrictions |
| v5 | 6.10+ | IOCTL restrictions |

## Known Limitations

### In landlock and landlock-only Modes

1. **Signal interception disabled**
   - Without seccomp, signals cannot be intercepted at the kernel level
   - Mitigation: PID namespace isolation + dropped CAP_KILL prevents signaling external processes

2. **Abstract Unix sockets unprotected**
   - Landlock only controls path-based filesystem access
   - Abstract Unix sockets (those not backed by filesystem paths) cannot be blocked
   - Path-based sockets like `/var/run/docker.sock` are protected

3. **Network restrictions require kernel 6.7+**
   - Landlock network support (ABI v4) is only available on newer kernels
   - Without it, no kernel-level network enforcement is possible
   - eBPF-based network monitoring requires the `full` mode

### In minimal Mode

- No kernel-level enforcement of execution or filesystem restrictions
- Relies entirely on shim-based policy checks
- Capability dropping provides baseline protection

## Strict Mode

When `strict: true`, agentsh validates that all requirements for the configured mode are met:

```yaml
security:
  mode: full
  strict: true  # Fail startup if seccomp/eBPF/FUSE unavailable
```

### Mode Requirements

| Mode | Required Capabilities |
|------|----------------------|
| `full` | Seccomp with user-notify, eBPF, FUSE |
| `landlock` | Landlock, FUSE |
| `landlock-only` | Landlock |
| `minimal` | (none) |

### Minimum Mode Requirement

Prevent auto-detection from selecting a mode weaker than desired:

```yaml
security:
  mode: auto
  minimum_mode: landlock-only  # Fail if Landlock is unavailable
```

## Startup Logging

When agentsh starts, it logs the detected security posture:

```
INFO  security capabilities detected
        mode=landlock
        seccomp=false
        seccomp_basic=false
        landlock=true
        landlock_abi=4
        landlock_network=true
        ebpf=false
        fuse=true
        capabilities=true
WARN  running in degraded security mode
        mode=landlock
        signal_interception=disabled
        unix_socket_interception=path-based-only
```

## Capability Dropping

Regardless of security mode, agentsh drops dangerous Linux capabilities:

### Always Dropped (Cannot Be Allowed)

| Capability | Reason |
|------------|--------|
| `CAP_SYS_ADMIN` | Mount, namespace escape, catch-all |
| `CAP_SYS_PTRACE` | Attach to processes, read memory |
| `CAP_SYS_MODULE` | Load kernel modules |
| `CAP_DAC_OVERRIDE` | Bypass file permissions |
| `CAP_DAC_READ_SEARCH` | Bypass read/search permissions |
| `CAP_SETUID` / `CAP_SETGID` | Change UID/GID |
| `CAP_CHOWN` | Change file ownership |
| `CAP_FOWNER` | Bypass owner permission checks |
| `CAP_MKNOD` | Create device files |
| `CAP_SYS_RAWIO` | Raw I/O port access |
| `CAP_SYS_BOOT` | Reboot system |
| `CAP_NET_ADMIN` | Network configuration |
| `CAP_SYS_CHROOT` | chroot escape vector |
| `CAP_LINUX_IMMUTABLE` | Modify immutable files |

### Default Dropped (Can Be Explicitly Allowed)

| Capability | Use Case If Needed |
|------------|-------------------|
| `CAP_NET_BIND_SERVICE` | Bind to ports < 1024 |
| `CAP_NET_RAW` | Raw sockets (ping) |
| `CAP_KILL` | Signal any same-UID process |
| `CAP_SETFCAP` | Set file capabilities |

## Policy Derivation

Landlock execute paths are automatically derived from command policy rules:

```yaml
# This command policy...
commands:
  - name: allow-git
    full_paths:
      - /usr/bin/git
    decision: allow

  - name: allow-node
    path_globs:
      - /usr/local/bin/node*
    decision: allow

# ...automatically allows execution in:
#   - /usr/bin
#   - /usr/local/bin
```

Explicit `landlock.allow_execute` paths are merged with derived paths.

## Session Enforcement Flow

When a command is executed in a session:

```
1. Pre-fork policy check (shim validates command)
2. Fork child process
3. Set PR_SET_NO_NEW_PRIVS
4. Drop capabilities
5. Apply Landlock ruleset
6. Apply cgroup limits (if available)
7. Execute actual command
```

This ordering ensures:
- No privilege escalation after restrictions are applied
- Landlock is enforced before the untrusted command runs
- Multiple layers of protection work together

## Related Documentation

- [Seccomp-BPF Syscall Filtering](seccomp.md) - Full seccomp mode details
- [Policy Documentation](operations/policies.md) - Command and signal policy configuration
