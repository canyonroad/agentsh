# Landlock Fallback Security Design

**Status:** Implemented (2026-01-19)

**Implementation:** See [Security Modes Documentation](../security-modes.md) for user-facing configuration guide.

---

When seccomp is unavailable (nested containers, restricted runtimes), this design provides alternative security enforcement using Landlock, capability dropping, and the existing shim.

## Problem Statement

In nested containers and restricted container runtimes (gVisor, etc.), seccomp-bpf is often unavailable. This leaves gaps in:

- Signal interception (kill/tkill/tgkill)
- Unix socket control (connect/bind to paths)
- General syscall filtering

This design achieves ~70% of seccomp's protection using available alternatives.

## Design Goals

1. **Graceful degradation** - Detect available primitives, use the best available
2. **Defense in depth** - Layer Landlock + shim + capabilities
3. **Configurable strictness** - Allow strict mode that fails if requirements not met
4. **Minimal config burden** - Derive Landlock paths from existing policy

## Priority Order

1. Execution control - which binaries can run
2. Filesystem access - read/write restrictions
3. Unix socket blocking - prevent container escape via docker.sock
4. Signal blocking - prevent killing external processes
5. Network restrictions - TCP bind/connect limits

---

## Security Modes

### Mode Detection

At startup, detect available security primitives:

```go
type SecurityCapabilities struct {
    Seccomp         bool  // seccomp-bpf + user-notify
    SeccompBasic    bool  // seccomp-bpf without user-notify
    Landlock        bool  // any Landlock support
    LandlockABI     int   // 1-5, determines features
    LandlockNetwork bool  // ABI v4+, kernel 6.7+
    eBPF            bool  // network monitoring
    FUSE            bool  // filesystem interception
    Capabilities    bool  // can drop capabilities
    PIDNamespace    bool  // isolated PID namespace
}
```

### Available Modes

| Mode | Requirements | Description |
|------|--------------|-------------|
| `full` | seccomp + eBPF + FUSE | Full security, all features |
| `landlock` | Landlock + FUSE | Kernel-enforced exec/FS, no signal/unix-socket interception |
| `landlock-only` | Landlock | Landlock covers FS too, reduced granularity |
| `minimal` | Capabilities only | Drop caps, shim policy checks, no kernel enforcement |

### Configuration

```yaml
security:
  mode: auto              # auto | full | landlock | landlock-only | minimal
  strict: false           # If true, fail if mode requirements not met
  minimum_mode: ""        # Fail if auto-detect picks worse than this
  warn_degraded: true     # Log warnings when running in degraded mode
```

---

## Landlock Integration

### Ruleset Construction

Build Landlock ruleset from multiple sources:

```
1. Workspace path (auto-allow execute + read + write)
2. Paths derived from command policy rules
3. Explicit config overrides
4. Hardcoded deny paths (always applied by omission)
```

### Access Types by Mode

| Mode | EXECUTE | READ | WRITE | Network (6.7+) |
|------|---------|------|-------|----------------|
| `landlock` (FUSE available) | Restricted | FUSE handles | FUSE handles | If available |
| `landlock-only` (no FUSE) | Restricted | Restricted | Restricted | If available |

### Policy Derivation

Extract execute paths from existing command policy:

```go
func deriveLandlockExecutePaths(policy *Policy) []string {
    paths := map[string]struct{}{}

    for _, rule := range policy.Commands {
        if rule.Decision == Allow {
            for _, p := range rule.FullPaths {
                paths[filepath.Dir(p)] = struct{}{}
            }
            for _, g := range rule.PathGlobs {
                paths[extractBaseDir(g)] = struct{}{}
            }
        }
    }
    return maps.Keys(paths)
}
```

### Configuration

```yaml
landlock:
  enabled: true

  # Explicit path allowlists (merged with derived paths)
  allow_execute:
    - /usr/bin
    - /bin
    - /usr/local/bin
  allow_read:
    - /etc/ssl/certs
    - /etc/resolv.conf
  allow_write: []

  # Always denied (by omission from ruleset)
  deny_paths:
    - /var/run/docker.sock
    - /run/docker.sock
    - /run/containerd/containerd.sock
    - /run/crio/crio.sock
    - /var/run/secrets/kubernetes.io
    - /run/systemd/private

  # Network (kernel 6.7+ only)
  network:
    allow_connect_tcp: true
    allow_bind_tcp: false
    bind_ports: []
```

---

## Capability Dropping

### Three-Tier Model

#### Always Drop (Hardcoded)

Cannot be overridden - these are never available:

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

#### Default Drop

Dropped unless explicitly allowed:

| Capability | Use Case If Needed |
|------------|-------------------|
| `CAP_NET_BIND_SERVICE` | Bind to ports < 1024 |
| `CAP_NET_RAW` | Raw sockets (ping) |
| `CAP_KILL` | Signal any same-UID process |
| `CAP_SETFCAP` | Set file capabilities |

#### Explicit Allow

Empty by default. For edge cases requiring specific capabilities.

### Configuration

```yaml
capabilities:
  allow: []

  # Example: agent that needs to ping
  # allow:
  #   - CAP_NET_RAW
```

---

## Shim Integration

### Defense in Depth Model

```
┌─────────────────────────────────────────────────────────┐
│  Landlock (always applied when available)               │
│  - Kernel-enforced outer fence                          │
│  - Execute restricted to allowed paths                  │
│  - Baseline protection that can't be bypassed           │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│  FUSE (when available)                                  │
│  - Fine-grained file operation control                  │
│  - Per-operation policy                                 │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│  Shim (always)                                          │
│  - Binary + argument matching                           │
│  - Complex policy logic                                 │
│  - The "smart" layer                                    │
└─────────────────────────────────────────────────────────┘
```

### What Shim Does That Landlock Can't

| Feature | Landlock | Shim |
|---------|----------|------|
| Block specific binary in allowed dir | No | Yes (basename matching) |
| Argument inspection | No | Yes (regex on args) |
| Approval workflows | No | Yes |
| Command redirection | No | Yes |
| Context-aware decisions | No | Yes |

---

## Session Enforcement Flow

### Capability Drop & Landlock Timing

```
Session.Exec(cmd)
         │
         ▼
┌─────────────────────────────────────┐
│ 1. Policy pre-check (before fork)   │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ 2. Fork child process               │
└─────────────────────────────────────┘
         │
         ▼ (in child, before exec)
┌─────────────────────────────────────┐
│ 3. Set PR_SET_NO_NEW_PRIVS          │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ 4. Drop capabilities                │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ 5. Apply Landlock ruleset           │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ 6. Apply cgroups (if available)     │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ 7. Exec actual command              │
└─────────────────────────────────────┘
```

---

## Known Limitations

### Feature Matrix by Mode

| Feature | full | landlock | landlock-only | minimal |
|---------|------|----------|---------------|---------|
| Execution control (shim) | Yes | Yes | Yes | Yes |
| Execution control (kernel) | seccomp | Landlock | Landlock | No |
| Filesystem (fine-grained) | FUSE | FUSE | Landlock (coarse) | No |
| Unix sockets (path-based) | seccomp | Landlock paths | Landlock paths | No |
| Unix sockets (abstract) | seccomp | No | No | No |
| Signals | seccomp | No* | No* | No* |
| Network (kernel) | eBPF | Landlock 6.7+ | Landlock 6.7+ | No |
| Resource limits | cgroups | cgroups | cgroups | cgroups |

*Relies on PID namespace isolation + dropped CAP_KILL

### Accepted Limitations

1. **Abstract Unix sockets** - Cannot be blocked without seccomp. Path-based sockets (docker.sock) are blocked via Landlock.

2. **Signal interception** - Relies on:
   - PID namespace isolation (can only see own processes)
   - Dropped CAP_KILL (can only signal same-UID)
   - This is acceptable for nested container scenarios

3. **Network restrictions** - Requires kernel 6.7+ for Landlock network support. Without it, no kernel-level network enforcement.

---

## Strict Mode

### Validation

When `strict: true`, validate mode requirements:

```go
func validateStrictMode(mode string, caps *SecurityCapabilities) error {
    switch mode {
    case "full":
        // Requires seccomp, eBPF, FUSE
    case "landlock":
        // Requires Landlock, FUSE
    case "landlock-only":
        // Requires Landlock
    case "minimal":
        // Always passes
    }
}
```

### Policy Warnings

Warn when policy rules can't be enforced:

- Unix socket rules defined but seccomp unavailable
- Signal rules defined but seccomp unavailable
- Network rules defined but no enforcement available

---

## Startup Logging

```
INFO  Security detection complete
INFO    Landlock: available (ABI v4, network support)
INFO    Seccomp:  unavailable (nested container)
INFO    eBPF:     unavailable (no CAP_BPF)
INFO    FUSE:     available
WARN  Running in degraded mode: landlock
WARN    - Signal interception disabled
WARN    - Unix socket interception disabled (abstract sockets)
INFO  Security mode: landlock (auto-detected)
```

---

## Security Posture Summary

| Mode | Overall Protection |
|------|-------------------|
| full | 100% |
| landlock | ~85% |
| landlock-only | ~80% |
| minimal | ~50% |

The `landlock` mode with FUSE provides strong protection for the primary threat vectors (execution control, filesystem access, container escape via docker.sock) while accepting limitations in signal and abstract socket control.
