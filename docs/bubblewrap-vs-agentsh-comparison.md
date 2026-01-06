# Bubblewrap vs agentsh: Linux Container Sandboxing Comparison

This document compares Bubblewrap (bwrap), a lightweight unprivileged sandboxing tool, with agentsh running in a Linux container environment for AI agent security.

## Table of Contents

- [Executive Summary](#executive-summary)
- [Architecture Overview](#architecture-overview)
- [Feature Comparison Matrix](#feature-comparison-matrix)
- [Namespace and Isolation Support](#namespace-and-isolation-support)
- [Seccomp and Syscall Filtering](#seccomp-and-syscall-filtering)
- [Network Filtering](#network-filtering)
- [Filesystem Control](#filesystem-control)
- [Resource Limits](#resource-limits)
- [Security Model Comparison](#security-model-comparison)
- [Performance Characteristics](#performance-characteristics)
- [Use Case Analysis](#use-case-analysis)
- [Known Vulnerabilities and Limitations](#known-vulnerabilities-and-limitations)
- [Conclusion](#conclusion)
- [References](#references)

---

## Executive Summary

| Aspect | Bubblewrap | agentsh |
|--------|------------|---------|
| **Purpose** | Unprivileged sandbox construction tool | AI agent security platform |
| **Target User** | Desktop apps (Flatpak), security-conscious devs | AI/ML workloads, enterprise security |
| **Isolation Approach** | Static namespace-based sandbox | Multi-layer dynamic policy enforcement |
| **Policy Model** | Command-line flags at sandbox creation | Runtime YAML policies with per-operation evaluation |
| **Network Control** | Network namespace (isolate or allow) | eBPF + iptables + domain allowlisting + TLS inspection |
| **Filesystem Control** | Mount bind options at creation | FUSE with per-file, per-operation policy |
| **Seccomp** | User-provided filter (manual) | Built-in + extensible syscall blocking |
| **Security Score** | Varies by configuration | 100% on Linux (full enforcement) |

**Bottom Line**: Bubblewrap is a flexible, low-level sandbox *construction* tool—it provides the primitives for isolation but requires manual configuration and offers no runtime policy enforcement. agentsh is a complete security *platform* with continuous policy evaluation, semantic understanding of operations, and defense-in-depth architecture.

---

## Architecture Overview

### Bubblewrap Architecture

Bubblewrap creates sandboxes by constructing isolated namespaces. It's essentially a setuid implementation of a subset of user namespaces that enables running unprivileged containers.

```
┌─────────────────────────────────────────────────────────────────┐
│                    BUBBLEWRAP SANDBOX                           │
│                                                                 │
│  Host System                                                    │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  bwrap command (one-time setup)                           │ │
│  │                                                           │ │
│  │  --unshare-user    → User namespace                       │ │
│  │  --unshare-net     → Network namespace (loopback only)    │ │
│  │  --unshare-pid     → PID namespace                        │ │
│  │  --unshare-ipc     → IPC namespace                        │ │
│  │  --unshare-uts     → UTS namespace                        │ │
│  │  --ro-bind /usr    → Read-only mount                      │ │
│  │  --bind /workspace → Read-write mount                     │ │
│  │  --seccomp 3       → Apply filter from fd 3               │ │
│  │                                                           │ │
│  └───────────────────────────────────────────────────────────┘ │
│                              │                                  │
│                              ▼                                  │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                    Sandbox Environment                     │ │
│  │                                                           │ │
│  │   Process runs with:                                      │ │
│  │   - Isolated namespaces (static)                          │ │
│  │   - Filtered syscalls (if provided)                       │ │
│  │   - Mounted filesystems (static bind mounts)              │ │
│  │   - No network (or full network)                          │ │
│  │                                                           │ │
│  │   ⚠️ No runtime policy changes                            │ │
│  │   ⚠️ No per-operation decisions                           │ │
│  │   ⚠️ No semantic understanding                            │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### agentsh Architecture

agentsh provides multi-layer, continuous enforcement with semantic policy evaluation:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         AGENTSH SECURITY ARCHITECTURE                          │
│                                                                                │
│  ┌──────────────────────────────────────────────────────────────────────────┐ │
│  │  Layer 5: LLM Proxy (DLP, token tracking)                                │ │
│  │  └─ Redaction/tokenization of PII, API keys, custom patterns            │ │
│  ├──────────────────────────────────────────────────────────────────────────┤ │
│  │  Layer 4: eBPF Network (kernel-enforced connection control)              │ │
│  │  └─ Domain allowlisting, CIDR rules, DNS interception, per-connection    │ │
│  ├──────────────────────────────────────────────────────────────────────────┤ │
│  │  Layer 3: FUSE Filesystem (per-file, per-operation policy)               │ │
│  │  └─ Glob patterns, soft-delete, symlink validation, event streaming      │ │
│  ├──────────────────────────────────────────────────────────────────────────┤ │
│  │  Layer 2: Command API (policy before execution)                          │ │
│  │  └─ Argument matching, flag detection, human approval gates              │ │
│  ├──────────────────────────────────────────────────────────────────────────┤ │
│  │  Layer 1: Shell Shim (intercepts ALL shell invocations)                  │ │
│  │  └─ /bin/sh, /bin/bash replaced; recursion guards                        │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                                                                                │
│  ┌──────────────────────────────────────────────────────────────────────────┐ │
│  │  Kernel-Level Enforcement:                                               │ │
│  │  - seccomp-bpf: Block dangerous syscalls (ptrace, mount, kexec)          │ │
│  │  - eBPF cgroup: Network filtering at kernel level                        │ │
│  │  - Linux namespaces: User, mount, PID, IPC, network                      │ │
│  │  - cgroups v2: CPU, memory, I/O, process limits                          │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                                                                                │
│  Defeating any single layer doesn't defeat the system.                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Feature Comparison Matrix

| Feature | Bubblewrap | agentsh | Notes |
|---------|:----------:|:-------:|-------|
| **Namespace Isolation** |
| User namespace | ✅ | ✅ | Both support unprivileged isolation |
| Mount namespace | ✅ | ✅ | |
| PID namespace | ✅ | ✅ | bwrap includes trivial pid1 |
| Network namespace | ✅ | ✅ | |
| IPC namespace | ✅ | ✅ | |
| UTS namespace | ✅ | ✅ | |
| cgroup namespace | ✅ | ✅ | |
| **Seccomp Filtering** |
| Seccomp support | ✅ Manual | ✅ Built-in | bwrap requires user-provided filter |
| User-notify mode | ❌ | ✅ | agentsh uses SECCOMP_RET_USER_NOTIF |
| Dangerous syscall blocking | ❌ Manual | ✅ Default | ptrace, mount, kexec, etc. |
| Per-syscall policy | ❌ | ✅ | Runtime policy decisions |
| **Network Control** |
| Network isolation | ✅ Binary | ✅ Granular | bwrap: isolated or not; agentsh: per-connection |
| Domain allowlisting | ❌ | ✅ | DNS-based filtering |
| CIDR filtering | ❌ | ✅ | IP range blocking |
| Port filtering | ❌ | ✅ | Per-port rules |
| TLS inspection | ❌ | ✅ | MITM proxy for HTTPS |
| DNS interception | ❌ | ✅ | Policy-checked resolution |
| Kernel enforcement | ❌ | ✅ | eBPF cgroup programs |
| **Filesystem Control** |
| Mount binding | ✅ | ✅ | |
| Read-only mounts | ✅ | ✅ | |
| tmpfs mounts | ✅ | ✅ | |
| Overlay filesystems | ✅ | ✅ | |
| Per-file policy | ❌ | ✅ | FUSE per-operation |
| Glob pattern rules | ❌ | ✅ | `*.py`, `**/secrets/*` |
| Soft-delete (trash) | ❌ | ✅ | Recoverable deletes |
| Symlink validation | ❌ | ✅ | Escape prevention |
| **Resource Limits** |
| CPU limits | ❌ | ✅ | cgroups v2 |
| Memory limits | ❌ | ✅ | cgroups v2 |
| Process limits | ❌ | ✅ | pids.max |
| Disk I/O limits | ❌ | ✅ | cgroups v2 io.max |
| **Runtime Features** |
| Dynamic policy changes | ❌ | ✅ | Policy evaluated per-operation |
| Human approval gates | ❌ | ✅ | WebAuthn/TOTP verification |
| Structured audit logs | ❌ | ✅ | JSON event streaming |
| Session correlation | ❌ | ✅ | Cross-operation tracking |
| Environment filtering | ❌ | ✅ | Per-variable control |
| **Startup Performance** |
| Container startup | ~instant | ~50-100ms | bwrap uses unshare directly |
| Per-operation overhead | None | 5-20µs (FUSE) | Policy evaluation cost |

---

## Namespace and Isolation Support

### Bubblewrap Namespaces

Bubblewrap supports all Linux namespace types via command-line flags:

```bash
bwrap \
  --unshare-user \      # CLONE_NEWUSER
  --unshare-pid \       # CLONE_NEWPID
  --unshare-net \       # CLONE_NEWNET
  --unshare-uts \       # CLONE_NEWUTS
  --unshare-ipc \       # CLONE_NEWIPC
  --unshare-cgroup \    # CLONE_NEWCGROUP
  --ro-bind /usr /usr \
  --bind /workspace /workspace \
  /bin/sh
```

**Key Characteristics:**
- Namespaces created at sandbox start (static)
- No runtime modification of isolation
- User namespace enables unprivileged operation
- PID namespace includes trivial pid1 (avoids Docker pid1 problem)
- Network namespace creates loopback-only environment
- `--disable-userns` can prevent nested user namespaces

### agentsh Namespaces

agentsh uses Linux namespaces as one layer of a multi-layer defense:

```go
// internal/platform/linux/sandbox.go
SysProcAttr: &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWUSER |  // UID/GID remapping
                syscall.CLONE_NEWNS |     // Mount isolation
                syscall.CLONE_NEWPID |    // PID isolation
                syscall.CLONE_NEWIPC,     // IPC isolation
}
```

**Three Isolation Levels:**

| Level | Namespaces | Requirements |
|-------|------------|--------------|
| Full | User + Mount + PID + IPC + Network | Unprivileged, seccomp support |
| Partial | Mount + PID + IPC | May require root |
| Minimal | Process group only | Fallback mode |

**Key Difference**: agentsh uses namespaces for process isolation but adds FUSE, eBPF, and seccomp layers for semantic policy enforcement. Bubblewrap provides namespaces only—policy logic must be built externally.

---

## Seccomp and Syscall Filtering

### Bubblewrap Seccomp

Bubblewrap accepts a pre-compiled seccomp filter via file descriptor:

```bash
# User must provide their own filter
bwrap --seccomp 3 3< my-filter.bpf /bin/sh
```

**Limitations:**
- No built-in filter—requires libseccomp knowledge
- Classic BPF only (4096 instruction limit)
- Cannot dereference pointers (cannot inspect sockaddr)
- No user-notify mode (cannot make runtime decisions)
- Filter is static once applied

### agentsh Seccomp

agentsh uses dual-mode seccomp with built-in dangerous syscall blocking:

**Mode 1: User-Notify (Policy Decisions)**
```go
// Unix socket syscalls intercepted for policy evaluation
// SECCOMP_RET_USER_NOTIF allows runtime allow/deny decisions
syscalls := []string{"socket", "connect", "bind", "listen", "sendto"}
```

**Mode 2: Kill (Dangerous Syscalls)**
```go
// Default blocked syscalls - SECCOMP_RET_KILL_PROCESS
blocked := []string{
    "ptrace",           // Process debugging/injection
    "process_vm_readv", // Cross-process memory access
    "process_vm_writev",
    "mount", "umount2", // Filesystem operations
    "pivot_root",
    "reboot",           // System operations
    "kexec_load",
    "init_module",      // Kernel module loading
    "finit_module",
    "delete_module",
    "personality",      // Execution domain changes
}
```

**Key Difference**: agentsh provides:
1. Built-in dangerous syscall blocking (no configuration needed)
2. User-notify mode for runtime policy decisions
3. Extensible syscall rules via configuration
4. SIGSYS detection and event emission when processes are killed

---

## Network Filtering

### Bubblewrap Network

Bubblewrap offers binary network isolation:

```bash
# Option 1: Full isolation (loopback only)
bwrap --unshare-net /bin/sh

# Option 2: Shared network (full access)
bwrap /bin/sh  # No --unshare-net
```

**Limitations:**
- No per-connection filtering
- No domain-based rules
- No DNS inspection
- Cannot allow specific endpoints while blocking others
- Creating veth pairs for selective network requires external tooling (not built-in)

### agentsh Network

agentsh provides multi-layer network enforcement:

**Layer 1: Network Namespace + iptables**
```bash
# Per-session network namespace with veth bridging
iptables -t nat -A POSTROUTING -s <subnet> -j MASQUERADE
iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination <proxy>
iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination <dns>
```

**Layer 2: eBPF Cgroup Filtering**
```c
// Kernel-level TCP connect filtering
// Maps: allowlist, denylist, lpm4_allow, lpm6_allow
// Decision made before connection established
SEC("cgroup/connect4")
int filter_connect4(struct bpf_sock_addr *ctx) {
    // LPM (longest prefix match) for CIDR rules
    // Exact IP+port matching for allowlist/denylist
}
```

**Layer 3: Application-Level Proxy**
- Domain allowlisting with DNS resolution
- TLS inspection (MITM proxy)
- Per-request logging and policy evaluation

**Example Policy:**
```yaml
network:
  mode: "allowlist"
  allowed:
    - domain: "*.github.com"
    - domain: "pypi.org"
    - cidr: "10.0.0.0/8"
  blocked:
    - domain: "*.evil.com"
    - cidr: "0.0.0.0/0"  # Block all IPv4 by default
```

**Key Difference**: Bubblewrap provides binary network isolation. agentsh provides granular, kernel-enforced, per-connection policy with domain awareness.

---

## Filesystem Control

### Bubblewrap Filesystem

Bubblewrap constructs filesystems via bind mounts:

```bash
bwrap \
  --ro-bind /usr /usr \           # Read-only system libs
  --ro-bind /lib /lib \
  --bind /workspace /workspace \  # Read-write workspace
  --tmpfs /tmp \                  # Ephemeral tmpfs
  --dev /dev \                    # Device access
  --proc /proc \                  # Proc filesystem
  /bin/sh
```

**Capabilities:**
- Read-only vs read-write mounts
- tmpfs for ephemeral storage
- Overlay filesystems (layered views)
- Symlink following control

**Limitations:**
- Mount-level granularity only (directory, not file)
- No runtime policy changes
- Cannot distinguish read vs write vs delete
- No per-file rules (e.g., allow `*.log` but deny `*.py`)
- No soft-delete or recovery
- Static configuration at sandbox creation

### agentsh Filesystem

agentsh uses FUSE for per-operation policy enforcement:

```
┌─────────────────────────────────────────────────────────────┐
│                    FUSE INTERCEPTION                         │
│                                                             │
│   Application                                               │
│        │                                                    │
│        ▼                                                    │
│   open("/workspace/config.yaml", O_RDWR)                    │
│        │                                                    │
│        ▼                                                    │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  FUSE Filesystem (/workspace)                        │   │
│   │                                                      │   │
│   │  1. Parse operation: READ or WRITE?                  │   │
│   │  2. Match against policy rules                       │   │
│   │  3. Check: *.yaml → allow read, deny write           │   │
│   │  4. Decision: ALLOW READ, DENY WRITE                 │   │
│   │  5. Emit event: file_open, path, mode, decision      │   │
│   └─────────────────────────────────────────────────────┘   │
│        │                                                    │
│        ▼                                                    │
│   Underlying filesystem (if allowed)                        │
└─────────────────────────────────────────────────────────────┘
```

**Per-Operation Policy:**
```yaml
filesystem:
  rules:
    - pattern: "**/*.py"
      permissions: [read]       # Read only, no write
    - pattern: "**/*.log"
      permissions: [read, write, create]
    - pattern: "**/secrets/*"
      permissions: []           # No access
    - pattern: "**/*"
      permissions: [read]       # Default: read-only
  soft_delete:
    enabled: true
    trash_path: "/workspace/.trash"
```

**Capabilities:**
- Per-file, per-operation (read/write/create/delete) policy
- Glob pattern matching (`*.py`, `**/secrets/*`)
- Soft-delete with recovery
- Symlink escape prevention (EvalSymlinks + boundary check)
- Runtime policy updates
- Structured event emission

**Key Difference**: Bubblewrap provides static mount-level access control. agentsh provides dynamic per-operation policy with semantic understanding of file operations.

---

## Resource Limits

### Bubblewrap Resources

Bubblewrap does not provide resource limiting. It creates sandbox environments but has no mechanism to enforce:
- CPU quotas
- Memory limits
- Process count limits
- Disk I/O limits

Resource limits must be applied externally (e.g., via systemd slices, cgroups manually, or container runtime).

### agentsh Resources

agentsh uses cgroups v2 for comprehensive resource limits:

```go
// internal/limits/cgroupv2_linux.go
// Per-session cgroup at /sys/fs/cgroup/agentsh/<session-id>

type Limits struct {
    Memory      int64 // bytes
    CPUQuota    int   // percent (100 = 1 core)
    PidsMax     int   // max processes
    IOReadBPS   int64 // bytes/sec read
    IOWriteBPS  int64 // bytes/sec write
}
```

**Enforcement:**
```bash
# Memory limit
echo 1073741824 > /sys/fs/cgroup/agentsh/<session>/memory.max

# CPU limit (50% of one core)
echo "50000 100000" > /sys/fs/cgroup/agentsh/<session>/cpu.max

# Process limit
echo 100 > /sys/fs/cgroup/agentsh/<session>/pids.max

# Disk I/O limit
echo "8:0 rbps=10485760 wbps=10485760" > /sys/fs/cgroup/agentsh/<session>/io.max
```

**Key Difference**: Bubblewrap provides no resource limiting. agentsh provides comprehensive cgroups v2 enforcement for CPU, memory, I/O, and process count.

---

## Security Model Comparison

### Bubblewrap Security Model

**Philosophy**: Bubblewrap is a *tool* for constructing sandbox environments, not a complete sandbox with a security policy. Security depends entirely on how it's configured.

From the [Bubblewrap README](https://github.com/containers/bubblewrap):

> "Bubblewrap is not a complete, ready-made sandbox with a specific security policy. The level of protection between the sandboxed processes and the host system is entirely determined by the arguments passed to bubblewrap."

**Trust Model:**
- Unprivileged operation via user namespaces
- PR_SET_NO_NEW_PRIVS prevents privilege escalation
- Capabilities dropped within sandbox
- Security relies on correct configuration

**Attack Surface:**
- Minimal codebase (~2000 LOC C)
- setuid root historically (now optional with user namespaces)
- No network inspection capability
- No runtime policy evaluation

### agentsh Security Model

**Philosophy**: Defense-in-depth with semantic understanding. Multiple independent enforcement layers ensure defeating one layer doesn't defeat the system.

**Trust Model:**
- Host kernel is trusted
- agentsh daemon runs unprivileged when possible
- Agent process runs in isolated namespaces
- Policy files are read-only to the agent

**Defense Layers:**

| Layer | Enforcement | Bypass Requires |
|-------|-------------|-----------------|
| Shell Shim | All shell invocations intercepted | Binary replacement attack |
| Command API | Argument matching, approval gates | Exploit in policy engine |
| FUSE Filesystem | Per-operation policy | FUSE bypass or kernel exploit |
| eBPF Network | Kernel-level connection control | Kernel exploit |
| seccomp | Syscall blocking | Kernel exploit |
| cgroups | Resource limits | Kernel exploit |

**Key Difference**: Bubblewrap security depends on correct configuration by the user. agentsh provides built-in security policies with sensible defaults and defense-in-depth architecture.

---

## Performance Characteristics

### Bubblewrap Performance

**Startup**: Near-instant (~1ms) because `unshare` is a single syscall.

**Runtime**: No overhead after sandbox creation—processes run at native speed.

**Trade-off**: Fast startup but no runtime policy enforcement means no per-operation overhead, but also no per-operation protection.

### agentsh Performance

**Startup**: ~50-100ms for full namespace + FUSE + eBPF initialization.

**Runtime Overhead:**

| Component | Overhead | Notes |
|-----------|----------|-------|
| FUSE file operations | 5-20µs per op | Kernel-userspace context switch |
| eBPF network | <1µs | Kernel-space evaluation |
| seccomp | <1µs | Kernel-space filtering |
| Policy cache hit | 1-5µs | In-memory lookup |
| Policy cache miss | 50-200µs | Full policy evaluation |

**Throughput Impact:**
- Sequential I/O: 3-8% reduction
- Random I/O: 10-15% reduction
- Network latency: 0.1-1ms added per connection

**Trade-off**: Higher per-operation cost but continuous security enforcement.

---

## Use Case Analysis

### When to Use Bubblewrap

| Use Case | Suitability | Notes |
|----------|:-----------:|-------|
| Desktop app sandboxing (Flatpak) | ✅ Excellent | Primary use case |
| Untrusted binary isolation | ✅ Good | Simple containment |
| Developer environment isolation | ✅ Good | Namespace isolation |
| Build reproducibility | ✅ Good | Isolated build environment |
| Quick prototyping | ✅ Good | Near-instant startup |
| AI agent security | ⚠️ Insufficient | No semantic policy, no network filtering |
| Enterprise compliance | ⚠️ Insufficient | No audit trails, no DLP |

### When to Use agentsh

| Use Case | Suitability | Notes |
|----------|:-----------:|-------|
| AI agent execution | ✅ Excellent | Primary use case |
| Enterprise security compliance | ✅ Excellent | Full audit trails, DLP |
| Untrusted code analysis | ✅ Excellent | Multi-layer protection |
| Sensitive data handling | ✅ Excellent | Per-file policy, DLP |
| CI/CD with security | ✅ Good | Structured output, limits |
| Quick prototyping | ⚠️ Overhead | Startup cost may be significant |
| Desktop app sandboxing | ⚠️ Overkill | Simpler tools sufficient |

### Comparison for AI Agent Workloads

| Requirement | Bubblewrap | agentsh |
|-------------|:----------:|:-------:|
| Prevent file exfiltration | ⚠️ Mount-level only | ✅ Per-file policy |
| Prevent network exfiltration | ❌ Binary (isolated or not) | ✅ Domain allowlisting |
| Prevent credential theft | ❌ No env filtering | ✅ Environment policy |
| Detect prompt injection effects | ❌ No visibility | ✅ Action-level audit |
| Human approval for dangerous ops | ❌ No mechanism | ✅ WebAuthn/TOTP gates |
| Recover from accidental deletion | ❌ No mechanism | ✅ Soft-delete + trash |
| Audit trail for compliance | ❌ No structured logs | ✅ JSON event stream |

---

## Known Vulnerabilities and Limitations

### Bubblewrap Vulnerabilities

**CVE-2017-5226 (TIOCSTI)**: Sandbox escape via terminal injection.
- **Impact**: Commands injected into parent terminal
- **Mitigation**: Use `--new-session` flag

**CVE-2024-42472 (Flatpak)**: Sandbox escape via persistent directory symlink race.
- **Impact**: Access to files outside sandbox
- **Mitigation**: Update to bubblewrap ≥ 0.10.0 with `--bind-fd`

**CVE-2024-32462 (Flatpak)**: Sandbox escape via RequestBackground portal.
- **Impact**: Arbitrary command execution outside sandbox
- **Mitigation**: Update Flatpak and xdg-desktop-portal

**Architectural Limitations:**
- No network content inspection
- No runtime policy modification
- seccomp BPF cannot dereference pointers (cannot inspect sockaddr)
- User must provide correct configuration
- No built-in dangerous syscall blocking

### agentsh Limitations

**NOT protected against:**
- Kernel exploits (runs in userspace, trusts kernel)
- Root-level attacks (assumes unprivileged execution)
- Hardware side-channels (Spectre/Meltdown)
- Pre-existing malware on host
- Malicious agentsh binary (assumes trusted installation)

**Known edge cases:**
- TOCTOU window between policy check and operation (~microseconds)
- DNS rebinding attacks (mitigated by TTL limits)
- Process tree escapes if namespace setup fails

**Architectural trade-offs:**
- Higher startup latency than bubblewrap
- Per-operation overhead for FUSE/eBPF
- Requires root or CAP_SYS_ADMIN for full features

---

## Conclusion

### Summary Comparison

| Dimension | Bubblewrap | agentsh |
|-----------|------------|---------|
| **Design Goal** | Sandbox construction primitives | AI agent security platform |
| **Complexity** | Low (~2000 LOC) | High (multi-component system) |
| **Configuration** | Manual, expert-required | YAML with sensible defaults |
| **Policy Evaluation** | One-time at creation | Continuous per-operation |
| **Network Control** | Binary (isolated or not) | Granular (domain, CIDR, port) |
| **Filesystem Control** | Mount-level | Per-file, per-operation |
| **Resource Limits** | None | Full cgroups v2 |
| **Audit/Compliance** | None | Comprehensive JSON events |
| **Startup Time** | ~1ms | ~50-100ms |
| **Runtime Overhead** | None | 5-20µs per FUSE operation |

### Recommendation

**Use Bubblewrap when:**
- You need lightweight, fast namespace isolation
- You're building Flatpak applications
- You have expertise to configure security correctly
- Per-operation policy is not required
- You'll add network filtering externally (e.g., network namespaces + veth)

**Use agentsh when:**
- Running AI agents or LLM-powered tools
- Handling sensitive data (PII, credentials)
- Enterprise compliance requirements
- Need granular network and filesystem control
- Need human approval workflows
- Need audit trails and structured logging
- Defense-in-depth architecture is required

**Use both together when:**
- You want bubblewrap's fast namespace isolation AND agentsh's policy enforcement
- agentsh can run inside a bubblewrap sandbox for additional isolation
- Container-in-container scenarios with policy enforcement

---

## References

### Bubblewrap
- [GitHub - containers/bubblewrap](https://github.com/containers/bubblewrap)
- [Bubblewrap - ArchWiki](https://wiki.archlinux.org/title/Bubblewrap)
- [Sandboxing for the unprivileged with bubblewrap - LWN.net](https://lwn.net/Articles/686113/)
- [Notes on running containers with bubblewrap - Julia Evans](https://jvns.ca/blog/2022/06/28/some-notes-on-bubblewrap/)
- [The flatpak security model - Alexander Larsson](https://blogs.gnome.org/alexl/2017/01/18/the-flatpak-security-model-part-1-the-basics/)

### Security Advisories
- [CVE-2024-42472 - Flatpak --persist sandbox escape](https://github.com/flatpak/flatpak/security/advisories/GHSA-7hgv-f2j8-xw87)
- [CVE-2024-32462 - Flatpak RequestBackground escape](https://github.com/flatpak/flatpak/security/advisories/GHSA-phv6-cpc2-2fgj)

### Technical References
- [Seccomp BPF - Linux Kernel Documentation](https://www.kernel.org/doc/html/v4.19/userspace-api/seccomp_filter.html)
- [eBPF seccomp() filters - LWN.net](https://lwn.net/Articles/857228/)
- [Linux Namespaces - man7.org](https://man7.org/linux/man-pages/man7/namespaces.7.html)
