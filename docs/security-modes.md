# Security Modes

agentsh supports multiple security modes depending on available kernel features. The system automatically detects available primitives and selects the best mode, or you can explicitly configure a specific mode.

## Overview

Security enforcement is provided through a combination of:
- **Landlock** - Kernel-enforced filesystem and network sandboxing
- **Seccomp** - Syscall filtering with user-notify support
- **Ptrace** - Syscall-level exec, file, network, and signal interception via PTRACE_SEIZE
- **FUSE** - Filesystem interception for fine-grained control
- **eBPF** - Network monitoring and policy enforcement
- **Capability dropping** - Linux capability restrictions

## Available Modes

| Mode | Requirements | Protection Level | Description |
|------|--------------|------------------|-------------|
| `full` | seccomp + eBPF + FUSE | 100% | Full security with all features |
| `ptrace` | SYS_PTRACE capability | ~95% | Exec, file, network, and signal interception via ptrace (for restricted containers) |
| `landlock` | Landlock + FUSE | ~85% | Kernel-enforced execution and FS control |
| `landlock-only` | Landlock | ~80% | Landlock without FUSE granularity |
| `minimal` | (none) | ~50% | Capability dropping and shim policy only |

### macOS Modes

| Mode | Requirements | Protection Level | Description |
|------|--------------|------------------|-------------|
| `esf` | ESF entitlement (Apple approval) | ~90% | Endpoint Security Framework |
| `lima` | limactl available | ~85% | Full Linux enforcement inside Lima VM |
| `dynamic-seatbelt-fuse` | agentsh-macwrap + FUSE-T | ~75% | Policy-driven seatbelt + FUSE-T file interception |
| `fuse-t` | FUSE-T installed | ~70% | FUSE-T with static sandbox profile |
| `dynamic-seatbelt` | agentsh-macwrap | ~65% | Policy-driven seatbelt without FUSE-T |
| `sandbox-exec` | (built-in) | ~60% | Static sandbox profile only |

Dynamic seatbelt modes generate SBPL profiles from policy at session start — replacing blanket allows with deny-default + specific allows for file paths, exec paths, Mach services, and network. Extension tokens provide runtime file access grants. See `docs/superpowers/specs/2026-03-23-dynamic-seatbelt-design.md` for details.

### Mode Selection

By default, agentsh auto-detects the best available mode at startup.

**Tip:** Use `agentsh detect` to see what security features are available in your environment before configuring. See [Detecting Available Capabilities](cross-platform.md#detecting-available-capabilities).

```
┌─────────────────────────────────────────────┐
│ Seccomp + eBPF + FUSE available?            │
│   Yes → full mode                           │
│   No ↓                                      │
├─────────────────────────────────────────────┤
│ SYS_PTRACE capability available?            │
│   Yes → ptrace mode                         │
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
  mode: auto              # auto | full | ptrace | landlock | landlock-only | minimal
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

### Ptrace Configuration

When ptrace mode is selected (environments with `SYS_PTRACE` but no seccomp user-notify, e.g. AWS Fargate):

```yaml
ptrace:
  enabled: true

  trace:
    execve: true        # Intercept execve/execveat syscalls
    file: true          # File syscall tracing (openat, unlinkat, renameat2, mkdirat, etc.)
    network: true       # Network syscall tracing (connect, bind)
    signal: true        # Signal syscall tracing (kill, tkill, tgkill, rt_sigqueueinfo)

  # Anti-detection: mask TracerPid in /proc/*/status reads (default: false)
  mask_tracer_pid: "off"

  performance:
    max_tracees: 1024           # Maximum concurrent traced threads
    max_hold_ms: 5000           # Maximum time to hold a syscall for policy (fail-closed: deny with EACCES)
    seccomp_prefilter: true     # Use seccomp-BPF to filter non-traced syscalls

  on_attach_failure: fail_open  # "fail_open" or "fail_closed"
```

**Note:** Ptrace mode is mutually exclusive with `seccomp.execve` and `unix_sockets`. Enabling ptrace with either of these will cause a startup validation error.

**How it works:**
- Uses `PTRACE_SEIZE` (non-stopping) to attach to child processes and their descendants
- Intercepts `execve`/`execveat` syscalls at entry, reads filename/argv from tracee memory
- Intercepts file syscalls (`openat`, `openat2`, `unlinkat`, `renameat2`, `mkdirat`, `linkat`, `symlinkat`, `fchmodat`, `fchmodat2`, `fchownat`, plus legacy amd64 equivalents) with full path resolution including symlink handling
- Intercepts network syscalls (`connect`, `bind`) with sockaddr parsing for IPv4, IPv6, and Unix sockets
- Intercepts signal syscalls (`kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`) with optional signal redirect via register rewrite
- Policy evaluation via `ExecHandler`, `FileHandler`, `NetworkHandler`, and `SignalHandler` interfaces
- Deny: invalidates syscall number (`nr = -1`), fixes up return value with `-EACCES`
- Two tracing modes: `TRACESYSGOOD` (all syscalls) or `TRACESECCOMP` (prefiltered via seccomp-BPF)
- Process tree tracking for fork/clone/vfork descendants with depth calculation
- `max_hold_ms` timeout enforcement: parked tracees (awaiting async policy approval) are automatically denied with `EACCES` if the timeout expires. Kill fallback if deny fails. Timeout is swept on every event loop iteration (not load-dependent).
- Graceful degradation: tracees that exit while parked are cleaned up automatically; resume requests for dead tracees are safely skipped; ESRCH errors in allow/deny trigger cleanup instead of SIGKILL
- DNS redirect: in-process dual-stack DNS proxy intercepts connect/sendto to port 53; tracee DNS queries are redirected to the proxy via sockaddr rewrite (when `NetworkHandler` is configured)
- SNI rewrite: TLS ClientHello interception on connect-redirect sockets; in-place SNI replacement with length field fixups (best-effort, single `write()` only)
- TracerPid masking: intercepts `/proc/*/status` reads on syscall-exit and patches `TracerPid` to `0` (when `mask_tracer_pid: true`)

**Monitoring:**

Ptrace mode exposes Prometheus metrics at the `/metrics` endpoint:
- `agentsh_ptrace_tracees_active` — current number of traced threads (gauge)
- `agentsh_ptrace_attach_failures_total{reason}` — attach failures by reason: eperm, esrch, other (counter)
- `agentsh_ptrace_timeouts_total` — max_hold_ms timeout events (counter)

## Feature Matrix

### By Security Mode

| Feature | full | ptrace | landlock | landlock-only | minimal |
|---------|------|--------|----------|---------------|---------|
| Execution control (shim) | Yes | Yes | Yes | Yes | Yes |
| Execution control (kernel) | seccomp | ptrace | Landlock | Landlock | No |
| Filesystem (fine-grained) | FUSE | ptrace | FUSE | Landlock | No |
| Unix sockets (path-based) | seccomp | ptrace | Landlock | Landlock | No |
| Unix sockets (abstract) | seccomp | No | No | No | No |
| Signal interception | seccomp | ptrace | No* | No* | No* |
| Network (kernel) | eBPF | ptrace | Landlock** | Landlock** | No |
| Resource limits | cgroups | cgroups | cgroups | cgroups | cgroups |

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

### In ptrace Mode

1. **DNS and SNI interception are best-effort**
   - DNS redirect intercepts UDP port 53 via connect and sendto rewriting to an in-process proxy
   - SNI rewrite handles single `write()` ClientHello only (no writev, sendmsg, or partial sends)
   - Neither is a security boundary — use the LLM proxy for API routing instead
   - Mitigation: shim-based policy checks still apply for command steering

2. **No FUSE or eBPF**
   - Ptrace mode is designed for environments without seccomp user-notify (e.g. AWS Fargate)
   - Fine-grained filesystem interception (FUSE path rewriting) and eBPF network monitoring are unavailable
   - Mitigation: ptrace intercepts the same file and network syscalls at the kernel level

3. **Performance overhead**
   - Each traced syscall requires two context switches (entry + exit) in TRACESYSGOOD mode
   - Seccomp prefilter (`seccomp_prefilter: true`) injects a BPF filter that returns `SECCOMP_RET_TRACE` only for traced syscalls; non-traced syscalls pass through at kernel speed
   - The prefilter is injected via ptrace syscall injection at attach time; injection failure falls back to TRACESYSGOOD (all syscalls trapped)
   - Per-syscall resume optimization uses `PtraceCont` instead of `PtraceSyscall` for entry-only syscalls, skipping unnecessary exit stops
   - Fd-aware exit stop optimization further reduces overhead by checking the fd tracker at entry: reads on non-status fds and connects to non-TLS ports skip the exit stop entirely
   - Single-threaded event loop may become a bottleneck with many concurrent tracees
   - Mitigation: Prometheus metrics (`agentsh_ptrace_tracees_active`, `agentsh_ptrace_timeouts_total`) help identify bottlenecks

4. **Attach race window**
   - In the exec path, a brief window exists between `cmd.Start()` and `PTRACE_SEIZE` where the child is untraced
   - Ptrace auto-attaches to fork/clone/vfork children via `PTRACE_O_TRACECLONE` etc.
   - The initial exec target is typically a known-safe binary; a pipe-based start barrier is planned for a follow-up
   - In the wrap path, the CLI connects to the server after the shell starts, sends the child PID, and waits for an ACK confirming attach before proceeding

5. **Timeout behavior is fail-closed**
   - When `max_hold_ms` expires on a parked tracee, the syscall is denied with `EACCES`
   - This prevents hung policy decisions from blocking the workload indefinitely
   - If both deny and kill fail, the tracee remains parked for retry on the next sweep

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

4. **Landlock network rules are port-specific**
   - Landlock network rules must specify individual ports; there is no "allow all ports" wildcard
   - To allow unrestricted network access, network must be excluded from the handled access mask entirely
   - For selective restrictions (e.g., block bind but allow connect), specific port rules are required

5. **Symlink limitations in deny paths**
   - Symlinks pointing to denied paths are not explicitly detected during policy setup
   - However, Landlock operates on resolved paths, so protection is still enforced at the kernel level
   - Example: `/tmp/link -> /var/run/docker.sock` will be blocked by Landlock even if the symlink is added to allow paths

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
| `ptrace` | SYS_PTRACE capability |
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
        ptrace=false
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
| `CAP_SETPCAP` | Modify capability bounding set (could re-add dropped caps) |
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

When a command is executed in a session, the enforcement path depends on the active security mode:

### Seccomp/Full Mode

```
1. Pre-fork policy check (shim validates command)
2. Fork child process (with seccomp wrapper)
3. Set PR_SET_NO_NEW_PRIVS
4. Drop capabilities
5. Apply Landlock ruleset
6. Apply cgroup limits (if available)
7. Execute actual command (seccomp user-notify intercepts syscalls)
```

### Ptrace Mode

```
1. Pre-fork policy check (shim validates command)
2. Fork child process (normal start, no seccomp wrapper)
3. Tracer attaches via PTRACE_SEIZE + PTRACE_INTERRUPT (stops process)
4. Apply cgroup limits while process is stopped
5. Tracer resumes process
6. Tracer intercepts syscalls for ongoing enforcement
```

Note: In ptrace mode, there is a brief pre-attach window between fork and PTRACE_SEIZE where the child process may execute a few instructions untraced. This is acceptable for Phase 1 since the initial exec target is typically a known-safe binary path, and the seccomp prefilter auto-attaches to fork/clone descendants.

## Performance Benchmarks

Measured with `make bench`, which runs a Dockerized workload under each mode (baseline with sandbox disabled, full seccomp+FUSE, ptrace with seccomp prefilter + config-driven BPF filter + config-aware exit stops + lazy BPF escalation + PTRACE_GET_SYSCALL_INFO) using a realistic policy with deny, redirect, and allow rules plus full audit logging. Results are median of 3 runs.

### Results

| Phase | Baseline | Full mode | Full overhead | Ptrace | Ptrace overhead |
|---|---|---|---|---|---|
| Process spawn (120 execs) | 3549ms | 3458ms | -2.6% | 11846ms | +234% |
| File I/O (1000 ops) | 282ms | 275ms | -2.5% | 560ms | +99% |
| Git workflow (clone+grep+commit) | 53ms | 51ms | -3.8% | 323ms | +509% |
| Network (10 curl) | 368ms | 339ms | -7.9% | 7185ms | +1852% |
| Deny enforcement (50 blocked) | 631ms | 551ms | -12.7% | 674ms | +7% |
| Redirect enforcement (50 redirected) | 1787ms | 1733ms | -3.0% | 4351ms | +143% |
| Deep process tree (20x 4-level) | 650ms | 624ms | -4.0% | 8249ms | +1169% |
| Wide process tree (10x 10-fan) | 327ms | 316ms | -3.4% | 1341ms | +310% |
| **Total** | **7647ms** | **7347ms** | **-3.9%** | **34529ms** | **+352%** |

### Analysis

**Full mode** (seccomp+FUSE) adds **<1% total overhead**. Non-file phases show no measurable overhead.

**Ptrace mode** adds **~3.5x total overhead** with all optimizations enabled. This is expected — ptrace intercepts syscalls via context switches rather than kernel-internal notification. Breakdown:

1. **Per-exec RPC dominates.** Each `agentsh exec` call goes through CLI → HTTP → server → fork/exec (~30ms). The ptrace attach (PTRACE_SEIZE + seccomp BPF injection + WaitAttached) adds ~15ms per exec on top.

2. **Deny enforcement is free.** Policy deny short-circuits before fork, so ptrace overhead is zero for denied commands.

3. **File I/O is moderate (~2x).** The 1000-op file phase runs inside a single exec through the workspace directory. Ptrace traps each `openat`/`unlinkat` at entry. Config-aware exit stops skip `openat` exit processing when `MaskTracerPid` is off — saving one context switch per file operation. The narrow BPF filter excludes read/write, so file reads pass through untraced.

4. **Network is the worst case (~19x).** `curl` generates hundreds of syscalls (DNS, TLS, connect, read/write). The config-driven BPF filter removes `socket`, `listen`, and `close` from the traced set when fd tracking is inactive — saving ~15-25 ptrace stops per curl invocation. Lazy BPF escalation keeps read/write out of the traced set for processes that don't need them.

5. **Process trees scale with depth (~12x).** Deep nesting (sh→sh→sh→sh→true) multiplies the per-exec attach cost. Wide fan-out (10 parallel children, ~4x) is better since children inherit the seccomp filter via fork.

6. **PTRACE_GET_SYSCALL_INFO** provides a lighter entry path (~96 bytes vs 216 bytes for full register read) for syscall dispatch. All handlers (`handleExecve`, `handleFile`, `handleNetwork`, `handleSignal`) use `SyscallContext.Info.Args` directly on the allow path without loading full registers. `PTRACE_GETREGS` is only called for redirect/rewrite operations.

7. **Config-driven BPF filter** removes always-allowed syscalls (`socket`, `listen`) and conditionally-needed syscalls (`sendto`, `close`) from the seccomp filter. This eliminates ptrace stops for syscalls that would always be allowed by the handler.

8. **Static deny support** via `SECCOMP_RET_ERRNO` enables BPF-level enforcement for policies that always deny certain syscalls (e.g., all network connections). Denied operations are handled entirely in-kernel without any ptrace stop.

9. **Ptrace mode is designed for restricted environments** (e.g., AWS Fargate) where seccomp user-notify, eBPF, and FUSE are unavailable. The overhead tradeoff is acceptable for these environments where no alternative enforcement mechanism exists.

### Reproducing

```bash
make bench
```

Requires Docker with `--cap-add SYS_ADMIN --cap-add SYS_PTRACE --device /dev/fuse --security-opt seccomp=unconfined`. Total runtime ~15-20 minutes.

## Related Documentation

- [Detecting Available Capabilities](cross-platform.md#detecting-available-capabilities) - `agentsh detect` command
- [Seccomp-BPF Syscall Filtering](seccomp.md) - Full seccomp mode details
- [Policy Documentation](operations/policies.md) - Command and signal policy configuration
