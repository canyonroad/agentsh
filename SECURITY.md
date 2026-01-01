# Security

This document describes the threat model, security mechanisms, and known limitations of agentsh.

## Overview

agentsh is a security sandbox for AI agent command execution. It interposes between an AI agent and the host system to enforce policies on file access, network connections, command execution, and environment variables.

## Threat Model

### What agentsh Protects Against

agentsh is designed to mitigate risks from **semi-trusted AI agents** operating within a defined workspace:

| Threat | Protection |
|--------|------------|
| Arbitrary file access | FUSE filesystem with policy-based access control |
| Credential theft via files | Deny rules for `.ssh/`, `.aws/`, `.env`, etc. |
| Credential theft via environment | Deny list for secrets + dangerous vars (LD_PRELOAD, etc.) |
| Unauthorized network access | eBPF/policy-based network filtering |
| Dangerous command execution | Command allowlists with args pattern matching |
| Resource exhaustion | cgroup limits (memory, CPU, PIDs) |
| Destructive operations | Approval workflows, soft-delete to trash |

### What agentsh Does NOT Protect Against

agentsh is **not** a full security sandbox like a VM or container with seccomp. It does not protect against:

| Threat | Reason |
|--------|--------|
| **Kernel exploits** | Runs in userspace; kernel bugs bypass all protections |
| **Root-level attacks** | Assumes agent runs as unprivileged user |
| **Hardware side-channels** | No protection against Spectre/Meltdown-class attacks |
| **Malicious agentsh binary** | Assumes agentsh itself is not compromised |
| **Pre-existing malware** | Does not scan for or remove existing threats |
| **Social engineering** | Cannot prevent agent from outputting phishing content |
| **Denial of service to host** | Resource limits help but don't fully prevent |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                         HOST SYSTEM                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    agentsh daemon                      │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐   │  │
│  │  │   Policy    │  │    FUSE     │  │    eBPF      │   │  │
│  │  │   Engine    │  │  Intercept  │  │   Network    │   │  │
│  │  └─────────────┘  └─────────────┘  └──────────────┘   │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │              AGENT SANDBOX                       │  │  │
│  │  │  • Restricted file access (/workspace only)     │  │  │
│  │  │  • Filtered environment variables               │  │  │
│  │  │  • Controlled network egress                    │  │  │
│  │  │  • Resource limits (cgroups)                    │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Trust assumptions:**
- The host kernel is trusted
- The agentsh binary is trusted
- Policy files are trusted (not writable by agent)
- The AI agent is semi-trusted (may attempt policy violations)

## Security Mechanisms

### File Access Control (FUSE)

- Virtual filesystem mounted at `/workspace`
- All file operations intercepted and checked against policy
- Symlink escape prevention via `EvalSymlinks` + boundary checks
- Operations: read, write, create, delete, chmod, rename, etc.

**Policy evaluation:** First matching rule wins. Default is deny.

### Network Control (eBPF)

- Attaches to process cgroup before execution begins
- Filters connections by domain, CIDR, and port
- DNS resolution for domain-based rules (with timeout)

**Race condition mitigation:** Processes start in ptrace-stopped state; eBPF attaches before process resumes.

### Command Execution

- Pre-execution policy check on command + arguments
- Three matching modes:
  - **Basename:** `sh` matches any path ending in `/sh`
  - **Full path:** `/bin/sh` matches only that exact path
  - **Glob pattern:** `/usr/*/python3` matches `/usr/bin/python3`, `/usr/local/python3`
- Args pattern matching for dangerous flag combinations

**Default behavior:** Deny if no rule matches.

### Environment Variables

- Deny list for known secrets (AWS keys, API tokens, etc.)
- Deny list for code injection vectors:
  - Linux: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`
  - macOS: `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`
  - Languages: `PYTHONPATH`, `NODE_OPTIONS`, `RUBYLIB`, `PERL5LIB`
  - Shell: `BASH_ENV`, `ENV`, `PROMPT_COMMAND`
- Allow/deny patterns configurable per-policy

### Resource Limits (cgroups v2)

- Memory limits (with swap disabled)
- CPU quota
- Process count limits
- Command and session timeouts

### Approval Workflows

- Risky operations can require human approval
- Configurable timeout (default: deny on timeout)
- Audit logging of approval decisions

## Known Limitations

### TOCTOU (Time-of-Check-Time-of-Use)

File policy is checked when a file is opened. Between open and subsequent reads/writes, the underlying file could theoretically change (e.g., via hard links from outside the sandbox). This is inherent to userspace filesystem interception.

**Mitigation:** The window is small, and the agent cannot create hard links to files outside `/workspace`.

### DNS Rebinding

Network rules based on domain names resolve DNS at connection time. An attacker controlling DNS could potentially:
1. Resolve `evil.com` to an allowed IP during policy check
2. Change DNS to point to a blocked IP for actual connection

**Mitigation:** Use CIDR rules for critical blocks (e.g., metadata services at `169.254.169.254/32`). Domain rules are convenience, not security boundaries.

### Process Tree Escapes

If the eBPF/cgroup attachment fails after process start, child processes might execute before controls are in place.

**Mitigation:** Ptrace-stopped start ensures attachment completes before any user code runs. Hook failures result in process termination.

### Approval Bypass via Timing

If an approval request times out, the operation is denied. However, a patient attacker could retry until a human mistakenly approves.

**Mitigation:** Audit logging; approval fatigue is a human factors problem.

## Platform-Specific Limitations

### macOS (darwin)

macOS has significantly reduced security enforcement compared to Linux due to platform limitations:

| Component | Linux | macOS | Impact |
|-----------|-------|-------|--------|
| File blocking | FUSE (enforced) | FSEvents (observe-only) | **File policies not enforced** |
| Network blocking | eBPF/iptables | pf (loopback only) | **Network policies incomplete** |
| Process isolation | Namespaces | None | No isolation between agent and host |
| Resource limits | cgroups v2 | None | Memory/CPU limits not enforced |
| Syscall filtering | seccomp | None | Cannot restrict syscalls |
| Process tracking | ptrace/wait | Polling (100ms) | Processes may escape detection |

**Security tiers on macOS:**

| Tier | Score | Requirements | Capabilities |
|------|-------|--------------|--------------|
| Enterprise | 95% | ESF + Network Extension entitlements | Full enforcement (requires Apple approval) |
| Full | 75% | FUSE-T + root | File + network blocking |
| Network Only | 50% | pf + root | Network only, file observation |
| Monitor Only | 25% | None | Observation only |
| Minimal | 10% | None | Command logging only |

**Current implementation status:**
- FUSE-T mounting: **Not implemented** (detection only)
- FSEvents fallback: **Observation only** (cannot block)
- pf network rules: **Loopback only** (real interfaces not intercepted)
- Endpoint Security Framework: **Not implemented** (requires entitlements)

**Recommendations for macOS deployments:**
- Use containers (Docker/Podman) with Linux for enforcement
- Treat macOS as audit/observation mode only
- Do not rely on file or network policy enforcement
- Consider the security score when evaluating risk

### Windows

Windows has partial security enforcement with significant gaps in filesystem and network interception:

| Component | Linux | Windows | Impact |
|-----------|-------|---------|--------|
| File blocking | FUSE (enforced) | WinFsp (stub) | **File policies not enforced** |
| Network blocking | eBPF/iptables | WFP/WinDivert (stub) | **Network policies not enforced** |
| Process isolation | Namespaces | AppContainer (stub) | **Sandbox not enforced** |
| Resource limits | cgroups v2 | Job Objects | ✅ **Working** |
| Process tracking | ptrace/wait | Job Objects + polling | ✅ **Working** |
| PTY/terminal | pty (enforced) | ConPTY | **Not supported** |
| Registry monitoring | N/A | RegNotify | Observation only |

**What works on Windows:**
- **Job Objects** for resource limits (memory, CPU, process count) ✅
- **Process tracking** via Job Objects with automatic child tracking ✅
- **Named pipe monitoring** via polling (observation only, no blocking)
- **Registry path risk detection** with MITRE ATT&CK mappings (observation only)
- **Shell shimming** via PowerShell profile hooks and batch wrappers ✅

**Current implementation status:**
- WinFsp filesystem: **Detection only** (`Mount()` returns "not yet implemented")
- WinDivert network: **Detection only** (`setupWinDivert()` is a stub)
- WFP network: **Detection only** (`setupWFP()` and `AddBlockRule()` are stubs)
- AppContainer sandbox: **Detection only** (`Execute()` runs without sandboxing)
- PTY engine: **Returns ErrNotSupported** for all operations
- Registry blocking: **Not implemented** (requires kernel driver/minifilter)

**Recommendations for Windows deployments:**
- Use WSL2 with Linux for full enforcement
- Treat Windows native as audit/observation mode only (except resource limits)
- Do not rely on file, network, or sandbox policy enforcement
- Job Objects provide effective resource limiting for CPU/memory/processes
- Consider containerized deployments (Docker with WSL2 backend)

See [Platform Comparison Matrix](docs/platform-comparison.md) for detailed feature support.

## Security Defaults

| Component | Default |
|-----------|---------|
| File access | Deny (unless explicitly allowed) |
| Network access | Deny (unless explicitly allowed) |
| Command execution | Deny (unless explicitly allowed) |
| Unix sockets | Deny (unless explicitly allowed) |
| Environment variables | Allow (unless in deny list or explicit allow-list defined) |
| Approval timeout | Deny |

## Reporting Security Issues

If you discover a security vulnerability in agentsh:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers privately
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and will coordinate disclosure timing with you.

## Security Checklist for Operators

Before deploying agentsh in production:

- [ ] Review and customize the default policy for your use case
- [ ] Ensure policy files are not writable by the agent user
- [ ] Enable audit logging and monitor for policy violations
- [ ] Set appropriate resource limits for your workload
- [ ] Use CIDR rules (not just domains) for critical network blocks
- [ ] Test approval workflows to ensure timeouts result in deny
- [ ] Run agentsh as a non-root user
- [ ] Keep agentsh updated for security fixes

## Changelog

| Date | Change |
|------|--------|
| 2025-01-01 | Added LD_PRELOAD and code injection env vars to deny list |
| 2025-01-01 | Fixed eBPF race condition with ptrace-stopped start |
| 2025-01-01 | Added full-path and glob matching for commands |
| 2025-01-01 | Changed command default from allow to deny |
