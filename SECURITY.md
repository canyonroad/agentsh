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
| PII leakage to LLMs | Embedded proxy with DLP redaction before requests reach provider |
| Untracked LLM usage | Request/response logging with token usage for cost attribution |

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

### LLM Proxy and Data Loss Prevention (DLP)

agentsh includes an embedded HTTP proxy that intercepts all LLM API requests from agents:

**Architecture:**
- Proxy starts automatically with each session on a random port
- Agent environment is configured to route through proxy (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`)
- Requests are intercepted, processed, and forwarded to upstream LLM providers

**DLP Redaction:**
- Request bodies are scanned for PII using regex patterns
- Matches are replaced with `[REDACTED:pattern_type]` before forwarding
- Built-in patterns: email, phone, credit card, SSN, API keys
- Custom patterns can be defined for organization-specific data

**Audit Logging:**
- All requests and responses logged to session storage (JSONL format)
- Token usage extracted and normalized across providers
- Redaction events tracked with field paths and pattern types

**Dialect Detection:**
- Anthropic: `x-api-key` or `anthropic-version` headers
- OpenAI API: `Authorization: Bearer sk-*` tokens
- ChatGPT: OAuth tokens (non-sk- Bearer tokens)

**Limitations:**
- Only scans text content (not images or encoded data)
- Regex patterns may miss obfuscated PII
- Agent could theoretically bypass proxy (combine with network rules for defense in depth)

See [LLM Proxy Documentation](docs/llm-proxy.md) for configuration and usage details.

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
| File blocking | FUSE (enforced) | FUSE-T (enforced with CGO) | **Enforced when built with CGO** |
| Network blocking | eBPF/iptables | pf (loopback only) | **Network policies incomplete** |
| Process isolation | Namespaces | sandbox-exec (minimal) | **Minimal isolation via SBPL profiles** |
| Resource limits | cgroups v2 | None | Memory/CPU limits not enforced |
| Syscall filtering | seccomp | None | Cannot restrict syscalls |
| Process tracking | ptrace/wait | Polling (100ms) | Processes may escape detection |

**Security tiers on macOS:**

| Tier | Score | Requirements | Capabilities |
|------|-------|--------------|--------------|
| Enterprise | 95% | ESF (Apple approval) + Network Extension | Full enforcement |
| Full | 75% | FUSE-T + root | File + network blocking |
| Network Only | 50% | pf + root | Network only, file observation |
| Monitor Only | 25% | None | Observation only |
| Minimal | 10% | None | Command logging only |

**Entitlement requirements:**
- **ESF (Endpoint Security):** Requires Apple approval - submit business justification via Developer Portal
- **Network Extension:** Standard capability since November 2016 - enable in Xcode, no Apple approval needed

**Current implementation status:**
- FUSE-T mounting: **Implemented** (requires CGO + FUSE-T: `brew install fuse-t`)
- FSEvents fallback: **Observation only** (cannot block, used when CGO unavailable)
- pf network rules: **Loopback only** (real interfaces not intercepted)
- Endpoint Security Framework: **Implemented** (requires Apple approval for ESF entitlement)
- Network Extension: **Implemented** (standard capability - no Apple approval needed)
- sandbox-exec: **Implemented** (SBPL-based process sandboxing, deprecated but functional)

**ESF+NE Enterprise Mode:**

When running with ESF entitlements (requires Apple approval) and Network Extension (standard capability), agentsh provides near-Linux-level enforcement:
- ESF (Endpoint Security Framework) intercepts file and process events with AUTH mode blocking
- Network Extension (FilterDataProvider + DNSProxyProvider) enforces network and DNS policies
- XPC bridge connects the System Extension to the Go policy engine
- Session tracking maps processes to agentsh sessions for policy scoping

See [macOS ESF+NE Architecture](docs/macos-esf-ne-architecture.md) for deployment details.

**sandbox-exec Process Sandboxing:**

For non-enterprise deployments, agentsh uses macOS's `sandbox-exec` command with SBPL (Sandbox Profile Language) profiles to provide minimal process isolation:

| Feature | Description |
|---------|-------------|
| Default policy | Deny-all (`(deny default)`) with explicit allows |
| File access | Restricted to workspace and explicitly allowed paths |
| Network access | Denied by default, enabled via `capabilities: ["network"]` |
| System access | Read-only access to system libraries and frameworks |
| Temporary files | Full access to `/tmp`, `/private/tmp`, `/var/folders` |
| TTY/PTY access | Interactive terminal support for commands |
| IPC operations | POSIX IPC allowed; Mach/XPC configurable via `sandbox.xpc` |

**Default Readable Paths (Always Allowed):**

| Category | Paths |
|----------|-------|
| System libraries | `/usr/lib`, `/System/Library`, `/Library/Frameworks`, `/private/var/db/dyld` |
| System tools | `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin` |
| Homebrew | `/opt/homebrew/bin`, `/opt/homebrew/Cellar` |
| Shared resources | `/usr/share` |
| Device nodes | `/dev/null`, `/dev/random`, `/dev/urandom`, `/dev/zero` |

**Configuration Options:**

```yaml
sandbox:
  # Primary workspace - full read/write access
  workspace: /path/to/workspace

  # Additional paths to allow (full access)
  allowed_paths:
    - /home/user/.config/myapp
    - /usr/local/share/data

  # Capabilities to enable
  capabilities:
    - network    # Enables network access (network*)
```

**SBPL Profile Structure:**

The generated profile follows this structure:
1. `(deny default)` - Start with deny-all
2. Allow process operations (fork, exec, self-signal)
3. Allow sysctl reads for system info
4. Allow reading system paths (libraries, frameworks, tools)
5. Allow TTY/PTY access for interactive commands
6. Allow temp file operations
7. Allow workspace full access (from config)
8. Allow additional paths (from config)
9. Conditionally allow network (if `network` capability set)
10. Allow Mach and POSIX IPC for inter-process communication
11. Apply mach-lookup restrictions (if `sandbox.xpc.enabled`)

**sandbox-exec Limitations:**
- `sandbox-exec` is deprecated by Apple but still functional on all macOS versions
- Provides file and network restrictions only (no process namespace isolation)
- Cannot enforce resource limits (CPU, memory)
- Cannot filter syscalls (unlike Linux seccomp-bpf)
- Profile is passed inline via `-p` flag
- No cgroup equivalent for resource accounting
- Child processes inherit the sandbox (escape via fork not possible, but no PID namespace isolation)

**XPC/Mach IPC Control:**

When `sandbox.xpc.enabled: true`, agentsh restricts which XPC/Mach services sandboxed processes can connect to. This prevents:
- Data exfiltration via clipboard (`com.apple.pasteboard.1`)
- Privilege escalation via auth dialogs (`com.apple.security.authhost`)
- TCC bypass attempts (`com.apple.tccd.*`)
- AppleScript execution (`com.apple.coreservices.appleevents`)
- Accessibility API abuse (`com.apple.accessibility.*`)

Configuration:
```yaml
sandbox:
  xpc:
    enabled: true
    mode: enforce  # enforce | audit | disabled
    mach_services:
      default_action: deny  # deny (allowlist) | allow (blocklist)
      allow:
        - "com.apple.system.logger"
        - "com.apple.CoreServices.coreservicesd"
      block_prefixes:
        - "com.apple.accessibility."
```

Default allow list includes essential services: system logger, CoreServices, launch services, SecurityServer, and cfprefsd. See [macOS XPC Sandbox](docs/macos-xpc-sandbox.md) for full documentation.

**Recommendations for macOS deployments:**
- **Enterprise:** Use ESF+NE mode for full enforcement (ESF requires Apple approval; NE is standard capability)
- **Standard:** Install FUSE-T (`brew install fuse-t`) for file policy enforcement
- Build with CGO enabled for FUSE-T support: `CGO_ENABLED=1 go build`
- ESF+NE mode automatically falls back to FUSE-T if entitlements are unavailable
- Use containers (Docker/Podman) with Linux for full enforcement if entitlements unavailable
- Without FUSE-T or ESF, treat macOS as audit/observation mode only
- Do not rely on network policy enforcement without ESF+NE or pf configuration
- Consider the security score when evaluating risk

### macOS + Lima VM

For production macOS deployments requiring full Linux-level security, agentsh supports Lima VM mode. When Lima is detected (running VM via `limactl`), agentsh automatically delegates operations to the Linux environment inside the VM:

| Component | macOS Native | macOS + Lima | Impact |
|-----------|--------------|--------------|--------|
| File blocking | FUSE-T | FUSE3 in VM | ✅ **Full enforcement** |
| Network blocking | pf (limited) | iptables DNAT | ✅ **Full enforcement** |
| Process isolation | None | Linux namespaces | ✅ **Full isolation** |
| Resource limits | None | cgroups v2 | ✅ **Full enforcement** |
| Syscall filtering | None | seccomp-bpf | ✅ **Available** |

**Lima Implementation Details:**

| Feature | Implementation |
|---------|----------------|
| Resource limits | cgroups v2 at `/sys/fs/cgroup/agentsh/<session>` |
| CPU limits | `cpu.max` (quota/period in microseconds) |
| Memory limits | `memory.max` (bytes) |
| Process limits | `pids.max` |
| Disk I/O limits | `io.max` (rbps/wbps per device) |
| Network interception | iptables DNAT via `AGENTSH` chain |
| TCP redirect | All outbound TCP (except localhost) to proxy port |
| DNS redirect | UDP port 53 to DNS proxy port |

**Security Score:** 85% (Full Linux capabilities with slight VM overhead)

**Recommendations for Lima deployments:**
- Use Lima for production macOS environments requiring isolation
- Lima automatically detected when `limactl` is installed with running VM
- Force Lima mode via config: `platform.mode: darwin-lima`
- VM overhead is ~200-500MB RAM with slightly slower file I/O via virtiofs

### Windows

Windows now has **kernel-level enforcement** via a mini filter driver, providing near-Linux-level security:

| Component | Linux | Windows | Impact |
|-----------|-------|---------|--------|
| File blocking | FUSE (enforced) | Mini filter driver | ✅ **Enforced** |
| Network blocking | eBPF/iptables | WinDivert + WFP fallback | ✅ **Enforced** |
| Registry blocking | N/A | CmRegisterCallbackEx | ✅ **Enforced** |
| Process isolation | Namespaces | Driver session tracking | ✅ **Working** |
| Resource limits | cgroups v2 | Job Objects | ✅ **Working** |
| Process tracking | ptrace/wait | Driver + Job Objects | ✅ **Working** |

**Driver Components:**

| Component | Technology | Status |
|-----------|------------|--------|
| Filesystem | FltRegisterFilter (Mini Filter) | ✅ **Enforced** - Create, write, delete, rename |
| Filesystem (alt) | WinFsp (cgofuse) | ✅ **Enforced** - FUSE-style mounting with soft-delete |
| Network | WinDivert (transparent proxy) | ✅ **Enforced** - TCP/DNS interception |
| Network fallback | WFP (Windows Filtering Platform) | ✅ **Block-only mode** |
| Registry | CmRegisterCallbackEx | ✅ **Enforced** - All operations |
| Process | PsSetCreateProcessNotifyRoutineEx | ✅ **Tracking** - Session association |

**Registry Security Features:**

The driver provides comprehensive registry protection:

- **Operation interception:** Query, set, delete, create, rename keys and values
- **Policy enforcement:** Allow, deny, or require approval based on registry rules
- **High-risk path detection:** Automatic detection and blocking of persistence/security paths
- **MITRE ATT&CK mapping:** Events include technique IDs for security monitoring

| High-Risk Path | Risk | MITRE Technique | Default |
|----------------|------|-----------------|---------|
| `HKLM\...\CurrentVersion\Run*` | Critical | T1547.001 - Registry Run Keys | **Deny** |
| `HKLM\...\Winlogon*` | Critical | T1547.004 - Winlogon Helper DLL | **Deny** |
| `HKLM\SYSTEM\...\Services\*` | High | T1543.003 - Windows Service | **Approve** |
| `HKLM\...\Windows Defender\*` | Critical | T1562.001 - Disable Security Tools | **Deny** |
| `HKLM\...\Control\Lsa\*` | Critical | T1003 - Credential Dumping | **Deny** |
| `HKLM\...\Image File Execution Options\*` | Critical | T1546.012 - IFEO Injection | **Deny** |
| `HKLM\...\KnownDLLs\*` | Critical | T1574.001 - DLL Search Order Hijacking | **Deny** |

**Driver Fail Modes:**

| Mode | Behavior | Use Case |
|------|----------|----------|
| `FAIL_MODE_OPEN` | Allow on service unavailable | Development, availability-first |
| `FAIL_MODE_CLOSED` | Deny on service unavailable | Production, security-first |

**Deployment Requirements:**

| Environment | Signing Requirement |
|-------------|---------------------|
| Development | Test signing (`bcdedit /set testsigning on`) |
| Production | EV code signing + Microsoft attestation |
| Enterprise | WHQL certification (optional, recommended) |

**Current implementation status:**
- Mini filter driver: ✅ **Enforced** (file create, write, delete, rename)
- WinFsp filesystem: ✅ **Enforced** (FUSE-style mounting via cgofuse, soft-delete support)
- WinDivert network: ✅ **Enforced** (TCP proxy, DNS interception)
- WFP fallback: ✅ **Block-only** (when WinDivert unavailable)
- Registry blocking: ✅ **Enforced** (all operations with high-risk protection)
- Process tracking: ✅ **Working** (driver-based session association)
- Policy caching: ✅ **Working** (configurable TTL, per-rule override)
- AppContainer sandbox: ✅ **Enforced** (process isolation with output capture)

**Recommendations for Windows deployments:**
- Use the mini filter driver for production deployments
- Enable `FAIL_MODE_CLOSED` for high-security environments
- Review registry policy rules - high-risk paths are blocked by default
- Monitor fail mode transitions in SIEM
- EV code signing required for production (no test signing)
- Consider WHQL certification for enterprise deployment
- WinFsp provides an alternative FUSE-style filesystem with soft-delete capabilities

**WinFsp Filesystem Mounting:**

WinFsp provides FUSE-style filesystem mounting on Windows using the shared `internal/platform/fuse/` package (cgofuse). This offers:

| Feature | Description |
|---------|-------------|
| Cross-platform code | Same FUSE implementation works on macOS (FUSE-T) and Windows (WinFsp) |
| Soft-delete | Files moved to trash instead of permanent deletion |
| Policy enforcement | Same policy engine as minifilter with file operation checks |
| Minifilter coexistence | Process exclusion prevents double-interception when both are active |

**Requirements:**
- WinFsp installed: `winget install WinFsp.WinFsp`
- CGO enabled build: `CGO_ENABLED=1 go build`

**Double-interception prevention:** When both minifilter and WinFsp are active, the Go client calls `ExcludeSelf()` before mounting to tell the minifilter to skip file operations from the agentsh process, preventing duplicate event capture.

**AppContainer Sandbox Isolation:**

Windows 8+ supports AppContainer, a kernel-enforced capability isolation mechanism. agentsh uses AppContainer as the primary process isolation layer, with the minifilter driver providing defense-in-depth:

| Layer | Technology | Purpose |
|-------|------------|---------|
| Primary | AppContainer | Kernel-enforced capability isolation |
| Secondary | Minifilter driver | Policy-based file/registry rules |

**How It Works:**

When agentsh executes a command in a sandboxed session, it:
1. Creates an AppContainer profile with a unique SID via `CreateAppContainerProfile`
2. Grants the container SID access to the workspace (read/write) via ACL modification
3. Grants the container SID access to system directories (read/execute)
4. Optionally adds network capability SIDs (internetClient, privateNetwork)
5. Spawns the process inside the container with extended startup info
6. Captures stdout/stderr via inheritable pipes
7. Cleans up ACLs (using `REVOKE_ACCESS` mode) and deletes the profile when done

**AppContainer Features:**

| Feature | Description |
|---------|-------------|
| Capability isolation | Kernel-level enforcement of allowed capabilities |
| Registry isolation | Automatic isolation of registry access |
| Network control | Configurable network access levels |
| ACL granting | Explicit path access required for file system access |
| Output capture | Full stdout/stderr capture from sandboxed processes |
| ACL cleanup | Automatic removal of granted ACLs on sandbox close |

**Network Access Levels:**

| Level | Capability SIDs | Use Case |
|-------|-----------------|----------|
| `NetworkNone` | None | Maximum isolation (default) |
| `NetworkOutbound` | S-1-15-3-1 (internetClient) | Outbound connections only |
| `NetworkLocal` | S-1-15-3-3 (privateNetwork) | Private network only |
| `NetworkFull` | Both SIDs | Full network access |

**Configuration Options:**

```go
WindowsSandboxOptions{
    UseAppContainer:         true,  // Enable AppContainer (default)
    UseMinifilter:           true,  // Enable minifilter policy (default)
    NetworkAccess:           NetworkNone,  // Network level (default: none)
    FailOnAppContainerError: true,  // Fail hard on setup error (default)
}
```

**Isolation Level:** Windows reports `IsolationPartial` when AppContainer is available (capability-based, not namespace-based like Linux).

**AppContainer Limitations:**
- Requires Windows 8+ (version 6.2+)
- Capability-based, not namespace-based (sandboxed processes see all system processes)
- Cannot enforce resource limits (use Job Objects via minifilter for that)
- Cannot filter syscalls (no equivalent to Linux seccomp)
- Requires modifying filesystem ACLs for path access
- Profile names must not contain special characters (sanitized automatically)

**Recommendations for Windows sandboxed execution:**
- Enable AppContainer for process isolation (`UseAppContainer: true`)
- Combine with minifilter for comprehensive policy enforcement
- Use `NetworkNone` for commands that don't need network access
- Set `FailOnAppContainerError: true` in high-security environments
- Consider WSL2 mode for full Linux-level isolation

**Implementation:** See `internal/platform/windows/sandbox.go` and `internal/platform/windows/appcontainer.go`.

See [Windows Driver Deployment Guide](docs/windows-driver-deployment.md) for installation and configuration.

### Windows WSL2

For Windows deployments requiring full Linux-level security, agentsh supports WSL2 mode. WSL2 runs a real Linux kernel, providing full Linux capabilities:

| Component | Windows Native | Windows WSL2 | Impact |
|-----------|----------------|--------------|--------|
| File blocking | Mini Filter | FUSE3 in VM | ✅ **Full enforcement** |
| Network blocking | WinDivert | iptables DNAT | ✅ **Full enforcement** |
| Process isolation | AppContainer | Linux namespaces | ✅ **Full isolation** |
| Resource limits | Job Objects | cgroups v2 | ✅ **Full enforcement** |
| Syscall filtering | None | seccomp-bpf | ✅ **Available** |
| Registry monitoring | Mini Filter | N/A | ❌ Not available |

**WSL2 Implementation Details:**

| Feature | Implementation |
|---------|----------------|
| Resource limits | cgroups v2 at `/sys/fs/cgroup/agentsh/<session>` |
| CPU limits | `cpu.max` (quota/period in microseconds) |
| Memory limits | `memory.max` (bytes) |
| Process limits | `pids.max` |
| Disk I/O limits | `io.max` (rbps/wbps per device) |
| Network interception | iptables DNAT via `AGENTSH` chain |
| TCP redirect | All outbound TCP (except localhost) to proxy port |
| DNS redirect | UDP port 53 to DNS proxy port |

**Security Score:** 100% (Full Linux capabilities inside VM)

**Trade-offs vs Windows Native:**
- ✅ Full Linux security features (namespaces, seccomp, cgroups)
- ✅ Better isolation than AppContainer
- ❌ No Windows registry monitoring
- ❌ Slight VM overhead
- ❌ File I/O to Windows drives (`/mnt/c/`) slower than native

**Recommendations for WSL2 deployments:**
- Use WSL2 for maximum security on Windows
- Keep workspaces on Linux filesystem (`/home/...`) for best performance
- Install WSL2 with: `wsl --install -d Ubuntu`
- agentsh auto-detects WSL2 when running inside the VM

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
- [ ] Configure DLP patterns for organization-specific sensitive data
- [ ] Enable network rules to force LLM traffic through the proxy
- [ ] Review LLM usage reports for unexpected token consumption

## Changelog

| Date | Change |
|------|--------|
| 2026-01-03 | Wired up unix socket enforcement via seccomp user-notify (Linux only) |
| 2026-01-03 | Implemented macOS sandbox-exec wrapper with SBPL profiles |
| 2026-01-03 | Implemented FUSE event emission for file operation monitoring |
| 2026-01-03 | Implemented Lima and WSL2 Linux namespace isolation via unshare |
| 2026-01-03 | Implemented Lima and WSL2 bindfs-based filesystem mounting inside VMs |
| 2026-01-03 | Implemented WSL2 cgroups v2 resource limits and iptables network interception |
| 2026-01-03 | Implemented Lima VM cgroups v2 resource limits and iptables network interception |
| 2026-01-02 | Added embedded LLM proxy with DLP redaction and usage tracking |
| 2026-01-02 | Implemented AppContainer sandbox execution with stdout/stderr capture |
| 2026-01-02 | Added ACL cleanup on AppContainer sandbox close |
| 2026-01-02 | Added WinFsp filesystem mounting with shared fuse package for Windows |
| 2026-01-02 | Added minifilter process exclusion for WinFsp coexistence |
| 2026-01-01 | Implemented macOS ESF+NE for enterprise-tier enforcement (90% security score) |
| 2026-01-01 | Added XPC bridge for System Extension ↔ Go policy engine communication |
| 2026-01-01 | Added session tracking for process-to-session mapping on macOS |
| 2025-12-31 | Implemented FUSE-T mounting for macOS file policy enforcement |
| 2025-01-01 | Added LD_PRELOAD and code injection env vars to deny list |
| 2025-01-01 | Fixed eBPF race condition with ptrace-stopped start |
| 2025-01-01 | Added full-path and glob matching for commands |
| 2025-01-01 | Changed command default from allow to deny |
