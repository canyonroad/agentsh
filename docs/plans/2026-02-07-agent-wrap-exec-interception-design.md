# Agent Wrap: Exec Interception for AI Agents on Developer Machines

**Date**: 2026-02-07
**Status**: Design

## Problem

AI coding agents (Claude Code, Codex CLI, OpenCode, Amp, Cursor, Antigravity) spawn shell commands via `/bin/bash -c "..."` or similar. On developer machines — unlike containers — we cannot replace `/bin/bash` with a shim because that would break the underlying OS.

We need a mechanism to intercept every `execve()` / `CreateProcess()` from a supervised agent and its descendants, routing each call through the full agentsh exec pipeline (policy check, approval workflow, audit logging, output capture) without modifying system binaries.

## Requirements

- Works on Linux, macOS, and Windows
- Does not modify system binaries (`/bin/bash`, `/bin/sh`, etc.)
- Does not break the underlying OS — interception is scoped to the agent process tree only
- Routes through the **full agentsh exec pipeline**, not just allow/deny
- Supports all decision types: allow, deny, approve, redirect
- Minimal overhead for allowed commands (the common case)
- Not blocked by enterprise EDR tools
- Supports both CLI agents and GUI IDEs (Cursor)

## Architecture

### Three Layers

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: agentsh wrap (CLI command)                │
│  Creates session, launches interceptor + agent      │
├─────────────────────────────────────────────────────┤
│  Layer 2: OS-specific exec interceptor              │
│  Catches execve/CreateProcess from agent tree       │
│  ┌─────────────┬──────────────┬──────────────┐      │
│  │   Linux     │    macOS     │   Windows    │      │
│  │  seccomp    │  ES AUTH_    │  Kernel      │      │
│  │  user-      │  EXEC        │  driver +    │      │
│  │  notify     │              │  userspace   │      │
│  │             │              │  service     │      │
│  └─────────────┴──────────────┴──────────────┘      │
├─────────────────────────────────────────────────────┤
│  Layer 3: agentsh exec pipeline (existing)          │
│  policy → approval → audit → execute → capture      │
└─────────────────────────────────────────────────────┘
```

### Interception Flow

```
Agent spawns: bash -c "npm install"
       │
       ▼
OS interceptor catches execve
       │
       ▼
POST /sessions/{sid}/exec
  body: {command: "bash", args: ["-c", "npm install"]}
       │
       ▼
Policy engine evaluates command rules
       │
       ├── allow   → execute, audit, return result
       ├── deny    → fail execve with EPERM, audit
       ├── approve → hold, send approval request, wait
       └── redirect → rewrite command, execute, audit
       │
       ▼
Result (exit code, stdout, stderr) proxied back to agent
```

### Recursion Guard

When agentsh itself spawns the allowed command, that child exec must NOT be re-intercepted:

- **Linux**: Child processes spawned by agentsh inherit a clean seccomp filter (no user-notify). Secondary guard via `AGENTSH_IN_SESSION=1` env var.
- **macOS**: `es_mute_process()` on any process spawned by the agentsh server. Muted processes and all descendants are invisible to the ES client.
- **Windows**: Driver maintains a "muted PIDs" set. Processes spawned by `agentsh-svc.exe` are added to it and excluded from interception.

## Linux Implementation: seccomp user-notify

Extends the existing `agentsh-unixwrap` from allow/deny to full pipeline routing.

### Current Flow (today)

1. Install seccomp filter with `SECCOMP_RET_USER_NOTIF` on `execve`/`execveat`
2. Supervisor goroutine receives notifications
3. Policy check → allow or deny the syscall
4. If allowed, `SECCOMP_IOCTL_NOTIF_SEND` continues the syscall in-place

### New Flow (full pipeline routing)

1. Same seccomp filter installation
2. Supervisor receives execve notification
3. Read target binary path and argv from `/proc/<pid>/mem`
4. Send to agentsh server API (`POST /sessions/{sid}/exec`)
5. Server runs full pipeline: policy → approval → audit → execute
6. **If allowed (common case)**: `SECCOMP_IOCTL_NOTIF_SEND` continues the syscall in-place. Zero overhead.
7. **If routed through pipeline**: Block the original execve with `ENOSYS`. The agentsh server spawns the command as a child of the session. Result (exit code, stdout, stderr) is proxied back via pipes that replaced the original fds.
8. **If denied**: Fail the syscall with `EPERM`.

### Taint Tracking

The existing `ProcessTaint` system tracks process ancestry. All children of the wrapped agent are tainted and subject to interception. Processes outside the tree are untouched.

### EDR Risk: LOW

seccomp is a defensive kernel mechanism used by Docker, Flatpak, Chrome sandbox, and systemd. EDR tools recognize it as a legitimate security tool.

## macOS Implementation: Endpoint Security AUTH_EXEC

New binary `agentsh-macwrap-es` using Apple's Endpoint Security framework.

### Architecture

- `agentsh-macwrap-es` is a privileged daemon that registers as an ES client
- Subscribes to `ES_EVENT_TYPE_AUTH_EXEC` events
- Runs as root (required by ES framework)
- Communicates with the user-space agentsh server over local API

### Flow

1. `agentsh wrap -- claude-code` launches the agent as a child process
2. `agentsh-macwrap-es` records the agent's PID as the taint root
3. When any descendant calls execve, ES delivers an `AUTH_EXEC` event
4. Handler checks if the process is in the tainted tree (via `es_process_t.ppid` chain or agentsh taint cache)
5. If tainted: extract target binary path and argv from `es_event_exec_arg_get()`
6. Send to agentsh server API (`POST /sessions/{sid}/exec`)
7. Based on pipeline result:
   - **Allow**: `ES_AUTH_RESULT_ALLOW` — process runs natively, event is audited
   - **Deny**: `ES_AUTH_RESULT_DENY` — process gets `EPERM`
   - **Redirect**: Deny original exec, rewrite to launch `agentsh-stub` (see I/O Proxying below)

### Recursion Guard

`es_mute_process()` on any process spawned by the agentsh server. Muted processes and all descendants are invisible to the ES client — no events, no overhead.

### Entitlements and Distribution

- Requires `com.apple.developer.endpoint-security.client` entitlement
- Must be signed and notarized
- Delivered as a System Extension (`.systemextension` inside app bundle)
- Installed via `OSSystemExtensionRequest`
- User grants permission once in System Settings > Privacy & Security
- Same distribution pattern as CrowdStrike Falcon and other macOS EDR tools

### EDR Risk: LOW

The ES framework IS the mechanism that EDR tools use. An ES client is never flagged by other EDRs — it's the blessed Apple approach.

## Windows Implementation: Kernel Driver + Userspace Service

### Components

- **`agentsh-drv.sys`** — Kernel driver (C only, ~1500 lines). Registers process creation callbacks, maintains taint table, communicates with userspace via filter port.
- **`agentsh-svc.exe`** — Windows service (Go). Communicates with the driver via IOCTL, routes intercepted execs through the agentsh server API, spawns allowed processes.
- **`agentsh-stub.exe`** — I/O proxy stub (Go). Lightweight binary that proxies stdin/stdout/stderr from the agentsh-spawned command back to the original parent.

### Kernel Driver Flow

1. Register `PsSetCreateProcessNotifyRoutineEx` callback
2. Callback fires on every `NtCreateUserProcess` system-wide
3. Check if parent PID is in the tainted process tree (kernel-side hash table)
4. If not tainted: return immediately — zero overhead for unrelated processes
5. If tainted:
   - Set `CreationStatus = STATUS_ACCESS_DENIED` to block process creation
   - Queue message to userspace via `FltSendMessage` (filter communication port)
   - Message contains: parent PID, target image path, command line, environment

### Userspace Service Flow

1. `agentsh-svc.exe` receives blocked exec notification via IOCTL
2. Sends to agentsh server API (`POST /sessions/{sid}/exec`)
3. Pipeline runs: policy → approval → audit → execute
4. If allowed: spawns the process via `CreateProcessAsUser` with the original user token, proxies I/O back
5. If denied: returns denial (parent already got `ACCESS_DENIED`)

### Taint Tree Management

- `agentsh wrap -- claude-code.exe` registers agent PID with driver via IOCTL
- Driver adds PID to taint table
- On process creation: if parent is tainted, child is automatically tainted
- On process exit (`PsSetCreateProcessNotifyRoutine`): PID removed from taint table

### Signing Roadmap

| Phase | Signing | EDR Status |
|-------|---------|------------|
| Phase 1 | EV code-signed | Requires EDR whitelisting |
| Phase 2 | WHQL-certified via Microsoft Hardware Dev Center | Trusted by all EDRs |

### EDR Whitelisting Documentation

Ship documentation for whitelisting `agentsh-drv.sys` in:
- CrowdStrike Falcon (IOA exclusion)
- SentinelOne (process exclusion)
- Microsoft Defender for Endpoint (ASR exclusion)
- Palo Alto Cortex XDR (behavioral exception)

### Installation

Delivered as a driver package (`.inf` + `.sys` + `.cat`), installed via `PnPUtil` or custom installer. Service registered as standard Windows service.

## I/O Proxying and Stub Process

When an intercepted exec is routed through the pipeline (not just allowed in-place), the calling process expects a child that produces output and exits with a code.

### The Problem

An AI agent calls `subprocess.Popen(["bash", "-c", "ls -la"])`. The OS intercepts the execve, blocks it, and agentsh runs the command instead. But the agent is waiting on a child process with stdin/stdout/stderr pipes and an exit code.

### Solution: Per-OS Stub Pattern

**Linux (seccomp)**:
The original process is suspended mid-syscall. Fail the execve with `ENOSYS`, but replace the process's fds with pipes connected to the agentsh-spawned command. The original process's shell loop reads from the pipe and gets the output. Exit code propagated via `waitpid`.

**macOS (ES)**:
Instead of denying the exec outright, allow it but replace the target binary with `agentsh-stub`. The ES `AUTH_EXEC` event lets us modify the process before it runs. The stub binary:
- Connects to the agentsh server via Unix socket
- Receives proxied stdout/stderr from the actual command
- Exits with the proxied exit code

The parent process sees a child that spawned, produced output, and exited normally.

**Windows**:
Same stub pattern. The service spawns `agentsh-stub.exe` as the "child" of the original parent (using `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), which proxies I/O from the actual command running under the agentsh pipeline.

### Common Case Optimization

Most intercepted commands are **allowed** (audit-only). In that case:
- Linux: syscall continues normally, zero proxy overhead
- macOS: `ES_AUTH_RESULT_ALLOW`, process runs natively
- Windows: driver doesn't block, process creates normally

The proxy path only activates for redirected or approval-required commands.

## Agent Launch Examples

### CLI Command

`agentsh wrap` is the single user-facing command across all OSes:

```bash
# CLI agents (identical on all OSes)
agentsh wrap -- claude-code
agentsh wrap -- codex
agentsh wrap -- opencode
agentsh wrap -- amp
agentsh wrap -- antigravity

# Cursor IDE
agentsh wrap -- cursor                                              # Linux
agentsh wrap -- open -a Cursor                                      # macOS
agentsh wrap -- "C:\Users\%USERNAME%\AppData\Local\Programs\Cursor\Cursor.exe"  # Windows

# With explicit session and policy
agentsh wrap --session my-dev --policy strict -- claude-code
agentsh wrap --session pr-review --policy read-only -- cursor

# With auto-created session
agentsh wrap --root /home/dev/myproject --policy default -- claude-code
```

### What `agentsh wrap` Does

1. Creates or reuses a session
2. Starts the OS-specific interceptor (unixwrap / macwrap-es / drv+svc)
3. Registers the agent PID as taint root
4. Launches the agent process
5. On exit: generates a session report, cleans up

## Default Policies

### `agent-default.yaml`

Ships with agentsh. Applied when no `--policy` is specified.

```yaml
name: agent-default
description: Default policy for AI agent supervision

command_rules:
  # Common dev tools — allow, audit
  - name: dev-tools
    commands: ["ls", "cat", "grep", "find", "git", "node", "npm", "npx",
               "python", "python3", "pip", "go", "cargo", "make", "cmake"]
    decision: allow

  # Shell invocations — allow, full audit
  - name: shell-exec
    commands: ["bash", "sh", "zsh"]
    decision: allow
    events: all

  # Package installs — require human approval
  - name: pkg-install
    commands: ["apt", "yum", "brew", "pip", "npm"]
    args_patterns: ["install", "add", "upgrade"]
    decision: approve

  # Dangerous commands — block
  - name: dangerous
    commands: ["rm", "dd", "mkfs", "fdisk"]
    args_patterns: ["-rf /", "--no-preserve-root"]
    decision: deny

file_rules:
  # Workspace — full access
  - name: workspace
    paths: ["${SESSION_ROOT}/**"]
    operations: [read, write, create, delete]
    decision: allow

  # System files — read only
  - name: system-read
    paths: ["/etc/**", "/usr/**"]
    operations: [read]
    decision: allow

  # System files — block writes
  - name: system-write
    paths: ["/etc/**", "/usr/**", "/bin/**", "/sbin/**"]
    operations: [write, create, delete]
    decision: deny

network_rules:
  # Package registries
  - name: package-registries
    destinations: ["registry.npmjs.org", "pypi.org", "proxy.golang.org"]
    decision: allow

  # GitHub
  - name: github
    destinations: ["github.com", "*.githubusercontent.com"]
    decision: allow

  # Everything else — require approval
  - name: other-network
    destinations: ["*"]
    decision: approve
```

### `agent-strict.yaml`

For high-security environments:
- All commands require approval except read-only operations
- Network access blocked by default
- File writes only within workspace

### `agent-observe.yaml`

Audit-only mode for initial profiling:
- Everything allowed, everything logged
- Use with `agentsh policy generate` to create a custom policy from observed behavior (profile-then-lock workflow)

## EDR Compatibility Summary

| OS | Mechanism | MITRE ATT&CK | EDR Risk | Rationale |
|----|-----------|---------------|----------|-----------|
| Linux | seccomp user-notify | N/A (defensive) | LOW | Used by Docker, Flatpak, Chrome. Defensive mechanism. |
| macOS | ES AUTH_EXEC | N/A (blessed API) | LOW | This IS the EDR API. Same mechanism CrowdStrike uses. |
| Windows (Phase 1) | Kernel driver (EV-signed) | N/A (driver) | MEDIUM | Requires EDR whitelisting. Documented process per vendor. |
| Windows (Phase 2) | Kernel driver (WHQL) | N/A (certified) | LOW | Microsoft-certified. Trusted by all EDRs. |

### Techniques Evaluated and Rejected

| Technique | EDR Risk | Why Rejected |
|-----------|----------|-------------|
| LD_PRELOAD | MEDIUM | T1574.006 — known hijacking technique |
| DYLD_INSERT_LIBRARIES | MEDIUM-HIGH | T1574.006 — SIP restrictions, actively monitored |
| Detours / DLL injection | HIGH | T1055.001 — flagged by all major EDRs |
| IFEO | MEDIUM-HIGH | T1546.012 — known persistence technique |
| ptrace | MEDIUM | Anti-debug detection by some EDRs |
| Shell shim (replace /bin/bash) | N/A | Breaks underlying OS on developer machines |

## Implementation Roadmap

### Phase 1: Linux (4-6 weeks)

- Extend `agentsh-unixwrap` from allow/deny to full pipeline routing
- Implement stub process and I/O proxy for redirected commands
- Add `agentsh wrap` CLI command
- Ship default agent policies (`agent-default`, `agent-strict`, `agent-observe`)
- Test with: Claude Code, Codex CLI, OpenCode, Amp, Cursor, Antigravity

### Phase 2: macOS (6-8 weeks)

- Build `agentsh-macwrap-es` using Endpoint Security framework
- Apply for ES entitlement from Apple
- Implement System Extension packaging and installation flow
- Port stub process pattern to macOS
- Notarize and sign binary
- Test with all 6 agents

### Phase 3: Windows (10-14 weeks)

- Build `agentsh-drv.sys` kernel driver in C
  - Process creation callback (`PsSetCreateProcessNotifyRoutineEx`)
  - Kernel-side taint hash table
  - Filter communication port (`FltSendMessage`)
- Build `agentsh-svc.exe` Go service
  - IOCTL communication with driver
  - Pipeline routing via agentsh server API
  - `CreateProcessAsUser` for spawning allowed processes
- Build `agentsh-stub.exe` I/O proxy
- EV code-sign driver
- Document EDR whitelisting (CrowdStrike, SentinelOne, Defender, Cortex XDR)
- Test with all 6 agents

### Phase 3b: WHQL Certification

- Submit driver to Microsoft Hardware Dev Center
- Complete HLK (Hardware Lab Kit) testing
- Obtain WHQL signature

### Phase 4: Polish

- `agentsh wrap --detect` — auto-detect agent type, apply recommended policy
- VS Code / Cursor extension showing agentsh session status
- Web dashboard for monitoring wrapped agents across a team
