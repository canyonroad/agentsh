# Process Network ACL (PNACL) Design

**Date:** 2026-01-13
**Status:** Draft

## Overview

Control network access per-process with allow/deny/approve rules for hostnames, IPs, CIDRs, ports, and protocols. Works for both agentsh-spawned processes and external applications like Claude Code, Claude Desktop, or Cursor.

### Goals

- Define allow/deny lists of hostnames, IPs, and CIDRs per process
- Support process identification by name, path, or bundle ID (macOS)
- Apply policies to external apps (not spawned by agentsh) and child processes within sessions
- Interactive approval flow for unknown destinations
- Cross-platform support: Linux, macOS, Windows

## Core Concepts

### 1. Process Matcher

Identifies target processes via:
- Process name (`claude-code`)
- Executable path with globs (`/usr/bin/claude*`)
- macOS bundle ID (`com.anthropic.claudecode`)
- Windows package family name
- Matching mode: `flexible` (default) or `strict`

### 2. Network Target

Specifies allowed/denied destinations:
- Hostname (`api.anthropic.com`) with glob support (`*.anthropic.com`)
- IP address (`104.18.0.1`)
- CIDR block (`10.0.0.0/8`)
- Port: single (`443`), range (`8000-9000`), or wildcard (`*`)
- Protocol: `tcp`, `udp`, or `*`

### 3. Policy Decision

What happens on match:
- `allow` - Permit connection silently
- `deny` - Block connection silently
- `approve` - Block and prompt user for decision
- `allow_once_then_approve` - First connection allowed, then prompt
- `audit` - Allow but log for review

### 4. Inheritance Model

For child processes:
- Children inherit parent's network policy by default
- Child-specific rules can extend or restrict inherited policy
- Most-specific rule wins (child override > parent default)

## Configuration Schema

Can be defined in existing policy files under a new `network_acl` block, or in a dedicated `network-acl.yaml` file that gets merged.

```yaml
# In policy.yaml or standalone network-acl.yaml
network_acl:
  # Default behavior for unlisted connections
  default: deny  # or: allow, approve, audit

  processes:
    - name: "claude-code"
      match:
        process_name: "claude-code"
        # Optional stricter matching:
        # path: "/usr/bin/claude-code"
        # bundle_id: "com.anthropic.claudecode"  # macOS
        # strict: true  # Require exact match

      default: approve  # Default for this process if no rule matches

      rules:
        - target: "api.anthropic.com"
          port: 443
          protocol: tcp
          decision: allow

        - target: "*.anthropic.com"
          port: 443
          decision: allow

        - target: "10.0.0.0/8"
          decision: deny  # Block private network access

      # Child process overrides
      children:
        - name: "curl"
          match:
            process_name: "curl"
          inherit: true  # Start with parent's rules
          rules:
            - target: "pypi.org"
              port: 443
              decision: allow  # Extend: allow pip downloads

            - target: "*.anthropic.com"
              decision: deny  # Restrict: block API access from curl
```

**Merging behavior:** When both policy file and dedicated file define rules for the same process, they're merged with dedicated file taking precedence on conflicts.

## Platform Implementation

### Linux (eBPF)

- Extend existing `internal/netmonitor/ebpf/` to support system-wide process filtering
- Hook `tcp_connect` and `udp_sendmsg` kprobes to intercept outbound connections
- Use `bpf_get_current_pid_tgid()` to identify calling process
- Resolve process name/path via `/proc/<pid>/exe` and `/proc/<pid>/comm`
- For `approve` decisions: hold connection in userspace via socket redirect, prompt user, then allow/deny
- Requires `CAP_BPF` + `CAP_NET_ADMIN` (or root)

### macOS (Network Extension)

- Extend existing Swift Network Extension in `macos/`
- Use `NEFilterDataProvider` to intercept flows system-wide
- Get process info via `NEFilterFlow.sourceAppAuditToken` → `SecCodeCopySigningInformation` for bundle ID
- For `approve` decisions: return `.drop()` initially, prompt via XPC to main app, update verdict
- Requires System Extension approval + Network Extension entitlement

### Windows (WFP - Windows Filtering Platform)

- Add new WFP callout driver alongside existing minifilter in `drivers/windows/`
- Register at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` to intercept outbound connections
- Use `FwpsGetPacketFromNetBufferList` + `PsGetProcessId` for process identification
- For `approve` decisions: pend the classify, signal userspace service, complete after decision
- Requires driver signing (or test signing mode)

### Shared Userspace

All platforms communicate decisions to a common Go service (`internal/netmonitor/pnacl/`) that handles policy evaluation, approval prompts, and event logging.

## Approval Flow & User Interaction

### Approval Modes (per-policy configurable)

| Mode | Behavior | Use Case |
|------|----------|----------|
| `approve` | Block connection, prompt immediately | High-security, real-time control |
| `allow_once_then_approve` | First connection passes, then prompt for future | Discovery mode, less disruptive |
| `audit` | Allow all, log for later review | Learning phase, policy generation |

### Prompt Delivery

1. **Terminal (TTY)** - For interactive sessions, show prompt in terminal:
   ```
   [PNACL] claude-code → api.openai.com:443 (tcp)
   Process: /usr/bin/claude-code (pid: 12345)
   Action: [A]llow once | Allow [P]ermanent | [D]eny once | Deny [F]orever | [S]kip
   ```

2. **Desktop notification** - For background/external processes, use system notifications with action buttons (via existing approval infrastructure)

3. **Remote API** - Forward decision requests to external approval service (for team/enterprise use)

### Decision Persistence

- `Allow once` / `Deny once` - Session-scoped, not saved to config
- `Allow permanent` / `Deny forever` - Writes rule to config file automatically
- Auto-generated rules include timestamp and source: `# Auto-added 2026-01-13 via PNACL prompt`

### Timeout Behavior

- Configurable timeout per approval mode (default: 30s)
- On timeout: configurable fallback (`deny`, `allow`, or `use_default`)

## Integration with agentsh

### New Package: `internal/netmonitor/pnacl/`

- `matcher.go` - Process identification and matching logic
- `policy.go` - Rule evaluation, inheritance resolution
- `manager.go` - Coordinates platform backends, handles decisions
- `config.go` - Schema parsing, config merging

### Event Integration

Emit events through existing `internal/events/` broker:

```go
type NetworkACLEvent struct {
    Timestamp   time.Time
    ProcessName string
    ProcessPath string
    PID         int
    ParentPID   int
    Target      string  // hostname or IP
    Port        int
    Protocol    string  // tcp/udp
    Decision    string  // allow/deny/approve
    RuleSource  string  // which rule matched
    UserAction  string  // if prompted, what user chose
}
```

### CLI Commands

```bash
# Manage network ACL
agentsh network-acl list                    # Show active rules
agentsh network-acl add <process> <target>  # Add rule interactively
agentsh network-acl remove <rule-id>        # Remove rule
agentsh network-acl test <process> <target> # Test what decision would be made

# Monitor live
agentsh network-acl watch                   # Stream connection attempts
agentsh network-acl watch --process claude  # Filter by process

# Learning mode
agentsh network-acl learn --process claude-code --duration 1h
# ^ Runs in audit mode, then generates suggested policy
```

### Existing Integration Points

- Hooks into `internal/session/` for agentsh-spawned process tracking
- Uses `internal/approvals/` for prompt delivery
- Writes to `internal/store/` for audit persistence

## Edge Cases & Security Considerations

### Process Spoofing Prevention

- In `strict` mode, validate executable signature (macOS code signing, Linux ELF hash)
- Option to pin executable hash: `hash: "sha256:abc123..."` in matcher
- Warn when `flexible` mode matches a process with unexpected path

### Race Conditions

- Process exits before decision made → default to `deny`, log as "process_exited"
- Config reload during pending approval → honor in-flight decision, apply new rules to next connection
- Rapid connection bursts → coalesce identical prompts within 1s window

### DNS Considerations

- Hostname rules need DNS resolution; cache results with TTL
- Option `resolve_dns: false` to match raw hostname only (for SNI-based matching)
- Handle DNS-over-HTTPS: intercept at TLS layer via SNI, or require DoH endpoints in policy

### Short-lived Processes

- Processes like `curl` may exit before prompt completes
- For `approve` mode: connection held at kernel level, process waits
- For `allow_once_then_approve`: capture happens post-connection, no blocking

### Inheritance Edge Cases

- Orphaned processes (parent dies) → keep inherited rules for session lifetime
- Process re-exec (same PID, new binary) → re-evaluate matcher, may change policy
- Fork without exec → inherits parent policy until exec

### Failure Modes

- eBPF/driver load fails → configurable: `fail_open` (allow all) or `fail_closed` (deny all)
- Default recommendation: `fail_closed` for security tools

## Startup Daemon & Session Context

### Startup Integration (per-platform)

| Platform | Mechanism | Trigger |
|----------|-----------|---------|
| Linux | systemd user service (`~/.config/systemd/user/agentsh.service`) | User login |
| macOS | LaunchAgent (`~/Library/LaunchAgents/com.agentsh.pnacl.plist`) | User login |
| Windows | Task Scheduler or Registry Run key | User login |

Non-interactive environments (CI/CD, servers) use regular `agentsh session create` as they do today.

### Session Context Capture

```go
type PNACLSession struct {
    ID           string
    StartedAt    time.Time

    // Machine identity
    ComputerName string    // hostname
    ComputerIP   []string  // all active interface IPs

    // User identity
    Username     string    // logged-in user
    UserID       string    // UID (Linux/macOS) or SID (Windows)

    // Session state
    Status       string    // running, paused, stopped
    EventCount   int64     // connections tracked this session
}
```

### Startup Flow

1. OS triggers agentsh-daemon start
2. Gather context:
   - ComputerName: `os.Hostname()`
   - ComputerIP: enumerate network interfaces
   - Username: `os.User` (or platform-specific)
3. Create PNACL session (one per login cycle)
4. Load network-acl config
5. Initialize platform backend (eBPF/NE/WFP)
6. Begin monitoring, emit `session_started` event

### CLI for Daemon Management

```bash
agentsh daemon install    # Install startup integration for current OS
agentsh daemon uninstall  # Remove startup integration
agentsh daemon status     # Show current session info (name, IP, user, uptime)
agentsh daemon restart    # Restart monitoring with fresh session
```

### Session Persistence

- Session ID persists across agentsh restarts (within same login session)
- New session created on: reboot, logout/login, or explicit `daemon restart`
- Events tied to session ID for audit correlation

## Testing Strategy

### Unit Tests (`internal/netmonitor/pnacl/`)

- Matcher logic: process name matching, glob patterns, strict vs flexible modes
- Policy evaluation: rule precedence, inheritance resolution, default fallbacks
- Config parsing: YAML schema validation, merge behavior, error handling
- Target matching: hostname globs, CIDR containment, port ranges

### Integration Tests (per-platform)

```go
// Linux: test with real eBPF (requires privileges)
func TestEBPF_BlockConnection(t *testing.T) {
    // 1. Load PNACL with deny rule for httpbin.org
    // 2. Spawn curl to httpbin.org
    // 3. Assert connection blocked, event emitted
}

// Mock-based for CI without privileges
func TestPNACL_WithMockBackend(t *testing.T) {
    // Use mock platform backend
    // Test full flow: connection attempt → policy eval → decision
}
```

### Platform Test Matrix

| Test Type | Linux | macOS | Windows |
|-----------|-------|-------|---------|
| Unit tests | CI | CI | CI |
| Integration (privileged) | Dedicated VM | Dedicated VM | Dedicated VM |
| Integration (mock) | CI | CI | CI |

### End-to-End Scenarios

1. Allow rule works: `curl` to allowed host succeeds
2. Deny rule works: `curl` to denied host fails with connection refused
3. Approve flow: connection blocks, prompt appears, user allows, connection proceeds
4. Inheritance: child process inherits parent rules
5. Override: child-specific rule takes precedence
6. Learning mode: generates accurate policy from observed traffic

### Manual Test Script

```bash
# test-pnacl.sh - Run against real processes
agentsh network-acl learn --process curl --duration 30s &
curl https://api.anthropic.com  # Should be captured
curl https://example.com        # Should be captured
# Review generated policy
```

## Implementation Phases

### Phase 1: Core Policy Engine

- Create `internal/netmonitor/pnacl/` package
- Implement process matcher (name, path, bundle ID, strict/flexible modes)
- Implement network target matching (host, IP, CIDR, port, protocol)
- Implement rule evaluation with inheritance model
- Add config schema parsing and merging
- Unit tests for all matching logic

### Phase 2: Linux eBPF Backend

- Extend `internal/netmonitor/ebpf/` for system-wide process filtering
- Add `tcp_connect` / `udp_sendmsg` hooks with PID tracking
- Implement connection hold mechanism for `approve` decisions
- Wire up to PNACL policy engine
- Integration tests with privileged runner

### Phase 3: Approval Flow Integration

- Integrate with `internal/approvals/` for prompt delivery
- Implement all decision modes (approve, allow_once_then_approve, audit)
- Add rule auto-persistence on permanent decisions
- Add timeout handling and fallback behavior
- Event emission through `internal/events/`

### Phase 4: CLI & Daemon (Linux)

- Add `agentsh network-acl` commands (list, add, remove, test, watch)
- Add `agentsh daemon` commands (install, uninstall, status, restart)
- Implement systemd user service generation
- Session context capture (hostname, IP, username)
- Learning mode implementation

### Phase 5: macOS Backend

- Extend Swift Network Extension for PNACL
- Process identification via audit token → bundle ID
- XPC communication for approval prompts
- LaunchAgent installation
- Platform-specific integration tests

### Phase 6: Windows Backend

- Add WFP callout driver for connection interception
- Process identification via PID lookup
- Userspace service for policy evaluation
- Task Scheduler / Registry integration
- Platform-specific integration tests
