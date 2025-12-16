# agentsh: Secure Agent Shell Specification

**Version:** 0.1.0-draft  
**Date:** December 2024  
**Status:** Draft

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Goals and Non-Goals](#3-goals-and-non-goals)
4. [Architecture Overview](#4-architecture-overview)
5. [Core Components](#5-core-components)
6. [Session Management](#6-session-management)
7. [I/O Interception](#7-io-interception)
8. [Network Interception](#8-network-interception)
9. [Policy Engine](#9-policy-engine)
10. [Structured Output](#10-structured-output)
11. [API Design](#11-api-design)
12. [CLI Interface](#12-cli-interface)
13. [Security Model](#13-security-model)
14. [Performance Considerations](#14-performance-considerations)
15. [Configuration](#15-configuration)
16. [Deployment](#16-deployment)
17. [Future Considerations](#17-future-considerations)

---

## 1. Executive Summary

**agentsh** is a purpose-built shell environment for AI agents that provides comprehensive monitoring, policy enforcement, and structured I/O for command execution. Unlike traditional shells (bash, zsh) designed for human interaction, agentsh treats the shell as an intelligent intermediary that understands context, risk, and intent.

### Key Differentiators

| Capability | Traditional Shell | agentsh |
|------------|------------------|---------|
| Output format | Human-readable text | Structured JSON |
| Error handling | Text error messages | Structured errors with suggestions |
| Security | User-level permissions | Policy-based, operation-level control |
| Visibility | Command-level only | Full I/O and network interception |
| Session state | Implicit | Explicit, inspectable, persistent |
| Risk awareness | None | Built-in risk assessment |

### Primary Use Cases

1. **AI Agent Sandboxing**: Secure execution environment for autonomous AI agents
2. **Audit & Compliance**: Complete visibility into agent operations
3. **Policy Enforcement**: Fine-grained control over what agents can do
4. **Debugging & Observability**: Understand exactly what agents did and why

---

## 2. Problem Statement

### 2.1 The Challenge of Agent Autonomy

AI agents increasingly need to execute code, manipulate files, and interact with networks. Traditional approaches have significant limitations:

**Docker/Container Isolation**
- Coarse-grained (whole container vs. individual operations)
- No semantic understanding of agent actions
- Limited visibility into what happens inside
- No built-in approval workflows

**Traditional Shells**
- Designed for humans, not machines
- Unstructured output that's hard to parse
- No risk awareness or policy enforcement
- Commands are opaque black boxes

**Wrapper Scripts**
- Brittle and easily bypassed
- Can't intercept operations within scripts
- No visibility into subprocess I/O

### 2.2 The Visibility Gap

When an agent runs `python script.py`, a traditional shell sees:

```
Input:  "python script.py"
Output: exit code 0
```

What actually happened inside is invisible:
- Which files were read or written?
- What network connections were made?
- What subprocesses were spawned?
- Was any sensitive data accessed?

### 2.3 Requirements

An agent execution environment must provide:

1. **Complete Visibility**: See all file I/O, network operations, and subprocess activity
2. **Policy Enforcement**: Allow/deny/approve operations based on rules
3. **Structured Output**: Machine-parseable results, not human text
4. **Session Persistence**: Maintain state across multiple commands efficiently
5. **Acceptable Overhead**: Performance impact must be reasonable for real workloads

---

## 3. Goals and Non-Goals

### 3.1 Goals

| Priority | Goal | Description |
|----------|------|-------------|
| P0 | File I/O interception | Capture all file read/write/delete operations |
| P0 | Network interception | Capture all network connections and DNS queries |
| P0 | Policy enforcement | Allow/deny operations based on configurable rules |
| P0 | Structured output | JSON output for all commands and events |
| P0 | Session persistence | Keep sandbox alive across commands |
| P1 | Risk assessment | Classify operations by risk level |
| P1 | Approval workflows | Human-in-the-loop for dangerous operations |
| P1 | Audit logging | Complete audit trail of all operations |
| P1 | Resource limits | CPU, memory, disk, network quotas |
| P2 | Dry-run mode | Preview effects of commands |
| P2 | Transaction support | Checkpoint and rollback capability |
| P2 | Intent tracking | Associate operations with declared goals |

### 3.2 Non-Goals

| Non-Goal | Rationale |
|----------|-----------|
| Replace bash/zsh for humans | Different use case; humans need different UX |
| Perfect security | Defense in depth, not impenetrable fortress |
| Zero overhead | Monitoring has costs; aim for acceptable overhead |
| Cross-platform (initially) | Focus on Linux first; macOS/Windows later |
| Kernel modifications | Stay in userspace for easier deployment |

---

## 4. Architecture Overview

### 4.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Agent                                       │
│                         (Claude, GPT, etc.)                             │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTP/gRPC/Unix Socket
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           agentsh Server                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   Session   │  │   Policy    │  │   Audit     │  │   API       │    │
│  │   Manager   │  │   Engine    │  │   Logger    │  │   Server    │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
         ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
         │    Session 1    │ │  Session 2  │ │    Session N    │
         │                 │ │             │ │                 │
         │ ┌─────────────┐ │ │             │ │                 │
         │ │ Sandbox     │ │ │    ...      │ │      ...        │
         │ │ ┌─────────┐ │ │ │             │ │                 │
         │ │ │  FUSE   │ │ │ │             │ │                 │
         │ │ │Workspace│ │ │ │             │ │                 │
         │ │ └─────────┘ │ │ │             │ │                 │
         │ │ ┌─────────┐ │ │ │             │ │                 │
         │ │ │ Network │ │ │ │             │ │                 │
         │ │ │  Proxy  │ │ │ │             │ │                 │
         │ │ └─────────┘ │ │ │             │ │                 │
         │ │ ┌─────────┐ │ │ │             │ │                 │
         │ │ │Namespace│ │ │ │             │ │                 │
         │ │ └─────────┘ │ │ │             │ │                 │
         │ └─────────────┘ │ │             │ │                 │
         └─────────────────┘ └─────────────┘ └─────────────────┘
```

### 4.2 Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| API Server | External interface (HTTP/gRPC), authentication |
| Session Manager | Create, track, destroy sessions; handle lifecycle |
| Policy Engine | Evaluate operations against rules; make allow/deny decisions |
| Audit Logger | Record all operations with full context |
| Sandbox | Isolated execution environment per session |
| FUSE Workspace | Intercept all file operations |
| Network Proxy | Intercept all network traffic and DNS |
| Namespace | Linux namespace isolation (mount, net, PID, UTS) |

### 4.3 Technology Choices

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Language | Go | Single binary, good perf, excellent syscall support |
| File interception | FUSE (go-fuse) | Userspace, no kernel modules |
| Network interception | Transparent proxy + iptables | Works with all protocols |
| DNS interception | Custom DNS resolver | Full visibility into lookups |
| Namespaces | Linux namespaces | Native isolation, no Docker dependency |
| IPC | Unix sockets | Low latency for local communication |
| API | HTTP/2 + gRPC | Streaming support, wide compatibility |
| Config | YAML | Human-readable, widely supported |

---

## 5. Core Components

### 5.1 Session Manager

The Session Manager handles the lifecycle of agent sessions.

#### 5.1.1 Session States

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ creating │────▶│  ready   │────▶│   busy   │────▶│ stopping │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
                      │  ▲              │                │
                      │  │              │                │
                      │  └──────────────┘                │
                      │                                  ▼
                      │                            ┌──────────┐
                      └───────────────────────────▶│ stopped  │
                                                   └──────────┘
```

#### 5.1.2 Session Configuration

```yaml
session:
  id: "session-abc123"              # Unique identifier
  workspace: "/home/user/project"   # Root directory to expose
  timeout: "4h"                     # Maximum session duration
  idle_timeout: "30m"               # Kill after inactivity
  policy: "default"                 # Policy profile to use
  
  resource_limits:
    max_memory_mb: 2048
    max_cpu_percent: 80
    max_disk_mb: 1000
    max_network_mb: 500
    command_timeout: "5m"
  
  network:
    allowed_domains:
      - "github.com"
      - "*.npmjs.org"
      - "pypi.org"
    blocked_domains:
      - "*.malware.com"
    allowed_ports: [80, 443]
    
  environment:
    PATH: "/usr/bin:/bin"
    HOME: "/workspace"
    LANG: "en_US.UTF-8"
```

#### 5.1.3 Session Data Model

```go
type Session struct {
    ID              string
    State           SessionState
    Config          SessionConfig
    
    // Runtime state
    WorkingDir      string            // Current working directory
    Environment     map[string]string // Accumulated env vars
    
    // Metrics
    Created         time.Time
    LastActivity    time.Time
    CommandCount    int64
    TotalFileOps    int64
    TotalNetOps     int64
    TotalBytesRead  int64
    TotalBytesWritten int64
    
    // References
    Sandbox         *Sandbox
}
```

### 5.2 Sandbox

Each session gets an isolated sandbox with persistent monitoring infrastructure.

#### 5.2.1 Sandbox Components

```
┌─────────────────────────────────────────────────────────────┐
│                         Sandbox                              │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                  Linux Namespaces                      │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │  │
│  │  │  Mount  │ │ Network │ │   PID   │ │   UTS   │     │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘     │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────┐  ┌─────────────────────────────┐  │
│  │    FUSE Workspace   │  │     Network Subsystem       │  │
│  │                     │  │                             │  │
│  │  /workspace ────────┼──┼▶ Transparent TCP Proxy     │  │
│  │    ├── src/         │  │                             │  │
│  │    ├── tests/       │  │  DNS Interceptor            │  │
│  │    └── config/      │  │    └─▶ Policy check         │  │
│  │                     │  │    └─▶ Upstream resolver    │  │
│  │  All ops monitored  │  │                             │  │
│  │  Policy enforced    │  │  iptables REDIRECT rules    │  │
│  └─────────────────────┘  └─────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                 Command Executor                     │   │
│  │                                                      │   │
│  │  • Receives commands via Unix socket                │   │
│  │  • Manages working directory state                  │   │
│  │  • Handles shell builtins (cd, export, etc.)       │   │
│  │  • Executes external commands                       │   │
│  │  • Collects events per-command                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  Event Collector                     │   │
│  │                                                      │   │
│  │  • Aggregates events from FUSE and Network          │   │
│  │  • Streams to connected clients                     │   │
│  │  • Buffers per-command for response                 │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

#### 5.2.2 Sandbox Lifecycle

```go
// Sandbox startup (once per session)
func (s *Sandbox) Start() error {
    // 1. Create session directory structure
    // 2. Mount FUSE filesystem
    // 3. Start network proxy
    // 4. Configure iptables in network namespace
    // 5. Start command listener on Unix socket
    // 6. Start event collector
}

// Command execution (many per session)
func (s *Sandbox) Execute(req ExecRequest) (*ExecResponse, error) {
    // 1. Clear per-command event buffer
    // 2. Resolve command and arguments
    // 3. Handle shell builtins or execute external command
    // 4. Collect stdout/stderr
    // 5. Gather events from FUSE and network
    // 6. Return structured response
}

// Sandbox teardown (once per session)
func (s *Sandbox) Stop() error {
    // 1. Stop event collector
    // 2. Close command listener
    // 3. Stop network proxy
    // 4. Unmount FUSE filesystem
    // 5. Cleanup session directory
}
```

---

## 6. Session Management

### 6.1 Session Persistence Model

Sessions persist their sandbox infrastructure between commands, amortizing setup costs.

```
Traditional (per-command sandbox):
  
  cmd1: [setup 200ms][exec 50ms][teardown 50ms] = 300ms
  cmd2: [setup 200ms][exec 30ms][teardown 50ms] = 280ms
  cmd3: [setup 200ms][exec 100ms][teardown 50ms] = 350ms
  ─────────────────────────────────────────────────────
  Total: 930ms overhead for 180ms of actual work

Session-based:

  session: [setup 200ms]
    cmd1: [exec 50ms + 5ms overhead] = 55ms
    cmd2: [exec 30ms + 5ms overhead] = 35ms
    cmd3: [exec 100ms + 5ms overhead] = 105ms
  session: [teardown 50ms]
  ─────────────────────────────────────────────────────
  Total: 250ms overhead for 180ms of actual work
  
  Improvement: ~73% reduction in overhead
```

### 6.2 State Persistence

The session maintains state that persists across commands:

| State | Persistence | Notes |
|-------|-------------|-------|
| Working directory | Session lifetime | `cd` changes persist |
| Environment variables | Session lifetime | `export` changes persist |
| Open file handles | Command lifetime | Closed after each command |
| Network connections | Command lifetime | Closed after each command |
| FUSE mount | Session lifetime | Stays mounted |
| Network namespace | Session lifetime | Stays configured |

### 6.3 Session Shell Builtins

These commands are handled directly by the session, not executed externally:

| Builtin | Behavior |
|---------|----------|
| `cd <path>` | Change session working directory |
| `pwd` | Return current working directory |
| `export KEY=value` | Add/update environment variable |
| `unset KEY` | Remove environment variable |
| `env` | List all environment variables |
| `alias name=value` | Create command alias |
| `unalias name` | Remove alias |
| `history` | Show command history for session |

### 6.4 Idle Timeout and Cleanup

```go
type SessionCleanupPolicy struct {
    IdleTimeout     time.Duration  // Kill after no commands
    MaxDuration     time.Duration  // Kill after total time
    MaxCommands     int64          // Kill after N commands
    MaxFileOps      int64          // Kill after N file operations
    MaxNetOps       int64          // Kill after N network operations
}
```

---

## 7. I/O Interception

### 7.1 FUSE Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FUSE Mount Point                          │
│                    /session/workspace                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ VFS operations
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Kernel FUSE Module                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ /dev/fuse
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    agentsh FUSE Daemon                       │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Policy    │  │   Event     │  │   Passthrough       │ │
│  │   Check     │──│   Emit      │──│   to Real FS        │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ syscalls
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Real Filesystem                            │
│                   /actual/workspace/path                     │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Intercepted Operations

| Operation | FUSE Method | Events Emitted |
|-----------|-------------|----------------|
| Open file | `Open()` | `file_open` |
| Read file | `Read()` | `file_read` (with byte count) |
| Write file | `Write()` | `file_write` (with byte count) |
| Create file | `Create()` | `file_create` |
| Delete file | `Unlink()` | `file_delete` |
| Rename file | `Rename()` | `file_rename` |
| Make directory | `Mkdir()` | `dir_create` |
| Remove directory | `Rmdir()` | `dir_delete` |
| List directory | `ReadDir()` | `dir_list` |
| Get attributes | `Getattr()` | `file_stat` |
| Set attributes | `Setattr()` | `file_chmod`, `file_chown` |
| Symlink | `Symlink()` | `symlink_create` |
| Read symlink | `Readlink()` | `symlink_read` |

### 7.3 File Event Schema

```json
{
  "timestamp": "2024-12-15T10:30:45.123Z",
  "type": "file_write",
  "session_id": "session-abc123",
  "command_id": "cmd-xyz789",
  "pid": 12345,
  "path": "/workspace/src/main.py",
  "real_path": "/home/user/project/src/main.py",
  "operation": {
    "bytes": 1024,
    "offset": 0,
    "flags": ["O_WRONLY", "O_TRUNC"]
  },
  "decision": "allow",
  "policy_rule": "allow-workspace-write",
  "latency_us": 234,
  "metadata": {
    "file_type": "text/x-python",
    "file_size_before": 512,
    "file_size_after": 1024
  }
}
```

### 7.4 Performance Optimization

#### Read-ahead and Caching

```go
type FUSEConfig struct {
    // Kernel-level caching
    EntryTimeout    time.Duration  // How long to cache directory entries
    AttrTimeout     time.Duration  // How long to cache file attributes
    
    // Read optimization
    MaxReadahead    int            // Maximum readahead in bytes
    AsyncRead       bool           // Allow async read operations
    
    // Write optimization  
    WritebackCache  bool           // Enable writeback caching
    
    // Event batching
    EventBatchSize  int            // Batch events before sending
    EventBatchDelay time.Duration  // Max delay before flushing
}

// Recommended defaults
var DefaultFUSEConfig = FUSEConfig{
    EntryTimeout:    1 * time.Second,
    AttrTimeout:     1 * time.Second,
    MaxReadahead:    128 * 1024,
    AsyncRead:       true,
    WritebackCache:  false,  // Keep false for audit accuracy
    EventBatchSize:  100,
    EventBatchDelay: 10 * time.Millisecond,
}
```

#### Selective Monitoring

Not all paths need FUSE interception:

```yaml
filesystem:
  # Full FUSE monitoring
  monitored_paths:
    - "/workspace"
    
  # Bind-mount passthrough (no monitoring, full speed)
  passthrough_paths:
    - "/usr"         # Read-only system binaries
    - "/lib"         # Read-only libraries
    - "/etc/ssl"     # SSL certificates
    
  # Blocked entirely
  blocked_paths:
    - "/etc/passwd"
    - "/etc/shadow"
    - "/root"
```

---

## 8. Network Interception

### 8.1 Network Namespace Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Host Network                              │
└─────────────────────────────────────────────────────────────┘
         │                                    ▲
         │ veth pair                          │
         ▼                                    │
┌─────────────────────────────────────────────────────────────┐
│              Sandbox Network Namespace                       │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              iptables NAT Rules                      │   │
│  │                                                      │   │
│  │  -A OUTPUT -p tcp -j REDIRECT --to-port 8080        │   │
│  │  -A OUTPUT -p udp --dport 53 -j REDIRECT --to 5353  │   │
│  └─────────────────────────────────────────────────────┘   │
│                         │                                   │
│           ┌─────────────┴─────────────┐                    │
│           ▼                           ▼                    │
│  ┌─────────────────┐         ┌─────────────────┐          │
│  │  TCP Proxy      │         │  DNS Resolver   │          │
│  │  (port 8080)    │         │  (port 5353)    │          │
│  │                 │         │                 │          │
│  │  • Intercept    │         │  • Intercept    │          │
│  │  • Log          │         │  • Log          │          │
│  │  • Policy check │         │  • Policy check │          │
│  │  • Forward      │         │  • Forward      │          │
│  └─────────────────┘         └─────────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 Transparent TCP Proxy

The proxy intercepts all outbound TCP connections:

```go
type TCPProxy struct {
    listenPort    int
    policy        *PolicyEngine
    events        chan NetworkEvent
    
    // Metrics
    connections   atomic.Int64
    bytesSent     atomic.Int64
    bytesReceived atomic.Int64
}

func (p *TCPProxy) handleConnection(clientConn net.Conn) {
    // 1. Get original destination (from iptables SO_ORIGINAL_DST)
    origDst := getOriginalDst(clientConn)
    
    // 2. Policy check
    event := NetworkEvent{
        Type:       EventNetConnect,
        RemoteAddr: origDst.IP.String(),
        RemotePort: origDst.Port,
        Protocol:   "tcp",
    }
    
    decision := p.policy.CheckNetwork(event)
    event.Decision = decision
    p.emit(event)
    
    if decision == Deny {
        clientConn.Close()
        return
    }
    
    // 3. Connect to actual destination
    serverConn := net.Dial("tcp", origDst.String())
    
    // 4. Bidirectional proxy with monitoring
    go p.proxyWithMonitor(clientConn, serverConn, origDst)
    go p.proxyWithMonitor(serverConn, clientConn, origDst)
}
```

### 8.3 DNS Interception

All DNS queries are intercepted for visibility and policy enforcement:

```go
type DNSInterceptor struct {
    listenPort     int
    upstream       string  // e.g., "8.8.8.8:53"
    policy         *PolicyEngine
    events         chan NetworkEvent
    
    // Domain blocklist/allowlist
    blockedDomains map[string]bool
    allowedDomains map[string]bool  // If set, only these allowed
}

func (d *DNSInterceptor) handleQuery(query []byte, clientAddr *net.UDPAddr) {
    domain := parseDNSDomain(query)
    
    event := NetworkEvent{
        Type: EventDNSQuery,
        Metadata: map[string]any{
            "domain": domain,
            "type":   parseDNSType(query),
        },
    }
    
    decision := d.checkDomainPolicy(domain)
    event.Decision = decision
    d.emit(event)
    
    if decision == Deny {
        // Return NXDOMAIN or REFUSED
        d.sendDNSError(query, clientAddr)
        return
    }
    
    // Forward to upstream and return response
    response := d.forwardToUpstream(query)
    d.sendResponse(response, clientAddr)
}
```

### 8.4 Network Event Schema

```json
{
  "timestamp": "2024-12-15T10:30:45.123Z",
  "type": "net_connect",
  "session_id": "session-abc123",
  "command_id": "cmd-xyz789",
  "pid": 12345,
  "connection": {
    "remote_addr": "140.82.121.4",
    "remote_port": 443,
    "local_port": 54321,
    "protocol": "tcp"
  },
  "dns": {
    "domain": "api.github.com",
    "resolved_from": "dns_cache"
  },
  "decision": "allow",
  "policy_rule": "allow-https",
  "tls": {
    "sni": "api.github.com",
    "version": "TLS1.3"
  }
}
```

### 8.5 Network Metrics Per-Command

```json
{
  "network_summary": {
    "connections": 3,
    "dns_queries": 2,
    "bytes_sent": 4096,
    "bytes_received": 65536,
    "blocked_connections": 1,
    "unique_destinations": [
      {"host": "api.github.com", "port": 443},
      {"host": "registry.npmjs.org", "port": 443}
    ]
  }
}
```

---

## 9. Policy Engine

### 9.1 Policy Model

Policies define what operations are allowed, denied, or require approval.

```
┌─────────────────────────────────────────────────────────────┐
│                     Policy Evaluation                        │
│                                                             │
│   Operation ──▶ Match Rules ──▶ First Match Wins ──▶ Decision│
│                                                             │
│   Decisions:                                                │
│     • allow   - Operation proceeds                         │
│     • deny    - Operation blocked, error returned          │
│     • approve - Operation blocked pending human approval   │
│     • log     - Operation proceeds, marked for attention   │
└─────────────────────────────────────────────────────────────┘
```

### 9.2 Policy Configuration

```yaml
# /etc/agentsh/policies/default.yaml
version: 1
name: default
description: Standard policy for AI agent execution

# File operation rules
file_rules:
  # Explicitly allowed operations
  - name: allow-workspace-read
    paths: ["/workspace/**"]
    operations: [read, open, stat, list]
    decision: allow
    
  - name: allow-workspace-write
    paths: ["/workspace/**"]
    operations: [write, create]
    decision: allow
    
  - name: approve-workspace-delete
    paths: ["/workspace/**"]
    operations: [delete]
    decision: approve
    message: "Agent wants to delete: {path}"
    
  - name: allow-tmp
    paths: ["/tmp/**", "/var/tmp/**"]
    operations: ["*"]
    decision: allow
    
  # Explicitly denied operations
  - name: deny-etc
    paths: ["/etc/**"]
    operations: ["*"]
    decision: deny
    
  - name: deny-sensitive
    paths: 
      - "/home/**/.ssh/**"
      - "/home/**/.aws/**"
      - "**/.env"
      - "**/secrets/**"
    operations: ["*"]
    decision: deny
    
  # Default deny
  - name: default-deny-file
    paths: ["**"]
    operations: ["*"]
    decision: deny

# Network rules
network_rules:
  - name: allow-https
    ports: [443]
    decision: allow
    
  - name: allow-http
    ports: [80]
    decision: allow
    
  - name: allow-package-registries
    domains:
      - "registry.npmjs.org"
      - "pypi.org"
      - "files.pythonhosted.org"
      - "crates.io"
    decision: allow
    
  - name: allow-github
    domains: ["*.github.com", "*.githubusercontent.com"]
    decision: allow
    
  - name: block-internal
    cidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    decision: deny
    
  - name: default-deny-network
    domains: ["*"]
    decision: deny

# Command rules (optional pre-execution check)
command_rules:
  - name: allow-safe-commands
    commands: [ls, cat, head, tail, grep, find, pwd, echo]
    decision: allow
    
  - name: approve-package-install
    commands: [npm, pip, cargo, apt]
    args_pattern: ["install*", "add*"]
    decision: approve
    message: "Agent wants to install packages: {args}"
    
  - name: deny-dangerous
    commands: [rm, dd, mkfs, fdisk]
    args_pattern: ["-rf*", "-r *"]
    decision: deny
```

### 9.3 Policy Engine Implementation

```go
type PolicyEngine struct {
    fileRules    []FileRule
    networkRules []NetworkRule
    commandRules []CommandRule
    
    // Caching
    decisionCache sync.Map
    cacheTTL      time.Duration
    
    // Approval handling
    approvalChan chan ApprovalRequest
    approvals    map[string]chan bool
}

type FileRule struct {
    Name       string
    Paths      []glob.Glob
    Operations []string
    Decision   Decision
    Message    string
}

func (p *PolicyEngine) CheckFileOp(event FileEvent) Decision {
    // Check cache first
    cacheKey := fmt.Sprintf("file:%s:%s", event.Path, event.Operation)
    if cached, ok := p.decisionCache.Load(cacheKey); ok {
        return cached.(Decision)
    }
    
    // Evaluate rules in order
    for _, rule := range p.fileRules {
        if !matchesOperation(rule.Operations, event.Operation) {
            continue
        }
        if !matchesPath(rule.Paths, event.Path) {
            continue
        }
        
        // Cache and return
        p.decisionCache.Store(cacheKey, rule.Decision)
        return rule.Decision
    }
    
    // Default deny
    return Deny
}
```

### 9.4 Approval Workflow

For operations requiring human approval:

```
┌─────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────┐
│  Agent  │────▶│   agentsh   │────▶│  Approval   │────▶│  Human  │
│         │     │             │     │   Gateway   │     │         │
└─────────┘     └─────────────┘     └─────────────┘     └─────────┘
                      │                    │                  │
                      │  Operation blocked │                  │
                      │◀───────────────────│                  │
                      │                    │    Review        │
                      │                    │◀─────────────────│
                      │                    │                  │
                      │                    │  Verify human    │
                      │                    │  (WebAuthn/TOTP) │
                      │                    │◀─────────────────│
                      │                    │                  │
                      │                    │  Approve/Deny    │
                      │                    │◀─────────────────│
                      │  Signed token      │                  │
                      │◀───────────────────│                  │
                      │                    │                  │
                      ▼                    │                  │
              Continue or Error            │                  │
```

#### Human Verification

To ensure approvals come from actual humans (not agents or bots), agentsh requires verification:

| Method | Security | Description |
|--------|----------|-------------|
| **WebAuthn/FIDO2** | High | Hardware security key or biometric (recommended) |
| **TOTP** | Medium-High | Time-based code from authenticator app |
| **Interactive Challenge** | Medium | Math problem, type filename, or timed delay |
| **Local TTY** | High | Terminal prompt (cannot be accessed by agent) |

**See [APPROVAL_AUTH.md](APPROVAL_AUTH.md) for complete approval authentication specification.**

#### Key Security Properties

1. **Credential Separation**: Agent API keys cannot access approval endpoints
2. **Network Isolation**: Approval service runs on separate port, blocked from agent's network namespace
3. **Signed Tokens**: Approvals are cryptographically signed and bound to specific requests
4. **Replay Prevention**: Tokens include nonces, timestamps, and are marked as used
5. **Verification Required**: Every approval requires human verification (WebAuthn, TOTP, or challenge)

```json
// Approval request (sent to human)
{
  "request_id": "approval-123",
  "session_id": "session-abc",
  "timestamp": "2024-12-15T10:30:45Z",
  "operation": {
    "type": "file_delete",
    "path": "/workspace/important-file.txt",
    "details": {
      "file_size": 4096,
      "last_modified": "2024-12-14T08:00:00Z"
    }
  },
  "context": {
    "command": "rm important-file.txt",
    "working_dir": "/workspace",
    "recent_commands": [
      "ls -la",
      "cat important-file.txt"
    ]
  },
  "policy_rule": "approve-workspace-delete",
  "message": "Agent wants to delete: /workspace/important-file.txt",
  "timeout": "5m",
  "verification_required": ["webauthn", "totp"]
}

// Signed approval token (from verified human)
{
  "request_id": "approval-123",
  "decision": "approve",
  "approved_by": "user@example.com",
  "verification_method": "webauthn",
  "credential_id": "abc123...",
  "timestamp": "2024-12-15T10:31:02Z",
  "expires_at": "2024-12-15T10:36:02Z",
  "request_hash": "sha256:...",
  "signature": "base64:..."
}
```

---

## 10. Structured Output

### 10.1 Design Philosophy

Traditional shells output human-readable text. agentsh outputs structured JSON that agents can parse reliably.

```
Traditional shell:
  $ ls -la
  total 48
  drwxr-xr-x  12 user staff   384 Dec 15 10:00 .
  drwxr-xr-x   5 user staff   160 Dec 14 09:00 ..
  -rw-r--r--   1 user staff  1420 Dec 15 09:55 README.md
  
agentsh:
  $ ls -la
  {
    "cwd": "/workspace",
    "entries": [
      {
        "name": "README.md",
        "type": "file",
        "size": 1420,
        "mode": "644",
        "owner": "user",
        "group": "staff",
        "mtime": "2024-12-15T09:55:00Z"
      }
    ],
    "summary": {
      "files": 1,
      "directories": 0,
      "total_size": 1420
    }
  }
```

### 10.2 Command Response Schema

Every command execution returns a structured response:

```json
{
  "command_id": "cmd-xyz789",
  "session_id": "session-abc123",
  "timestamp": "2024-12-15T10:30:45.123Z",
  
  "request": {
    "command": "python",
    "args": ["process_data.py"],
    "working_dir": "/workspace",
    "timeout": "5m"
  },
  
  "result": {
    "exit_code": 0,
    "stdout": "Processed 1000 records\n",
    "stderr": "",
    "duration_ms": 2341
  },
  
  "events": {
    "file_operations": [
      {
        "type": "file_read",
        "path": "/workspace/input.csv",
        "bytes": 45000,
        "decision": "allow"
      },
      {
        "type": "file_write",
        "path": "/workspace/output.json",
        "bytes": 62000,
        "decision": "allow"
      }
    ],
    "network_operations": [
      {
        "type": "dns_query",
        "domain": "api.example.com",
        "decision": "allow"
      },
      {
        "type": "net_connect",
        "remote": "93.184.216.34:443",
        "bytes_sent": 1024,
        "bytes_received": 8192,
        "decision": "allow"
      }
    ],
    "blocked_operations": [
      {
        "type": "file_read",
        "path": "/etc/passwd",
        "decision": "deny",
        "policy_rule": "deny-etc"
      }
    ]
  },
  
  "resources": {
    "cpu_time_ms": 890,
    "memory_peak_mb": 128,
    "disk_read_mb": 0.04,
    "disk_write_mb": 0.06,
    "net_sent_kb": 1.0,
    "net_received_kb": 8.0
  }
}
```

### 10.3 Structured Errors

Errors include context and suggestions:

```json
{
  "command_id": "cmd-xyz789",
  "result": {
    "exit_code": 1,
    "error": {
      "code": "ENOENT",
      "message": "File not found",
      "path": "/workspace/missing.txt",
      "context": {
        "working_dir": "/workspace",
        "command": "cat missing.txt"
      },
      "suggestions": [
        {
          "action": "list_directory",
          "command": "ls /workspace",
          "reason": "See what files exist"
        },
        {
          "action": "search",
          "command": "find /workspace -name '*.txt'",
          "reason": "Find similar files"
        }
      ],
      "similar_files": [
        "/workspace/missing-backup.txt",
        "/workspace/data/missing.txt"
      ]
    }
  }
}
```

### 10.4 Output Truncation

Large outputs are automatically truncated with pagination:

```json
{
  "result": {
    "stdout": "[first 10000 bytes of output...]",
    "stdout_truncated": true,
    "stdout_total_bytes": 5242880,
    "stdout_total_lines": 100000,
    "pagination": {
      "current_offset": 0,
      "current_limit": 10000,
      "has_more": true,
      "next_command": "agentsh output cmd-xyz789 --offset=10000 --limit=10000"
    }
  }
}
```

### 10.5 Builtin Structured Commands

agentsh provides structured alternatives to common commands:

| Command | Structured Version | Output |
|---------|-------------------|--------|
| `ls` | `als` | JSON directory listing |
| `cat` | `acat` | JSON with content + metadata |
| `find` | `afind` | JSON array of matches |
| `stat` | `astat` | JSON file attributes |
| `ps` | `aps` | JSON process list |
| `env` | `aenv` | JSON environment map |
| `df` | `adf` | JSON disk usage |
| `du` | `adu` | JSON directory sizes |

---

## 11. API Design

### 11.1 API Overview

agentsh exposes both HTTP REST and gRPC APIs for programmatic access.

```
┌─────────────────────────────────────────────────────────────┐
│                      API Gateway                             │
│                                                             │
│  ┌─────────────────┐         ┌─────────────────────────┐   │
│  │   HTTP/REST     │         │        gRPC             │   │
│  │   Port 8080     │         │      Port 9090          │   │
│  └─────────────────┘         └─────────────────────────┘   │
│           │                            │                    │
│           └────────────┬───────────────┘                    │
│                        ▼                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Request Router                          │   │
│  │                                                      │   │
│  │  /sessions/*     → Session Manager                  │   │
│  │  /exec           → Command Executor                 │   │
│  │  /events         → Event Stream (SSE/gRPC stream)   │   │
│  │  /approvals      → Approval Handler                 │   │
│  │  /health         → Health Check                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 11.2 REST API Endpoints

#### Sessions

```
POST   /api/v1/sessions              Create new session
GET    /api/v1/sessions              List all sessions
GET    /api/v1/sessions/{id}         Get session details
DELETE /api/v1/sessions/{id}         Destroy session
PATCH  /api/v1/sessions/{id}         Update session config
```

#### Command Execution

```
POST   /api/v1/sessions/{id}/exec    Execute command
POST   /api/v1/sessions/{id}/exec/stream Execute command (SSE output)
GET    /api/v1/sessions/{id}/output/{cmd_id}  Get command output (pagination)
POST   /api/v1/sessions/{id}/kill/{cmd_id}    Kill running command
```

#### Events

```
GET    /api/v1/sessions/{id}/events  Stream events (SSE)
GET    /api/v1/sessions/{id}/history Get event history
```

#### Approvals

```
GET    /api/v1/approvals             List pending approvals
POST   /api/v1/approvals/{id}        Approve/deny request
```

### 11.3 REST API Examples

#### Create Session

```http
POST /api/v1/sessions HTTP/1.1
Content-Type: application/json

{
  "id": "session-abc123",
  "workspace": "/home/user/project",
  "policy": "default",
  "idle_timeout": "30m",
  "resource_limits": {
    "max_memory_mb": 2048,
    "command_timeout": "5m"
  },
  "network": {
    "allowed_domains": ["github.com", "npmjs.org"]
  }
}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "id": "session-abc123",
  "state": "ready",
  "created": "2024-12-15T10:30:00Z",
  "workspace": "/home/user/project",
  "endpoints": {
    "exec": "/api/v1/sessions/session-abc123/exec",
    "events": "/api/v1/sessions/session-abc123/events"
  }
}
```

#### Execute Command

```http
POST /api/v1/sessions/session-abc123/exec HTTP/1.1
Content-Type: application/json

{
  "command": "npm",
  "args": ["install"],
  "timeout": "5m",
  "stream_output": false
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "command_id": "cmd-xyz789",
  "exit_code": 0,
  "stdout": "added 847 packages in 12.3s\n",
  "stderr": "",
  "duration_ms": 12345,
  "events": {
    "file_operations": [...],
    "network_operations": [...],
    "blocked_operations": []
  }
}
```

#### Stream Events

```http
GET /api/v1/sessions/session-abc123/events HTTP/1.1
Accept: text/event-stream
```

```
HTTP/1.1 200 OK
Content-Type: text/event-stream

data: {"type":"file_open","path":"/workspace/package.json","decision":"allow"}

data: {"type":"net_connect","remote":"registry.npmjs.org:443","decision":"allow"}

data: {"type":"file_write","path":"/workspace/node_modules/.package-lock.json","bytes":4096}

```

### 11.4 gRPC API

```protobuf
syntax = "proto3";

package agentsh.v1;

service AgentShell {
  // Session management
  rpc CreateSession(CreateSessionRequest) returns (Session);
  rpc GetSession(GetSessionRequest) returns (Session);
  rpc ListSessions(ListSessionsRequest) returns (ListSessionsResponse);
  rpc DestroySession(DestroySessionRequest) returns (Empty);
  
  // Command execution
  rpc Execute(ExecuteRequest) returns (ExecuteResponse);
  rpc ExecuteStream(ExecuteRequest) returns (stream ExecuteEvent);
  
  // Event streaming
  rpc StreamEvents(StreamEventsRequest) returns (stream IOEvent);
  
  // Approvals
  rpc ListApprovals(ListApprovalsRequest) returns (ListApprovalsResponse);
  rpc HandleApproval(HandleApprovalRequest) returns (Empty);
}

message ExecuteRequest {
  string session_id = 1;
  string command = 2;
  repeated string args = 3;
  map<string, string> env = 4;
  string working_dir = 5;
  google.protobuf.Duration timeout = 6;
  string stdin = 7;
  bool stream_output = 8;
}

message ExecuteResponse {
  string command_id = 1;
  int32 exit_code = 2;
  string stdout = 3;
  string stderr = 4;
  google.protobuf.Duration duration = 5;
  repeated IOEvent file_operations = 6;
  repeated IOEvent network_operations = 7;
  repeated IOEvent blocked_operations = 8;
  ResourceUsage resources = 9;
}
```

### 11.5 Client Libraries

Official client libraries for common languages:

```go
// Go client
import "github.com/agentsh/agentsh-go"

client := agentsh.NewClient("localhost:8080")

session, err := client.CreateSession(ctx, agentsh.SessionConfig{
    Workspace: "/home/user/project",
    Policy:    "default",
})

result, err := client.Execute(ctx, session.ID, agentsh.ExecRequest{
    Command: "npm",
    Args:    []string{"install"},
})

fmt.Printf("Exit code: %d\n", result.ExitCode)
fmt.Printf("Files written: %d\n", len(result.Events.FileOperations))
```

```python
# Python client
from agentsh import Client, SessionConfig, ExecRequest

client = Client("localhost:8080")

session = client.create_session(SessionConfig(
    workspace="/home/user/project",
    policy="default"
))

result = client.execute(session.id, ExecRequest(
    command="python",
    args=["script.py"]
))

print(f"Exit code: {result.exit_code}")
print(f"Network calls: {len(result.events.network_operations)}")
```

```typescript
// TypeScript client
import { AgentShClient, SessionConfig } from '@agentsh/client';

const client = new AgentShClient('localhost:8080');

const session = await client.createSession({
  workspace: '/home/user/project',
  policy: 'default'
});

const result = await client.execute(session.id, {
  command: 'node',
  args: ['script.js']
});

console.log(`Exit code: ${result.exitCode}`);
console.log(`Blocked ops: ${result.events.blockedOperations.length}`);
```

---

## 12. CLI Interface

### 12.1 CLI Overview

agentsh provides both a server daemon and a client CLI.

```
agentsh
├── server      Start the agentsh server
├── session     Manage sessions
│   ├── create  Create new session
│   ├── list    List sessions
│   ├── info    Get session details
│   ├── destroy Destroy session
│   └── attach  Attach to session (interactive)
├── exec        Execute command in session
├── events      Stream session events
├── approve     Handle pending approvals
├── policy      Manage policies
│   ├── list    List policies
│   ├── show    Show policy details
│   └── validate Validate policy file
└── config      Manage configuration
    ├── show    Show resolved config
    └── validate Validate config file
```

### 12.2 CLI Examples

#### Start Server

```bash
# Start with default config
$ agentsh server

# Start with custom config
$ agentsh server --config /etc/agentsh/config.yaml

# Start with debug logging
$ agentsh server --log-level debug
```

#### Session Management

```bash
# Create session
$ agentsh session create \
    --workspace /home/user/project \
    --policy default \
    --idle-timeout 30m
Session created: session-abc123

# List sessions
$ agentsh session list
ID              STATE   CREATED              COMMANDS  WORKSPACE
session-abc123  ready   2024-12-15T10:30:00  42       /home/user/project
session-def456  busy    2024-12-15T10:25:00  108      /home/user/other

# Get session info
$ agentsh session info session-abc123
ID:            session-abc123
State:         ready
Created:       2024-12-15T10:30:00Z
Last Activity: 2024-12-15T11:45:23Z
Commands:      42
File Ops:      1,234
Net Ops:       89
Working Dir:   /workspace/src

# Destroy session
$ agentsh session destroy session-abc123
Session destroyed: session-abc123
```

#### Command Execution

```bash
# Execute single command
$ agentsh exec session-abc123 -- npm install
{
  "exit_code": 0,
  "stdout": "added 847 packages in 12.3s\n",
  "duration_ms": 12345,
  ...
}

# Execute with timeout
$ agentsh exec session-abc123 --timeout 1m -- npm run build

# Execute with JSON input
$ agentsh exec session-abc123 --json '{"command":"ls","args":["-la"]}'

# Stream output
$ agentsh exec session-abc123 --stream -- npm install
[stdout] added 100 packages...
[stdout] added 200 packages...
[file] write: /workspace/node_modules/.package-lock.json (4096 bytes)
[net] connect: registry.npmjs.org:443
...

# Interactive mode (attach to session)
$ agentsh session attach session-abc123
agentsh:session-abc123:/workspace$ ls -la
{
  "entries": [...]
}
agentsh:session-abc123:/workspace$ cd src
agentsh:session-abc123:/workspace/src$ 
```

#### Event Streaming

```bash
# Stream all events
$ agentsh events session-abc123
{"type":"file_open","path":"/workspace/src/main.py",...}
{"type":"net_connect","remote":"api.github.com:443",...}

# Stream with filter
$ agentsh events session-abc123 --type file_write,file_delete

# Stream to file
$ agentsh events session-abc123 > events.jsonl
```

#### Approval Handling

```bash
# List pending approvals
$ agentsh approve list
ID           SESSION        TYPE         PATH/TARGET            WAITING
approval-1   session-abc    file_delete  /workspace/data.db     2m
approval-2   session-def    net_connect  internal.corp.com:443  5m

# Approve request
$ agentsh approve approval-1 --allow --reason "backup exists"

# Deny request  
$ agentsh approve approval-2 --deny --reason "internal network blocked"

# Interactive approval mode
$ agentsh approve watch
[approval-3] session-abc wants to delete /workspace/config.json
  Context: rm config.json
  Recent commands: ls, cat config.json
  Allow? [y/n/d(etails)]: 
```

---

## 13. Security Model

### 13.1 Defense in Depth

agentsh implements multiple security layers:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: API Authentication                                  │
│ • API keys or JWT tokens                                    │
│ • Per-agent credentials                                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Session Isolation                                   │
│ • Linux namespaces (mount, net, PID, UTS)                  │
│ • Separate filesystem view per session                     │
│ • Isolated network namespace                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Policy Enforcement                                  │
│ • File path restrictions                                    │
│ • Network destination restrictions                         │
│ • Command restrictions                                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Resource Limits                                     │
│ • CPU and memory limits (cgroups)                          │
│ • Disk I/O limits                                          │
│ • Network bandwidth limits                                  │
│ • Command timeout                                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 5: Syscall Filtering                                   │
│ • seccomp-bpf rules                                        │
│ • Block dangerous syscalls (ptrace, mount, etc.)           │
└─────────────────────────────────────────────────────────────┘
```

### 13.2 Namespace Isolation

Each session runs in isolated Linux namespaces:

| Namespace | Isolation Provided |
|-----------|-------------------|
| Mount | Separate filesystem view; FUSE mounted at /workspace |
| Network | Separate network stack; all traffic through proxy |
| PID | Cannot see host processes |
| UTS | Separate hostname |
| User | Optional; map to unprivileged user |

### 13.3 seccomp-bpf Profile

Block dangerous syscalls:

```go
var blockedSyscalls = []int{
    syscall.SYS_PTRACE,       // No debugging/tracing
    syscall.SYS_MOUNT,        // No mounting filesystems
    syscall.SYS_UMOUNT2,      // No unmounting
    syscall.SYS_PIVOT_ROOT,   // No changing root
    syscall.SYS_SWAPON,       // No swap manipulation
    syscall.SYS_SWAPOFF,
    syscall.SYS_REBOOT,       // No system reboot
    syscall.SYS_KEXEC_LOAD,   // No kernel loading
    syscall.SYS_INIT_MODULE,  // No kernel modules
    syscall.SYS_DELETE_MODULE,
    syscall.SYS_ACCT,         // No process accounting
    syscall.SYS_SETTIMEOFDAY, // No time manipulation
    syscall.SYS_STIME,
    syscall.SYS_CLOCK_SETTIME,
}
```

### 13.4 Resource Limits (cgroups v2)

```yaml
resource_limits:
  # Memory
  memory_max_mb: 2048
  memory_swap_max_mb: 0      # Disable swap
  
  # CPU
  cpu_quota_percent: 80      # Max 80% of one CPU
  cpu_period_us: 100000
  
  # I/O
  io_read_bps_max: 104857600   # 100 MB/s
  io_write_bps_max: 52428800   # 50 MB/s
  
  # PIDs
  pids_max: 100              # Max 100 processes
  
  # Network (via tc)
  net_bandwidth_mbps: 100
```

### 13.5 Threat Model

| Threat | Mitigation |
|--------|------------|
| Agent escapes sandbox | Namespaces + seccomp + FUSE root |
| Agent accesses sensitive files | Policy enforcement + path restrictions |
| Agent exfiltrates data | Network policy + egress monitoring |
| Agent DoS via resources | cgroups resource limits |
| Agent exploits kernel | seccomp blocks dangerous syscalls |
| Agent escapes via symlinks | FUSE resolves and validates symlinks |
| Agent uses covert channels | Network proxy inspects all traffic |

### 13.6 Audit Trail

All operations are logged with full context:

```json
{
  "audit_id": "audit-123456",
  "timestamp": "2024-12-15T10:30:45.123456Z",
  "session_id": "session-abc123",
  "agent_id": "agent-xyz",
  "command_id": "cmd-789",
  
  "operation": {
    "type": "file_delete",
    "path": "/workspace/important.txt",
    "real_path": "/home/user/project/important.txt"
  },
  
  "policy": {
    "decision": "approve",
    "rule": "approve-workspace-delete",
    "approval_id": "approval-456",
    "approved_by": "user@example.com",
    "approval_time": "2024-12-15T10:31:02Z"
  },
  
  "context": {
    "working_dir": "/workspace",
    "command": "rm important.txt",
    "command_history": [
      "ls -la",
      "cat important.txt",
      "rm important.txt"
    ]
  },
  
  "outcome": {
    "success": true,
    "duration_us": 1234
  }
}
```

---

## 14. Performance Considerations

### 14.1 Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Session creation | < 500ms | One-time cost |
| Command overhead | < 10ms | Per command |
| FUSE latency | < 100μs | Per file operation |
| Network proxy latency | < 1ms | Per connection |
| Throughput overhead | < 20% | For I/O-bound workloads |

### 14.2 FUSE Optimizations

```go
// FUSE mount options for performance
var fuseOptions = []string{
    "allow_other",          // Allow access from sandbox processes
    "default_permissions",  // Let kernel check permissions
    "max_read=131072",      // 128KB max read size
    "max_write=131072",     // 128KB max write size
    "async_read",           // Async read operations
    "big_writes",           // Enable large write buffers
}

// Attribute caching
var cacheTimeouts = FUSECacheConfig{
    EntryTimeout: 1 * time.Second,  // Cache directory entries
    AttrTimeout:  1 * time.Second,  // Cache file attributes
    NegativeTimeout: 0,             // Don't cache ENOENT
}
```

### 14.3 Event Batching

```go
type EventBatcher struct {
    buffer     []IOEvent
    bufferSize int
    flushDelay time.Duration
    output     chan []IOEvent
    mu         sync.Mutex
}

func (b *EventBatcher) Add(event IOEvent) {
    b.mu.Lock()
    defer b.mu.Unlock()
    
    b.buffer = append(b.buffer, event)
    
    if len(b.buffer) >= b.bufferSize {
        b.flush()
    }
}

func (b *EventBatcher) flushLoop() {
    ticker := time.NewTicker(b.flushDelay)
    for range ticker.C {
        b.mu.Lock()
        if len(b.buffer) > 0 {
            b.flush()
        }
        b.mu.Unlock()
    }
}
```

### 14.4 Policy Caching

```go
type PolicyCache struct {
    cache sync.Map
    ttl   time.Duration
}

type cacheEntry struct {
    decision Decision
    rule     string
    expires  time.Time
}

func (c *PolicyCache) Get(key string) (Decision, string, bool) {
    if val, ok := c.cache.Load(key); ok {
        entry := val.(*cacheEntry)
        if time.Now().Before(entry.expires) {
            return entry.decision, entry.rule, true
        }
        c.cache.Delete(key)
    }
    return "", "", false
}
```

### 14.5 Selective Monitoring

For maximum performance, use selective monitoring:

```yaml
monitoring:
  # Full FUSE monitoring (slower, complete visibility)
  full_monitor:
    - "/workspace"
    
  # Read-only bind mount (faster, write operations still logged)
  read_only_passthrough:
    - "/usr"
    - "/lib"
    - "/opt"
    
  # Full passthrough (fastest, no monitoring)
  passthrough:
    - "/dev"
    - "/proc"
    - "/sys"
```

### 14.6 Benchmark Results

Expected overhead by workload type:

| Workload | Overhead | Notes |
|----------|----------|-------|
| CPU-bound computation | ~2% | Minimal I/O |
| Large file processing | 15-25% | Sequential I/O |
| Many small files (npm install) | 25-40% | High metadata ops |
| Network-heavy | 5-15% | Proxy overhead |
| Mixed workload | 15-25% | Typical agent usage |

---

## 15. Configuration

### 15.1 Server Configuration

```yaml
# /etc/agentsh/config.yaml

server:
  http_addr: "0.0.0.0:8080"
  grpc_addr: "0.0.0.0:9090"
  unix_socket: "/var/run/agentsh/agentsh.sock"
  
  tls:
    enabled: true
    cert_file: "/etc/agentsh/tls/server.crt"
    key_file: "/etc/agentsh/tls/server.key"
  
  auth:
    type: "api_key"  # or "jwt", "mtls"
    api_keys_file: "/etc/agentsh/api_keys.yaml"

logging:
  level: "info"      # debug, info, warn, error
  format: "json"     # json, text
  output: "/var/log/agentsh/server.log"
  
  # Separate audit log
  audit:
    enabled: true
    output: "/var/log/agentsh/audit.log"
    include_stdout: false  # Include command stdout in audit

sessions:
  base_dir: "/var/lib/agentsh/sessions"
  max_sessions: 100
  default_timeout: "4h"
  default_idle_timeout: "30m"
  cleanup_interval: "1m"

sandbox:
  # FUSE settings
  fuse:
    entry_timeout: "1s"
    attr_timeout: "1s"
    max_readahead: 131072
    async_read: true
    
  # Network proxy settings
  network:
    proxy_port_range: "10000-20000"
    dns_upstream: "8.8.8.8:53"
    
  # Resource limits defaults
  resource_limits:
    max_memory_mb: 2048
    max_cpu_percent: 80
    command_timeout: "5m"
    pids_max: 100

policies:
  dir: "/etc/agentsh/policies"
  default: "default"
  
approvals:
  timeout: "5m"
  notification:
    type: "webhook"
    url: "https://example.com/agentsh/approvals"
```

### 15.2 Policy Configuration

See [Section 9.2](#92-policy-configuration) for policy file format.

### 15.3 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENTSH_CONFIG` | Config file path | `/etc/agentsh/config.yaml` |
| `AGENTSH_LOG_LEVEL` | Log level | `info` |
| `AGENTSH_HTTP_ADDR` | HTTP listen address | `0.0.0.0:8080` |
| `AGENTSH_GRPC_ADDR` | gRPC listen address | `0.0.0.0:9090` |
| `AGENTSH_DATA_DIR` | Data directory | `/var/lib/agentsh` |
| `AGENTSH_NO_AUTO` | Disable CLI auto-start/auto-create behaviors | unset |

---

## 16. Deployment

### 16.0 Cross-Platform Support

agentsh provides full security features on Linux. For Windows and macOS, we support deployment strategies that run agentsh inside a Linux environment.

| Platform | Strategy | Security Level |
|----------|----------|----------------|
| **Linux** | Native | ✅ Full |
| **Windows** | WSL2 or Docker | ✅ Full |
| **macOS** | Tiered (FUSE → sandbox → Lima/Docker) | ⚠️ Varies by tier |
| **Container Dev** | Linux container with agentsh | ✅ Full |

**See [CROSS_PLATFORM.md](CROSS_PLATFORM.md) for detailed platform-specific setup instructions.**

### 16.1 System Requirements (Linux Native)

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Linux 5.4+ | Linux 5.15+ (io_uring) |
| Architecture | amd64, arm64 | amd64 |
| Memory | 512MB + 256MB/session | 2GB + 512MB/session |
| Disk | 10GB | 50GB+ |
| Kernel features | namespaces, FUSE, cgroups v2 | + seccomp, eBPF |

### 16.2 Installation

```bash
# Download binary
curl -LO https://github.com/agentsh/agentsh/releases/latest/download/agentsh-linux-amd64
chmod +x agentsh-linux-amd64
sudo mv agentsh-linux-amd64 /usr/local/bin/agentsh

# Create directories
sudo mkdir -p /etc/agentsh/policies
sudo mkdir -p /var/lib/agentsh
sudo mkdir -p /var/log/agentsh
sudo mkdir -p /var/run/agentsh

# Copy default config and policies
sudo cp config.yaml /etc/agentsh/
sudo cp policies/*.yaml /etc/agentsh/policies/

# Create systemd service
sudo cp agentsh.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable agentsh
sudo systemctl start agentsh
```

### 16.3 Docker Deployment

agentsh is available as a Docker image that works on Linux, Windows (Docker Desktop), and macOS (Docker Desktop, Colima, OrbStack).

```dockerfile
FROM ubuntu:24.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    fuse3 \
    libfuse3-dev \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy agentsh binary
COPY agentsh /usr/local/bin/

# Copy configuration
COPY config.yaml /etc/agentsh/
COPY policies/ /etc/agentsh/policies/

# Create directories
RUN mkdir -p /var/lib/agentsh /var/log/agentsh /var/run/agentsh

# Need privileged mode for namespaces
# Or specific capabilities: CAP_SYS_ADMIN, CAP_NET_ADMIN
EXPOSE 8080 9090

CMD ["agentsh", "server"]
```

```bash
# Run with required capabilities (works on all platforms with Docker)
docker run -d \
  --name agentsh \
  --cap-add SYS_ADMIN \
  --cap-add NET_ADMIN \
  --device /dev/fuse \
  --security-opt apparmor=unconfined \
  -p 8080:8080 \
  -p 9090:9090 \
  -v /path/to/workspaces:/workspaces \
  ghcr.io/agentsh/agentsh:latest
```

**See [docker-compose.yml](docker-compose.yml) for a complete Docker Compose configuration.**

### 16.4 Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentsh
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agentsh
  template:
    metadata:
      labels:
        app: agentsh
    spec:
      containers:
      - name: agentsh
        image: agentsh:latest
        ports:
        - containerPort: 8080
        - containerPort: 9090
        securityContext:
          privileged: true  # Required for namespaces
        volumeMounts:
        - name: config
          mountPath: /etc/agentsh
        - name: workspaces
          mountPath: /workspaces
        - name: data
          mountPath: /var/lib/agentsh
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
      volumes:
      - name: config
        configMap:
          name: agentsh-config
      - name: workspaces
        persistentVolumeClaim:
          claimName: agentsh-workspaces
      - name: data
        emptyDir: {}
```

---

## 17. Future Considerations

### 17.1 Planned Features

| Feature | Priority | Description |
|---------|----------|-------------|
| eBPF monitoring | High | Lower overhead alternative to FUSE |
| Transaction support | Medium | Checkpoint and rollback |
| Intent tracking | Medium | Associate operations with goals |
| Multi-node | Medium | Distributed session management |
| GPU passthrough | Low | Support for ML workloads |
| Windows support | Low | Port to Windows |
| macOS support | Low | Port to macOS |

### 17.2 eBPF Monitoring Mode

Future hybrid mode using eBPF for monitoring, FUSE only for blocking:

```yaml
monitoring:
  mode: "hybrid"  # "fuse", "ebpf", "hybrid"
  
  hybrid:
    # eBPF for read-only monitoring (low overhead)
    ebpf_monitor:
      - "/workspace"
      - "/tmp"
      
    # FUSE only for paths that need blocking
    fuse_enforce:
      - "/workspace/secrets"
```

### 17.3 MCP Integration

Model Context Protocol server mode for direct Claude integration:

```json
{
  "mcpServers": {
    "agentsh": {
      "command": "agentsh",
      "args": ["mcp-server"],
      "env": {
        "AGENTSH_WORKSPACE": "/home/user/project",
        "AGENTSH_POLICY": "default"
      }
    }
  }
}
```

### 17.4 Intent Tracking

Future feature to associate operations with declared goals:

```bash
# Declare intent
$ agentsh intent "Refactor authentication module"

# Operations are tagged with intent
$ agentsh exec session-abc -- vim src/auth.py

# Query what happened for an intent
$ agentsh intent show intent-123
Intent: Refactor authentication module
Duration: 45 minutes
Files modified: 12
Tests run: 3
Commits: 2
```

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| Session | A persistent sandbox environment for an agent |
| Sandbox | Isolated execution environment with FUSE and network proxy |
| Policy | Rules defining allowed/denied operations |
| Event | Structured record of an I/O or network operation |
| Approval | Human-in-the-loop authorization for sensitive operations |
| FUSE | Filesystem in Userspace; used for file I/O interception |

## Appendix B: Error Codes

| Code | Name | Description |
|------|------|-------------|
| `E_SESSION_NOT_FOUND` | Session not found | Session ID does not exist |
| `E_SESSION_BUSY` | Session busy | Session is executing another command |
| `E_SESSION_STOPPED` | Session stopped | Session has been terminated |
| `E_POLICY_DENIED` | Policy denied | Operation blocked by policy |
| `E_APPROVAL_TIMEOUT` | Approval timeout | Human approval not received in time |
| `E_APPROVAL_DENIED` | Approval denied | Human denied the operation |
| `E_RESOURCE_LIMIT` | Resource limit | Resource quota exceeded |
| `E_COMMAND_TIMEOUT` | Command timeout | Command execution timed out |

## Appendix C: References

- [FUSE Documentation](https://www.kernel.org/doc/html/latest/filesystems/fuse.html)
- [Linux Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [cgroups v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [go-fuse Library](https://github.com/hanwen/go-fuse)

---

*This specification is a living document and will be updated as agentsh evolves.*
