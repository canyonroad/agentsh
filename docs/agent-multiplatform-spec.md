# agentsh Multi-Platform Support Specification

## Executive Summary

This document specifies the architecture for cross-platform agentsh support, enabling secure AI agent execution on Linux, macOS, Windows (native), and Windows (WSL2). The goal is to maintain API compatibility while leveraging platform-native security primitives, with clear documentation of security trade-offs.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Cross-Platform Abstraction Layer](#2-cross-platform-abstraction-layer)
3. [Linux Implementation (Reference)](#3-linux-implementation-reference)
4. [macOS Implementation](#4-macos-implementation)
5. [Windows Native Implementation](#5-windows-native-implementation)
6. [Windows WSL2 Implementation](#6-windows-wsl2-implementation)
7. [Environment Variable Protection](#7-environment-variable-protection-cross-platform)
8. [Unified Configuration](#8-unified-configuration)
9. [Installation & Deployment](#9-installation--deployment)
10. [Testing Strategy](#10-testing-strategy)
11. [Platform Comparison Matrix](#11-platform-comparison-matrix)
12. [Appendix: Go Dependencies](#12-appendix-go-dependencies)
13. [Conclusion](#13-conclusion)

---

## 1. Architecture Overview

### 1.1 Core Components

agentsh requires five core security components:

| Component | Purpose | Security Impact |
|-----------|---------|-----------------|
| **Filesystem Interception** | Monitor and control all file I/O | Essential - policy enforcement |
| **Network Interception** | Monitor and control all network traffic | Essential - policy enforcement |
| **Process Isolation** | Isolate agent from host system | Critical - containment |
| **Syscall Filtering** | Block dangerous system calls | Important - defense in depth |
| **Resource Limits** | Limit CPU, memory, disk, network | Important - DoS prevention |

### 1.2 Platform Security Levels

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Security Level Hierarchy                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ████████████████████████████████████████  Linux Native (100%)          │
│  ████████████████████████████████████████  Windows WSL2 (100%)          │
│                                                                          │
│  ████████████████████████████████████░░░░  macOS ESF+NE (90%)           │
│                                            (requires Apple entitlements) │
│                                                                          │
│  ██████████████████████████████████░░░░░░  macOS + Lima (85%)           │
│                                            (full Linux in VM)            │
│                                                                          │
│  ████████████████████████████░░░░░░░░░░░░  macOS FUSE-T + pf (70%)      │
│                                            (no isolation/resources)      │
│                                                                          │
│  ██████████████████████░░░░░░░░░░░░░░░░░░  Windows Native (55%)         │
│                                            (partial isolation)           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.3 Platform Primitive Mapping

| Component | Linux | macOS ESF+NE | macOS FUSE-T | macOS Lima | Win Native | Win WSL2 |
|-----------|-------|--------------|--------------|------------|------------|----------|
| Filesystem | FUSE3 | Endpoint Security | FUSE-T | FUSE3 | WinFsp | FUSE3 |
| Network | iptables | Network Extension | pf | iptables | WinDivert | iptables |
| Isolation | Namespaces | ❌ None | ❌ None | Namespaces | AppContainer | Namespaces |
| Syscall | seccomp-bpf | ⚠️ Exec only | ❌ None | seccomp-bpf | ❌ None | seccomp-bpf |
| Resources | cgroups v2 | ❌ None | ❌ None | cgroups v2 | Job Objects | cgroups v2 |

---

## 2. Cross-Platform Abstraction Layer

### 2.1 Core Interfaces

```go
// pkg/platform/interfaces.go

package platform

import (
    "context"
    "net"
    "os"
)

// Platform is the main interface for platform-specific implementations
type Platform interface {
    // Identity
    Name() string
    Capabilities() Capabilities
    
    // Core components
    Filesystem() FilesystemInterceptor
    Network() NetworkInterceptor
    Sandbox() SandboxManager
    Resources() ResourceLimiter
    
    // Lifecycle
    Initialize(ctx context.Context, config Config) error
    Shutdown(ctx context.Context) error
}

// Capabilities describes what this platform supports
type Capabilities struct {
    // Filesystem
    HasFUSE              bool
    FUSEImplementation   string // "fuse3", "fuse-t", "winfsp"
    
    // Network
    HasNetworkIntercept  bool
    NetworkImplementation string // "iptables", "pf", "windivert", "wfp", "network-extension"
    CanRedirectTraffic   bool
    CanInspectTLS        bool
    
    // Isolation
    HasMountNamespace    bool
    HasNetworkNamespace  bool
    HasPIDNamespace      bool
    HasUserNamespace     bool
    HasAppContainer      bool   // Windows-specific
    IsolationLevel       IsolationLevel
    
    // Syscall filtering
    HasSeccomp           bool
    
    // Resource control
    HasCgroups           bool
    HasJobObjects        bool   // Windows-specific
    CanLimitCPU          bool
    CanLimitMemory       bool
    CanLimitDiskIO       bool
    CanLimitNetworkBW    bool
    CanLimitProcessCount bool
    
    // Windows-specific: Registry monitoring
    HasRegistryMonitoring bool  // Can observe registry changes
    HasRegistryBlocking   bool  // Can block registry changes (requires driver)
    
    // macOS-specific: Apple frameworks
    HasEndpointSecurity  bool   // ESF entitlement approved
    HasNetworkExtension  bool   // NE entitlement approved
}

type IsolationLevel int

const (
    IsolationNone     IsolationLevel = iota // No isolation available
    IsolationMinimal                        // Basic file restrictions only
    IsolationPartial                        // AppContainer or similar
    IsolationFull                           // Full namespace isolation
)

// FilesystemInterceptor handles FUSE-based file monitoring
type FilesystemInterceptor interface {
    Mount(config FSConfig) (FSMount, error)
    Unmount(mount FSMount) error
    Available() bool
    Implementation() string
}

type FSConfig struct {
    SourcePath    string            // Real filesystem path
    MountPoint    string            // Where to mount (path or drive letter)
    PolicyEngine  PolicyEngine      // For access decisions
    EventChannel  chan<- IOEvent    // For event streaming
    Options       map[string]string // Platform-specific options
}

type FSMount interface {
    Path() string
    Stats() FSStats
    Close() error
}

// NetworkInterceptor handles network traffic interception
type NetworkInterceptor interface {
    Setup(config NetConfig) error
    Teardown() error
    Available() bool
    Implementation() string
}

type NetConfig struct {
    ProxyPort     int           // Local proxy port for TCP
    DNSPort       int           // Local DNS proxy port
    PolicyEngine  PolicyEngine  // For access decisions
    EventChannel  chan<- IOEvent
    InterceptMode InterceptMode
}

type InterceptMode int

const (
    InterceptAll       InterceptMode = iota // Intercept all traffic
    InterceptTCPOnly                        // TCP only (no UDP except DNS)
    InterceptMonitor                        // Monitor only, don't redirect
)

// SandboxManager handles process isolation
type SandboxManager interface {
    Create(config SandboxConfig) (Sandbox, error)
    Available() bool
    IsolationLevel() IsolationLevel
}

type SandboxConfig struct {
    Name          string
    WorkspacePath string
    AllowedPaths  []string          // Additional paths to allow
    Capabilities  []string          // Allowed capabilities
    Environment   map[string]string
}

type Sandbox interface {
    ID() string
    Execute(ctx context.Context, cmd string, args ...string) (*ExecResult, error)
    Close() error
}

// ResourceLimiter handles resource constraints
type ResourceLimiter interface {
    Apply(config ResourceConfig) (ResourceHandle, error)
    Available() bool
    SupportedLimits() []ResourceType
}

type ResourceConfig struct {
    MaxMemoryMB       uint64
    MaxCPUPercent     uint32
    MaxProcesses      uint32
    MaxDiskReadMBps   uint32
    MaxDiskWriteMBps  uint32
    MaxNetworkMbps    uint32
    CPUAffinity       []int
}

type ResourceType int

const (
    ResourceCPU ResourceType = 1 << iota
    ResourceMemory
    ResourceProcessCount
    ResourceDiskIO
    ResourceNetworkBW
    ResourceCPUAffinity
)
```

### 2.2 Platform Factory

```go
// pkg/platform/factory.go

package platform

import (
    "fmt"
    "runtime"
)

// New creates the appropriate platform implementation
func New() (Platform, error) {
    switch runtime.GOOS {
    case "linux":
        return NewLinuxPlatform()
    case "darwin":
        return NewDarwinPlatform()
    case "windows":
        // Check if running in WSL2
        if isWSL2() {
            return NewLinuxPlatform() // WSL2 uses Linux implementation
        }
        return NewWindowsPlatform()
    default:
        return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
    }
}

// NewWithMode creates a platform with specific mode
func NewWithMode(mode PlatformMode) (Platform, error) {
    switch mode {
    case ModeLinuxNative:
        return NewLinuxPlatform()
    case ModeDarwinNative:
        return NewDarwinPlatform()
    case ModeDarwinLima:
        return NewDarwinLimaPlatform()
    case ModeWindowsNative:
        return NewWindowsPlatform()
    case ModeWindowsWSL2:
        return NewWindowsWSL2Platform()
    default:
        return New() // Auto-detect
    }
}

type PlatformMode int

const (
    ModeAuto PlatformMode = iota
    ModeLinuxNative
    ModeDarwinNative
    ModeDarwinLima
    ModeWindowsNative
    ModeWindowsWSL2
)

func isWSL2() bool {
    // Check for WSL2 indicators
    data, err := os.ReadFile("/proc/version")
    if err != nil {
        return false
    }
    return strings.Contains(strings.ToLower(string(data)), "microsoft") ||
           strings.Contains(strings.ToLower(string(data)), "wsl")
}
```

### 2.3 Unified Event Types

```go
// pkg/types/events.go

package types

import "time"

type IOEvent struct {
    Timestamp   time.Time         `json:"timestamp"`
    SessionID   string            `json:"session_id"`
    Type        EventType         `json:"type"`
    
    // File operations
    Path        string            `json:"path,omitempty"`
    Operation   FileOperation     `json:"operation,omitempty"`
    BytesCount  int64             `json:"bytes,omitempty"`
    
    // Network operations
    Protocol    string            `json:"protocol,omitempty"`
    LocalAddr   string            `json:"local_addr,omitempty"`
    LocalPort   int               `json:"local_port,omitempty"`
    RemoteAddr  string            `json:"remote_addr,omitempty"`
    RemotePort  int               `json:"remote_port,omitempty"`
    Domain      string            `json:"domain,omitempty"`
    
    // Decision & Interception
    Decision    Decision          `json:"decision"`
    PolicyRule  string            `json:"policy_rule,omitempty"`
    HeldMs      int64             `json:"held_ms,omitempty"`       // Time held for decision
    
    // Redirect (when Decision == "redirect")
    Redirected      bool          `json:"redirected,omitempty"`
    RedirectTarget  string        `json:"redirect_target,omitempty"`  // New path/host
    OriginalTarget  string        `json:"original_target,omitempty"` // What was requested
    
    // Manual Approval (when Decision == "pending")
    ApprovalID      string        `json:"approval_id,omitempty"`
    ApprovedBy      string        `json:"approved_by,omitempty"`
    ApprovalLatency time.Duration `json:"approval_latency_ns,omitempty"`
    
    // Metadata
    ProcessID   int               `json:"pid,omitempty"`
    ProcessName string            `json:"process_name,omitempty"`
    Latency     time.Duration     `json:"latency_ns,omitempty"`
    Error       string            `json:"error,omitempty"`
    Platform    string            `json:"platform,omitempty"`
    Metadata    map[string]any    `json:"metadata,omitempty"`
}

type EventType string

const (
    EventFileOpen     EventType = "file_open"
    EventFileRead     EventType = "file_read"
    EventFileWrite    EventType = "file_write"
    EventFileCreate   EventType = "file_create"
    EventFileDelete   EventType = "file_delete"
    EventFileRename   EventType = "file_rename"
    EventFileStat     EventType = "file_stat"
    EventDirRead      EventType = "dir_read"
    EventDNSQuery     EventType = "dns_query"
    EventNetConnect   EventType = "net_connect"
    EventNetListen    EventType = "net_listen"
    EventNetAccept    EventType = "net_accept"
    EventNetClose     EventType = "net_close"
    EventNetData      EventType = "net_data"
    EventProcessExec  EventType = "process_exec"
    EventProcessExit  EventType = "process_exit"
    
    // Environment variable events (cross-platform)
    EventEnvRead      EventType = "env_read"      // getenv() / GetEnvironmentVariable
    EventEnvList      EventType = "env_list"      // Enumerate environ / GetEnvironmentStrings
    EventEnvWrite     EventType = "env_write"     // setenv() / SetEnvironmentVariable
    EventEnvDelete    EventType = "env_delete"    // unsetenv() / SetEnvironmentVariable(name, NULL)
    
    // Windows-only: Registry events
    EventRegistryRead    EventType = "registry_read"
    EventRegistryWrite   EventType = "registry_write"
    EventRegistryCreate  EventType = "registry_create"
    EventRegistryDelete  EventType = "registry_delete"
    EventRegistryRename  EventType = "registry_rename"
)

type FileOperation string

const (
    OpRead    FileOperation = "read"
    OpWrite   FileOperation = "write"
    OpCreate  FileOperation = "create"
    OpDelete  FileOperation = "delete"
    OpRename  FileOperation = "rename"
    OpStat    FileOperation = "stat"
    OpList    FileOperation = "list"
)

type Decision string

const (
    DecisionAllow    Decision = "allow"     // Allow operation to proceed
    DecisionDeny     Decision = "deny"      // Block operation, return error
    DecisionRedirect Decision = "redirect"  // Redirect to different target
    DecisionPending  Decision = "pending"   // Awaiting human approval
    DecisionTimeout  Decision = "timeout"   // Approval timed out
    DecisionError    Decision = "error"     // Internal error
)

// RedirectTarget specifies where to redirect an operation
type RedirectTarget struct {
    // For file operations
    FilePath    string `json:"file_path,omitempty"`     // Redirect to different file
    
    // For network operations
    Host        string `json:"host,omitempty"`          // Redirect to different host
    Port        int    `json:"port,omitempty"`          // Redirect to different port
    
    // For DNS
    IPAddress   string `json:"ip_address,omitempty"`    // Return different IP
    
    // For environment variables
    Value       string `json:"value,omitempty"`         // Return different value
}

// InterceptedOperation represents an operation held for decision
type InterceptedOperation struct {
    ID          string        `json:"id"`
    Type        EventType     `json:"type"`
    Timestamp   time.Time     `json:"timestamp"`
    
    // Original request details
    Request     OperationRequest `json:"request"`
    
    // Decision state
    Decision    Decision      `json:"decision"`
    Redirect    *RedirectTarget `json:"redirect,omitempty"`
    
    // Timing
    HeldAt      time.Time     `json:"held_at"`
    DecidedAt   *time.Time    `json:"decided_at,omitempty"`
    Timeout     time.Duration `json:"timeout"`
    
    // For manual approval
    ApprovalURL string        `json:"approval_url,omitempty"`
    ApprovedBy  string        `json:"approved_by,omitempty"`
    
    // Response channel (internal)
    responseCh  chan DecisionResponse `json:"-"`
}

type OperationRequest struct {
    // File operations
    Path        string `json:"path,omitempty"`
    Operation   string `json:"operation,omitempty"`
    Flags       int    `json:"flags,omitempty"`
    
    // Network operations
    RemoteAddr  string `json:"remote_addr,omitempty"`
    RemotePort  int    `json:"remote_port,omitempty"`
    Protocol    string `json:"protocol,omitempty"`
    
    // DNS operations
    Domain      string `json:"domain,omitempty"`
    QueryType   string `json:"query_type,omitempty"`
    
    // Environment operations
    Variable    string `json:"variable,omitempty"`
    Value       string `json:"value,omitempty"`
    
    // Process info
    PID         int    `json:"pid"`
    ProcessName string `json:"process_name,omitempty"`
    CommandLine string `json:"command_line,omitempty"`
}

type DecisionResponse struct {
    Decision Decision
    Redirect *RedirectTarget
    Error    error
}
```

### 2.4 Synchronous Interception Model

The core capability that enables blocking, redirecting, and manual approval is **synchronous interception** - the ability to hold an operation until a decision is made.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Synchronous Interception Flow                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Agent Process              agentsh                     Policy Engine        │
│       │                        │                             │               │
│       │  1. open("/etc/passwd")│                             │               │
│       │───────────────────────>│                             │               │
│       │                        │  2. Check policy            │               │
│       │                        │────────────────────────────>│               │
│       │                        │                             │               │
│       │        ┌───────────────┴───────────────┐             │               │
│       │        │     OPERATION HELD HERE       │             │               │
│       │        │     (process is blocked)      │             │               │
│       │        └───────────────┬───────────────┘             │               │
│       │                        │                             │               │
│       │                        │  3. Decision + Redirect?    │               │
│       │                        │<────────────────────────────│               │
│       │                        │                             │               │
│       │  4a. ALLOW: proceed    │                             │               │
│       │<───────────────────────│                             │               │
│       │                        │                             │               │
│       │  4b. DENY: EACCES      │                             │               │
│       │<───────────────────────│                             │               │
│       │                        │                             │               │
│       │  4c. REDIRECT: open    │                             │               │
│       │      different file    │                             │               │
│       │<───────────────────────│                             │               │
│       │                        │                             │               │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 2.4.1 Decision Types

| Decision | Behavior | Use Case |
|----------|----------|----------|
| **allow** | Operation proceeds normally | Permitted by policy |
| **deny** | Operation fails with error | Blocked by policy |
| **redirect** | Operation redirected to different target | Honeypot, sandboxing, testing |
| **pending** | Operation held awaiting approval | Sensitive operations requiring human review |
| **timeout** | Held operation timed out | Approval not received in time |

#### 2.4.2 Redirect Capabilities by Operation Type

| Operation | Redirect Capability | Example |
|-----------|---------------------|---------|
| **File Read** | Different file path | `/etc/passwd` → `/opt/agentsh/fake/passwd` |
| **File Write** | Different file path | `~/.ssh/authorized_keys` → `/dev/null` |
| **Network Connect** | Different host:port | `api.openai.com:443` → `localhost:8443` |
| **DNS Query** | Different IP response | `malware.com` → `0.0.0.0` |
| **Env Read** | Different value | `$OPENAI_API_KEY` → `"[REDACTED]"` |

#### 2.4.3 Manual Approval Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Manual Approval Flow                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Agent          agentsh              Approval UI            Human            │
│    │               │                      │                   │              │
│    │ 1. DELETE     │                      │                   │              │
│    │   /important  │                      │                   │              │
│    │──────────────>│                      │                   │              │
│    │               │                      │                   │              │
│    │               │ 2. Create approval   │                   │              │
│    │               │    request           │                   │              │
│    │               │─────────────────────>│                   │              │
│    │               │                      │                   │              │
│    │               │                      │ 3. Notify         │              │
│    │               │                      │───────────────────>│             │
│    │   [WAITING]   │                      │                   │              │
│    │               │                      │                   │              │
│    │               │                      │ 4. Review &       │              │
│    │               │                      │    Decide         │              │
│    │               │                      │<──────────────────│              │
│    │               │                      │                   │              │
│    │               │ 5. Decision          │                   │              │
│    │               │    (allow/deny)      │                   │              │
│    │               │<─────────────────────│                   │              │
│    │               │                      │                   │              │
│    │ 6. Result     │                      │                   │              │
│    │<──────────────│                      │                   │              │
│    │               │                      │                   │              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 2.4.4 Platform Support for Synchronous Interception

| Platform | File Ops | Network Ops | DNS | Env Vars | Registry | Process Exec |
|----------|:--------:|:-----------:|:---:|:--------:|:--------:|:------------:|
| **Linux** | ✅ FUSE | ✅ iptables+proxy | ✅ DNS proxy | ✅ LD_PRELOAD | N/A | ✅ seccomp |
| **macOS ESF+NE** | ✅ ESF AUTH | ✅ Network Ext | ✅ NE DNS | ✅ Spawn | N/A | ✅ ESF |
| **macOS FUSE-T** | ✅ FUSE-T | ✅ pf+proxy | ✅ DNS proxy | ⚠️ Partial | N/A | ❌ |
| **macOS + Lima** | ✅ FUSE | ✅ iptables+proxy | ✅ DNS proxy | ✅ LD_PRELOAD | N/A | ✅ seccomp |
| **Windows Native** | ✅ WinFsp | ✅ WinDivert | ✅ DNS proxy | ⚠️ Detours | ⚠️ Minifilter | ❌ |
| **Windows WSL2** | ✅ FUSE | ✅ iptables+proxy | ✅ DNS proxy | ✅ LD_PRELOAD | N/A | ✅ seccomp |

**Legend:** ✅ Full sync hold | ⚠️ Partial/requires driver | ❌ Not available | N/A Not applicable

#### 2.4.5 How Each Hold Mechanism Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Synchronous Hold Mechanisms by Type                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  FILE OPERATIONS (FUSE/WinFsp/ESF)                                          │
│  ├── Request arrives at FUSE handler                                        │
│  ├── Handler blocks (doesn't return)                                        │
│  ├── Policy engine evaluates → decision                                     │
│  ├── Handler returns result or redirects                                    │
│  └── Process resumes with result                                            │
│                                                                              │
│  NETWORK OPERATIONS (Transparent Proxy)                                      │
│  ├── iptables/pf/WinDivert redirects packets to proxy                       │
│  ├── Proxy accepts connection, holds before upstream connect                │
│  ├── Policy engine evaluates → decision                                     │
│  ├── Proxy connects to original or redirect target                          │
│  └── Data flows through proxy                                               │
│                                                                              │
│  DNS QUERIES (DNS Proxy)                                                     │
│  ├── DNS redirected to local resolver (port 53 → agentsh)                   │
│  ├── Resolver holds query                                                   │
│  ├── Policy engine evaluates → decision                                     │
│  ├── Return real IP, redirect IP, or NXDOMAIN                               │
│  └── Client receives response                                               │
│                                                                              │
│  ENVIRONMENT VARIABLES (LD_PRELOAD/DYLD/Detours)                            │
│  ├── getenv() call intercepted by shim                                      │
│  ├── Shim queries policy (local cache or IPC to daemon)                     │
│  ├── Return real value, fake value, or NULL                                 │
│  └── For spawn: filter env before exec()                                    │
│                                                                              │
│  REGISTRY (Windows Minifilter Driver)                                        │
│  ├── Registry operation triggers minifilter callback                        │
│  ├── Driver sends request to userspace daemon                               │
│  ├── Daemon evaluates policy → decision                                     │
│  ├── Driver allows, blocks, or modifies operation                           │
│  └── Application receives result                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 2.4.6 Interception Manager

```go
// pkg/intercept/manager.go

package intercept

import (
    "context"
    "sync"
    "time"
)

type InterceptionManager struct {
    mu              sync.RWMutex
    pendingOps      map[string]*InterceptedOperation
    policyEngine    PolicyEngine
    approvalService ApprovalService
    eventChan       chan<- IOEvent
    logger          *zap.Logger
    
    // Configuration
    defaultTimeout  time.Duration
    maxPending      int
}

func NewInterceptionManager(config InterceptionConfig) *InterceptionManager {
    return &InterceptionManager{
        pendingOps:     make(map[string]*InterceptedOperation),
        defaultTimeout: config.DefaultTimeout,
        maxPending:     config.MaxPendingOperations,
    }
}

// Intercept holds an operation and returns a decision
// This is the core synchronous interception point
func (m *InterceptionManager) Intercept(ctx context.Context, op *InterceptedOperation) DecisionResponse {
    // 1. Quick policy check for immediate decisions
    decision := m.policyEngine.Evaluate(op.Request)
    
    switch decision.Action {
    case DecisionAllow, DecisionDeny:
        // Immediate decision - no hold needed
        m.emitEvent(op, decision)
        return DecisionResponse{Decision: decision.Action}
        
    case DecisionRedirect:
        // Redirect - return immediately with new target
        m.emitEvent(op, decision)
        return DecisionResponse{
            Decision: DecisionRedirect,
            Redirect: decision.RedirectTarget,
        }
        
    case DecisionPending:
        // Requires manual approval - hold the operation
        return m.holdForApproval(ctx, op)
    }
    
    return DecisionResponse{Decision: DecisionAllow}
}

// holdForApproval blocks until approval received or timeout
func (m *InterceptionManager) holdForApproval(ctx context.Context, op *InterceptedOperation) DecisionResponse {
    // Create response channel
    op.responseCh = make(chan DecisionResponse, 1)
    op.HeldAt = time.Now()
    op.Decision = DecisionPending
    
    // Generate approval URL
    op.ID = generateOperationID()
    op.ApprovalURL = m.approvalService.CreateApprovalRequest(op)
    
    // Store pending operation
    m.mu.Lock()
    if len(m.pendingOps) >= m.maxPending {
        m.mu.Unlock()
        return DecisionResponse{Decision: DecisionDeny, Error: ErrTooManyPending}
    }
    m.pendingOps[op.ID] = op
    m.mu.Unlock()
    
    // Notify about pending approval
    m.emitPendingEvent(op)
    
    // Wait for decision
    timeout := op.Timeout
    if timeout == 0 {
        timeout = m.defaultTimeout
    }
    
    select {
    case response := <-op.responseCh:
        now := time.Now()
        op.DecidedAt = &now
        m.cleanup(op.ID)
        m.emitDecisionEvent(op, response)
        return response
        
    case <-time.After(timeout):
        m.cleanup(op.ID)
        response := DecisionResponse{Decision: DecisionTimeout}
        m.emitTimeoutEvent(op)
        return response
        
    case <-ctx.Done():
        m.cleanup(op.ID)
        return DecisionResponse{Decision: DecisionDeny, Error: ctx.Err()}
    }
}

// Approve handles an approval decision from the UI/API
func (m *InterceptionManager) Approve(opID string, approved bool, redirect *RedirectTarget, approvedBy string) error {
    m.mu.RLock()
    op, exists := m.pendingOps[opID]
    m.mu.RUnlock()
    
    if !exists {
        return ErrOperationNotFound
    }
    
    op.ApprovedBy = approvedBy
    
    response := DecisionResponse{}
    if approved {
        if redirect != nil {
            response.Decision = DecisionRedirect
            response.Redirect = redirect
        } else {
            response.Decision = DecisionAllow
        }
    } else {
        response.Decision = DecisionDeny
    }
    
    // Send response to waiting goroutine
    select {
    case op.responseCh <- response:
        return nil
    default:
        return ErrOperationAlreadyDecided
    }
}

func (m *InterceptionManager) cleanup(opID string) {
    m.mu.Lock()
    delete(m.pendingOps, opID)
    m.mu.Unlock()
}
```

#### 2.4.7 FUSE Integration for File Redirect

```go
// pkg/platform/fuse_redirect.go

// Open handles file open with redirect support
func (fs *AgentFS) Open(path string, flags int) (int, uint64) {
    ctx := context.Background()
    
    op := &InterceptedOperation{
        Type: EventFileOpen,
        Request: OperationRequest{
            Path:      path,
            Operation: "open",
            Flags:     flags,
            PID:       fuse.GetContext().Pid,
        },
    }
    
    // Synchronously wait for decision
    response := fs.interceptor.Intercept(ctx, op)
    
    switch response.Decision {
    case DecisionAllow:
        // Open the original file
        return fs.openReal(path, flags)
        
    case DecisionDeny:
        return -fuse.EACCES, 0
        
    case DecisionRedirect:
        // Open the redirect target instead
        redirectPath := response.Redirect.FilePath
        fs.logger.Info("Redirecting file access",
            zap.String("original", path),
            zap.String("redirect", redirectPath),
        )
        return fs.openReal(redirectPath, flags)
        
    case DecisionTimeout:
        // Approval timed out - default deny
        return -fuse.ETIMEDOUT, 0
        
    default:
        return -fuse.EIO, 0
    }
}
```

#### 2.4.8 Network Redirect via Transparent Proxy

```go
// pkg/network/proxy_redirect.go

func (p *TransparentProxy) handleConnection(clientConn net.Conn) {
    // Get original destination
    origDst := getOriginalDest(clientConn)
    
    op := &InterceptedOperation{
        Type: EventNetConnect,
        Request: OperationRequest{
            RemoteAddr: origDst.IP.String(),
            RemotePort: origDst.Port,
            Protocol:   "tcp",
        },
    }
    
    response := p.interceptor.Intercept(context.Background(), op)
    
    switch response.Decision {
    case DecisionAllow:
        // Connect to original destination
        p.proxyTo(clientConn, origDst)
        
    case DecisionDeny:
        clientConn.Close()
        
    case DecisionRedirect:
        // Connect to redirect target
        redirectAddr := net.JoinHostPort(
            response.Redirect.Host,
            strconv.Itoa(response.Redirect.Port),
        )
        p.logger.Info("Redirecting connection",
            zap.String("original", origDst.String()),
            zap.String("redirect", redirectAddr),
        )
        p.proxyToAddr(clientConn, redirectAddr)
    }
}
```

#### 2.4.9 DNS Redirect

```go
// pkg/network/dns_redirect.go

func (d *DNSProxy) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
    question := r.Question[0]
    
    op := &InterceptedOperation{
        Type: EventDNSQuery,
        Request: OperationRequest{
            Domain:    question.Name,
            QueryType: dns.TypeToString[question.Qtype],
        },
    }
    
    response := d.interceptor.Intercept(context.Background(), op)
    
    switch response.Decision {
    case DecisionAllow:
        // Forward to upstream DNS
        d.forwardQuery(w, r)
        
    case DecisionDeny:
        // Return NXDOMAIN
        d.respondNXDOMAIN(w, r)
        
    case DecisionRedirect:
        // Return fake IP address
        d.logger.Info("Redirecting DNS",
            zap.String("domain", question.Name),
            zap.String("redirect_ip", response.Redirect.IPAddress),
        )
        d.respondWithIP(w, r, response.Redirect.IPAddress)
    }
}
```

#### 2.4.10 Environment Variable Interception with Hold

The LD_PRELOAD shim can synchronously hold getenv() calls while waiting for policy decisions. This enables redirect (return fake value) and approval workflows.

```c
// shim/linux/envshim_sync.c
// Synchronous getenv interception with IPC to daemon

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#define AGENTSH_SOCKET "/tmp/agentsh-env.sock"
#define RESPONSE_TIMEOUT_MS 5000

static char* (*original_getenv)(const char*) = NULL;
static int daemon_socket = -1;
static pthread_mutex_t socket_mutex = PTHREAD_MUTEX_INITIALIZER;

// Response from daemon
typedef struct {
    int decision;        // 0=allow, 1=deny, 2=redirect
    char redirect_value[4096];
} EnvResponse;

// Query daemon for decision - BLOCKS until response
static EnvResponse query_daemon(const char* varname) {
    EnvResponse resp = {0, ""};
    
    pthread_mutex_lock(&socket_mutex);
    
    if (daemon_socket < 0) {
        // Reconnect if needed
        daemon_socket = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, AGENTSH_SOCKET, sizeof(addr.sun_path) - 1);
        
        if (connect(daemon_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(daemon_socket);
            daemon_socket = -1;
            pthread_mutex_unlock(&socket_mutex);
            resp.decision = 0; // Allow on failure
            return resp;
        }
    }
    
    // Send request
    char request[512];
    snprintf(request, sizeof(request), 
        "{\"op\":\"env_read\",\"var\":\"%s\",\"pid\":%d}", 
        varname, getpid());
    
    if (send(daemon_socket, request, strlen(request), 0) < 0) {
        pthread_mutex_unlock(&socket_mutex);
        resp.decision = 0;
        return resp;
    }
    
    // Wait for response (BLOCKING)
    char response_buf[8192];
    struct timeval tv = {RESPONSE_TIMEOUT_MS / 1000, (RESPONSE_TIMEOUT_MS % 1000) * 1000};
    setsockopt(daemon_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int n = recv(daemon_socket, response_buf, sizeof(response_buf) - 1, 0);
    if (n > 0) {
        response_buf[n] = '\0';
        // Parse JSON response
        // {"decision":"allow|deny|redirect","value":"..."}
        if (strstr(response_buf, "\"deny\"")) {
            resp.decision = 1;
        } else if (strstr(response_buf, "\"redirect\"")) {
            resp.decision = 2;
            // Extract redirect value
            char* val = strstr(response_buf, "\"value\":\"");
            if (val) {
                val += 9;
                char* end = strchr(val, '"');
                if (end) {
                    size_t len = end - val;
                    if (len < sizeof(resp.redirect_value)) {
                        strncpy(resp.redirect_value, val, len);
                    }
                }
            }
        }
    }
    
    pthread_mutex_unlock(&socket_mutex);
    return resp;
}

// Intercepted getenv - can HOLD, BLOCK, or REDIRECT
char* getenv(const char* name) {
    if (!name) return NULL;
    
    // Query daemon - this BLOCKS until decision
    EnvResponse resp = query_daemon(name);
    
    switch (resp.decision) {
    case 0: // Allow
        return original_getenv(name);
        
    case 1: // Deny
        return NULL;
        
    case 2: // Redirect - return fake value
        // Store in thread-local to avoid memory issues
        static __thread char redirect_buf[4096];
        strncpy(redirect_buf, resp.redirect_value, sizeof(redirect_buf) - 1);
        return redirect_buf;
    }
    
    return original_getenv(name);
}
```

#### 2.4.11 Windows Registry Interception

Registry synchronous interception requires a kernel-mode minifilter driver. The driver communicates with the userspace daemon for policy decisions.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   Windows Registry Minifilter Architecture                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  User Mode                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  agentsh daemon                                                      │    │
│  │  ├── Policy Engine                                                   │    │
│  │  ├── Approval Service                                                │    │
│  │  └── Filter Port Listener ◄──── Decision requests from driver       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                               │
│                              │ FltSendMessage / FltGetMessage               │
│                              │                                               │
│  ────────────────────────────┼──────────────────────────────────────────    │
│  Kernel Mode                 │                                               │
│                              ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  agentsh-regflt.sys (Registry Minifilter)                           │    │
│  │  ├── CmRegisterCallbackEx() - Registry callback registration        │    │
│  │  ├── Pre-operation callbacks (HOLD operation)                       │    │
│  │  ├── Filter communication port                                      │    │
│  │  └── Post-operation callbacks (logging)                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                               │
│                              ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Windows Registry                                                    │    │
│  │  HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, etc.                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

```c
// driver/regflt/regflt.c (Kernel mode - simplified)
// Windows Registry Minifilter Driver

#include <ntddk.h>
#include <wdm.h>

// Registry callback - called for ALL registry operations
NTSTATUS RegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,  // REG_NOTIFY_CLASS
    PVOID Argument2   // Operation-specific data
) {
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    
    // Only intercept pre-operation events (can block/redirect)
    switch (notifyClass) {
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = Argument2;
        
        // Build request for userspace
        REGISTRY_REQUEST request = {0};
        request.Operation = REG_OP_WRITE;
        request.ProcessId = PsGetCurrentProcessId();
        CopyKeyName(&request.KeyPath, info->Object);
        CopyValueName(&request.ValueName, info->ValueName);
        
        // Send to userspace daemon - BLOCKS HERE
        REGISTRY_RESPONSE response;
        NTSTATUS status = SendToUserspace(&request, &response);
        
        if (NT_SUCCESS(status)) {
            switch (response.Decision) {
            case DECISION_ALLOW:
                return STATUS_SUCCESS;
                
            case DECISION_DENY:
                return STATUS_ACCESS_DENIED;
                
            case DECISION_REDIRECT:
                // Modify the value being written
                if (response.RedirectValueSize > 0) {
                    info->Data = response.RedirectValue;
                    info->DataSize = response.RedirectValueSize;
                }
                return STATUS_SUCCESS;
            }
        }
        break;
    }
    
    case RegNtPreQueryValueKey: {
        PREG_QUERY_VALUE_KEY_INFORMATION info = Argument2;
        
        // Similar handling for reads
        // Can redirect to return fake value
        break;
    }
    
    case RegNtPreDeleteKey:
    case RegNtPreDeleteValueKey:
        // Require approval for destructive operations
        break;
    }
    
    return STATUS_SUCCESS;
}

// Send request to userspace and wait for response
NTSTATUS SendToUserspace(
    PREGISTRY_REQUEST Request,
    PREGISTRY_RESPONSE Response
) {
    LARGE_INTEGER timeout;
    timeout.QuadPart = -50000000LL; // 5 seconds
    
    // Send via filter communication port
    return FltSendMessage(
        g_FilterHandle,
        &g_ClientPort,
        Request,
        sizeof(REGISTRY_REQUEST),
        Response,
        sizeof(REGISTRY_RESPONSE),
        &timeout
    );
}
```

```go
// pkg/platform/windows_registry_intercept.go
// +build windows

package platform

import (
    "context"
    "encoding/binary"
    "syscall"
    "unsafe"
)

// RegistryInterceptor handles registry operation interception
type RegistryInterceptor struct {
    interceptor *InterceptionManager
    filterPort  syscall.Handle
    logger      *zap.Logger
}

// RegistryRequest from kernel driver
type RegistryRequest struct {
    Operation   uint32
    ProcessID   uint32
    KeyPath     [512]uint16
    ValueName   [256]uint16
    DataType    uint32
    DataSize    uint32
    Data        [4096]byte
}

// RegistryResponse to kernel driver
type RegistryResponse struct {
    Decision          uint32
    RedirectValueSize uint32
    RedirectValue     [4096]byte
}

const (
    RegOpRead   = 1
    RegOpWrite  = 2
    RegOpCreate = 3
    RegOpDelete = 4
)

// ListenForRequests handles requests from kernel driver
func (r *RegistryInterceptor) ListenForRequests(ctx context.Context) error {
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }
        
        // Wait for message from driver
        var request RegistryRequest
        var response RegistryResponse
        
        err := r.getMessage(&request)
        if err != nil {
            continue
        }
        
        // Convert to InterceptedOperation
        op := &InterceptedOperation{
            Type: r.eventType(request.Operation),
            Request: OperationRequest{
                Path:        syscall.UTF16ToString(request.KeyPath[:]),
                Variable:    syscall.UTF16ToString(request.ValueName[:]),
                Operation:   r.opName(request.Operation),
                PID:         int(request.ProcessID),
            },
        }
        
        // Get decision - may BLOCK for approval
        decision := r.interceptor.Intercept(ctx, op)
        
        // Convert to driver response
        response.Decision = r.decisionToDriver(decision.Decision)
        if decision.Redirect != nil && decision.Redirect.Value != "" {
            // Copy redirect value for registry
            copy(response.RedirectValue[:], []byte(decision.Redirect.Value))
            response.RedirectValueSize = uint32(len(decision.Redirect.Value))
        }
        
        // Send response to driver
        r.sendMessage(&response)
    }
}

func (r *RegistryInterceptor) decisionToDriver(d Decision) uint32 {
    switch d {
    case DecisionAllow:
        return 0
    case DecisionDeny:
        return 1
    case DecisionRedirect:
        return 2
    default:
        return 1 // Deny on error
    }
}
```

**Note:** The registry minifilter driver requires:
- Windows Driver Kit (WDK) for building
- Code signing certificate (EV cert for production)
- Driver installation via `sc create` or INF file
- This is why registry blocking shows as ⚠️ in the platform matrix

### 2.5 Event Emission

```go
// EnvEvent represents an environment variable access event
type EnvEvent struct {
    IOEvent
    Variable    string      `json:"variable"`              // Variable name (or "*" for list)
    Value       string      `json:"value,omitempty"`       // Value (redacted for sensitive)
    OldValue    string      `json:"old_value,omitempty"`   // Previous value (for write)
    Operation   EnvOperation `json:"operation"`
    Sensitive   bool        `json:"sensitive"`             // Matched sensitive pattern
    Blocked     bool        `json:"blocked"`               // Was access blocked
    Source      string      `json:"source"`                // "shim", "spawn", "policy"
}

type EnvOperation string

const (
    EnvOpRead   EnvOperation = "read"      // getenv()
    EnvOpList   EnvOperation = "list"      // environ enumeration
    EnvOpWrite  EnvOperation = "write"     // setenv()
    EnvOpDelete EnvOperation = "delete"    // unsetenv()
)

// EnvEventMetadata for embedding in IOEvent.Metadata
type EnvEventMetadata struct {
    Variable      string   `json:"variable"`
    Operation     string   `json:"operation"`
    Sensitive     bool     `json:"sensitive"`
    Blocked       bool     `json:"blocked"`
    MatchedPolicy string   `json:"matched_policy,omitempty"`  // Which rule matched
    ValueRedacted bool     `json:"value_redacted,omitempty"`  // Was value hidden
    ListCount     int      `json:"list_count,omitempty"`      // For list: number of vars enumerated
    ListBlocked   int      `json:"list_blocked,omitempty"`    // For list: number blocked
}
```

---

## 3. Linux Implementation (Reference)

Linux is the reference implementation with full security capabilities.

### 3.1 Capabilities

```go
// pkg/platform/linux.go
// +build linux

func (p *LinuxPlatform) Capabilities() Capabilities {
    return Capabilities{
        // Filesystem
        HasFUSE:              true,
        FUSEImplementation:   p.detectFUSEVersion(), // "fuse2" or "fuse3"
        
        // Network
        HasNetworkIntercept:  true,
        NetworkImplementation: "iptables",
        CanRedirectTraffic:   true,
        CanInspectTLS:        true,
        
        // Isolation
        HasMountNamespace:    true,
        HasNetworkNamespace:  true,
        HasPIDNamespace:      true,
        HasUserNamespace:     p.checkUserNS(),
        IsolationLevel:       IsolationFull,
        
        // Syscall filtering
        HasSeccomp:           p.checkSeccomp(),
        
        // Resource control
        HasCgroups:           p.checkCgroups(),
        CanLimitCPU:          true,
        CanLimitMemory:       true,
        CanLimitDiskIO:       true,
        CanLimitNetworkBW:    true,
        CanLimitProcessCount: true,
    }
}
```

### 3.2 Component Implementations

```go
// Filesystem: go-fuse or cgofuse with FUSE3
type LinuxFilesystem struct {
    server *fuse.Server
    root   *AgentFS
}

func (fs *LinuxFilesystem) Mount(config FSConfig) (FSMount, error) {
    opts := &fuse.MountOptions{
        AllowOther:   true,
        FsName:       "agentfs",
        MaxReadAhead: 128 * 1024,
    }
    
    root := NewAgentFS(config.SourcePath, config.PolicyEngine, config.EventChannel)
    server, err := fuse.Mount(config.MountPoint, root, opts)
    if err != nil {
        return nil, err
    }
    
    return &linuxFSMount{server: server, path: config.MountPoint}, nil
}

// Network: iptables + transparent proxy
type LinuxNetwork struct {
    proxyPort int
    dnsPort   int
    rules     []iptablesRule
}

func (n *LinuxNetwork) Setup(config NetConfig) error {
    // Create network namespace if needed
    // Set up iptables REDIRECT rules
    // Start transparent proxy
    
    rules := []string{
        fmt.Sprintf("-t nat -A OUTPUT -p tcp -j REDIRECT --to-ports %d", config.ProxyPort),
        fmt.Sprintf("-t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports %d", config.DNSPort),
    }
    
    for _, rule := range rules {
        if err := exec.Command("iptables", strings.Split(rule, " ")...).Run(); err != nil {
            return err
        }
    }
    
    return nil
}

// Sandbox: Linux namespaces + seccomp
type LinuxSandbox struct {
    pid       int
    namespace *Namespace
    cgroup    *Cgroup
    seccomp   *SeccompFilter
}

func (m *LinuxSandboxManager) Create(config SandboxConfig) (Sandbox, error) {
    // Create namespaces
    ns, err := createNamespaces(
        CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWUTS,
    )
    if err != nil {
        return nil, err
    }
    
    // Set up cgroup
    cg, err := createCgroup(config.Name)
    if err != nil {
        ns.Close()
        return nil, err
    }
    
    // Create seccomp filter
    filter, err := createSeccompFilter(config.Capabilities)
    if err != nil {
        cg.Close()
        ns.Close()
        return nil, err
    }
    
    return &LinuxSandbox{
        namespace: ns,
        cgroup:    cg,
        seccomp:   filter,
    }, nil
}

// Resources: cgroups v2
type LinuxResources struct {
    cgroupPath string
}

func (r *LinuxResources) Apply(config ResourceConfig) (ResourceHandle, error) {
    // Write to cgroup controllers
    if config.MaxMemoryMB > 0 {
        writeCgroup("memory.max", fmt.Sprintf("%d", config.MaxMemoryMB*1024*1024))
    }
    if config.MaxCPUPercent > 0 {
        // cpu.max format: "$MAX $PERIOD" e.g., "50000 100000" for 50%
        period := 100000
        max := (int(config.MaxCPUPercent) * period) / 100
        writeCgroup("cpu.max", fmt.Sprintf("%d %d", max, period))
    }
    if config.MaxProcesses > 0 {
        writeCgroup("pids.max", fmt.Sprintf("%d", config.MaxProcesses))
    }
    // io.max for disk limits
    // net.bw_limit for network (if available)
    
    return &linuxResourceHandle{path: r.cgroupPath}, nil
}
```

---

## 4. macOS Implementation

### 4.1 Overview

macOS has limited native security primitives compared to Linux, but offers several approaches with different trade-offs:

| Approach | Permissions Required | Blocking | Apple Approval |
|----------|---------------------|----------|----------------|
| **Endpoint Security + Network Extension** | Entitlements | ✅ Full | Required |
| **FUSE-T + pf** | Root for pf | ✅ Full | Not required |
| **FSEvents + pcap** | Optional root | ❌ Observe only | Not required |

**Note:** macFUSE is not supported due to its kernel extension requirement. Apple has deprecated kexts and they require special approval in System Settings, making deployment unreliable.

### 4.2 Filesystem Interception Options

#### 4.2.1 Option 1: FUSE-T (Recommended)

**FUSE-T** is a modern FUSE implementation that uses NFSv4 instead of a kernel extension. This is the recommended approach because:

| Advantage | Description |
|-----------|-------------|
| No kernel extension | Uses macOS built-in NFS client |
| No security approval | Works without System Preferences approval |
| Apple Silicon native | Full support without reduced security mode |
| Future-proof | Not affected by Apple's kext deprecation |
| Easy installation | `brew install fuse-t` |

```go
// pkg/platform/darwin_fuset.go
// +build darwin

package platform

import (
    "fmt"
    "os"
    "os/exec"
    
    "github.com/winfsp/cgofuse/fuse"
    "go.uber.org/zap"
)

// FuseTFilesystem implements filesystem interception via FUSE-T
type FuseTFilesystem struct {
    available bool
    version   string
    logger    *zap.Logger
}

func NewFuseTFilesystem(logger *zap.Logger) *FuseTFilesystem {
    fs := &FuseTFilesystem{logger: logger}
    fs.available, fs.version = fs.checkFuseT()
    return fs
}

func (fs *FuseTFilesystem) checkFuseT() (bool, string) {
    // Check for FUSE-T installation
    paths := []string{
        "/usr/local/lib/libfuse-t.dylib",
        "/opt/homebrew/lib/libfuse-t.dylib",
        "/Library/Frameworks/FUSE-T.framework",
    }
    
    for _, path := range paths {
        if _, err := os.Stat(path); err == nil {
            // Get version
            cmd := exec.Command("fuse-t", "--version")
            if output, err := cmd.Output(); err == nil {
                return true, string(output)
            }
            return true, "installed"
        }
    }
    return false, ""
}

func (fs *FuseTFilesystem) Available() bool {
    return fs.available
}

func (fs *FuseTFilesystem) Implementation() string {
    return "fuse-t"
}

func (fs *FuseTFilesystem) Mount(config FSConfig) (FSMount, error) {
    if !fs.available {
        return nil, fmt.Errorf("FUSE-T not installed. Install via: brew install fuse-t")
    }
    
    fs.logger.Info("Using FUSE-T for file interception",
        zap.String("version", fs.version),
        zap.String("mount_point", config.MountPoint),
        zap.Bool("can_block", true),
        zap.String("backend", "NFSv4"),
    )
    
    // Create FUSE filesystem using cgofuse
    // cgofuse works with FUSE-T when FUSE-T's libfuse compatibility layer is used
    agentFS := &DarwinAgentFS{
        rootPath:     config.SourcePath,
        policyEngine: config.PolicyEngine,
        eventChan:    config.EventChannel,
    }
    
    host := fuse.NewFileSystemHost(agentFS)
    
    // FUSE-T specific mount options
    opts := []string{
        "-o", "local",
        "-o", "volname=agentsh",
        "-o", "noappledouble",
        "-o", "noapplexattr",
        "-o", "defer_permissions",  // Let our FUSE handle permissions
    }
    
    // Set FUSE-T library path
    os.Setenv("FUSE_LIBRARY_PATH", getFuseTLibPath())
    
    go func() {
        if !host.Mount(config.MountPoint, opts) {
            config.EventChannel <- IOEvent{
                Type:     EventFileOpen,
                Error:    "FUSE-T mount failed",
                Decision: DecisionError,
                Platform: "darwin-fuse-t",
            }
        }
    }()
    
    return &fuseTMount{
        host: host,
        path: config.MountPoint,
    }, nil
}

func getFuseTLibPath() string {
    // Check Homebrew locations
    paths := []string{
        "/opt/homebrew/lib/libfuse-t.dylib",  // Apple Silicon
        "/usr/local/lib/libfuse-t.dylib",      // Intel
    }
    for _, p := range paths {
        if _, err := os.Stat(p); err == nil {
            return p
        }
    }
    return ""
}

type fuseTMount struct {
    host *fuse.FileSystemHost
    path string
}

func (m *fuseTMount) Path() string   { return m.path }
func (m *fuseTMount) Stats() FSStats { return FSStats{} }
func (m *fuseTMount) Close() error   { m.host.Unmount(); return nil }
```

#### 4.2.2 Option 2: Endpoint Security Framework (Enterprise)

The **Endpoint Security Framework (ESF)** is Apple's official API for security tools. It provides the most comprehensive monitoring and blocking capabilities, but requires Apple-approved entitlements.

**Capabilities:**
- File operations: open, close, create, delete, rename, write, truncate, link, unlink
- Process operations: exec, fork, exit, signal
- Network operations: (limited, use Network Extension for full coverage)
- Kernel events: kext load, iokit open, mmap, mount, remount

**Requirements:**
- macOS 10.15 (Catalina) or later
- `com.apple.developer.endpoint-security.client` entitlement
- Must be approved by Apple (requires business justification)
- App must be notarized

```go
// pkg/platform/darwin_endpointsecurity.go
// +build darwin

package platform

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework EndpointSecurity
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

extern void esEventCallback(es_client_t *client, const es_message_t *msg);
*/
import "C"

import (
    "fmt"
    "sync"
    "unsafe"
    
    "go.uber.org/zap"
)

// EndpointSecurityMonitor provides comprehensive system monitoring via ESF
type EndpointSecurityMonitor struct {
    client       unsafe.Pointer // es_client_t*
    policyEngine PolicyEngine
    eventChan    chan<- IOEvent
    logger       *zap.Logger
    
    mu           sync.RWMutex
    running      bool
}

func NewEndpointSecurityMonitor(policyEngine PolicyEngine, eventChan chan<- IOEvent, logger *zap.Logger) (*EndpointSecurityMonitor, error) {
    monitor := &EndpointSecurityMonitor{
        policyEngine: policyEngine,
        eventChan:    eventChan,
        logger:       logger,
    }
    
    // Check if we have the entitlement
    if !checkESFEntitlement() {
        return nil, fmt.Errorf("Endpoint Security entitlement not available. " +
            "This requires com.apple.developer.endpoint-security.client entitlement from Apple")
    }
    
    return monitor, nil
}

func checkESFEntitlement() bool {
    // Check if running with ES entitlement
    cmd := exec.Command("codesign", "-d", "--entitlements", "-", os.Args[0])
    output, err := cmd.Output()
    if err != nil {
        return false
    }
    return strings.Contains(string(output), "endpoint-security.client")
}

func (m *EndpointSecurityMonitor) Start() error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    if m.running {
        return nil
    }
    
    // Create ES client
    var client C.es_client_t
    result := C.es_new_client(&client, (*[0]byte)(C.esEventCallback))
    
    if result != C.ES_NEW_CLIENT_RESULT_SUCCESS {
        return fmt.Errorf("failed to create ES client: %d", result)
    }
    
    m.client = unsafe.Pointer(client)
    
    // Subscribe to events
    events := []C.es_event_type_t{
        // File events
        C.ES_EVENT_TYPE_AUTH_OPEN,
        C.ES_EVENT_TYPE_AUTH_CREATE,
        C.ES_EVENT_TYPE_AUTH_UNLINK,
        C.ES_EVENT_TYPE_AUTH_RENAME,
        C.ES_EVENT_TYPE_AUTH_TRUNCATE,
        C.ES_EVENT_TYPE_AUTH_LINK,
        C.ES_EVENT_TYPE_AUTH_WRITE,
        
        // Process events
        C.ES_EVENT_TYPE_AUTH_EXEC,
        C.ES_EVENT_TYPE_NOTIFY_FORK,
        C.ES_EVENT_TYPE_NOTIFY_EXIT,
        
        // Mount events
        C.ES_EVENT_TYPE_AUTH_MOUNT,
        C.ES_EVENT_TYPE_AUTH_REMOUNT,
    }
    
    result = C.es_subscribe(client, &events[0], C.uint32_t(len(events)))
    if result != C.ES_RETURN_SUCCESS {
        C.es_delete_client(client)
        return fmt.Errorf("failed to subscribe to events: %d", result)
    }
    
    m.running = true
    m.logger.Info("Endpoint Security monitoring started",
        zap.Int("subscribed_events", len(events)),
    )
    
    return nil
}

func (m *EndpointSecurityMonitor) Stop() error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    if !m.running {
        return nil
    }
    
    if m.client != nil {
        C.es_unsubscribe_all((*C.es_client_t)(m.client))
        C.es_delete_client((*C.es_client_t)(m.client))
        m.client = nil
    }
    
    m.running = false
    return nil
}

// Callback from C - handles ES events
//export esEventCallback
func esEventCallback(client *C.es_client_t, msg *C.es_message_t) {
    // Get the global monitor instance
    monitor := getGlobalESMonitor()
    if monitor == nil {
        // Allow by default if monitor not ready
        C.es_respond_auth_result(client, msg, C.ES_AUTH_RESULT_ALLOW, false)
        return
    }
    
    event := monitor.convertESEvent(msg)
    
    // Check policy for AUTH events
    if msg.action_type == C.ES_ACTION_TYPE_AUTH {
        decision := monitor.policyEngine.CheckFileAccess(event.Path, event.Operation)
        event.Decision = decision
        
        var result C.es_auth_result_t
        if decision == DecisionAllow {
            result = C.ES_AUTH_RESULT_ALLOW
        } else {
            result = C.ES_AUTH_RESULT_DENY
        }
        
        C.es_respond_auth_result(client, msg, result, false)
    }
    
    // Send event to channel
    monitor.eventChan <- event
}

func (m *EndpointSecurityMonitor) convertESEvent(msg *C.es_message_t) IOEvent {
    event := IOEvent{
        Timestamp: time.Now(),
        Platform:  "darwin-endpoint-security",
        Decision:  DecisionAllow,
    }
    
    switch msg.event_type {
    case C.ES_EVENT_TYPE_AUTH_OPEN:
        event.Type = EventFileOpen
        event.Path = C.GoString(msg.event.open.file.path.data)
        
    case C.ES_EVENT_TYPE_AUTH_CREATE:
        event.Type = EventFileCreate
        event.Operation = OpCreate
        // Extract path from create event
        
    case C.ES_EVENT_TYPE_AUTH_UNLINK:
        event.Type = EventFileDelete
        event.Operation = OpDelete
        
    case C.ES_EVENT_TYPE_AUTH_EXEC:
        event.Type = EventProcessExec
        // Extract exec details
        
    // ... handle other event types
    }
    
    event.Metadata = map[string]any{
        "source":     "endpoint-security",
        "can_block":  true,
        "auth_event": msg.action_type == C.ES_ACTION_TYPE_AUTH,
    }
    
    return event
}
```

**Endpoint Security Event Types:**

| Category | AUTH Events (can block) | NOTIFY Events (observe) |
|----------|------------------------|-------------------------|
| **File** | OPEN, CREATE, UNLINK, RENAME, TRUNCATE, LINK, WRITE, CLONE, EXCHANGEDATA | CLOSE, ACCESS, CHDIR, CHROOT, READDIR, READLINK, STAT |
| **Process** | EXEC, SIGNAL | FORK, EXIT |
| **System** | MOUNT, REMOUNT, IOKIT_OPEN, KEXT_LOAD | MMAP, MPROTECT |

### 4.3 Network Interception Options

#### 4.3.1 Option 1: Network Extension Framework (Premium)

**Network Extension** provides deep network control but requires entitlements:

| Provider Type | Capability | Entitlement Required |
|--------------|------------|---------------------|
| **Content Filter** | Inspect/block flows | `com.apple.developer.networking.networkextension` |
| **Transparent Proxy** | Full traffic interception | Same + proxy entitlement |
| **DNS Proxy** | DNS query interception | Same + DNS entitlement |
| **App Proxy** | Per-app traffic routing | Same |

```go
// pkg/platform/darwin_networkextension.go
// +build darwin

package platform

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework NetworkExtension
#include <NetworkExtension/NetworkExtension.h>
*/
import "C"

import (
    "fmt"
    
    "go.uber.org/zap"
)

// NetworkExtensionProvider provides network interception via NE framework
type NetworkExtensionProvider struct {
    providerType NEProviderType
    logger       *zap.Logger
    available    bool
}

type NEProviderType int

const (
    NEContentFilter NEProviderType = iota
    NETransparentProxy
    NEDNSProxy
    NEAppProxy
)

func NewNetworkExtensionProvider(providerType NEProviderType, logger *zap.Logger) (*NetworkExtensionProvider, error) {
    provider := &NetworkExtensionProvider{
        providerType: providerType,
        logger:       logger,
    }
    
    // Check entitlements
    if !provider.checkEntitlements() {
        return nil, fmt.Errorf("Network Extension entitlements not available. " +
            "Requires com.apple.developer.networking.networkextension from Apple")
    }
    
    provider.available = true
    return provider, nil
}

func (p *NetworkExtensionProvider) checkEntitlements() bool {
    cmd := exec.Command("codesign", "-d", "--entitlements", "-", os.Args[0])
    output, err := cmd.Output()
    if err != nil {
        return false
    }
    return strings.Contains(string(output), "networking.networkextension")
}

func (p *NetworkExtensionProvider) Available() bool {
    return p.available
}

func (p *NetworkExtensionProvider) Implementation() string {
    switch p.providerType {
    case NEContentFilter:
        return "network-extension-content-filter"
    case NETransparentProxy:
        return "network-extension-transparent-proxy"
    case NEDNSProxy:
        return "network-extension-dns-proxy"
    default:
        return "network-extension"
    }
}
```

**Network Extension Capabilities:**

| Feature | Content Filter | Transparent Proxy | DNS Proxy |
|---------|---------------|-------------------|-----------|
| Inspect TCP | ✅ | ✅ | ❌ |
| Inspect UDP | ✅ | ✅ | ✅ DNS only |
| Block connections | ✅ | ✅ | ✅ |
| Modify traffic | ❌ | ✅ | ✅ |
| TLS inspection | ❌ | ✅ With MITM | ❌ |
| Per-app filtering | ✅ | ✅ | ❌ |

#### 4.3.2 Option 2: pf (Packet Filter) - No Entitlements Required

pf is always available and requires only root access:

```go
// pkg/platform/darwin_pf.go
// +build darwin

package platform

type PFNetwork struct {
    anchorName string
    proxyPort  int
    dnsPort    int
    enabled    bool
    logger     *zap.Logger
}

func NewPFNetwork(logger *zap.Logger) *PFNetwork {
    return &PFNetwork{
        anchorName: "com.agentsh",
        logger:     logger,
    }
}

func (n *PFNetwork) Available() bool {
    // pf is always available, but requires root to use
    return os.Geteuid() == 0
}

func (n *PFNetwork) Implementation() string {
    return "pf"
}

func (n *PFNetwork) Setup(config NetConfig) error {
    if os.Geteuid() != 0 {
        return fmt.Errorf("pf requires root access. Run with: sudo agentsh server")
    }
    
    n.proxyPort = config.ProxyPort
    n.dnsPort = config.DNSPort
    
    n.logger.Info("Setting up pf network interception",
        zap.Int("proxy_port", n.proxyPort),
        zap.Int("dns_port", n.dnsPort),
    )
    
    rules := n.generatePFRules()
    
    // Write rules to temp file
    rulesFile := "/tmp/agentsh-pf.rules"
    if err := os.WriteFile(rulesFile, []byte(rules), 0600); err != nil {
        return err
    }
    
    // Load rules
    cmds := [][]string{
        {"pfctl", "-a", n.anchorName, "-f", rulesFile},
        {"pfctl", "-e"}, // Enable pf if not already
    }
    
    for _, cmd := range cmds {
        if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
            if cmd[1] != "-e" { // Ignore "already enabled" error
                return fmt.Errorf("failed to execute %v: %w", cmd, err)
            }
        }
    }
    
    n.enabled = true
    return nil
}

func (n *PFNetwork) generatePFRules() string {
    return fmt.Sprintf(`
# agentsh network interception rules

# Redirect outbound TCP to transparent proxy
rdr pass on lo0 proto tcp from any to any port 1:65535 -> 127.0.0.1 port %d

# Redirect DNS to DNS proxy  
rdr pass on lo0 proto udp from any to any port 53 -> 127.0.0.1 port %d

# Required for rdr to work
pass out quick on lo0 all
`, n.proxyPort, n.dnsPort)
}

func (n *PFNetwork) Teardown() error {
    if !n.enabled {
        return nil
    }
    return exec.Command("pfctl", "-a", n.anchorName, "-F", "all").Run()
}
```

### 4.4 Graceful Degradation System

agentsh automatically detects available permissions and enables the best possible feature set.

#### 4.4.1 Permission Tiers (Updated)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     macOS Permission Tiers                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Tier 0: Enterprise (Apple Entitlements)                                 │
│  ├── Endpoint Security entitlement                                       │
│  ├── Network Extension entitlement                                       │
│  └── Full Disk Access                                                    │
│  Features: Complete system monitoring + blocking (like EDR products)     │
│  Security: ★★★★★ 95%                                                     │
│                                                                          │
│  Tier 1: Full (FUSE-T + pf)                                              │
│  ├── FUSE-T installed (no kext needed)                                   │
│  ├── Root/sudo access for pf                                             │
│  └── Full Disk Access (recommended)                                      │
│  Features: FUSE file interception + pf network + Full monitoring         │
│  Security: ★★★★ 75%                                                      │
│                                                                          │
│  Tier 2: Network Only (No FUSE)                                          │
│  ├── Root/sudo access for pf                                             │
│  └── FSEvents for file monitoring (observation only)                     │
│  Features: Network blocking + File observation                           │
│  Security: ★★★ 50%                                                       │
│                                                                          │
│  Tier 3: Monitor Only (No root)                                          │
│  ├── FSEvents for file changes                                           │
│  └── libpcap for network (if available)                                  │
│  Features: Observation only, no policy enforcement                       │
│  Security: ★★ 25%                                                        │
│                                                                          │
│  Tier 4: Minimal (No special permissions)                                │
│  └── Process-level monitoring only                                       │
│  Features: Command execution logging                                     │
│  Security: ★ 10%                                                         │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 4.4.2 Feature Availability by Tier

| Feature | Tier 0 (Enterprise) | Tier 1 (FUSE-T) | Tier 2 (Network) | Tier 3 (Monitor) | Tier 4 (Minimal) |
|---------|:------------------:|:---------------:|:----------------:|:----------------:|:----------------:|
| **File Operations** |
| Read interception | ✅ Block (ESF) | ✅ Block (FUSE) | ⚠️ Observe | ⚠️ Observe | ❌ |
| Write interception | ✅ Block (ESF) | ✅ Block (FUSE) | ⚠️ Observe | ⚠️ Observe | ❌ |
| Create/Delete | ✅ Block | ✅ Block | ⚠️ Observe | ⚠️ Observe | ❌ |
| Policy enforcement | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Network** |
| TCP interception | ✅ Block (NE) | ✅ Block (pf) | ✅ Block (pf) | ⚠️ Observe | ❌ |
| UDP interception | ✅ Block | ✅ Block | ✅ Block | ⚠️ Observe | ❌ |
| DNS interception | ✅ Block | ✅ Block | ✅ Block | ⚠️ Observe | ❌ |
| TLS inspection | ✅ | ✅ | ✅ | ❌ | ❌ |
| Per-app filtering | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Process** |
| Exec monitoring | ✅ Block | ⚠️ Observe | ⚠️ Observe | ⚠️ Observe | ⚠️ Observe |
| Fork/Exit | ✅ | ⚠️ Observe | ⚠️ Observe | ⚠️ Observe | ⚠️ Observe |
| **Other** |
| Command logging | ✅ | ✅ | ✅ | ✅ | ✅ |
| Kernel events | ✅ | ❌ | ❌ | ❌ | ❌ |

#### 4.4.3 Permission Detection

```go
// pkg/platform/darwin_permissions.go
// +build darwin

package platform

import (
    "fmt"
    "os"
    "os/exec"
    "strings"
    "time"
    
    "go.uber.org/zap"
)

type DarwinPermissions struct {
    // Apple Entitlements (Tier 0)
    HasEndpointSecurity   bool
    HasNetworkExtension   bool
    
    // FUSE Options (Tier 1)
    HasFuseT              bool
    FuseTVersion          string
    
    // Basic Permissions
    HasRootAccess         bool
    HasFullDiskAccess     bool
    
    // Fallbacks
    CanUsePF              bool
    HasFSEvents           bool  // Always true on macOS
    HasLibpcap            bool
    
    // Computed
    Tier                  PermissionTier
    MissingPermissions    []MissingPermission
    DetectedAt            time.Time
}

type PermissionTier int

const (
    TierEnterprise  PermissionTier = 0  // ESF + NE
    TierFull        PermissionTier = 1  // FUSE-T + pf
    TierNetworkOnly PermissionTier = 2  // pf only
    TierMonitorOnly PermissionTier = 3  // Observation only
    TierMinimal     PermissionTier = 4  // Logging only
)

func (t PermissionTier) String() string {
    switch t {
    case TierEnterprise:
        return "enterprise"
    case TierFull:
        return "full"
    case TierNetworkOnly:
        return "network-only"
    case TierMonitorOnly:
        return "monitor-only"
    case TierMinimal:
        return "minimal"
    default:
        return "unknown"
    }
}

func (t PermissionTier) SecurityScore() int {
    switch t {
    case TierEnterprise:
        return 95
    case TierFull:
        return 75
    case TierNetworkOnly:
        return 50
    case TierMonitorOnly:
        return 25
    case TierMinimal:
        return 10
    default:
        return 0
    }
}

func DetectPermissions(logger *zap.Logger) *DarwinPermissions {
    p := &DarwinPermissions{
        HasFSEvents: true,  // Always available
        DetectedAt:  time.Now(),
    }
    
    logger.Info("Detecting macOS permissions...")
    
    // Check Apple entitlements (Tier 0)
    p.HasEndpointSecurity = checkEntitlement("endpoint-security.client")
    p.HasNetworkExtension = checkEntitlement("networking.networkextension")
    
    // Check FUSE-T (Tier 1) - macFUSE not supported due to kext requirement
    p.HasFuseT, p.FuseTVersion = checkFuseT()
    
    // Check basic permissions
    p.HasRootAccess = os.Geteuid() == 0
    p.HasFullDiskAccess = checkFullDiskAccess()
    p.CanUsePF = p.HasRootAccess && checkPFAvailable()
    p.HasLibpcap = checkLibpcapAvailable()
    
    // Compute tier
    p.computeTier()
    p.computeMissingPermissions()
    
    return p
}

func checkEntitlement(name string) bool {
    cmd := exec.Command("codesign", "-d", "--entitlements", "-", os.Args[0])
    output, err := cmd.Output()
    if err != nil {
        return false
    }
    return strings.Contains(string(output), name)
}

func checkFuseT() (bool, string) {
    paths := []string{
        "/opt/homebrew/lib/libfuse-t.dylib",  // Apple Silicon Homebrew
        "/usr/local/lib/libfuse-t.dylib",      // Intel Homebrew
        "/Library/Frameworks/FUSE-T.framework",
    }
    
    for _, path := range paths {
        if _, err := os.Stat(path); err == nil {
            // Try to get version
            cmd := exec.Command("brew", "info", "fuse-t", "--json")
            if output, err := cmd.Output(); err == nil {
                // Parse version from JSON
                return true, "installed"
            }
            return true, "installed"
        }
    }
    return false, ""
}

func checkFullDiskAccess() bool {
    homeDir, _ := os.UserHomeDir()
    testPath := homeDir + "/Library/Mail"
    _, err := os.ReadDir(testPath)
    return err == nil
}

func checkPFAvailable() bool {
    return exec.Command("pfctl", "-s", "info").Run() == nil
}

func checkLibpcapAvailable() bool {
    _, err := exec.LookPath("tcpdump")
    return err == nil
}

func (p *DarwinPermissions) computeTier() {
    switch {
    case p.HasEndpointSecurity && p.HasNetworkExtension:
        p.Tier = TierEnterprise
    case p.HasFuseT && p.HasRootAccess && p.CanUsePF:
        p.Tier = TierFull
    case p.HasRootAccess && p.CanUsePF:
        p.Tier = TierNetworkOnly
    case p.HasFSEvents && (p.HasLibpcap || p.HasRootAccess):
        p.Tier = TierMonitorOnly
    default:
        p.Tier = TierMinimal
    }
}

func (p *DarwinPermissions) computeMissingPermissions() {
    p.MissingPermissions = []MissingPermission{}
    
    // Suggest FUSE-T if not available
    if !p.HasFuseT {
        p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
            Name:        "FUSE-T",
            Description: "Userspace filesystem for file interception (no kernel extension needed)",
            Impact:      "Cannot intercept or block file operations. File monitoring will be observation-only via FSEvents.",
            HowToEnable: "Install via Homebrew:\n  brew install fuse-t\n\nNo restart or security approval required!",
            Required:    false,
        })
    }
    
    if !p.HasRootAccess {
        p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
            Name:        "Root Access",
            Description: "Administrator privileges for pf network interception",
            Impact:      "Cannot use pf for network interception. Network policy enforcement disabled.",
            HowToEnable: "Run agentsh with sudo:\n  sudo agentsh server",
            Required:    false,
        })
    }
    
    if !p.HasFullDiskAccess {
        p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
            Name:        "Full Disk Access",
            Description: "Access to protected directories (Mail, Messages, Safari, etc.)",
            Impact:      "Cannot monitor file operations in protected system directories.",
            HowToEnable: "1. Open System Settings > Privacy & Security > Full Disk Access\n" +
                        "2. Click '+' and add Terminal.app or the agentsh binary\n" +
                        "3. Restart agentsh",
            Required:    false,
        })
    }
    
    // Suggest enterprise options if user might want them
    if !p.HasEndpointSecurity {
        p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
            Name:        "Endpoint Security Framework",
            Description: "Apple's official security monitoring API with full system visibility",
            Impact:      "Not using Apple's most comprehensive security API. Current tier provides good coverage.",
            HowToEnable: "Requires Apple Developer Program membership and approval:\n" +
                        "1. Apply for com.apple.developer.endpoint-security.client entitlement\n" +
                        "2. Provide business justification to Apple\n" +
                        "3. Build and notarize with approved provisioning profile",
            Required:    false,
        })
    }
}

func (p *DarwinPermissions) LogStatus(logger *zap.Logger) {
    logger.Info("═══════════════════════════════════════════════════════════════")
    logger.Info("                    macOS Permission Status                     ")
    logger.Info("═══════════════════════════════════════════════════════════════")
    
    logger.Info(fmt.Sprintf("Operating Tier: %d (%s) - Security Score: %d%%",
        p.Tier, p.Tier.String(), p.Tier.SecurityScore()))
    logger.Info("")
    
    // Apple Entitlements
    logger.Info("Apple Entitlements (Tier 0 - Enterprise):")
    logPermission(logger, "Endpoint Security", p.HasEndpointSecurity, "System-wide file/process monitoring")
    logPermission(logger, "Network Extension", p.HasNetworkExtension, "Deep network inspection")
    logger.Info("")
    
    // FUSE Options
    logger.Info("Filesystem Interception (Tier 1):")
    logPermission(logger, "FUSE-T", p.HasFuseT, "NFS-based FUSE (recommended, no kext)")
    logger.Info("")
    
    // Basic Permissions
    logger.Info("Basic Permissions:")
    logPermission(logger, "Root Access", p.HasRootAccess, "Required for pf network interception")
    logPermission(logger, "Full Disk Access", p.HasFullDiskAccess, "Access to protected directories")
    logPermission(logger, "pf Available", p.CanUsePF, "Packet filter for network")
    logPermission(logger, "libpcap", p.HasLibpcap, "Fallback network observation")
    logger.Info("")
    
    // Feature availability
    logger.Info("Feature Availability:")
    for _, feature := range p.AvailableFeatures() {
        logger.Info(fmt.Sprintf("  ✅ %s", feature))
    }
    for _, feature := range p.DisabledFeatures() {
        logger.Warn(fmt.Sprintf("  ❌ %s", feature))
    }
    
    logger.Info("")
    
    // Missing permissions
    if len(p.MissingPermissions) > 0 && p.Tier > TierEnterprise {
        logger.Warn("To enable more features:")
        for i, mp := range p.MissingPermissions {
            if mp.Required || p.Tier > TierFull {
                logger.Warn(fmt.Sprintf("  %d. %s", i+1, mp.Name))
                logger.Warn(fmt.Sprintf("     %s", mp.HowToEnable))
            }
        }
    }
    
    logger.Info("═══════════════════════════════════════════════════════════════")
}

func logPermission(logger *zap.Logger, name string, available bool, description string) {
    status := "❌"
    if available {
        status = "✅"
    }
    logger.Info(fmt.Sprintf("  %s %s - %s", status, name, description))
}

func (p *DarwinPermissions) AvailableFeatures() []string {
    switch p.Tier {
    case TierEnterprise:
        return []string{
            "file_read_interception (ESF - can block)",
            "file_write_interception (ESF - can block)",
            "process_exec_blocking (ESF)",
            "network_interception (NE - can block)",
            "per_app_network_filtering (NE)",
            "dns_interception",
            "tls_inspection",
            "kernel_event_monitoring",
            "command_logging",
        }
    case TierFull:
        return []string{
            "file_read_interception (FUSE - can block)",
            "file_write_interception (FUSE - can block)",
            "network_interception (pf - can block)",
            "dns_interception",
            "tls_inspection",
            "command_logging",
        }
    case TierNetworkOnly:
        return []string{
            "file_monitoring (FSEvents - observe only)",
            "network_interception (pf - can block)",
            "dns_interception",
            "tls_inspection",
            "command_logging",
        }
    case TierMonitorOnly:
        return []string{
            "file_monitoring (FSEvents - observe only)",
            "network_monitoring (pcap - observe only)",
            "command_logging",
        }
    case TierMinimal:
        return []string{
            "command_logging",
        }
    default:
        return []string{}
    }
}

func (p *DarwinPermissions) DisabledFeatures() []string {
    all := map[string]bool{
        "file_blocking": false,
        "network_blocking": false,
        "process_blocking": false,
        "per_app_filtering": false,
        "kernel_events": false,
    }
    
    switch p.Tier {
    case TierEnterprise:
        // All features available
        return []string{}
    case TierFull:
        return []string{"process_blocking", "per_app_filtering", "kernel_events"}
    case TierNetworkOnly:
        return []string{"file_blocking", "process_blocking", "per_app_filtering", "kernel_events"}
    case TierMonitorOnly:
        return []string{"file_blocking", "network_blocking", "process_blocking", "per_app_filtering", "kernel_events"}
    case TierMinimal:
        return []string{"file_monitoring", "file_blocking", "network_monitoring", "network_blocking", "process_blocking", "per_app_filtering", "kernel_events"}
    }
    
    var disabled []string
    for feature, available := range all {
        if !available {
            disabled = append(disabled, feature)
        }
    }
    return disabled
}
```

#### 4.4.4 Unified Platform Initialization

```go
// pkg/platform/darwin.go
// +build darwin

package platform

import (
    "context"
    "fmt"
    
    "go.uber.org/zap"
)

type DarwinPlatform struct {
    permissions *DarwinPermissions
    logger      *zap.Logger
    
    // Components (selected based on permissions)
    filesystem FilesystemInterceptor
    network    NetworkInterceptor
    esMonitor  *EndpointSecurityMonitor
    neProvider *NetworkExtensionProvider
}

func NewDarwinPlatform() (Platform, error) {
    logger, _ := zap.NewProduction()
    return NewDarwinPlatformWithLogger(logger)
}

func NewDarwinPlatformWithLogger(logger *zap.Logger) (Platform, error) {
    permissions := DetectPermissions(logger)
    permissions.LogStatus(logger)
    
    p := &DarwinPlatform{
        permissions: permissions,
        logger:      logger,
    }
    
    // Initialize components based on tier
    if err := p.initializeComponents(); err != nil {
        return nil, err
    }
    
    return p, nil
}

func (p *DarwinPlatform) initializeComponents() error {
    tier := p.permissions.Tier
    
    // Filesystem interception
    switch {
    case tier == TierEnterprise && p.permissions.HasEndpointSecurity:
        // Use ESF for file monitoring
        p.logger.Info("Using Endpoint Security Framework for file monitoring")
        
    case p.permissions.HasFuseT:
        p.logger.Info("Using FUSE-T for file interception")
        p.filesystem = NewFuseTFilesystem(p.logger)
        
    default:
        p.logger.Warn("No FUSE available, using FSEvents (observation only)")
        p.logger.Warn("Install FUSE-T with: brew install fuse-t")
        p.filesystem = NewFSEventsFilesystem(p.logger)
    }
    
    // Network interception
    switch {
    case tier == TierEnterprise && p.permissions.HasNetworkExtension:
        p.logger.Info("Using Network Extension for network interception")
        var err error
        p.neProvider, err = NewNetworkExtensionProvider(NETransparentProxy, p.logger)
        if err != nil {
            p.logger.Warn("Failed to initialize Network Extension, falling back to pf", zap.Error(err))
            p.network = NewPFNetwork(p.logger)
        }
        
    case p.permissions.CanUsePF:
        p.logger.Info("Using pf for network interception")
        p.network = NewPFNetwork(p.logger)
        
    case p.permissions.HasLibpcap:
        p.logger.Warn("Using libpcap for network monitoring (observation only)")
        p.network = NewPcapNetwork(p.logger)
        
    default:
        p.logger.Warn("No network interception available")
    }
    
    return nil
}

func (p *DarwinPlatform) Name() string {
    return fmt.Sprintf("darwin-%s", p.permissions.Tier.String())
}

func (p *DarwinPlatform) Capabilities() Capabilities {
    caps := Capabilities{
        IsolationLevel: IsolationNone,  // macOS never has Linux-style isolation
        HasSeccomp:     false,
        HasCgroups:     false,
    }
    
    tier := p.permissions.Tier
    
    switch tier {
    case TierEnterprise:
        caps.HasFUSE = true
        caps.FUSEImplementation = "endpoint-security"
        caps.HasNetworkIntercept = true
        caps.NetworkImplementation = "network-extension"
        caps.CanRedirectTraffic = true
        caps.CanInspectTLS = true
        caps.HasEndpointSecurity = true
        caps.HasNetworkExtension = true
        
    case TierFull:
        caps.HasFUSE = true
        caps.FUSEImplementation = "fuse-t"
        caps.HasNetworkIntercept = true
        caps.NetworkImplementation = "pf"
        caps.CanRedirectTraffic = true
        caps.CanInspectTLS = true
        
    case TierNetworkOnly:
        caps.HasFUSE = false
        caps.FUSEImplementation = "fsevents-observe"
        caps.HasNetworkIntercept = true
        caps.NetworkImplementation = "pf"
        caps.CanRedirectTraffic = true
        caps.CanInspectTLS = true
        
    case TierMonitorOnly:
        caps.HasFUSE = false
        caps.FUSEImplementation = "fsevents-observe"
        caps.HasNetworkIntercept = false
        caps.NetworkImplementation = "pcap-observe"
        caps.CanRedirectTraffic = false
        caps.CanInspectTLS = false
        
    case TierMinimal:
        caps.HasFUSE = false
        caps.HasNetworkIntercept = false
    }
    
    return caps
}

func (p *DarwinPlatform) Filesystem() FilesystemInterceptor {
    return p.filesystem
}

func (p *DarwinPlatform) Network() NetworkInterceptor {
    return p.network
}

func (p *DarwinPlatform) Sandbox() SandboxManager {
    return &DarwinNoopSandbox{logger: p.logger}
}

func (p *DarwinPlatform) Resources() ResourceLimiter {
    return &DarwinNoopResources{logger: p.logger}
}

func (p *DarwinPlatform) Initialize(ctx context.Context, config Config) error {
    p.logger.Info("Initializing agentsh on macOS",
        zap.String("tier", p.permissions.Tier.String()),
        zap.Int("security_score", p.permissions.Tier.SecurityScore()),
    )
    return nil
}

func (p *DarwinPlatform) Shutdown(ctx context.Context) error {
    return nil
}
```

### 4.5 Installation

```bash
#!/bin/bash
# install-macos.sh

set -e

echo "agentsh macOS Installer"
echo "======================="
echo ""

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install FUSE-T (recommended - no kernel extension)
install_fuse_t() {
    echo ""
    echo "Installing FUSE-T (recommended - no kernel extension needed)..."
    brew install fuse-t
    echo "✅ FUSE-T installed successfully!"
    echo "   No restart or security approval required."
}

# Install agentsh binary
install_agentsh() {
    local version="${1:-latest}"
    local arch=$(uname -m)
    
    case $arch in
        x86_64) arch="amd64" ;;
        arm64) arch="arm64" ;;
    esac
    
    echo ""
    echo "Installing agentsh..."
    curl -fsSL "https://github.com/agentsh/agentsh/releases/download/${version}/agentsh-darwin-${arch}" \
        -o /tmp/agentsh
    chmod +x /tmp/agentsh
    sudo mv /tmp/agentsh /usr/local/bin/agentsh
    echo "✅ agentsh installed to /usr/local/bin/agentsh"
}

# Show menu
echo "Select filesystem interception method:"
echo ""
echo "  1) FUSE-T (Recommended)"
echo "     - No kernel extension required"
echo "     - Works on Apple Silicon without reduced security"
echo "     - Easy install: brew install fuse-t"
echo "     - Security score: 70%"
echo ""
echo "  2) Lima VM (Full isolation)"
echo "     - Runs Linux in a lightweight VM"
echo "     - Full security features (namespaces, seccomp, cgroups)"
echo "     - Security score: 85%"
echo ""
echo "  3) Skip FUSE (Network interception only)"
echo "     - File monitoring will be observation-only"
echo "     - Network blocking still works with sudo"
echo "     - Security score: 50%"
echo ""

read -p "Choice [1/2/3]: " choice

case $choice in
    1)
        install_fuse_t
        ;;
    2)
        install_lima
        ;;
    3)
        echo "Skipping FUSE installation. File monitoring will use FSEvents (observation only)."
        ;;
    *)
        echo "Invalid choice, defaulting to FUSE-T"
        install_fuse_t
        ;;
esac

install_agentsh "$@"

echo ""
echo "============================================"
echo "Installation complete!"
echo ""
echo "To start agentsh with full network interception:"
echo "  sudo agentsh server"
echo ""
echo "To check your permission tier:"
echo "  agentsh status"
echo ""
echo "For Tier 0 (Enterprise) features, you need Apple entitlements."
echo "See: https://agentsh.dev/docs/macos-enterprise"
echo "============================================"
```

---

## 5. Windows Native Implementation

### 5.1 Overview

Windows provides different primitives that can achieve similar goals:

| Component | Windows Implementation | Notes |
|-----------|----------------------|-------|
| FUSE | WinFsp | Mature, well-supported |
| Network | WinDivert or WFP | WinDivert more flexible |
| Isolation | AppContainer | Partial isolation |
| Syscall | None | Not available |
| Resources | Job Objects | Partial support |

### 5.2 Capabilities

```go
// pkg/platform/windows.go
// +build windows

package platform

import (
    "golang.org/x/sys/windows/registry"
    "syscall"
)

type WindowsPlatform struct {
    hasWinFsp         bool
    hasWinDivert      bool
    hasRegistryDriver bool
}

func NewWindowsPlatform() (*WindowsPlatform, error) {
    p := &WindowsPlatform{}
    p.hasWinFsp = p.checkWinFsp()
    p.hasWinDivert = p.checkWinDivert()
    p.hasRegistryDriver = p.checkRegistryDriver()
    return p, nil
}

func (p *WindowsPlatform) Name() string {
    return "windows-native"
}

func (p *WindowsPlatform) Capabilities() Capabilities {
    return Capabilities{
        // Filesystem
        HasFUSE:              p.hasWinFsp,
        FUSEImplementation:   "winfsp",
        
        // Network
        HasNetworkIntercept:  true, // WFP always available
        NetworkImplementation: p.networkImpl(),
        CanRedirectTraffic:   p.hasWinDivert,
        CanInspectTLS:        true,
        
        // Isolation - AppContainer provides partial isolation
        HasMountNamespace:    false,
        HasNetworkNamespace:  false,
        HasPIDNamespace:      false,
        HasUserNamespace:     false,
        HasAppContainer:      true,
        IsolationLevel:       IsolationPartial,
        
        // Syscall filtering - not available on Windows
        HasSeccomp:           false,
        
        // Resource control via Job Objects
        HasCgroups:           false,
        HasJobObjects:        true,
        CanLimitCPU:          true,
        CanLimitMemory:       true,
        CanLimitDiskIO:       false, // Not supported by Job Objects
        CanLimitNetworkBW:    false, // Not supported by Job Objects
        CanLimitProcessCount: true,
        
        // Windows-specific features
        HasRegistryMonitoring: true,
        HasRegistryBlocking:   p.hasRegistryDriver,
    }
}

func (p *WindowsPlatform) checkWinFsp() bool {
    key, err := registry.OpenKey(
        registry.LOCAL_MACHINE,
        `Software\WinFsp`,
        registry.READ,
    )
    if err != nil {
        return false
    }
    key.Close()
    return true
}

func (p *WindowsPlatform) checkWinDivert() bool {
    dll, err := syscall.LoadDLL("WinDivert.dll")
    if err != nil {
        return false
    }
    dll.Release()
    return true
}

func (p *WindowsPlatform) checkRegistryDriver() bool {
    // Check if our registry filter driver is loaded
    // This is optional - monitoring works without it, but blocking requires it
    dll, err := syscall.LoadDLL("agentsh_regfilter.sys")
    if err != nil {
        return false
    }
    dll.Release()
    return true
}

func (p *WindowsPlatform) networkImpl() string {
    if p.hasWinDivert {
        return "windivert"
    }
    return "wfp"
}
```

### 5.3 Filesystem: WinFsp via cgofuse

```go
// pkg/platform/windows_fs.go
// +build windows

package platform

import (
    "fmt"
    "github.com/winfsp/cgofuse/fuse"
    "path/filepath"
)

type WindowsFilesystem struct {
    available bool
}

func NewWindowsFilesystem() *WindowsFilesystem {
    return &WindowsFilesystem{
        available: checkWinFsp(),
    }
}

func (fs *WindowsFilesystem) Available() bool {
    return fs.available
}

func (fs *WindowsFilesystem) Implementation() string {
    return "winfsp"
}

func (fs *WindowsFilesystem) Mount(config FSConfig) (FSMount, error) {
    if !fs.available {
        return nil, fmt.Errorf("WinFsp not installed. Download from https://winfsp.dev/")
    }
    
    agentFS := &WindowsAgentFS{
        rootPath:     config.SourcePath,
        policyEngine: config.PolicyEngine,
        eventChan:    config.EventChannel,
    }
    
    host := fuse.NewFileSystemHost(agentFS)
    
    // Windows mount options
    // Mount point can be a drive letter (e.g., "X:") or UNC path
    mountPoint := config.MountPoint
    if len(mountPoint) == 1 {
        mountPoint = mountPoint + ":"
    }
    
    opts := []string{
        "-o", "uid=-1,gid=-1",           // Map to current user
        "-o", "FileSystemName=agentfs",
        "-o", fmt.Sprintf("volprefix=\\agentsh\\%s", filepath.Base(config.SourcePath)),
    }
    
    go func() {
        if !host.Mount(mountPoint, opts) {
            config.EventChannel <- IOEvent{
                Type:     EventFileOpen,
                Error:    "mount failed",
                Decision: DecisionError,
                Platform: "windows",
            }
        }
    }()
    
    return &windowsFSMount{
        host: host,
        path: mountPoint,
    }, nil
}

// WindowsAgentFS implements cgofuse.FileSystemInterface
type WindowsAgentFS struct {
    fuse.FileSystemBase
    rootPath     string
    policyEngine PolicyEngine
    eventChan    chan<- IOEvent
}

func (fs *WindowsAgentFS) Open(path string, flags int) (int, uint64) {
    // Convert to Windows path
    fullPath := filepath.Join(fs.rootPath, filepath.FromSlash(path))
    
    decision := fs.policyEngine.CheckFileAccess(fullPath, flagsToOp(flags))
    
    fs.eventChan <- IOEvent{
        Type:      EventFileOpen,
        Path:      path,
        Operation: flagsToOp(flags),
        Decision:  decision,
        Platform:  "windows",
    }
    
    if decision == DecisionDeny {
        return -fuse.EACCES, 0
    }
    
    // Open real file
    // ... implementation
    return 0, fh
}
```

### 5.4 Network: WinDivert

```go
// pkg/platform/windows_net_windivert.go
// +build windows

package platform

import (
    "fmt"
    "net"
    
    "github.com/williamfhe/godivert"
    "github.com/williamfhe/godivert/header"
)

type WindowsWinDivertNetwork struct {
    handle       *godivert.WinDivertHandle
    proxyPort    int
    dnsPort      int
    policyEngine PolicyEngine
    eventChan    chan<- IOEvent
    stopChan     chan struct{}
}

func NewWindowsWinDivertNetwork() *WindowsWinDivertNetwork {
    return &WindowsWinDivertNetwork{
        stopChan: make(chan struct{}),
    }
}

func (n *WindowsWinDivertNetwork) Available() bool {
    handle, err := godivert.NewWinDivertHandle("false") // Test handle
    if err != nil {
        return false
    }
    handle.Close()
    return true
}

func (n *WindowsWinDivertNetwork) Implementation() string {
    return "windivert"
}

func (n *WindowsWinDivertNetwork) Setup(config NetConfig) error {
    n.proxyPort = config.ProxyPort
    n.dnsPort = config.DNSPort
    n.policyEngine = config.PolicyEngine
    n.eventChan = config.EventChannel
    
    // Capture all outbound TCP and DNS
    filter := "outbound and (tcp or (udp.DstPort == 53))"
    
    handle, err := godivert.NewWinDivertHandle(filter)
    if err != nil {
        return fmt.Errorf("failed to open WinDivert: %w", err)
    }
    n.handle = handle
    
    // Start packet processing
    go n.processPackets()
    
    // Start transparent proxy
    go n.runTransparentProxy()
    
    return nil
}

func (n *WindowsWinDivertNetwork) processPackets() {
    packetChan, err := n.handle.Packets()
    if err != nil {
        return
    }
    
    for {
        select {
        case <-n.stopChan:
            return
        case packet := <-packetChan:
            n.handlePacket(packet)
        }
    }
}

func (n *WindowsWinDivertNetwork) handlePacket(packet *godivert.Packet) {
    dstIP := packet.DstIP()
    dstPort := packet.DstPort()
    
    // Check policy
    decision := n.policyEngine.CheckNetworkAccess(dstIP.String(), int(dstPort))
    
    event := IOEvent{
        Type:       EventNetConnect,
        RemoteAddr: dstIP.String(),
        RemotePort: int(dstPort),
        Protocol:   n.getProtocol(packet),
        Platform:   "windows",
    }
    
    if decision == DecisionDeny {
        event.Decision = DecisionDeny
        n.eventChan <- event
        // Don't reinject - packet is dropped
        return
    }
    
    event.Decision = DecisionAllow
    n.eventChan <- event
    
    // Redirect to our proxy
    if packet.NextHeaderType() == header.TCP {
        packet.SetDstIP(net.ParseIP("127.0.0.1"))
        packet.SetDstPort(uint16(n.proxyPort))
    } else if packet.DstPort() == 53 {
        packet.SetDstIP(net.ParseIP("127.0.0.1"))
        packet.SetDstPort(uint16(n.dnsPort))
    }
    
    // Reinject modified packet
    n.handle.Send(packet)
}

func (n *WindowsWinDivertNetwork) Teardown() error {
    close(n.stopChan)
    if n.handle != nil {
        return n.handle.Close()
    }
    return nil
}
```

### 5.5 Network Fallback: WFP

```go
// pkg/platform/windows_net_wfp.go
// +build windows

package platform

import (
    "inet.af/wf"
)

type WindowsWFPNetwork struct {
    session  *wf.Session
    sublayer wf.SublayerID
}

func NewWindowsWFPNetwork() *WindowsWFPNetwork {
    return &WindowsWFPNetwork{}
}

func (n *WindowsWFPNetwork) Available() bool {
    return true // WFP is always available on Windows Vista+
}

func (n *WindowsWFPNetwork) Implementation() string {
    return "wfp"
}

func (n *WindowsWFPNetwork) Setup(config NetConfig) error {
    session, err := wf.New(&wf.Options{
        Name:    "agentsh",
        Dynamic: true, // Rules removed when process exits
    })
    if err != nil {
        return err
    }
    n.session = session
    
    // Create sublayer
    sublayer := wf.Sublayer{
        Key:    generateGUID(),
        Name:   "agentsh network filter",
        Weight: 0x100,
    }
    if err := session.AddSublayer(&sublayer); err != nil {
        return err
    }
    n.sublayer = sublayer.Key
    
    // Note: WFP can block/allow but not easily redirect like WinDivert
    // We use WFP for monitoring + blocking, not transparent proxy
    
    return nil
}

func (n *WindowsWFPNetwork) AddBlockRule(ip string, port int) error {
    rule := &wf.Rule{
        Key:      generateGUID(),
        Name:     fmt.Sprintf("Block %s:%d", ip, port),
        Layer:    wf.LayerALEAuthConnectV4,
        Sublayer: n.sublayer,
        Action:   wf.ActionBlock,
        Weight:   100,
        Matches: []wf.Match{
            {Field: wf.FieldIPRemoteAddress, Op: wf.MatchEqual, Value: net.ParseIP(ip)},
            {Field: wf.FieldIPRemotePort, Op: wf.MatchEqual, Value: uint16(port)},
        },
    }
    return n.session.AddRule(rule)
}

func (n *WindowsWFPNetwork) Teardown() error {
    if n.session != nil {
        return n.session.Close()
    }
    return nil
}
```

### 5.6 Sandbox: AppContainer

```go
// pkg/platform/windows_sandbox.go
// +build windows

package platform

import (
    "context"
    "fmt"
    "os"
    "syscall"
    "unsafe"
    
    "golang.org/x/sys/windows"
)

type WindowsSandboxManager struct{}

func (m *WindowsSandboxManager) Available() bool {
    return true // AppContainer available on Windows 8+
}

func (m *WindowsSandboxManager) IsolationLevel() IsolationLevel {
    return IsolationPartial
}

func (m *WindowsSandboxManager) Create(config SandboxConfig) (Sandbox, error) {
    sandbox := &WindowsAppContainerSandbox{
        name:          config.Name,
        workspacePath: config.WorkspacePath,
    }
    
    // Create AppContainer profile
    if err := sandbox.createProfile(); err != nil {
        return nil, err
    }
    
    // Grant access to workspace
    if err := sandbox.grantFolderAccess(config.WorkspacePath); err != nil {
        sandbox.Close()
        return nil, err
    }
    
    // Grant access to additional paths
    for _, path := range config.AllowedPaths {
        if err := sandbox.grantFolderAccess(path); err != nil {
            sandbox.Close()
            return nil, err
        }
    }
    
    return sandbox, nil
}

type WindowsAppContainerSandbox struct {
    name          string
    workspacePath string
    sid           *windows.SID
}

func (s *WindowsAppContainerSandbox) ID() string {
    return s.name
}

func (s *WindowsAppContainerSandbox) createProfile() error {
    namePtr, _ := syscall.UTF16PtrFromString(s.name)
    displayName, _ := syscall.UTF16PtrFromString("agentsh sandbox: " + s.name)
    desc, _ := syscall.UTF16PtrFromString("Sandbox for AI agent execution")
    
    var sid *windows.SID
    
    // CreateAppContainerProfile
    r, _, err := procCreateAppContainerProfile.Call(
        uintptr(unsafe.Pointer(namePtr)),
        uintptr(unsafe.Pointer(displayName)),
        uintptr(unsafe.Pointer(desc)),
        0, // No capabilities
        0,
        uintptr(unsafe.Pointer(&sid)),
    )
    
    if r != 0 {
        // Profile may already exist, try to get it
        r, _, err = procDeriveAppContainerSidFromAppContainerName.Call(
            uintptr(unsafe.Pointer(namePtr)),
            uintptr(unsafe.Pointer(&sid)),
        )
        if r != 0 {
            return fmt.Errorf("failed to create/get AppContainer profile: %w", err)
        }
    }
    
    s.sid = sid
    return nil
}

func (s *WindowsAppContainerSandbox) grantFolderAccess(path string) error {
    // Add AppContainer SID to folder ACL
    pathPtr, _ := syscall.UTF16PtrFromString(path)
    
    // Get current DACL
    var sd *windows.SECURITY_DESCRIPTOR
    err := windows.GetNamedSecurityInfo(
        pathPtr,
        windows.SE_FILE_OBJECT,
        windows.DACL_SECURITY_INFORMATION,
        nil, nil, nil, nil,
        &sd,
    )
    if err != nil {
        return err
    }
    
    // Add ACE for AppContainer SID with full control
    // ... ACL manipulation code
    
    return nil
}

func (s *WindowsAppContainerSandbox) Execute(ctx context.Context, cmd string, args ...string) (*ExecResult, error) {
    // Create process with AppContainer token
    cmdLine := cmd
    for _, arg := range args {
        cmdLine += " " + arg
    }
    
    var si windows.StartupInfo
    si.Cb = uint32(unsafe.Sizeof(si))
    
    var pi windows.ProcessInformation
    
    // Set up security capabilities for AppContainer
    caps := &SECURITY_CAPABILITIES{
        AppContainerSid: s.sid,
    }
    
    // Create extended startup info
    var attrList *PROC_THREAD_ATTRIBUTE_LIST
    var size uintptr
    
    // Get required size
    initializeProcThreadAttributeList(nil, 1, 0, &size)
    attrList = (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(&make([]byte, size)[0]))
    
    if err := initializeProcThreadAttributeList(attrList, 1, 0, &size); err != nil {
        return nil, err
    }
    
    // Add security capabilities attribute
    if err := updateProcThreadAttribute(
        attrList,
        0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        unsafe.Pointer(caps),
        unsafe.Sizeof(*caps),
        nil,
        nil,
    ); err != nil {
        return nil, err
    }
    
    siEx := &STARTUPINFOEX{
        StartupInfo:   si,
        AttributeList: attrList,
    }
    
    cmdLinePtr, _ := syscall.UTF16PtrFromString(cmdLine)
    dirPtr, _ := syscall.UTF16PtrFromString(s.workspacePath)
    
    err := createProcess(
        nil,
        cmdLinePtr,
        nil, nil,
        false,
        EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_NEW_CONSOLE,
        nil,
        dirPtr,
        &siEx.StartupInfo,
        &pi,
    )
    
    if err != nil {
        return nil, err
    }
    
    // Wait for process
    windows.WaitForSingleObject(pi.Process, windows.INFINITE)
    
    var exitCode uint32
    windows.GetExitCodeProcess(pi.Process, &exitCode)
    
    windows.CloseHandle(pi.Process)
    windows.CloseHandle(pi.Thread)
    
    return &ExecResult{
        ExitCode: int(exitCode),
    }, nil
}

func (s *WindowsAppContainerSandbox) Close() error {
    if s.sid != nil {
        namePtr, _ := syscall.UTF16PtrFromString(s.name)
        procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(namePtr)))
    }
    return nil
}
```

### 5.7 Registry Monitoring (Windows-Only)

The Windows Registry is a critical attack vector. Malware commonly modifies registry keys for persistence, privilege escalation, and defense evasion. agentsh monitors and can block registry operations.

#### 5.7.1 Registry Event Types

```go
// pkg/types/registry_events.go

package types

// Registry-specific event types (Windows only)
const (
    EventRegistryRead    EventType = "registry_read"
    EventRegistryWrite   EventType = "registry_write"
    EventRegistryCreate  EventType = "registry_create"
    EventRegistryDelete  EventType = "registry_delete"
    EventRegistryRename  EventType = "registry_rename"
)

type RegistryOperation string

const (
    RegOpQueryValue    RegistryOperation = "query_value"
    RegOpSetValue      RegistryOperation = "set_value"
    RegOpDeleteValue   RegistryOperation = "delete_value"
    RegOpCreateKey     RegistryOperation = "create_key"
    RegOpDeleteKey     RegistryOperation = "delete_key"
    RegOpRenameKey     RegistryOperation = "rename_key"
    RegOpEnumKeys      RegistryOperation = "enum_keys"
    RegOpEnumValues    RegistryOperation = "enum_values"
    RegOpOpenKey       RegistryOperation = "open_key"
    RegOpCloseKey      RegistryOperation = "close_key"
)

// RegistryEvent extends IOEvent with registry-specific fields
type RegistryEvent struct {
    IOEvent
    
    // Registry-specific fields
    Hive        RegistryHive      `json:"hive"`
    KeyPath     string            `json:"key_path"`
    ValueName   string            `json:"value_name,omitempty"`
    ValueType   RegistryValueType `json:"value_type,omitempty"`
    ValueData   any               `json:"value_data,omitempty"`
    OldValue    any               `json:"old_value,omitempty"`
    RegOperation RegistryOperation `json:"registry_operation"`
    
    // Security context
    AccessMask  uint32            `json:"access_mask,omitempty"`
    Disposition string            `json:"disposition,omitempty"` // Created vs Opened
}

type RegistryHive string

const (
    HiveClassesRoot   RegistryHive = "HKEY_CLASSES_ROOT"
    HiveCurrentUser   RegistryHive = "HKEY_CURRENT_USER"
    HiveLocalMachine  RegistryHive = "HKEY_LOCAL_MACHINE"
    HiveUsers         RegistryHive = "HKEY_USERS"
    HiveCurrentConfig RegistryHive = "HKEY_CURRENT_CONFIG"
)

type RegistryValueType string

const (
    RegNone              RegistryValueType = "REG_NONE"
    RegSZ                RegistryValueType = "REG_SZ"
    RegExpandSZ          RegistryValueType = "REG_EXPAND_SZ"
    RegBinary            RegistryValueType = "REG_BINARY"
    RegDWORD             RegistryValueType = "REG_DWORD"
    RegDWORDBigEndian    RegistryValueType = "REG_DWORD_BIG_ENDIAN"
    RegLink              RegistryValueType = "REG_LINK"
    RegMultiSZ           RegistryValueType = "REG_MULTI_SZ"
    RegResourceList      RegistryValueType = "REG_RESOURCE_LIST"
    RegQWORD             RegistryValueType = "REG_QWORD"
)
```

#### 5.7.2 High-Risk Registry Paths

```go
// pkg/platform/windows_registry_policy.go

package platform

// HighRiskRegistryPaths defines paths commonly used for malicious purposes
var HighRiskRegistryPaths = []RegistryPathPolicy{
    // Persistence - Auto-start locations
    {
        Path:        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        Risk:        RiskCritical,
        Description: "Programs that run at startup for all users",
        Technique:   "T1547.001 - Registry Run Keys",
    },
    {
        Path:        `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        Risk:        RiskCritical,
        Description: "Programs that run at startup for current user",
        Technique:   "T1547.001 - Registry Run Keys",
    },
    {
        Path:        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
        Risk:        RiskCritical,
        Description: "Programs that run once at next startup",
        Technique:   "T1547.001 - Registry Run Keys",
    },
    {
        Path:        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
        Risk:        RiskCritical,
        Description: "Winlogon process configuration (Shell, Userinit)",
        Technique:   "T1547.004 - Winlogon Helper DLL",
    },
    
    // Services
    {
        Path:        `HKLM\SYSTEM\CurrentControlSet\Services`,
        Risk:        RiskHigh,
        Description: "Windows services configuration",
        Technique:   "T1543.003 - Windows Service",
    },
    
    // Scheduled Tasks
    {
        Path:        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`,
        Risk:        RiskHigh,
        Description: "Scheduled tasks configuration",
        Technique:   "T1053.005 - Scheduled Task",
    },
    
    // DLL Search Order Hijacking
    {
        Path:        `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`,
        Risk:        RiskCritical,
        Description: "Known DLLs that Windows loads from System32",
        Technique:   "T1574.001 - DLL Search Order Hijacking",
    },
    
    // AppInit DLLs (deprecated but still works)
    {
        Path:        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
        Risk:        RiskCritical,
        Description: "AppInit_DLLs loaded into every process",
        Technique:   "T1546.010 - AppInit DLLs",
    },
    
    // Image File Execution Options (Debugger hijacking)
    {
        Path:        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
        Risk:        RiskCritical,
        Description: "Debugger settings - can redirect executables",
        Technique:   "T1546.012 - Image File Execution Options",
    },
    
    // COM Objects
    {
        Path:        `HKLM\SOFTWARE\Classes\CLSID`,
        Risk:        RiskHigh,
        Description: "COM object registrations",
        Technique:   "T1546.015 - COM Hijacking",
    },
    {
        Path:        `HKCU\SOFTWARE\Classes\CLSID`,
        Risk:        RiskHigh,
        Description: "Per-user COM object registrations (shadows HKLM)",
        Technique:   "T1546.015 - COM Hijacking",
    },
    
    // Security Settings
    {
        Path:        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`,
        Risk:        RiskHigh,
        Description: "Windows policy settings",
        Technique:   "Defense Evasion",
    },
    {
        Path:        `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`,
        Risk:        RiskCritical,
        Description: "Windows Defender configuration",
        Technique:   "T1562.001 - Disable or Modify Tools",
    },
    
    // Firewall
    {
        Path:        `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`,
        Risk:        RiskHigh,
        Description: "Windows Firewall configuration",
        Technique:   "T1562.004 - Disable or Modify Firewall",
    },
    
    // LSA (Credential Access)
    {
        Path:        `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`,
        Risk:        RiskCritical,
        Description: "Local Security Authority settings",
        Technique:   "T1003 - Credential Dumping",
    },
    {
        Path:        `HKLM\SECURITY\Policy\Secrets`,
        Risk:        RiskCritical,
        Description: "LSA Secrets storage",
        Technique:   "T1003.004 - LSA Secrets",
    },
    
    // Terminal Services
    {
        Path:        `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
        Risk:        RiskHigh,
        Description: "Remote Desktop settings",
        Technique:   "T1021.001 - Remote Desktop Protocol",
    },
}

type RegistryPathPolicy struct {
    Path        string
    Risk        RiskLevel
    Description string
    Technique   string // MITRE ATT&CK technique
}

type RiskLevel int

const (
    RiskLow RiskLevel = iota
    RiskMedium
    RiskHigh
    RiskCritical
)
```

#### 5.7.3 Registry Monitor Implementation

```go
// pkg/platform/windows_registry.go
// +build windows

package platform

import (
    "context"
    "fmt"
    "strings"
    "sync"
    "syscall"
    "time"
    "unsafe"
    
    "golang.org/x/sys/windows"
    "golang.org/x/sys/windows/registry"
    "go.uber.org/zap"
)

var (
    ntdll                    = windows.NewLazySystemDLL("ntdll.dll")
    procNtNotifyChangeKey    = ntdll.NewProc("NtNotifyChangeMultipleKeys")
)

// RegistryMonitor watches for registry changes
type RegistryMonitor struct {
    policyEngine PolicyEngine
    eventChan    chan<- IOEvent
    logger       *zap.Logger
    
    watches      map[string]*registryWatch
    watchMu      sync.RWMutex
    
    stopChan     chan struct{}
    wg           sync.WaitGroup
}

type registryWatch struct {
    hive       registry.Key
    path       string
    key        registry.Key
    event      windows.Handle
    recursive  bool
    policy     *RegistryPathPolicy
}

func NewRegistryMonitor(policyEngine PolicyEngine, eventChan chan<- IOEvent, logger *zap.Logger) *RegistryMonitor {
    return &RegistryMonitor{
        policyEngine: policyEngine,
        eventChan:    eventChan,
        logger:       logger,
        watches:      make(map[string]*registryWatch),
        stopChan:     make(chan struct{}),
    }
}

func (m *RegistryMonitor) Start() error {
    m.logger.Info("Starting Windows Registry monitor")
    
    // Set up watches for high-risk paths
    for _, policy := range HighRiskRegistryPaths {
        if err := m.addWatch(policy); err != nil {
            m.logger.Warn("Failed to watch registry path",
                zap.String("path", policy.Path),
                zap.Error(err),
            )
        }
    }
    
    // Start the event loop
    m.wg.Add(1)
    go m.eventLoop()
    
    return nil
}

func (m *RegistryMonitor) addWatch(policy RegistryPathPolicy) error {
    // Parse hive and path
    hive, subPath, err := parseRegistryPath(policy.Path)
    if err != nil {
        return err
    }
    
    // Open the key
    key, err := registry.OpenKey(hive, subPath, registry.NOTIFY|registry.READ)
    if err != nil {
        return fmt.Errorf("failed to open key: %w", err)
    }
    
    // Create event for notification
    event, err := windows.CreateEvent(nil, 0, 0, nil)
    if err != nil {
        key.Close()
        return fmt.Errorf("failed to create event: %w", err)
    }
    
    // Register for notifications
    err = regNotifyChangeKeyValue(
        key,
        true, // Watch subtree
        windows.REG_NOTIFY_CHANGE_NAME|
            windows.REG_NOTIFY_CHANGE_ATTRIBUTES|
            windows.REG_NOTIFY_CHANGE_LAST_SET|
            windows.REG_NOTIFY_CHANGE_SECURITY,
        event,
        true, // Async
    )
    if err != nil {
        windows.CloseHandle(event)
        key.Close()
        return fmt.Errorf("failed to register notification: %w", err)
    }
    
    watch := &registryWatch{
        hive:      hive,
        path:      subPath,
        key:       key,
        event:     event,
        recursive: true,
        policy:    &policy,
    }
    
    m.watchMu.Lock()
    m.watches[policy.Path] = watch
    m.watchMu.Unlock()
    
    m.logger.Debug("Watching registry path",
        zap.String("path", policy.Path),
        zap.String("risk", fmt.Sprintf("%d", policy.Risk)),
    )
    
    return nil
}

func (m *RegistryMonitor) eventLoop() {
    defer m.wg.Done()
    
    for {
        select {
        case <-m.stopChan:
            return
        default:
        }
        
        // Collect all watch events
        m.watchMu.RLock()
        events := make([]windows.Handle, 0, len(m.watches))
        watches := make([]*registryWatch, 0, len(m.watches))
        for _, w := range m.watches {
            events = append(events, w.event)
            watches = append(watches, w)
        }
        m.watchMu.RUnlock()
        
        if len(events) == 0 {
            time.Sleep(100 * time.Millisecond)
            continue
        }
        
        // Wait for any event
        result, err := windows.WaitForMultipleObjects(events, false, 1000)
        if err != nil {
            continue
        }
        
        if result >= windows.WAIT_OBJECT_0 && result < windows.WAIT_OBJECT_0+uint32(len(events)) {
            idx := result - windows.WAIT_OBJECT_0
            watch := watches[idx]
            
            // Handle the change
            m.handleRegistryChange(watch)
            
            // Re-register notification
            regNotifyChangeKeyValue(
                watch.key,
                watch.recursive,
                windows.REG_NOTIFY_CHANGE_NAME|
                    windows.REG_NOTIFY_CHANGE_ATTRIBUTES|
                    windows.REG_NOTIFY_CHANGE_LAST_SET|
                    windows.REG_NOTIFY_CHANGE_SECURITY,
                watch.event,
                true,
            )
        }
    }
}

func (m *RegistryMonitor) handleRegistryChange(watch *registryWatch) {
    fullPath := watch.policy.Path
    
    event := IOEvent{
        Timestamp: time.Now(),
        Type:      EventRegistryWrite,
        Path:      fullPath,
        Decision:  DecisionAllow,
        Platform:  "windows-registry",
        Metadata: map[string]any{
            "hive":        watch.hive,
            "risk_level":  watch.policy.Risk,
            "description": watch.policy.Description,
            "technique":   watch.policy.Technique,
        },
    }
    
    // Check policy
    decision := m.policyEngine.CheckRegistryAccess(fullPath, RegOpSetValue)
    event.Decision = decision
    
    if decision == DecisionDeny {
        m.logger.Warn("Blocked registry modification",
            zap.String("path", fullPath),
            zap.String("risk", watch.policy.Technique),
        )
    } else if watch.policy.Risk >= RiskHigh {
        m.logger.Warn("High-risk registry modification detected",
            zap.String("path", fullPath),
            zap.String("technique", watch.policy.Technique),
        )
    }
    
    m.eventChan <- event
}

func (m *RegistryMonitor) Stop() {
    close(m.stopChan)
    m.wg.Wait()
    
    m.watchMu.Lock()
    defer m.watchMu.Unlock()
    
    for _, watch := range m.watches {
        windows.CloseHandle(watch.event)
        watch.key.Close()
    }
    m.watches = nil
}

// parseRegistryPath splits a path like "HKLM\SOFTWARE\..." into hive and subpath
func parseRegistryPath(path string) (registry.Key, string, error) {
    parts := strings.SplitN(path, `\`, 2)
    if len(parts) != 2 {
        return 0, "", fmt.Errorf("invalid registry path: %s", path)
    }
    
    var hive registry.Key
    switch strings.ToUpper(parts[0]) {
    case "HKLM", "HKEY_LOCAL_MACHINE":
        hive = registry.LOCAL_MACHINE
    case "HKCU", "HKEY_CURRENT_USER":
        hive = registry.CURRENT_USER
    case "HKCR", "HKEY_CLASSES_ROOT":
        hive = registry.CLASSES_ROOT
    case "HKU", "HKEY_USERS":
        hive = registry.USERS
    case "HKCC", "HKEY_CURRENT_CONFIG":
        hive = registry.CURRENT_CONFIG
    default:
        return 0, "", fmt.Errorf("unknown hive: %s", parts[0])
    }
    
    return hive, parts[1], nil
}

func regNotifyChangeKeyValue(key registry.Key, watchSubtree bool, notifyFilter uint32, event windows.Handle, async bool) error {
    var watchSubtreeVal uint32
    if watchSubtree {
        watchSubtreeVal = 1
    }
    var asyncVal uint32
    if async {
        asyncVal = 1
    }
    
    ret, _, err := syscall.Syscall6(
        procRegNotifyChangeKeyValue.Addr(),
        5,
        uintptr(key),
        uintptr(watchSubtreeVal),
        uintptr(notifyFilter),
        uintptr(event),
        uintptr(asyncVal),
        0,
    )
    if ret != 0 {
        return err
    }
    return nil
}

var procRegNotifyChangeKeyValue = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegNotifyChangeKeyValue")
```

#### 5.7.4 Registry Interception via Minifilter (Optional Advanced)

For full registry blocking (not just monitoring), a kernel-mode minifilter is needed:

```go
// pkg/platform/windows_registry_filter.go
// +build windows

package platform

// RegistryFilter provides kernel-mode registry filtering via CmRegisterCallback
// This requires a signed kernel driver - see docs/windows-driver.md
type RegistryFilter struct {
    driverHandle windows.Handle
    policyEngine PolicyEngine
    eventChan    chan<- IOEvent
    logger       *zap.Logger
}

// The actual filtering happens in a kernel driver that communicates
// with this userspace component via IOCTL or filter ports

type RegistryFilterRequest struct {
    Operation    RegistryOperation `json:"operation"`
    Path         string            `json:"path"`
    ValueName    string            `json:"value_name,omitempty"`
    ValueType    uint32            `json:"value_type,omitempty"`
    ProcessID    uint32            `json:"pid"`
    ProcessName  string            `json:"process_name"`
}

type RegistryFilterResponse struct {
    Allow   bool   `json:"allow"`
    Reason  string `json:"reason,omitempty"`
}

// LoadRegistryFilter loads the kernel driver and starts filtering
func LoadRegistryFilter(driverPath string) (*RegistryFilter, error) {
    // Load driver via Service Control Manager
    // Connect via FilterConnectCommunicationPort
    // This is advanced functionality requiring a signed driver
    
    return nil, fmt.Errorf("registry filter driver not implemented - use monitoring mode")
}
```

#### 5.7.5 Registry Policy Configuration

```yaml
# agentsh.yaml - Registry policy section

policy:
  # Registry-specific rules (Windows only)
  registry_rules:
    - name: block-persistence
      paths:
        - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*"
        - "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*"
        - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*"
      operations: [set_value, create_key, delete_value]
      action: deny
      
    - name: block-defender-disable
      paths:
        - "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\*"
      operations: [set_value, create_key]
      action: deny
      
    - name: alert-service-creation
      paths:
        - "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*"
      operations: [create_key]
      action: approve  # Require human approval
      
    - name: allow-app-settings
      paths:
        - "HKCU\\SOFTWARE\\agentsh\\*"
      operations: [query_value, set_value, create_key, delete_key]
      action: allow
      
    - name: default-registry
      paths: ["*"]
      operations: [query_value, enum_keys, enum_values]
      action: allow
```

#### 5.7.6 Registry Events in API Response

```json
{
  "events": [
    {
      "timestamp": "2025-01-15T14:30:00Z",
      "type": "registry_write",
      "session_id": "sess_abc123",
      "decision": "deny",
      "policy_rule": "block-persistence",
      "platform": "windows-registry",
      "registry": {
        "hive": "HKEY_LOCAL_MACHINE",
        "key_path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "MaliciousApp",
        "value_type": "REG_SZ",
        "value_data": "C:\\temp\\evil.exe",
        "operation": "set_value"
      },
      "metadata": {
        "risk_level": "critical",
        "technique": "T1547.001 - Registry Run Keys",
        "description": "Programs that run at startup for all users"
      }
    }
  ]
}
```

### 5.8 Resources: Job Objects

```go
// pkg/platform/windows_resources.go
// +build windows

package platform

import (
    "unsafe"
    
    "golang.org/x/sys/windows"
)

type WindowsResources struct{}

func (r *WindowsResources) Available() bool {
    return true
}

func (r *WindowsResources) SupportedLimits() []ResourceType {
    return []ResourceType{
        ResourceCPU,
        ResourceMemory,
        ResourceProcessCount,
        ResourceCPUAffinity,
    }
}

func (r *WindowsResources) Apply(config ResourceConfig) (ResourceHandle, error) {
    // Create job object
    handle, err := windows.CreateJobObject(nil, nil)
    if err != nil {
        return nil, err
    }
    
    job := &WindowsJobObject{handle: handle}
    
    // Apply extended limit information
    var info JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    info.BasicLimitInformation.LimitFlags = 0
    
    if config.MaxMemoryMB > 0 {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY
        info.JobMemoryLimit = uintptr(config.MaxMemoryMB * 1024 * 1024)
    }
    
    if config.MaxProcesses > 0 {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        info.BasicLimitInformation.ActiveProcessLimit = config.MaxProcesses
    }
    
    if len(config.CPUAffinity) > 0 {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY
        var mask uintptr
        for _, cpu := range config.CPUAffinity {
            mask |= 1 << cpu
        }
        info.BasicLimitInformation.Affinity = mask
    }
    
    err = setInformationJobObject(
        handle,
        JobObjectExtendedLimitInformation,
        unsafe.Pointer(&info),
        uint32(unsafe.Sizeof(info)),
    )
    if err != nil {
        windows.CloseHandle(handle)
        return nil, err
    }
    
    // Apply CPU rate control (Windows 8+)
    if config.MaxCPUPercent > 0 {
        var cpuInfo JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
        cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                               JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        cpuInfo.CpuRate = config.MaxCPUPercent * 100 // In 100ths of a percent
        
        setInformationJobObject(
            handle,
            JobObjectCpuRateControlInformation,
            unsafe.Pointer(&cpuInfo),
            uint32(unsafe.Sizeof(cpuInfo)),
        )
    }
    
    return job, nil
}

type WindowsJobObject struct {
    handle windows.Handle
}

func (j *WindowsJobObject) AssignProcess(pid int) error {
    procHandle, err := windows.OpenProcess(
        windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
        false,
        uint32(pid),
    )
    if err != nil {
        return err
    }
    defer windows.CloseHandle(procHandle)
    
    return windows.AssignProcessToJobObject(j.handle, procHandle)
}

func (j *WindowsJobObject) Release() error {
    return windows.CloseHandle(j.handle)
}

func (j *WindowsJobObject) Stats() ResourceStats {
    var info JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION
    
    queryInformationJobObject(
        j.handle,
        JobObjectBasicAndIoAccountingInformation,
        unsafe.Pointer(&info),
        uint32(unsafe.Sizeof(info)),
        nil,
    )
    
    return ResourceStats{
        CPUTimeMs:       info.BasicInfo.TotalUserTime / 10000,
        MemoryPeakBytes: 0, // Need separate query
        IOReadBytes:     info.IoInfo.ReadTransferCount,
        IOWriteBytes:    info.IoInfo.WriteTransferCount,
    }
}
```

---

## 6. Windows WSL2 Implementation

### 6.1 Overview

WSL2 runs a real Linux kernel in a lightweight VM, providing full Linux capabilities. This is the recommended approach for Windows users needing maximum security.

### 6.2 Capabilities

```go
// pkg/platform/windows_wsl2.go
// +build windows

package platform

import (
    "bytes"
    "fmt"
    "os/exec"
    "strings"
)

type WindowsWSL2Platform struct {
    distro string
    inner  Platform // Linux platform running inside WSL2
}

func NewWindowsWSL2Platform() (*WindowsWSL2Platform, error) {
    p := &WindowsWSL2Platform{
        distro: "Ubuntu-24.04",
    }
    
    // Check WSL2 availability
    if !p.checkWSL2() {
        return nil, fmt.Errorf("WSL2 not available. Enable with: wsl --install")
    }
    
    // Check if our distro is installed
    if !p.distroExists() {
        if err := p.installDistro(); err != nil {
            return nil, err
        }
    }
    
    // Ensure agentsh is installed in WSL2
    if err := p.ensureAgentshInstalled(); err != nil {
        return nil, err
    }
    
    return p, nil
}

func (p *WindowsWSL2Platform) Name() string {
    return "windows-wsl2"
}

func (p *WindowsWSL2Platform) Capabilities() Capabilities {
    // WSL2 runs real Linux, so we get full Linux capabilities
    return Capabilities{
        HasFUSE:              true,
        FUSEImplementation:   "fuse3",
        HasNetworkIntercept:  true,
        NetworkImplementation: "iptables",
        CanRedirectTraffic:   true,
        CanInspectTLS:        true,
        HasMountNamespace:    true,
        HasNetworkNamespace:  true,
        HasPIDNamespace:      true,
        HasUserNamespace:     true,
        IsolationLevel:       IsolationFull,
        HasSeccomp:           true,
        HasCgroups:           true,
        CanLimitCPU:          true,
        CanLimitMemory:       true,
        CanLimitDiskIO:       true,
        CanLimitNetworkBW:    true,
        CanLimitProcessCount: true,
    }
}

func (p *WindowsWSL2Platform) checkWSL2() bool {
    cmd := exec.Command("wsl", "--status")
    output, err := cmd.CombinedOutput()
    if err != nil {
        return false
    }
    return strings.Contains(string(output), "Default Version: 2") ||
           strings.Contains(string(output), "WSL version")
}

func (p *WindowsWSL2Platform) distroExists() bool {
    cmd := exec.Command("wsl", "-l", "-q")
    output, _ := cmd.Output()
    return strings.Contains(string(output), p.distro)
}

func (p *WindowsWSL2Platform) installDistro() error {
    cmd := exec.Command("wsl", "--install", "-d", p.distro)
    return cmd.Run()
}

func (p *WindowsWSL2Platform) ensureAgentshInstalled() error {
    // Check if agentsh exists in WSL2
    cmd := p.wslCommand("which", "agentsh")
    if err := cmd.Run(); err != nil {
        // Install agentsh
        install := p.wslCommand("bash", "-c", "curl -fsSL https://get.agentsh.dev | bash")
        return install.Run()
    }
    return nil
}

func (p *WindowsWSL2Platform) wslCommand(args ...string) *exec.Cmd {
    wslArgs := append([]string{"-d", p.distro, "--"}, args...)
    return exec.Command("wsl", wslArgs...)
}

// ExecuteInWSL runs a command inside WSL2 and returns the result
func (p *WindowsWSL2Platform) ExecuteInWSL(cmd string, args ...string) (string, error) {
    command := p.wslCommand(append([]string{cmd}, args...)...)
    var stdout, stderr bytes.Buffer
    command.Stdout = &stdout
    command.Stderr = &stderr
    
    err := command.Run()
    if err != nil {
        return "", fmt.Errorf("%s: %w", stderr.String(), err)
    }
    
    return stdout.String(), nil
}

// Delegate to Linux implementation running in WSL2
func (p *WindowsWSL2Platform) Filesystem() FilesystemInterceptor {
    return &WSL2FilesystemProxy{platform: p}
}

func (p *WindowsWSL2Platform) Network() NetworkInterceptor {
    return &WSL2NetworkProxy{platform: p}
}

func (p *WindowsWSL2Platform) Sandbox() SandboxManager {
    return &WSL2SandboxProxy{platform: p}
}

func (p *WindowsWSL2Platform) Resources() ResourceLimiter {
    return &WSL2ResourcesProxy{platform: p}
}
```

### 6.3 WSL2 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Windows Host                                     │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    agentsh Windows Wrapper                       │   │
│  │              (API server, forwards to WSL2)                      │   │
│  └───────────────────────────┬─────────────────────────────────────┘   │
│                              │ WSL interop                              │
│  ┌───────────────────────────┼─────────────────────────────────────┐   │
│  │                      WSL2 VM (Linux)                             │   │
│  │                           │                                      │   │
│  │  ┌────────────────────────┴────────────────────────────────┐    │   │
│  │  │                    agentsh (Linux)                       │    │   │
│  │  │                                                          │    │   │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  │    │   │
│  │  │  │   FUSE   │  │ iptables │  │Namespaces│  │ seccomp │  │    │   │
│  │  │  │    ✅    │  │    ✅    │  │    ✅    │  │   ✅    │  │    │   │
│  │  │  └──────────┘  └──────────┘  └──────────┘  └─────────┘  │    │   │
│  │  │                                                          │    │   │
│  │  │  ┌──────────────────────────────────────────────────┐   │    │   │
│  │  │  │              cgroups v2 (resource limits)         │   │    │   │
│  │  │  │                        ✅                         │   │    │   │
│  │  │  └──────────────────────────────────────────────────┘   │    │   │
│  │  └──────────────────────────────────────────────────────────┘    │   │
│  │                                                                  │   │
│  │                  /mnt/c (Windows filesystem access)             │   │
│  │                  /mnt/d, /mnt/e, etc.                           │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Windows Filesystem                            │   │
│  │                  C:\Users\...\workspace                          │   │
│  │              (accessible from WSL2 as /mnt/c/...)                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.4 Path Translation

```go
// pkg/platform/windows_wsl2_paths.go
// +build windows

package platform

import (
    "path/filepath"
    "strings"
)

// WindowsToWSLPath converts a Windows path to WSL path
func WindowsToWSLPath(winPath string) string {
    // C:\Users\foo -> /mnt/c/Users/foo
    if len(winPath) >= 2 && winPath[1] == ':' {
        drive := strings.ToLower(string(winPath[0]))
        rest := filepath.ToSlash(winPath[2:])
        return "/mnt/" + drive + rest
    }
    return filepath.ToSlash(winPath)
}

// WSLToWindowsPath converts a WSL path to Windows path
func WSLToWindowsPath(wslPath string) string {
    // /mnt/c/Users/foo -> C:\Users\foo
    if strings.HasPrefix(wslPath, "/mnt/") && len(wslPath) >= 6 {
        drive := strings.ToUpper(string(wslPath[5]))
        rest := wslPath[6:]
        return drive + ":" + filepath.FromSlash(rest)
    }
    return filepath.FromSlash(wslPath)
}
```

---

## 7. Environment Variable Protection (Cross-Platform)

### 7.1 Overview

Environment variables are a critical attack vector for AI agents. Agents may attempt to:
- Read API keys, tokens, and secrets from environment variables
- Enumerate all environment variables to discover sensitive data
- Use environment variables to exfiltrate data or modify behavior

agentsh implements a multi-layer defense:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Environment Variable Protection Layers                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Layer 1: Process Creation Filtering (All Platforms)                        │
│  ├── Allowlist of permitted environment variables                           │
│  ├── Blocklist of sensitive patterns (API_KEY, TOKEN, SECRET, etc.)         │
│  └── Only approved vars passed to child process                             │
│                                                                              │
│  Layer 2: Runtime Interception (Platform-Specific)                          │
│  ├── Linux: LD_PRELOAD shim intercepting getenv(), environ                  │
│  ├── macOS: DYLD_INSERT_LIBRARIES (with SIP limitations)                    │
│  └── Windows: Detours/IAT hooking for GetEnvironmentVariable*               │
│                                                                              │
│  Layer 3: Monitoring & Alerting                                             │
│  └── Log all environment variable access attempts                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Platform Comparison

| Feature | Linux | macOS FUSE-T | macOS ESF | Windows Native | Windows WSL2 |
|---------|:-----:|:------------:|:---------:|:--------------:|:------------:|
| **Layer 1: Creation Filtering** |
| Control env at spawn | ✅ | ✅ | ✅ | ✅ | ✅ |
| Allowlist enforcement | ✅ | ✅ | ✅ | ✅ | ✅ |
| Secret redaction | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Layer 2: Runtime Interception** |
| Shim injection | ✅ LD_PRELOAD | ⚠️ DYLD* | ❌ | ⚠️ Detours | ✅ LD_PRELOAD |
| getenv() interception | ✅ | ⚠️ Non-SIP | ❌ | ⚠️ | ✅ |
| environ enumeration block | ✅ | ⚠️ Non-SIP | ❌ | ⚠️ | ✅ |
| **Layer 3: Monitoring** |
| Access logging | ✅ | ✅ | ✅ ESF | ✅ | ✅ |
| Alert on sensitive access | ✅ | ✅ | ✅ | ✅ | ✅ |

**Legend:** ✅ Full support | ⚠️ Partial/Limited | ❌ Not available

### 7.3 Cross-Platform Implementation

#### 7.3.1 Environment Policy Configuration

```go
// pkg/envprotect/policy.go

package envprotect

import (
    "regexp"
    "strings"
)

// EnvPolicy defines which environment variables are allowed/blocked
type EnvPolicy struct {
    // Mode: "allowlist" (default, most secure) or "blocklist"
    Mode string `yaml:"mode"`
    
    // Allowlist: only these vars (and patterns) are passed through
    Allowlist []string `yaml:"allowlist"`
    
    // Blocklist: these vars are always blocked (even if in allowlist)
    Blocklist []string `yaml:"blocklist"`
    
    // Patterns for sensitive variable detection
    SensitivePatterns []string `yaml:"sensitive_patterns"`
    
    // Redact: replace value with placeholder instead of removing
    RedactInsteadOfRemove bool `yaml:"redact_instead_of_remove"`
    
    // RedactPlaceholder: value to use when redacting
    RedactPlaceholder string `yaml:"redact_placeholder"`
    
    // LogAccess: log all environment variable access attempts
    LogAccess bool `yaml:"log_access"`
    
    // AlertOnSensitive: alert when sensitive vars are accessed
    AlertOnSensitive bool `yaml:"alert_on_sensitive"`
}

// LoadPolicy loads environment policy from configuration file
// No hardcoded defaults - all rules must be explicitly configured
func LoadPolicy(configPath string) (*EnvPolicy, error) {
    data, err := os.ReadFile(configPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read env policy: %w", err)
    }
    
    var policy EnvPolicy
    if err := yaml.Unmarshal(data, &policy); err != nil {
        return nil, fmt.Errorf("failed to parse env policy: %w", err)
    }
    
    // Validate required fields
    if policy.Mode == "" {
        return nil, fmt.Errorf("env policy must specify mode (allowlist or blocklist)")
    }
    if policy.Mode == "allowlist" && len(policy.Allowlist) == 0 {
        return nil, fmt.Errorf("allowlist mode requires at least one allowed pattern")
    }
    
    // Set defaults for optional fields
    if policy.RedactPlaceholder == "" {
        policy.RedactPlaceholder = "[REDACTED]"
    }
    
    return &policy, nil
}

// MustLoadPolicy loads policy or panics - use during startup
func MustLoadPolicy(configPath string) *EnvPolicy {
    policy, err := LoadPolicy(configPath)
    if err != nil {
        panic(fmt.Sprintf("failed to load env policy: %v", err))
    }
    return policy
}

// EnvFilter applies policy to filter environment variables
type EnvFilter struct {
    policy            *EnvPolicy
    compiledAllowlist []*regexp.Regexp
    compiledBlocklist []*regexp.Regexp
    compiledSensitive []*regexp.Regexp
    eventChan         chan<- EnvAccessEvent
}

type EnvAccessEvent struct {
    Timestamp   time.Time
    Variable    string
    Operation   string  // "read", "enumerate", "blocked"
    Allowed     bool
    Sensitive   bool
    ProcessID   int
    ProcessName string
}

func NewEnvFilter(policy *EnvPolicy, eventChan chan<- EnvAccessEvent) (*EnvFilter, error) {
    f := &EnvFilter{
        policy:    policy,
        eventChan: eventChan,
    }
    
    // Compile allowlist patterns
    for _, pattern := range policy.Allowlist {
        re, err := patternToRegex(pattern)
        if err != nil {
            return nil, fmt.Errorf("invalid allowlist pattern %q: %w", pattern, err)
        }
        f.compiledAllowlist = append(f.compiledAllowlist, re)
    }
    
    // Compile blocklist patterns
    for _, pattern := range policy.Blocklist {
        re, err := patternToRegex(pattern)
        if err != nil {
            return nil, fmt.Errorf("invalid blocklist pattern %q: %w", pattern, err)
        }
        f.compiledBlocklist = append(f.compiledBlocklist, re)
    }
    
    // Compile sensitive patterns
    for _, pattern := range policy.SensitivePatterns {
        re, err := regexp.Compile(pattern)
        if err != nil {
            return nil, fmt.Errorf("invalid sensitive pattern %q: %w", pattern, err)
        }
        f.compiledSensitive = append(f.compiledSensitive, re)
    }
    
    return f, nil
}

// patternToRegex converts glob-like patterns to regex
func patternToRegex(pattern string) (*regexp.Regexp, error) {
    // Escape special regex chars except *
    escaped := regexp.QuoteMeta(pattern)
    // Convert * to .*
    escaped = strings.ReplaceAll(escaped, `\*`, `.*`)
    // Anchor pattern
    return regexp.Compile("^" + escaped + "$")
}

// FilterEnvironment filters a map of environment variables
func (f *EnvFilter) FilterEnvironment(env map[string]string) map[string]string {
    filtered := make(map[string]string)
    
    for name, value := range env {
        allowed, sensitive := f.CheckVariable(name)
        
        if !allowed {
            if f.policy.LogAccess {
                f.eventChan <- EnvAccessEvent{
                    Timestamp: time.Now(),
                    Variable:  name,
                    Operation: "blocked",
                    Allowed:   false,
                    Sensitive: sensitive,
                }
            }
            continue
        }
        
        if sensitive && f.policy.RedactInsteadOfRemove {
            filtered[name] = f.policy.RedactPlaceholder
        } else if sensitive {
            // Block sensitive vars entirely
            continue
        } else {
            filtered[name] = value
        }
    }
    
    return filtered
}

// CheckVariable checks if a variable name is allowed
func (f *EnvFilter) CheckVariable(name string) (allowed bool, sensitive bool) {
    // Check if sensitive first
    for _, re := range f.compiledSensitive {
        if re.MatchString(name) {
            sensitive = true
            break
        }
    }
    
    // Check blocklist (always wins)
    for _, re := range f.compiledBlocklist {
        if re.MatchString(name) {
            return false, sensitive
        }
    }
    
    // In allowlist mode, must match allowlist
    if f.policy.Mode == "allowlist" {
        for _, re := range f.compiledAllowlist {
            if re.MatchString(name) {
                return true, sensitive
            }
        }
        return false, sensitive
    }
    
    // In blocklist mode, allow if not blocked
    return true, sensitive
}

// GetFilteredEnvSlice returns environment as []string for exec.Cmd.Env
func (f *EnvFilter) GetFilteredEnvSlice(env map[string]string) []string {
    filtered := f.FilterEnvironment(env)
    result := make([]string, 0, len(filtered))
    for k, v := range filtered {
        result = append(result, k+"="+v)
    }
    return result
}
```

#### 7.3.2 Process Spawning with Env Filtering

```go
// pkg/envprotect/spawn.go

package envprotect

import (
    "context"
    "os"
    "os/exec"
)

// SecureSpawner wraps exec.Cmd with environment filtering
type SecureSpawner struct {
    filter *EnvFilter
    logger *zap.Logger
}

func NewSecureSpawner(policy *EnvPolicy, eventChan chan<- EnvAccessEvent, logger *zap.Logger) (*SecureSpawner, error) {
    filter, err := NewEnvFilter(policy, eventChan)
    if err != nil {
        return nil, err
    }
    return &SecureSpawner{filter: filter, logger: logger}, nil
}

// Command creates a new exec.Cmd with filtered environment
func (s *SecureSpawner) Command(ctx context.Context, name string, args ...string) *exec.Cmd {
    cmd := exec.CommandContext(ctx, name, args...)
    
    // Get current environment as map
    currentEnv := make(map[string]string)
    for _, env := range os.Environ() {
        parts := strings.SplitN(env, "=", 2)
        if len(parts) == 2 {
            currentEnv[parts[0]] = parts[1]
        }
    }
    
    // Apply filtering
    cmd.Env = s.filter.GetFilteredEnvSlice(currentEnv)
    
    // Log what was filtered
    original := len(currentEnv)
    filtered := len(cmd.Env)
    if original != filtered {
        s.logger.Info("Environment filtered for command",
            zap.String("command", name),
            zap.Int("original_vars", original),
            zap.Int("allowed_vars", filtered),
            zap.Int("blocked_vars", original-filtered),
        )
    }
    
    return cmd
}

// CommandWithEnv creates a command with additional env vars (also filtered)
func (s *SecureSpawner) CommandWithEnv(ctx context.Context, extraEnv map[string]string, name string, args ...string) *exec.Cmd {
    cmd := s.Command(ctx, name, args...)
    
    // Filter and add extra env vars
    for k, v := range s.filter.FilterEnvironment(extraEnv) {
        cmd.Env = append(cmd.Env, k+"="+v)
    }
    
    return cmd
}
```

### 7.4 Linux: LD_PRELOAD Shim

The most comprehensive protection on Linux, intercepting runtime access to environment variables.

```c
// shim/linux/envshim.c
// Compile: gcc -shared -fPIC -o libenvshim.so envshim.c -ldl

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

// Socket path for communicating with agentsh daemon
#define AGENTSH_SOCKET "/tmp/agentsh-env.sock"

// Original function pointers
static char* (*original_getenv)(const char*) = NULL;
static int (*original_putenv)(char*) = NULL;
static int (*original_setenv)(const char*, const char*, int) = NULL;
static int (*original_unsetenv)(const char*) = NULL;

// Cached policy (loaded from agentsh daemon)
static char** allowed_vars = NULL;
static int allowed_count = 0;
static char** blocked_patterns = NULL;
static int blocked_count = 0;
static int policy_loaded = 0;

// Logging socket
static int log_socket = -1;

__attribute__((constructor))
static void init_shim(void) {
    // Load original functions
    original_getenv = dlsym(RTLD_NEXT, "getenv");
    original_putenv = dlsym(RTLD_NEXT, "putenv");
    original_setenv = dlsym(RTLD_NEXT, "setenv");
    original_unsetenv = dlsym(RTLD_NEXT, "unsetenv");
    
    // Connect to agentsh daemon to get policy
    load_policy_from_daemon();
    
    // Open logging socket
    log_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (log_socket >= 0) {
        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, AGENTSH_SOCKET, sizeof(addr.sun_path) - 1);
        connect(log_socket, (struct sockaddr*)&addr, sizeof(addr));
    }
}

static void load_policy_from_daemon(void) {
    // Read policy from environment (set by agentsh before exec)
    const char* policy = original_getenv("__AGENTSH_ENV_POLICY");
    if (!policy) {
        policy_loaded = 0;
        return;
    }
    
    // Parse policy from file or IPC
    // Policy format in /etc/agentsh/env-policy.conf or received via socket
    // ... parsing implementation
    
    policy_loaded = 1;
}

// Sensitive patterns loaded from policy file
static char** sensitive_patterns = NULL;
static int sensitive_count = 0;

static void load_sensitive_patterns(void) {
    // Load from policy file: /etc/agentsh/env-policy.conf
    // Format: sensitive_patterns=KEY,TOKEN,SECRET,PASSWORD
    // No hardcoded defaults - must be configured
    FILE* f = fopen("/etc/agentsh/env-policy.conf", "r");
    if (!f) return;
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "sensitive_patterns=", 19) == 0) {
            char* patterns = line + 19;
            // Parse comma-separated patterns
            char* token = strtok(patterns, ",\n");
            while (token && sensitive_count < 64) {
                sensitive_patterns = realloc(sensitive_patterns, 
                    (sensitive_count + 1) * sizeof(char*));
                sensitive_patterns[sensitive_count++] = strdup(token);
                token = strtok(NULL, ",\n");
            }
        }
    }
    fclose(f);
}

static int is_sensitive(const char* name) {
    // No hardcoded patterns - check against policy-defined patterns only
    if (sensitive_count == 0) return 0;
    
    char upper[256];
    strncpy(upper, name, sizeof(upper) - 1);
    for (char* p = upper; *p; p++) *p = toupper(*p);
    
    for (int i = 0; i < sensitive_count; i++) {
        if (strstr(upper, sensitive_patterns[i])) return 1;
    }
    return 0;
}

static int is_var_allowed(const char* name) {
    if (!policy_loaded) {
        return 1; // Allow all if no policy
    }
    
    // Check blocked patterns first
    for (int i = 0; i < blocked_count; i++) {
        if (match_pattern(name, blocked_patterns[i])) {
            return 0;
        }
    }
    
    // Check allowlist
    for (int i = 0; i < allowed_count; i++) {
        if (match_pattern(name, allowed_vars[i])) {
            return 1;
        }
    }
    
    return 0; // Default deny in allowlist mode
}

static int match_pattern(const char* str, const char* pattern) {
    // Simple glob matching for * wildcards
    while (*pattern) {
        if (*pattern == '*') {
            pattern++;
            if (!*pattern) return 1;
            while (*str) {
                if (match_pattern(str, pattern)) return 1;
                str++;
            }
            return 0;
        }
        if (*str != *pattern) return 0;
        str++;
        pattern++;
    }
    return !*str;
}

// Emit structured event to agentsh daemon
static void emit_env_event(const char* var, const char* op, int allowed, int sensitive) {
    if (log_socket < 0) return;
    
    // Get timestamp
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    // Map operation to event type
    const char* event_type;
    if (strcmp(op, "read") == 0) event_type = "env_read";
    else if (strcmp(op, "list") == 0) event_type = "env_list";
    else if (strcmp(op, "write") == 0) event_type = "env_write";
    else if (strcmp(op, "delete") == 0) event_type = "env_delete";
    else event_type = "env_read";
    
    char msg[1024];
    snprintf(msg, sizeof(msg),
        "{"
        "\"type\":\"%s\","
        "\"timestamp\":\"%ld.%09ld\","
        "\"decision\":\"%s\","
        "\"platform\":\"linux-ld-preload\","
        "\"metadata\":{"
            "\"variable\":\"%s\","
            "\"operation\":\"%s\","
            "\"sensitive\":%s,"
            "\"blocked\":%s,"
            "\"pid\":%d,"
            "\"source\":\"shim\""
        "}"
        "}",
        event_type,
        ts.tv_sec, ts.tv_nsec,
        allowed ? "allow" : "deny",
        var ? var : "*",
        op,
        sensitive ? "true" : "false",
        allowed ? "false" : "true",
        getpid()
    );
    
    send(log_socket, msg, strlen(msg), MSG_DONTWAIT);
}

// Intercepted getenv - emits env_read event
char* getenv(const char* name) {
    if (!name) return NULL;
    
    int sensitive = is_sensitive(name);
    int allowed = is_var_allowed(name);
    
    emit_env_event(name, "read", allowed, sensitive);
    
    if (!allowed) {
        return NULL; // Return as if variable doesn't exist
    }
    
    return original_getenv(name);
}

// Intercepted setenv - emits env_write event
int setenv(const char* name, const char* value, int overwrite) {
    if (!name) return -1;
    
    int sensitive = is_sensitive(name);
    int allowed = is_var_allowed(name);
    
    emit_env_event(name, "write", allowed, sensitive);
    
    if (!allowed) {
        errno = EPERM;
        return -1;
    }
    
    return original_setenv(name, value, overwrite);
}

// Intercepted unsetenv - emits env_delete event
int unsetenv(const char* name) {
    if (!name) return -1;
    
    int sensitive = is_sensitive(name);
    emit_env_event(name, "delete", 1, sensitive); // Always allow delete
    
    return original_unsetenv(name);
}

// Intercept environ enumeration by hiding the symbol
// This requires a more complex approach - see below
```

#### 7.4.1 Blocking environ Enumeration

```c
// shim/linux/environ_protect.c
// This prevents direct access to the environ array and emits env_list event

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// We can't easily hide `environ` since it's a global symbol
// Instead, we use a constructor to filter it in-place

extern char** environ;
extern int log_socket;  // From main shim

static char** original_environ = NULL;
static char** filtered_environ = NULL;
static int list_total_count = 0;
static int list_blocked_count = 0;

// Emit env_list event when environ is accessed
static void emit_env_list_event(int total, int blocked) {
    if (log_socket < 0) return;
    
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    char msg[1024];
    snprintf(msg, sizeof(msg),
        "{"
        "\"type\":\"env_list\","
        "\"timestamp\":\"%ld.%09ld\","
        "\"decision\":\"allow\","
        "\"platform\":\"linux-ld-preload\","
        "\"metadata\":{"
            "\"variable\":\"*\","
            "\"operation\":\"list\","
            "\"sensitive\":false,"
            "\"blocked\":false,"
            "\"list_count\":%d,"
            "\"list_blocked\":%d,"
            "\"pid\":%d,"
            "\"source\":\"shim\""
        "}"
        "}",
        ts.tv_sec, ts.tv_nsec,
        total - blocked,  // Visible count
        blocked,
        getpid()
    );
    
    send(log_socket, msg, strlen(msg), MSG_DONTWAIT);
}

__attribute__((constructor(101))) // Run early
static void filter_environ(void) {
    if (!environ) return;
    
    // Count variables
    int count = 0;
    for (char** e = environ; *e; e++) count++;
    
    // Save original (for internal use)
    original_environ = environ;
    
    // Create filtered copy
    filtered_environ = calloc(count + 1, sizeof(char*));
    
    int j = 0;
    int blocked = 0;
    for (int i = 0; i < count; i++) {
        char* var = environ[i];
        char* eq = strchr(var, '=');
        if (!eq) continue;
        
        // Extract name
        size_t name_len = eq - var;
        char name[256];
        if (name_len >= sizeof(name)) continue;
        strncpy(name, var, name_len);
        name[name_len] = '\0';
        
        // Check if allowed
        if (is_var_allowed(name)) {
            filtered_environ[j++] = var;
        } else {
            blocked++;
        }
    }
    filtered_environ[j] = NULL;
    
    // Store counts for event emission
    list_total_count = count;
    list_blocked_count = blocked;
    
    // Emit event that environ was filtered
    emit_env_list_event(count, blocked);
    
    // Replace environ with filtered version
    environ = filtered_environ;
}

// Allow agentsh internal code to access original
char** __agentsh_get_original_environ(void) {
    return original_environ;
}

// Hook for explicit enumeration via library calls
// Some programs use getenv in a loop or call specific enumeration functions
```

### 7.5 macOS: DYLD_INSERT_LIBRARIES

Similar to LD_PRELOAD but with System Integrity Protection (SIP) limitations.

```c
// shim/darwin/envshim.c
// Compile: clang -dynamiclib -o libenvshim.dylib envshim.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

// On macOS, we use interposing
typedef struct {
    const void* replacement;
    const void* replacee;
} interpose_t;

static char* hooked_getenv(const char* name);

__attribute__((used))
static const interpose_t interposers[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void*)hooked_getenv, (const void*)getenv },
};

// Policy checking (same as Linux)
static int is_var_allowed(const char* name);

static char* hooked_getenv(const char* name) {
    if (!name) return NULL;
    
    if (!is_var_allowed(name)) {
        log_blocked_access(name);
        return NULL;
    }
    
    return getenv(name); // Call through interpose
}
```

#### 7.5.1 macOS SIP Limitations

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    macOS DYLD_INSERT_LIBRARIES Limitations                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  SIP (System Integrity Protection) BLOCKS injection for:                     │
│  ├── /usr/bin/*           (system utilities)                                │
│  ├── /bin/*               (core utilities)                                  │
│  ├── /sbin/*              (system admin)                                    │
│  ├── /System/*            (system frameworks)                               │
│  └── Any Apple-signed binary with hardened runtime                          │
│                                                                              │
│  WORKS for:                                                                  │
│  ├── /usr/local/bin/*     (Homebrew, user-installed)                        │
│  ├── ~/Applications/*     (user apps)                                       │
│  ├── /opt/*               (optional software)                               │
│  └── Scripts and interpreters (python, node, etc.)                          │
│                                                                              │
│  Workarounds:                                                                │
│  ├── 1. Use wrapper scripts that set up filtered env before exec            │
│  ├── 2. For system binaries, rely on process creation filtering only        │
│  └── 3. Use Endpoint Security Framework (requires entitlements)             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 7.5.2 macOS Wrapper Approach

For system binaries where DYLD_INSERT_LIBRARIES doesn't work:

```go
// pkg/envprotect/darwin_wrapper.go
// +build darwin

package envprotect

import (
    "os"
    "os/exec"
    "path/filepath"
    "strings"
)

// DarwinEnvWrapper wraps commands to filter environment
type DarwinEnvWrapper struct {
    filter *EnvFilter
    logger *zap.Logger
}

// WrapCommand wraps a command with environment filtering
// For SIP-protected binaries, we can't use DYLD_INSERT_LIBRARIES
// Instead, we filter at spawn time only
func (w *DarwinEnvWrapper) WrapCommand(cmd *exec.Cmd) *exec.Cmd {
    // Check if binary is SIP-protected
    if w.isSIPProtected(cmd.Path) {
        w.logger.Debug("SIP-protected binary, using spawn-time filtering only",
            zap.String("path", cmd.Path),
        )
        // Filtering already applied via SecureSpawner
        return cmd
    }
    
    // For non-SIP binaries, add DYLD_INSERT_LIBRARIES
    shimPath := w.getShimPath()
    if shimPath != "" {
        cmd.Env = append(cmd.Env, "DYLD_INSERT_LIBRARIES="+shimPath)
        
        // Pass policy to shim
        policyStr := w.filter.PolicyToString()
        cmd.Env = append(cmd.Env, "__AGENTSH_ENV_POLICY="+policyStr)
    }
    
    return cmd
}

func (w *DarwinEnvWrapper) isSIPProtected(path string) bool {
    // SIP-protected paths
    sipPaths := []string{
        "/usr/bin/",
        "/bin/",
        "/sbin/",
        "/usr/sbin/",
        "/System/",
    }
    
    absPath, err := filepath.Abs(path)
    if err != nil {
        return true // Assume protected if can't resolve
    }
    
    // Resolve symlinks
    realPath, err := filepath.EvalSymlinks(absPath)
    if err != nil {
        realPath = absPath
    }
    
    for _, prefix := range sipPaths {
        if strings.HasPrefix(realPath, prefix) {
            return true
        }
    }
    
    return false
}

func (w *DarwinEnvWrapper) getShimPath() string {
    // Check standard locations
    paths := []string{
        "/usr/local/lib/agentsh/libenvshim.dylib",
        "/opt/homebrew/lib/agentsh/libenvshim.dylib",
    }
    
    for _, p := range paths {
        if _, err := os.Stat(p); err == nil {
            return p
        }
    }
    
    return ""
}
```

### 7.6 Windows: API Hooking with Detours

Windows doesn't have LD_PRELOAD, but we can use Microsoft Detours or similar libraries.

```cpp
// shim/windows/envshim.cpp
// Compile with: cl /LD envshim.cpp detours.lib

#include <windows.h>
#include <detours.h>
#include <string>
#include <vector>
#include <regex>

// Original function pointers
static DWORD (WINAPI *TrueGetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD) = GetEnvironmentVariableA;
static DWORD (WINAPI *TrueGetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD) = GetEnvironmentVariableW;
static LPCH (WINAPI *TrueGetEnvironmentStrings)(void) = GetEnvironmentStrings;
static LPWCH (WINAPI *TrueGetEnvironmentStringsW)(void) = GetEnvironmentStringsW;

// Policy
static std::vector<std::wregex> blockedPatterns;
static std::vector<std::wregex> allowedPatterns;
static bool policyLoaded = false;

// Convert string to wstring
std::wstring ToWide(const char* str) {
    if (!str) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    std::wstring result(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, str, -1, &result[0], len);
    return result;
}

bool IsVarAllowed(const std::wstring& name) {
    if (!policyLoaded) return true;
    
    // Check blocked first
    for (const auto& pattern : blockedPatterns) {
        if (std::regex_match(name, pattern)) {
            return false;
        }
    }
    
    // Check allowed
    for (const auto& pattern : allowedPatterns) {
        if (std::regex_match(name, pattern)) {
            return true;
        }
    }
    
    return false; // Default deny
}

void LogAccess(const wchar_t* name, const char* op, bool allowed) {
    // Send to agentsh daemon via named pipe
    HANDLE pipe = CreateFileW(
        L"\\\\.\\pipe\\agentsh-env",
        GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    if (pipe != INVALID_HANDLE_VALUE) {
        wchar_t msg[512];
        swprintf(msg, 512, L"{\"var\":\"%s\",\"op\":\"%S\",\"allowed\":%s}",
                 name, op, allowed ? L"true" : L"false");
        DWORD written;
        WriteFile(pipe, msg, wcslen(msg) * sizeof(wchar_t), &written, NULL);
        CloseHandle(pipe);
    }
}

// Hooked GetEnvironmentVariableA
DWORD WINAPI HookedGetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
    std::wstring wname = ToWide(lpName);
    bool allowed = IsVarAllowed(wname);
    LogAccess(wname.c_str(), "GetEnvironmentVariableA", allowed);
    
    if (!allowed) {
        SetLastError(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    }
    
    return TrueGetEnvironmentVariableA(lpName, lpBuffer, nSize);
}

// Hooked GetEnvironmentVariableW
DWORD WINAPI HookedGetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) {
    bool allowed = IsVarAllowed(lpName);
    LogAccess(lpName, "GetEnvironmentVariableW", allowed);
    
    if (!allowed) {
        SetLastError(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    }
    
    return TrueGetEnvironmentVariableW(lpName, lpBuffer, nSize);
}

// Hooked GetEnvironmentStringsW - filters the entire environment block
LPWCH WINAPI HookedGetEnvironmentStringsW(void) {
    LPWCH original = TrueGetEnvironmentStringsW();
    if (!original || !policyLoaded) return original;
    
    // Calculate size needed for filtered block
    std::vector<std::wstring> allowedVars;
    size_t totalSize = 0;
    
    LPWCH current = original;
    while (*current) {
        size_t len = wcslen(current);
        
        // Extract variable name
        const wchar_t* eq = wcschr(current, L'=');
        if (eq) {
            std::wstring name(current, eq - current);
            if (IsVarAllowed(name)) {
                allowedVars.push_back(current);
                totalSize += len + 1;
            }
        }
        
        current += len + 1;
    }
    totalSize++; // Final null
    
    // Build filtered block
    LPWCH filtered = (LPWCH)LocalAlloc(LMEM_FIXED, totalSize * sizeof(wchar_t));
    if (!filtered) return original;
    
    wchar_t* dest = filtered;
    for (const auto& var : allowedVars) {
        wcscpy(dest, var.c_str());
        dest += var.length() + 1;
    }
    *dest = L'\0';
    
    // Note: caller should free original, but we can't easily track this
    // In practice, most code doesn't free GetEnvironmentStrings result
    
    return filtered;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Load policy from environment or shared memory
        LoadPolicy();
        
        // Attach hooks
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueGetEnvironmentVariableA, HookedGetEnvironmentVariableA);
        DetourAttach(&(PVOID&)TrueGetEnvironmentVariableW, HookedGetEnvironmentVariableW);
        DetourAttach(&(PVOID&)TrueGetEnvironmentStringsW, HookedGetEnvironmentStringsW);
        DetourTransactionCommit();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        // Detach hooks
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueGetEnvironmentVariableA, HookedGetEnvironmentVariableA);
        DetourDetach(&(PVOID&)TrueGetEnvironmentVariableW, HookedGetEnvironmentVariableW);
        DetourDetach(&(PVOID&)TrueGetEnvironmentStringsW, HookedGetEnvironmentStringsW);
        DetourTransactionCommit();
    }
    return TRUE;
}
```

#### 7.6.1 Windows DLL Injection

```go
// pkg/envprotect/windows_inject.go
// +build windows

package envprotect

import (
    "fmt"
    "syscall"
    "unsafe"
    
    "golang.org/x/sys/windows"
)

var (
    kernel32           = windows.NewLazySystemDLL("kernel32.dll")
    procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
    procVirtualAllocEx = kernel32.NewProc("VirtualAllocEx")
    procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
)

// InjectEnvShim injects the environment shim DLL into a process
func InjectEnvShim(processHandle windows.Handle, dllPath string) error {
    // Allocate memory in target process for DLL path
    pathBytes := append([]byte(dllPath), 0)
    pathLen := len(pathBytes)
    
    remoteAddr, _, err := procVirtualAllocEx.Call(
        uintptr(processHandle),
        0,
        uintptr(pathLen),
        windows.MEM_COMMIT|windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    )
    if remoteAddr == 0 {
        return fmt.Errorf("VirtualAllocEx failed: %w", err)
    }
    
    // Write DLL path to target process
    var written uintptr
    ret, _, err := procWriteProcessMemory.Call(
        uintptr(processHandle),
        remoteAddr,
        uintptr(unsafe.Pointer(&pathBytes[0])),
        uintptr(pathLen),
        uintptr(unsafe.Pointer(&written)),
    )
    if ret == 0 {
        return fmt.Errorf("WriteProcessMemory failed: %w", err)
    }
    
    // Get LoadLibraryA address
    loadLibrary := kernel32.NewProc("LoadLibraryA").Addr()
    
    // Create remote thread to load DLL
    var threadId uint32
    ret, _, err = procCreateRemoteThread.Call(
        uintptr(processHandle),
        0,
        0,
        loadLibrary,
        remoteAddr,
        0,
        uintptr(unsafe.Pointer(&threadId)),
    )
    if ret == 0 {
        return fmt.Errorf("CreateRemoteThread failed: %w", err)
    }
    
    return nil
}

// WindowsSecureSpawner creates processes with env shim injected
type WindowsSecureSpawner struct {
    filter   *EnvFilter
    dllPath  string
    logger   *zap.Logger
}

func (s *WindowsSecureSpawner) SpawnWithEnvProtection(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
    // Create process suspended
    cmd := exec.CommandContext(ctx, name, args...)
    cmd.SysProcAttr = &syscall.SysProcAttr{
        CreationFlags: windows.CREATE_SUSPENDED,
    }
    
    // Apply env filtering at creation time
    cmd.Env = s.filter.GetFilteredEnvSlice(os.Environ())
    
    // Start process (suspended)
    if err := cmd.Start(); err != nil {
        return nil, err
    }
    
    // Inject DLL for runtime protection
    processHandle, err := windows.OpenProcess(
        windows.PROCESS_ALL_ACCESS,
        false,
        uint32(cmd.Process.Pid),
    )
    if err != nil {
        cmd.Process.Kill()
        return nil, fmt.Errorf("failed to open process: %w", err)
    }
    defer windows.CloseHandle(processHandle)
    
    if err := InjectEnvShim(processHandle, s.dllPath); err != nil {
        s.logger.Warn("Failed to inject env shim, continuing with spawn-time filtering only",
            zap.Error(err),
        )
    }
    
    // Resume process
    // (need to use NtResumeProcess or enumerate and resume threads)
    
    return cmd, nil
}
```

### 7.7 Configuration

```yaml
# agentsh.yaml - Environment protection section

env_protection:
  enabled: true
  
  # Mode: "allowlist" (most secure) or "blocklist"
  mode: allowlist
  
  # Allowed environment variables (glob patterns)
  allowlist:
    - PATH
    - HOME
    - USER
    - SHELL
    - TERM
    - LANG
    - LC_*
    - TZ
    - PWD
    - TMPDIR
    - EDITOR
    - VISUAL
    - AGENTSH_*
    
  # Always blocked (overrides allowlist)
  blocklist:
    - "*_KEY"
    - "*_TOKEN"
    - "*_SECRET"
    - "*_PASSWORD"
    - "*_CREDENTIAL*"
    - "AWS_*"
    - "AZURE_*"
    - "GCP_*"
    - "OPENAI_*"
    - "ANTHROPIC_*"
    - "GITHUB_TOKEN"
    - "DATABASE_URL"
    - "SSH_*"
    
  # Patterns that trigger alerts (regex)
  sensitive_patterns:
    - "(?i)api[_-]?key"
    - "(?i)secret"
    - "(?i)token"
    - "(?i)password"
    
  # Behavior options
  redact_instead_of_remove: false
  redact_placeholder: "[REDACTED]"
  
  # Logging
  log_all_access: true
  alert_on_sensitive: true
  
  # Platform-specific
  linux:
    use_ld_preload: true
    shim_path: /usr/local/lib/agentsh/libenvshim.so
    
  darwin:
    use_dyld_insert: true  # Only works for non-SIP binaries
    shim_path: /usr/local/lib/agentsh/libenvshim.dylib
    
  windows:
    use_detours: true
    shim_path: C:\Program Files\agentsh\envshim.dll
```

### 7.8 Environment Event Examples

**env_read - Blocked sensitive variable access:**
```json
{
  "type": "env_read",
  "timestamp": "2025-01-15T14:30:00.123456789Z",
  "decision": "deny",
  "platform": "linux-ld-preload",
  "metadata": {
    "variable": "OPENAI_API_KEY",
    "operation": "read",
    "sensitive": true,
    "blocked": true,
    "matched_policy": "*_KEY",
    "pid": 12345,
    "source": "shim"
  }
}
```

**env_read - Allowed system variable:**
```json
{
  "type": "env_read",
  "timestamp": "2025-01-15T14:30:00.234567890Z",
  "decision": "allow",
  "platform": "linux-ld-preload",
  "metadata": {
    "variable": "PATH",
    "operation": "read",
    "sensitive": false,
    "blocked": false,
    "pid": 12345,
    "source": "shim"
  }
}
```

**env_list - Environ enumeration (filtered):**
```json
{
  "type": "env_list",
  "timestamp": "2025-01-15T14:30:00.345678901Z",
  "decision": "allow",
  "platform": "linux-ld-preload",
  "metadata": {
    "variable": "*",
    "operation": "list",
    "sensitive": false,
    "blocked": false,
    "list_count": 15,
    "list_blocked": 8,
    "pid": 12345,
    "source": "shim"
  }
}
```

**env_write - Attempt to set sensitive variable:**
```json
{
  "type": "env_write",
  "timestamp": "2025-01-15T14:30:00.456789012Z",
  "decision": "deny",
  "platform": "linux-ld-preload",
  "metadata": {
    "variable": "AWS_SECRET_ACCESS_KEY",
    "operation": "write",
    "sensitive": true,
    "blocked": true,
    "matched_policy": "AWS_*",
    "pid": 12345,
    "source": "shim"
  }
}
```

**env_delete - Variable removal (logged but allowed):**
```json
{
  "type": "env_delete",
  "timestamp": "2025-01-15T14:30:00.567890123Z",
  "decision": "allow",
  "platform": "linux-ld-preload",
  "metadata": {
    "variable": "TEMP_VAR",
    "operation": "delete",
    "sensitive": false,
    "blocked": false,
    "pid": 12345,
    "source": "shim"
  }
}
```

**Spawn-time filtering event (Layer 1):**
```json
{
  "type": "env_list",
  "timestamp": "2025-01-15T14:30:00.678901234Z",
  "decision": "allow",
  "platform": "darwin-fuse-t",
  "metadata": {
    "variable": "*",
    "operation": "spawn_filter",
    "sensitive": false,
    "blocked": false,
    "list_count": 12,
    "list_blocked": 15,
    "command": "/usr/bin/python3",
    "args": ["script.py"],
    "source": "spawn"
  }
}
```

### 7.9 Redirect and Approval Event Examples

**File redirect - serving honeypot content:**
```json
{
  "type": "file_open",
  "timestamp": "2025-01-15T14:30:00.789012345Z",
  "decision": "redirect",
  "path": "/etc/passwd",
  "operation": "read",
  "redirected": true,
  "original_target": "/etc/passwd",
  "redirect_target": "/opt/agentsh/honeypot/fake-passwd",
  "policy_rule": "honeypot-passwd",
  "held_ms": 1,
  "pid": 12345,
  "process_name": "python3",
  "platform": "linux"
}
```

**Network redirect - routing to local mock:**
```json
{
  "type": "net_connect",
  "timestamp": "2025-01-15T14:30:00.890123456Z",
  "decision": "redirect",
  "protocol": "tcp",
  "remote_addr": "api.openai.com",
  "remote_port": 443,
  "redirected": true,
  "original_target": "api.openai.com:443",
  "redirect_target": "localhost:8080",
  "policy_rule": "redirect-openai",
  "held_ms": 2,
  "pid": 12345,
  "platform": "linux"
}
```

**DNS redirect - blocking C2 domain:**
```json
{
  "type": "dns_query",
  "timestamp": "2025-01-15T14:30:00.901234567Z",
  "decision": "redirect",
  "domain": "malware.evil.com",
  "redirected": true,
  "original_target": "malware.evil.com",
  "redirect_target": "127.0.0.1",
  "policy_rule": "block-c2",
  "held_ms": 1,
  "pid": 12345,
  "platform": "linux"
}
```

**Environment variable redirect - fake API key:**
```json
{
  "type": "env_read",
  "timestamp": "2025-01-15T14:30:00.012345678Z",
  "decision": "redirect",
  "redirected": true,
  "original_target": "OPENAI_API_KEY",
  "redirect_target": "sk-fake-key-for-testing-only",
  "policy_rule": "fake-openai-key",
  "metadata": {
    "variable": "OPENAI_API_KEY",
    "sensitive": true,
    "value_redacted": true
  },
  "platform": "linux-ld-preload"
}
```

**Manual approval - pending:**
```json
{
  "type": "file_delete",
  "timestamp": "2025-01-15T14:30:01.000000000Z",
  "decision": "pending",
  "path": "/workspace/important-data.db",
  "operation": "delete",
  "policy_rule": "require-approval-delete",
  "held_ms": 0,
  "approval_id": "appr_8x7k2m9n",
  "pid": 12345,
  "process_name": "python3",
  "platform": "linux",
  "metadata": {
    "approval_url": "http://localhost:9090/approve/appr_8x7k2m9n",
    "timeout_seconds": 300
  }
}
```

**Manual approval - approved:**
```json
{
  "type": "file_delete",
  "timestamp": "2025-01-15T14:30:45.000000000Z",
  "decision": "allow",
  "path": "/workspace/important-data.db",
  "operation": "delete",
  "policy_rule": "require-approval-delete",
  "held_ms": 44000,
  "approval_id": "appr_8x7k2m9n",
  "approved_by": "admin@example.com",
  "approval_latency_ns": 44000000000,
  "pid": 12345,
  "platform": "linux"
}
```

**Manual approval - denied:**
```json
{
  "type": "net_connect",
  "timestamp": "2025-01-15T14:31:30.000000000Z",
  "decision": "deny",
  "protocol": "tcp",
  "remote_addr": "unknown-server.com",
  "remote_port": 443,
  "policy_rule": "unknown-external",
  "held_ms": 15000,
  "approval_id": "appr_3y8m4p2q",
  "approved_by": "admin@example.com",
  "approval_latency_ns": 15000000000,
  "pid": 12345,
  "platform": "linux",
  "metadata": {
    "denial_reason": "Unknown external host not permitted"
  }
}
```

**Manual approval - timeout:**
```json
{
  "type": "file_write",
  "timestamp": "2025-01-15T14:35:00.000000000Z",
  "decision": "timeout",
  "path": "/workspace/config.yaml",
  "operation": "write",
  "policy_rule": "config-changes-approval",
  "held_ms": 300000,
  "approval_id": "appr_9z2n5r7s",
  "pid": 12345,
  "platform": "linux",
  "error": "approval timed out after 300s"
}
```

**Registry write blocked (Windows):**
```json
{
  "type": "registry_write",
  "timestamp": "2025-01-15T14:30:02.123456789Z",
  "decision": "deny",
  "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  "operation": "write",
  "policy_rule": "protect-run-keys",
  "held_ms": 5,
  "pid": 4567,
  "process_name": "python.exe",
  "platform": "windows",
  "metadata": {
    "value_name": "AgentBackdoor",
    "value_type": "REG_SZ",
    "value_data_redacted": true
  }
}
```

**Registry redirect - honeypot (Windows):**
```json
{
  "type": "registry_read",
  "timestamp": "2025-01-15T14:30:03.234567890Z",
  "decision": "redirect",
  "path": "HKLM\\SAM\\SAM\\Domains\\Account\\Users",
  "operation": "read",
  "redirected": true,
  "original_target": "HKLM\\SAM\\SAM\\Domains\\Account\\Users",
  "redirect_target": "[empty honeypot data]",
  "policy_rule": "honeypot-credentials",
  "held_ms": 3,
  "pid": 4567,
  "platform": "windows"
}
```

**Registry service creation - pending approval (Windows):**
```json
{
  "type": "registry_create",
  "timestamp": "2025-01-15T14:30:04.345678901Z",
  "decision": "pending",
  "path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SuspiciousService",
  "operation": "create",
  "policy_rule": "approve-services",
  "held_ms": 0,
  "approval_id": "appr_win_5k8m2n",
  "pid": 4567,
  "process_name": "python.exe",
  "platform": "windows",
  "metadata": {
    "approval_url": "http://localhost:9090/approve/appr_win_5k8m2n",
    "service_type": "Win32OwnProcess",
    "start_type": "Auto"
  }
}
```

### 7.10 Platform Support Summary

| Platform | Layer 1 (Spawn) | Layer 2 (Runtime) | Limitations |
|----------|:---------------:|:-----------------:|-------------|
| **Linux** | ✅ Full | ✅ LD_PRELOAD | None |
| **Windows WSL2** | ✅ Full | ✅ LD_PRELOAD | None (runs Linux) |
| **macOS FUSE-T** | ✅ Full | ⚠️ DYLD* | SIP blocks system binaries |
| **macOS ESF+NE** | ✅ Full | ❌ | No runtime interception |
| **macOS + Lima** | ✅ Full | ✅ LD_PRELOAD | Runs Linux in VM |
| **Windows Native** | ✅ Full | ⚠️ Detours | Requires admin for injection |

**Recommendations:**
- Always use Layer 1 (spawn-time filtering) - works everywhere
- Layer 2 provides defense-in-depth where available
- For maximum security, use Linux, WSL2, or Lima where LD_PRELOAD works fully

---

## 8. Soft Delete / Trash (Cross-Platform)

### 8.1 Overview

AI agents frequently delete files - sometimes intentionally, sometimes accidentally. The **soft delete** feature intercepts file deletions and diverts them to a shadow trash directory instead of permanently removing them. This provides:

1. **Recoverability** - Files can be restored if the agent makes a mistake
2. **Audit trail** - Complete record of what was deleted, when, and by which command
3. **AI guidance** - The agent receives a prompt showing how to restore files if needed
4. **Safety net** - Reduces risk of catastrophic data loss from autonomous agents

### 8.2 Core Data Structures

Based on the reference implementation:

```go
// pkg/trash/types.go

package trash

import (
    "os"
    "time"
)

// Entry describes one diverted (soft-deleted) item
type Entry struct {
    // Unique identifier for this trash entry
    Token        string      `json:"token"`
    
    // Original location before deletion
    OriginalPath string      `json:"original_path"`
    
    // Current location in trash
    TrashPath    string      `json:"trash_path"`
    
    // File metadata
    Size         int64       `json:"size"`
    Hash         string      `json:"hash,omitempty"`
    HashAlgo     string      `json:"hash_algo,omitempty"`
    Mode         os.FileMode `json:"mode"`
    UID          int         `json:"uid"`
    GID          int         `json:"gid"`
    Mtime        time.Time   `json:"mtime"`
    
    // Tracking
    Session      string      `json:"session"`
    Command      string      `json:"command"`
    Created      time.Time   `json:"created"`
    
    // Platform-specific metadata
    Platform     string      `json:"platform,omitempty"`
    
    // Windows-specific
    WinAttrs     uint32      `json:"win_attrs,omitempty"`     // FILE_ATTRIBUTE_*
    WinSecurity  []byte      `json:"win_security,omitempty"`  // Security descriptor
    
    // macOS-specific
    MacFlags     uint32      `json:"mac_flags,omitempty"`     // chflags
    MacXattrs    []Xattr     `json:"mac_xattrs,omitempty"`    // Extended attributes
}

type Xattr struct {
    Name  string `json:"name"`
    Value []byte `json:"value"`
}

// Config for trash operations
type Config struct {
    TrashDir       string        // Base directory for trash storage
    Session        string        // Current session ID
    Command        string        // Current command ID
    HashLimitBytes int64         // Max file size to compute hash (0 = disabled)
    HashAlgorithm  string        // "sha256", "blake3", etc.
    PreserveXattrs bool          // Preserve extended attributes (macOS/Linux)
    PreserveSecurity bool        // Preserve security descriptors (Windows)
}

// PurgeOptions controls trash cleanup
type PurgeOptions struct {
    TTL          time.Duration // Remove entries older than this
    QuotaBytes   int64         // Max total trash size
    QuotaCount   int           // Max number of entries
    Session      string        // Only purge entries from this session (empty = all)
    DryRun       bool          // Don't actually delete, just report
    Now          time.Time     // Current time (for testing)
}

// PurgeResult reports what was cleaned up
type PurgeResult struct {
    EntriesRemoved int
    BytesReclaimed int64
    Entries        []Entry // If DryRun, what would be removed
}
```

### 8.3 Core Operations

```go
// pkg/trash/trash.go

package trash

import (
    "context"
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "hash"
    "io"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"
    
    "golang.org/x/crypto/blake3"
)

const (
    payloadDirName  = "payload"
    manifestDirName = "manifest"
)

// Divert moves a file/directory to trash instead of deleting it
func Divert(ctx context.Context, path string, cfg Config) (*Entry, error) {
    if cfg.TrashDir == "" {
        return nil, fmt.Errorf("trash dir required")
    }
    
    // Get file info
    info, err := os.Lstat(path)
    if err != nil {
        return nil, fmt.Errorf("stat source: %w", err)
    }
    
    // Calculate total size (recursive for directories)
    size, err := sizeOf(path, info)
    if err != nil {
        return nil, fmt.Errorf("calculate size: %w", err)
    }
    
    // Compute hash for integrity verification (small files only)
    var hashVal, hashAlgo string
    if cfg.HashLimitBytes > 0 && !info.IsDir() && size <= cfg.HashLimitBytes {
        h, err := hashFile(path, cfg.HashAlgorithm)
        if err == nil {
            hashVal, hashAlgo = h.Value, h.Algo
        }
    }
    
    // Generate unique token
    token := fmt.Sprintf("%d-%s", time.Now().UnixNano(), generateShortID())
    
    // Build entry
    entry := &Entry{
        Token:        token,
        OriginalPath: path,
        TrashPath:    filepath.Join(cfg.TrashDir, payloadDirName, token),
        Size:         size,
        Hash:         hashVal,
        HashAlgo:     hashAlgo,
        Mode:         info.Mode(),
        Mtime:        info.ModTime(),
        Session:      cfg.Session,
        Command:      cfg.Command,
        Created:      time.Now().UTC(),
        Platform:     runtime.GOOS,
    }
    
    // Capture platform-specific metadata
    if err := capturePlatformMetadata(path, info, entry, cfg); err != nil {
        // Log but don't fail - metadata is nice-to-have
        log.Warn("Failed to capture platform metadata", zap.Error(err))
    }
    
    // Ensure trash directory exists
    if err := os.MkdirAll(filepath.Dir(entry.TrashPath), 0o755); err != nil {
        return nil, fmt.Errorf("create trash dir: %w", err)
    }
    
    // Move to trash (rename is atomic on same filesystem)
    if err := os.Rename(path, entry.TrashPath); err != nil {
        // Fallback to copy+delete for cross-filesystem moves
        if err := copyPath(path, entry.TrashPath, info, cfg); err != nil {
            return nil, fmt.Errorf("divert (copy fallback): %w", err)
        }
        if err := os.RemoveAll(path); err != nil {
            // Try to clean up the copy
            _ = os.RemoveAll(entry.TrashPath)
            return nil, fmt.Errorf("cleanup source: %w", err)
        }
    }
    
    // Write manifest
    if err := writeManifest(cfg.TrashDir, entry); err != nil {
        // Try to restore on manifest failure
        _ = os.Rename(entry.TrashPath, path)
        return nil, fmt.Errorf("write manifest: %w", err)
    }
    
    return entry, nil
}

// List returns all entries in the trash
func List(trashDir string) ([]Entry, error) {
    manDir := filepath.Join(trashDir, manifestDirName)
    files, err := os.ReadDir(manDir)
    if err != nil {
        if os.IsNotExist(err) {
            return nil, nil
        }
        return nil, err
    }
    
    var entries []Entry
    for _, f := range files {
        if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
            continue
        }
        
        b, err := os.ReadFile(filepath.Join(manDir, f.Name()))
        if err != nil {
            continue // Skip unreadable manifests
        }
        
        var e Entry
        if err := json.Unmarshal(b, &e); err != nil {
            continue // Skip corrupt manifests
        }
        
        entries = append(entries, e)
    }
    
    // Sort by creation time (oldest first)
    sort.Slice(entries, func(i, j int) bool {
        return entries[i].Created.Before(entries[j].Created)
    })
    
    return entries, nil
}

// Restore recovers a file from trash
func Restore(ctx context.Context, trashDir, token, dest string, force bool) (string, error) {
    entry, manPath, err := readManifest(trashDir, token)
    if err != nil {
        return "", fmt.Errorf("read manifest: %w", err)
    }
    
    // Determine target path
    target := dest
    if target == "" {
        target = entry.OriginalPath
    }
    
    // Check if destination exists
    if !force {
        if _, err := os.Lstat(target); err == nil {
            return "", fmt.Errorf("destination exists: %s (use force=true to overwrite)", target)
        }
    }
    
    // Ensure parent directory exists
    if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
        return "", fmt.Errorf("create parent dir: %w", err)
    }
    
    // Move from trash to target
    if err := os.Rename(entry.TrashPath, target); err != nil {
        // Fallback to copy
        info, err2 := os.Lstat(entry.TrashPath)
        if err2 != nil {
            return "", fmt.Errorf("stat trash payload: %w", err2)
        }
        if err := copyPath(entry.TrashPath, target, info, Config{}); err != nil {
            return "", fmt.Errorf("copy from trash: %w", err)
        }
        if err := os.RemoveAll(entry.TrashPath); err != nil {
            return "", fmt.Errorf("cleanup trash payload: %w", err)
        }
    }
    
    // Verify integrity if hash was recorded
    if entry.Hash != "" {
        actual, err := hashFile(target, entry.HashAlgo)
        if err != nil {
            return "", fmt.Errorf("hash restored file: %w", err)
        }
        if actual.Value != entry.Hash {
            return "", fmt.Errorf("integrity check failed: expected %s, got %s", 
                entry.Hash, actual.Value)
        }
    }
    
    // Restore platform-specific metadata
    if err := restorePlatformMetadata(target, entry); err != nil {
        log.Warn("Failed to restore platform metadata", zap.Error(err))
    }
    
    // Remove manifest
    _ = os.Remove(manPath)
    
    return target, nil
}

// Purge removes old entries from trash
func Purge(ctx context.Context, trashDir string, opts PurgeOptions) (*PurgeResult, error) {
    now := opts.Now
    if now.IsZero() {
        now = time.Now().UTC()
    }
    
    entries, err := List(trashDir)
    if err != nil {
        return nil, err
    }
    
    result := &PurgeResult{}
    var toRemove []Entry
    
    // Filter by session if specified
    if opts.Session != "" {
        filtered := make([]Entry, 0, len(entries))
        for _, e := range entries {
            if e.Session == opts.Session {
                filtered = append(filtered, e)
            }
        }
        entries = filtered
    }
    
    // Apply TTL filter
    if opts.TTL > 0 {
        for _, e := range entries {
            if e.Created.Add(opts.TTL).Before(now) {
                toRemove = append(toRemove, e)
            }
        }
    }
    
    // Apply quota (after TTL, so we keep newer files)
    remaining := make([]Entry, 0)
    for _, e := range entries {
        found := false
        for _, r := range toRemove {
            if r.Token == e.Token {
                found = true
                break
            }
        }
        if !found {
            remaining = append(remaining, e)
        }
    }
    
    // Count quota (remove oldest first)
    if opts.QuotaCount > 0 && len(remaining) > opts.QuotaCount {
        excess := remaining[:len(remaining)-opts.QuotaCount]
        toRemove = append(toRemove, excess...)
        remaining = remaining[len(remaining)-opts.QuotaCount:]
    }
    
    // Bytes quota
    if opts.QuotaBytes > 0 {
        var total int64
        for _, e := range remaining {
            total += e.Size
        }
        for total > opts.QuotaBytes && len(remaining) > 0 {
            oldest := remaining[0]
            toRemove = append(toRemove, oldest)
            total -= oldest.Size
            remaining = remaining[1:]
        }
    }
    
    // Perform removal
    if opts.DryRun {
        result.Entries = toRemove
        for _, e := range toRemove {
            result.EntriesRemoved++
            result.BytesReclaimed += e.Size
        }
    } else {
        for _, e := range toRemove {
            if err := removeEntry(trashDir, &e); err != nil {
                return result, fmt.Errorf("remove entry %s: %w", e.Token, err)
            }
            result.EntriesRemoved++
            result.BytesReclaimed += e.Size
        }
    }
    
    return result, nil
}
```

### 8.4 Platform-Specific Implementations

#### 8.4.1 Linux Implementation

```go
// pkg/trash/platform_linux.go
// +build linux

package trash

import (
    "os"
    "syscall"
    
    "golang.org/x/sys/unix"
)

func capturePlatformMetadata(path string, info os.FileInfo, entry *Entry, cfg Config) error {
    stat := info.Sys().(*syscall.Stat_t)
    entry.UID = int(stat.Uid)
    entry.GID = int(stat.Gid)
    
    // Capture extended attributes if requested
    if cfg.PreserveXattrs {
        xattrs, err := listXattrs(path)
        if err == nil {
            for _, name := range xattrs {
                value, err := getXattr(path, name)
                if err == nil {
                    entry.MacXattrs = append(entry.MacXattrs, Xattr{
                        Name:  name,
                        Value: value,
                    })
                }
            }
        }
    }
    
    return nil
}

func restorePlatformMetadata(path string, entry *Entry) error {
    // Restore ownership
    if entry.UID != 0 || entry.GID != 0 {
        if err := os.Lchown(path, entry.UID, entry.GID); err != nil {
            // Ignore permission errors
            if !os.IsPermission(err) {
                return err
            }
        }
    }
    
    // Restore extended attributes
    for _, xattr := range entry.MacXattrs {
        _ = setXattr(path, xattr.Name, xattr.Value)
    }
    
    return nil
}

func listXattrs(path string) ([]string, error) {
    size, err := unix.Llistxattr(path, nil)
    if err != nil || size == 0 {
        return nil, err
    }
    buf := make([]byte, size)
    size, err = unix.Llistxattr(path, buf)
    if err != nil {
        return nil, err
    }
    var names []string
    for _, name := range strings.Split(string(buf[:size]), "\x00") {
        if name != "" {
            names = append(names, name)
        }
    }
    return names, nil
}

func getXattr(path, name string) ([]byte, error) {
    size, err := unix.Lgetxattr(path, name, nil)
    if err != nil || size == 0 {
        return nil, err
    }
    buf := make([]byte, size)
    _, err = unix.Lgetxattr(path, name, buf)
    return buf, err
}

func setXattr(path, name string, value []byte) error {
    return unix.Lsetxattr(path, name, value, 0)
}
```

#### 8.4.2 macOS Implementation

```go
// pkg/trash/platform_darwin.go
// +build darwin

package trash

import (
    "os"
    "syscall"
    
    "golang.org/x/sys/unix"
)

func capturePlatformMetadata(path string, info os.FileInfo, entry *Entry, cfg Config) error {
    stat := info.Sys().(*syscall.Stat_t)
    entry.UID = int(stat.Uid)
    entry.GID = int(stat.Gid)
    entry.MacFlags = stat.Flags
    
    // Capture extended attributes (common on macOS for things like
    // com.apple.quarantine, com.apple.FinderInfo, etc.)
    if cfg.PreserveXattrs {
        xattrs, err := listXattrs(path)
        if err == nil {
            for _, name := range xattrs {
                value, err := getXattr(path, name)
                if err == nil {
                    entry.MacXattrs = append(entry.MacXattrs, Xattr{
                        Name:  name,
                        Value: value,
                    })
                }
            }
        }
    }
    
    return nil
}

func restorePlatformMetadata(path string, entry *Entry) error {
    // Restore ownership
    if entry.UID != 0 || entry.GID != 0 {
        if err := os.Lchown(path, entry.UID, entry.GID); err != nil {
            if !os.IsPermission(err) {
                return err
            }
        }
    }
    
    // Restore macOS file flags (immutable, hidden, etc.)
    if entry.MacFlags != 0 {
        if err := unix.Chflags(path, int(entry.MacFlags)); err != nil {
            // Log but don't fail
        }
    }
    
    // Restore extended attributes
    for _, xattr := range entry.MacXattrs {
        _ = setXattr(path, xattr.Name, xattr.Value)
    }
    
    return nil
}

// Same xattr functions as Linux - macOS uses compatible API
func listXattrs(path string) ([]string, error) {
    size, err := unix.Llistxattr(path, nil)
    if err != nil || size == 0 {
        return nil, err
    }
    buf := make([]byte, size)
    size, err = unix.Llistxattr(path, buf)
    if err != nil {
        return nil, err
    }
    var names []string
    for _, name := range strings.Split(string(buf[:size]), "\x00") {
        if name != "" {
            names = append(names, name)
        }
    }
    return names, nil
}

func getXattr(path, name string) ([]byte, error) {
    size, err := unix.Lgetxattr(path, name, nil)
    if err != nil || size == 0 {
        return nil, err
    }
    buf := make([]byte, size)
    _, err = unix.Lgetxattr(path, name, buf)
    return buf, err
}

func setXattr(path, name string, value []byte) error {
    return unix.Lsetxattr(path, name, value, 0)
}
```

#### 8.4.3 Windows Implementation

```go
// pkg/trash/platform_windows.go
// +build windows

package trash

import (
    "os"
    "syscall"
    "unsafe"
    
    "golang.org/x/sys/windows"
)

func capturePlatformMetadata(path string, info os.FileInfo, entry *Entry, cfg Config) error {
    // Get Windows file attributes
    pathPtr, err := syscall.UTF16PtrFromString(path)
    if err != nil {
        return err
    }
    
    attrs, err := syscall.GetFileAttributes(pathPtr)
    if err == nil {
        entry.WinAttrs = attrs
    }
    
    // Capture security descriptor if requested
    if cfg.PreserveSecurity {
        sd, err := getSecurityDescriptor(path)
        if err == nil {
            entry.WinSecurity = sd
        }
    }
    
    return nil
}

func restorePlatformMetadata(path string, entry *Entry) error {
    // Restore Windows file attributes
    if entry.WinAttrs != 0 {
        pathPtr, err := syscall.UTF16PtrFromString(path)
        if err == nil {
            _ = syscall.SetFileAttributes(pathPtr, entry.WinAttrs)
        }
    }
    
    // Restore security descriptor
    if len(entry.WinSecurity) > 0 {
        _ = setSecurityDescriptor(path, entry.WinSecurity)
    }
    
    return nil
}

func getSecurityDescriptor(path string) ([]byte, error) {
    var sd *windows.SECURITY_DESCRIPTOR
    err := windows.GetNamedSecurityInfo(
        path,
        windows.SE_FILE_OBJECT,
        windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
        nil, nil, nil, nil,
        &sd,
    )
    if err != nil {
        return nil, err
    }
    defer windows.LocalFree(windows.Handle(unsafe.Pointer(sd)))
    
    length := sd.Length()
    buf := make([]byte, length)
    copy(buf, (*[1 << 20]byte)(unsafe.Pointer(sd))[:length])
    return buf, nil
}

func setSecurityDescriptor(path string, sdBytes []byte) error {
    if len(sdBytes) == 0 {
        return nil
    }
    
    sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&sdBytes[0]))
    
    return windows.SetNamedSecurityInfo(
        path,
        windows.SE_FILE_OBJECT,
        windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
        nil, nil,
        sd.DACL(),
        nil,
    )
}

// Windows-specific: Option to use native Recycle Bin
func DivertToRecycleBin(path string) error {
    pathPtr, err := syscall.UTF16PtrFromString(path)
    if err != nil {
        return err
    }
    
    // SHFILEOPSTRUCT for SHFileOperation
    type SHFILEOPSTRUCT struct {
        hwnd                  uintptr
        wFunc                 uint32
        pFrom                 *uint16
        pTo                   *uint16
        fFlags                uint16
        fAnyOperationsAborted int32
        hNameMappings         uintptr
        lpszProgressTitle     *uint16
    }
    
    const (
        FO_DELETE          = 0x0003
        FOF_ALLOWUNDO      = 0x0040
        FOF_NOCONFIRMATION = 0x0010
        FOF_SILENT         = 0x0004
        FOF_NOERRORUI      = 0x0400
    )
    
    // Path must be double-null terminated
    pathBuf := make([]uint16, len(path)+2)
    copy(pathBuf, syscall.StringToUTF16(path))
    
    op := SHFILEOPSTRUCT{
        wFunc:  FO_DELETE,
        pFrom:  &pathBuf[0],
        fFlags: FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI,
    }
    
    shell32 := syscall.NewLazyDLL("shell32.dll")
    shFileOperation := shell32.NewProc("SHFileOperationW")
    
    ret, _, _ := shFileOperation.Call(uintptr(unsafe.Pointer(&op)))
    if ret != 0 {
        return fmt.Errorf("SHFileOperation failed: %d", ret)
    }
    
    return nil
}
```

### 8.5 FUSE Integration

The soft delete feature integrates with the FUSE filesystem layer to intercept delete operations:

```go
// pkg/fs/fuse_trash.go

package fs

import (
    "context"
    "syscall"
    
    "github.com/agentsh/agentsh/internal/trash"
    "github.com/hanwen/go-fuse/v2/fuse"
)

// Intercept unlink (file delete)
func (fs *AgentFS) Unlink(cancel <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
    path := fs.getPath(header.NodeId, name)
    ctx := fs.contextFromHeader(header)
    
    // Evaluate policy
    op := &InterceptedOperation{
        Type:      OpFileDelete,
        Path:      path,
        SessionID: fs.sessionID,
        CommandID: fs.currentCommandID,
    }
    
    decision := fs.policyEngine.Evaluate(op)
    
    switch decision.Action {
    case DecisionDeny:
        fs.emitEvent(ctx, op, decision)
        return fuse.EACCES
        
    case DecisionAllow:
        // Check if soft delete is enabled
        if fs.trashConfig.Enabled {
            return fs.softDelete(ctx, path, op)
        }
        // Hard delete
        return fs.realUnlink(path)
        
    case DecisionSoftDelete:
        // Policy explicitly requests soft delete
        return fs.softDelete(ctx, path, op)
        
    case DecisionApprove:
        // Wait for manual approval
        response := fs.interceptor.HoldForApproval(ctx, op)
        if response.Decision != DecisionAllow {
            return fuse.EACCES
        }
        if fs.trashConfig.Enabled {
            return fs.softDelete(ctx, path, op)
        }
        return fs.realUnlink(path)
    }
    
    return fuse.ENOSYS
}

// Intercept rmdir (directory delete)
func (fs *AgentFS) Rmdir(cancel <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
    path := fs.getPath(header.NodeId, name)
    ctx := fs.contextFromHeader(header)
    
    op := &InterceptedOperation{
        Type:      OpDirDelete,
        Path:      path,
        SessionID: fs.sessionID,
        CommandID: fs.currentCommandID,
    }
    
    decision := fs.policyEngine.Evaluate(op)
    
    if decision.Action == DecisionAllow || decision.Action == DecisionSoftDelete {
        if fs.trashConfig.Enabled {
            return fs.softDelete(ctx, path, op)
        }
    }
    
    // ... similar to Unlink
}

func (fs *AgentFS) softDelete(ctx context.Context, path string, op *InterceptedOperation) fuse.Status {
    entry, err := trash.Divert(ctx, path, trash.Config{
        TrashDir:       fs.trashConfig.TrashDir,
        Session:        fs.sessionID,
        Command:        fs.currentCommandID,
        HashLimitBytes: fs.trashConfig.HashLimitBytes,
        HashAlgorithm:  "sha256",
        PreserveXattrs: true,
    })
    if err != nil {
        fs.logger.Error("Soft delete failed", zap.Error(err), zap.String("path", path))
        return fuse.EIO
    }
    
    // Emit event with restore information
    fs.emitEvent(ctx, op, DecisionResponse{
        Decision: DecisionAllow,
        Metadata: map[string]string{
            "soft_delete":   "true",
            "trash_token":   entry.Token,
            "original_path": entry.OriginalPath,
            "restore_cmd":   fmt.Sprintf("agentsh restore %s", entry.Token),
        },
    })
    
    return fuse.OK
}
```

### 8.6 AI Agent Response Format

When a file is soft-deleted, the agent receives a structured response that helps it understand what happened and how to recover:

```json
{
  "type": "file_delete",
  "timestamp": "2025-01-15T14:30:00Z",
  "decision": "allow",
  "path": "/workspace/important-data.json",
  "metadata": {
    "soft_delete": "true",
    "trash_token": "1736951400123456789-a1b2c3",
    "original_path": "/workspace/important-data.json",
    "restore_hint": "File moved to trash. To restore, use: agentsh restore 1736951400123456789-a1b2c3",
    "restore_cmd": "agentsh restore 1736951400123456789-a1b2c3",
    "trash_size_bytes": 1024,
    "trash_hash": "sha256:abc123..."
  }
}
```

The AI agent can use this information to:
1. Know the deletion succeeded (from user's perspective)
2. Understand the file is recoverable
3. Execute the restore command if needed

### 8.7 Trash Cleanup Strategies

#### 8.7.1 Session-Based Cleanup

Clean up trash when a session ends:

```go
// pkg/session/cleanup.go

func (s *Session) Cleanup(ctx context.Context) error {
    if !s.trashConfig.PurgeOnSessionEnd {
        return nil
    }
    
    result, err := trash.Purge(ctx, s.trashConfig.TrashDir, trash.PurgeOptions{
        Session: s.ID,
    })
    if err != nil {
        return fmt.Errorf("purge session trash: %w", err)
    }
    
    s.logger.Info("Session trash purged",
        zap.Int("entries_removed", result.EntriesRemoved),
        zap.Int64("bytes_reclaimed", result.BytesReclaimed),
    )
    
    return nil
}
```

#### 8.7.2 TTL-Based Cleanup

Background goroutine for time-based cleanup:

```go
// pkg/trash/cleaner.go

type Cleaner struct {
    trashDir string
    config   CleanerConfig
    ticker   *time.Ticker
    done     chan struct{}
}

type CleanerConfig struct {
    Interval   time.Duration // How often to run cleanup
    TTL        time.Duration // Max age of trash entries
    QuotaBytes int64         // Max total trash size
    QuotaCount int           // Max number of entries
}

func NewCleaner(trashDir string, cfg CleanerConfig) *Cleaner {
    return &Cleaner{
        trashDir: trashDir,
        config:   cfg,
        ticker:   time.NewTicker(cfg.Interval),
        done:     make(chan struct{}),
    }
}

func (c *Cleaner) Start(ctx context.Context) {
    go func() {
        for {
            select {
            case <-c.ticker.C:
                c.cleanup(ctx)
            case <-c.done:
                return
            case <-ctx.Done():
                return
            }
        }
    }()
}

func (c *Cleaner) cleanup(ctx context.Context) {
    result, err := trash.Purge(ctx, c.trashDir, trash.PurgeOptions{
        TTL:        c.config.TTL,
        QuotaBytes: c.config.QuotaBytes,
        QuotaCount: c.config.QuotaCount,
    })
    if err != nil {
        log.Error("Trash cleanup failed", zap.Error(err))
        return
    }
    
    if result.EntriesRemoved > 0 {
        log.Info("Trash cleanup completed",
            zap.Int("entries_removed", result.EntriesRemoved),
            zap.Int64("bytes_reclaimed", result.BytesReclaimed),
        )
    }
}

func (c *Cleaner) Stop() {
    c.ticker.Stop()
    close(c.done)
}
```

#### 8.7.3 Quota-Based Cleanup

```yaml
# agentsh.yaml

trash:
  enabled: true
  
  # Trash location
  directory: "${DATA_DIR}/trash"
  
  # When to purge
  cleanup:
    # Run cleanup every hour
    interval: 1h
    
    # Remove entries older than 7 days
    ttl: 168h
    
    # Keep max 1GB of trash
    quota_bytes: 1073741824
    
    # Keep max 1000 entries
    quota_count: 1000
    
    # Purge session trash when session ends
    purge_on_session_end: false
    
  # Integrity
  hash_limit_bytes: 10485760  # Hash files up to 10MB
  hash_algorithm: sha256
  
  # Platform-specific
  preserve_xattrs: true       # Linux/macOS extended attributes
  preserve_security: true     # Windows security descriptors
  
  # Windows-specific: use native Recycle Bin instead
  use_recycle_bin: false
```

### 8.8 CLI Commands

```bash
# List trash contents
$ agentsh trash list
TOKEN                           ORIGINAL PATH                    SIZE     AGE
1736951400123456789-a1b2c3      /workspace/important.json        1.2 KB   2h
1736951300987654321-d4e5f6      /workspace/old-config.yaml       856 B    5h
1736950200111111111-g7h8i9      /workspace/src/deleted.go        4.3 KB   1d

# List with details
$ agentsh trash list --json
[
  {
    "token": "1736951400123456789-a1b2c3",
    "original_path": "/workspace/important.json",
    "size": 1234,
    "hash": "sha256:abc123...",
    "session": "sess_xyz",
    "command": "cmd_123",
    "created": "2025-01-15T14:30:00Z"
  }
]

# Restore a file
$ agentsh trash restore 1736951400123456789-a1b2c3
Restored: /workspace/important.json

# Restore to different location
$ agentsh trash restore 1736951400123456789-a1b2c3 --dest /workspace/recovered.json
Restored: /workspace/recovered.json

# Restore with force overwrite
$ agentsh trash restore 1736951400123456789-a1b2c3 --force

# Purge old entries
$ agentsh trash purge --ttl 24h
Purged 5 entries, reclaimed 12.3 MB

# Purge by quota
$ agentsh trash purge --quota 100MB
Purged 3 entries, reclaimed 8.1 MB

# Purge session trash
$ agentsh trash purge --session sess_xyz
Purged 2 entries, reclaimed 1.5 MB

# Dry run
$ agentsh trash purge --ttl 1h --dry-run
Would purge:
  1736950200111111111-g7h8i9  /workspace/src/deleted.go  4.3 KB

# Empty all trash
$ agentsh trash empty --confirm
Emptied trash: 10 entries, 45.2 MB reclaimed
```

### 8.9 Platform Support Matrix

| Feature | Linux | macOS | Windows Native | Windows WSL2 |
|---------|:-----:|:-----:|:--------------:|:------------:|
| Basic soft delete | ✅ | ✅ | ✅ | ✅ |
| Preserve permissions | ✅ | ✅ | ✅ | ✅ |
| Preserve ownership (UID/GID) | ✅ | ✅ | N/A | ✅ |
| Preserve xattrs | ✅ | ✅ | N/A | ✅ |
| Preserve macOS flags | N/A | ✅ | N/A | N/A |
| Preserve Windows attrs | N/A | N/A | ✅ | N/A |
| Preserve Windows ACLs | N/A | N/A | ✅ | N/A |
| Native Recycle Bin | N/A | N/A | ✅ Optional | N/A |
| Hash verification | ✅ | ✅ | ✅ | ✅ |
| Cross-filesystem move | ✅ | ✅ | ✅ | ✅ |
| Directory soft delete | ✅ | ✅ | ✅ | ✅ |

### 8.10 Security Considerations

1. **Trash directory permissions**: The trash directory should be created with restrictive permissions (0700) to prevent other users from accessing deleted files.

2. **Sensitive file handling**: Files matching sensitive patterns (e.g., `*.key`, `*.pem`) may need special handling - consider encrypting them in trash or immediate purge.

3. **Symlink handling**: Symlinks are preserved as symlinks in trash, not followed.

4. **Hard links**: Hard links are copied, not moved, to maintain correct reference counts.

5. **Quota enforcement**: Enforce trash quotas to prevent disk exhaustion attacks where an agent repeatedly deletes and recreates files.

```yaml
# Security-focused trash configuration
trash:
  enabled: true
  directory: "${DATA_DIR}/trash"
  
  # Encrypt sensitive files in trash
  encrypt_patterns:
    - "*.key"
    - "*.pem"
    - "*.p12"
    - "*secret*"
    - "*password*"
  encryption_key_env: "AGENTSH_TRASH_KEY"
  
  # Immediately purge (don't soft delete) these patterns
  hard_delete_patterns:
    - "*.tmp"
    - "*.log"
    - ".git/objects/*"
    
  # Strict quotas
  cleanup:
    quota_bytes: 104857600  # 100MB max
    quota_count: 100        # 100 entries max
```

---

## 9. Shell Shim (Cross-Platform)

### 9.1 Overview

The **shell shim** intercepts all shell invocations (`/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell.exe`) and routes them through agentsh. This ensures that:

1. **All commands are governed** - Even when tools spawn subshells
2. **Policy persists** - Commands inherit the session's policy
3. **Subprocess trees are tracked** - Child processes stay within the sandbox
4. **Autostart works** - First shell invocation can bootstrap the server

### 9.2 Linux Implementation

On Linux, the shim replaces shell binaries and uses symlinks/wrappers:

```go
// pkg/shim/linux.go

package shim

import (
    "os"
    "os/exec"
    "path/filepath"
    "syscall"
)

// ShimConfig for Linux
type LinuxShimConfig struct {
    ShimBinary     string   // Path to agentsh-shell-shim
    TargetShells   []string // Shells to intercept
    BackupSuffix   string   // Suffix for original binaries
    ServerSocket   string   // Unix socket to agentsh server
    SessionID      string   // Current session
}

var defaultTargetShells = []string{
    "/bin/sh",
    "/bin/bash",
    "/bin/dash",
    "/bin/zsh",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/zsh",
}

// Install replaces shell binaries with shim
func (c *LinuxShimConfig) Install() error {
    for _, shell := range c.TargetShells {
        if _, err := os.Stat(shell); os.IsNotExist(err) {
            continue
        }
        
        // Backup original
        backup := shell + c.BackupSuffix
        if _, err := os.Stat(backup); os.IsNotExist(err) {
            if err := os.Rename(shell, backup); err != nil {
                return fmt.Errorf("backup %s: %w", shell, err)
            }
        }
        
        // Create symlink to shim
        if err := os.Symlink(c.ShimBinary, shell); err != nil {
            return fmt.Errorf("symlink %s: %w", shell, err)
        }
    }
    return nil
}

// Uninstall restores original shells
func (c *LinuxShimConfig) Uninstall() error {
    for _, shell := range c.TargetShells {
        backup := shell + c.BackupSuffix
        if _, err := os.Stat(backup); err == nil {
            _ = os.Remove(shell)
            if err := os.Rename(backup, shell); err != nil {
                return fmt.Errorf("restore %s: %w", shell, err)
            }
        }
    }
    return nil
}
```

#### 9.2.1 Shell Shim Binary

```go
// cmd/agentsh-shell-shim/main.go

package main

import (
    "fmt"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
)

func main() {
    // Determine which shell we're shimming
    invokedAs := filepath.Base(os.Args[0])
    realShell := findRealShell(invokedAs)
    
    // Get server connection
    serverAddr := os.Getenv("AGENTSH_SERVER")
    if serverAddr == "" {
        serverAddr = "http://127.0.0.1:8080"
    }
    
    // Get or create session
    sessionID := os.Getenv("AGENTSH_SESSION")
    if sessionID == "" {
        // Autostart: create session if needed
        sessionID = autoCreateSession(serverAddr)
    }
    
    // Build command to execute via agentsh
    args := os.Args[1:]
    
    // Handle -c flag specially (most common case)
    if len(args) >= 2 && args[0] == "-c" {
        // Execute command string via agentsh
        executeViaAgentsh(serverAddr, sessionID, args[1])
    } else if len(args) == 0 {
        // Interactive shell - attach to session
        attachInteractive(serverAddr, sessionID, realShell)
    } else {
        // Script execution or other flags
        executeScript(serverAddr, sessionID, realShell, args)
    }
}

func findRealShell(name string) string {
    // Look for backup with suffix
    candidates := []string{
        "/bin/" + name + ".real",
        "/usr/bin/" + name + ".real",
        "/bin/" + name + ".orig",
    }
    for _, c := range candidates {
        if _, err := os.Stat(c); err == nil {
            return c
        }
    }
    // Fallback
    return "/bin/sh.real"
}

func executeViaAgentsh(server, session, command string) {
    // Connect to agentsh and execute
    client := NewAgentshClient(server)
    
    result, err := client.Exec(session, ExecRequest{
        Command: "/bin/sh",
        Args:    []string{"-c", command},
        Stdin:   os.Stdin,
        Stdout:  os.Stdout,
        Stderr:  os.Stderr,
    })
    
    if err != nil {
        fmt.Fprintf(os.Stderr, "agentsh: %v\n", err)
        os.Exit(1)
    }
    
    os.Exit(result.ExitCode)
}

func autoCreateSession(server string) string {
    // Check if server is running
    client := NewAgentshClient(server)
    
    if !client.IsHealthy() {
        // Start server if AGENTSH_NO_AUTO is not set
        if os.Getenv("AGENTSH_NO_AUTO") == "" {
            startServer()
        }
    }
    
    // Create session with current directory as workspace
    cwd, _ := os.Getwd()
    session, err := client.CreateSession(SessionConfig{
        Workspace: cwd,
        Policy:    os.Getenv("AGENTSH_POLICY_NAME"),
    })
    if err != nil {
        fmt.Fprintf(os.Stderr, "agentsh: failed to create session: %v\n", err)
        os.Exit(1)
    }
    
    return session.ID
}
```

### 9.3 macOS Implementation

macOS presents challenges due to System Integrity Protection (SIP):

```go
// pkg/shim/darwin.go

package shim

import (
    "os"
    "os/exec"
)

// DarwinShimConfig for macOS
type DarwinShimConfig struct {
    // Cannot replace /bin/sh due to SIP
    // Use alternative strategies
    Strategy     DarwinShimStrategy
    ShimBinary   string
    LaunchAgent  string // ~/Library/LaunchAgents/
}

type DarwinShimStrategy string

const (
    // Strategy 1: PATH manipulation - put shim directory first
    StrategyPATH DarwinShimStrategy = "path"
    
    // Strategy 2: Shell profile hooks - add to .zshrc/.bashrc
    StrategyProfile DarwinShimStrategy = "profile"
    
    // Strategy 3: Terminal.app/iTerm2 hooks
    StrategyTerminal DarwinShimStrategy = "terminal"
    
    // Strategy 4: Launch Agent that wraps default shell
    StrategyLaunchAgent DarwinShimStrategy = "launchagent"
)
```

#### 9.3.1 PATH-Based Shim (macOS)

```go
// Strategy 1: Create shims in a directory that comes first in PATH

func (c *DarwinShimConfig) InstallPATH() error {
    shimDir := filepath.Join(os.Getenv("HOME"), ".agentsh", "bin")
    if err := os.MkdirAll(shimDir, 0755); err != nil {
        return err
    }
    
    // Create shim scripts for each shell
    shells := []string{"sh", "bash", "zsh", "dash"}
    for _, shell := range shells {
        shimPath := filepath.Join(shimDir, shell)
        script := fmt.Sprintf(`#!/bin/bash
# agentsh shell shim for %s
exec %s shim-exec %s "$@"
`, shell, c.ShimBinary, shell)
        
        if err := os.WriteFile(shimPath, []byte(script), 0755); err != nil {
            return err
        }
    }
    
    // User must add to PATH in their shell profile:
    // export PATH="$HOME/.agentsh/bin:$PATH"
    
    return nil
}
```

#### 9.3.2 Profile Hook (macOS)

```bash
# ~/.zshrc or ~/.bashrc addition

# agentsh shell wrapper
if [[ -n "$AGENTSH_ENABLED" ]]; then
    # Wrap command execution
    preexec() {
        # Send command to agentsh before execution
        agentsh pre-exec "$1"
    }
    
    precmd() {
        # Report completion to agentsh
        agentsh post-exec $?
    }
fi

# Or more comprehensively, replace the shell entirely:
if [[ -z "$AGENTSH_INSIDE" && -n "$AGENTSH_ENABLED" ]]; then
    export AGENTSH_INSIDE=1
    exec agentsh session attach "$AGENTSH_SESSION"
fi
```

#### 9.3.3 Lima VM Strategy (macOS)

For full shim support on macOS, use Lima which runs Linux:

```yaml
# lima/agentsh.yaml

# Lima VM with full shell shim support
vmType: vz
rosetta:
  enabled: true

mounts:
  - location: "~"
    writable: true
    
provision:
  - mode: system
    script: |
      #!/bin/bash
      # Install agentsh
      curl -fsSL https://get.agentsh.dev | bash
      
      # Install shell shim (works fully in Linux)
      agentsh shim install-shell \
        --root / \
        --bash --sh --zsh \
        --i-understand-this-modifies-the-host

env:
  AGENTSH_SERVER: "http://127.0.0.1:8080"
```

### 9.4 Windows Implementation

Windows requires different approaches for CMD and PowerShell:

```go
// pkg/shim/windows.go

package shim

import (
    "os"
    "path/filepath"
)

type WindowsShimConfig struct {
    Strategy    WindowsShimStrategy
    ShimExe     string
    ProfilePath string
}

type WindowsShimStrategy string

const (
    // Strategy 1: PowerShell profile
    StrategyPSProfile WindowsShimStrategy = "psprofile"
    
    // Strategy 2: Executable wrapper in PATH
    StrategyWrapper WindowsShimStrategy = "wrapper"
    
    // Strategy 3: Registry shell replacement (admin required)
    StrategyRegistry WindowsShimStrategy = "registry"
    
    // Strategy 4: Windows Terminal settings
    StrategyTerminal WindowsShimStrategy = "terminal"
)
```

#### 9.4.1 PowerShell Profile Hook

```powershell
# $PROFILE (e.g., ~\Documents\PowerShell\Microsoft.PowerShell_profile.ps1)

# agentsh PowerShell integration
if ($env:AGENTSH_ENABLED) {
    # Wrap command execution
    Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
        $line = $null
        [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$null)
        
        if ($line.Trim()) {
            # Execute via agentsh
            $result = agentsh exec $env:AGENTSH_SESSION -- powershell -Command $line
            [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
            [Microsoft.PowerShell.PSConsoleReadLine]::Insert("")
        } else {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        }
    }
}

# Alternative: Function wrapper for common commands
function Invoke-AgentshCommand {
    param([string]$Command)
    agentsh exec $env:AGENTSH_SESSION -- cmd /c $Command
}
Set-Alias -Name ash -Value Invoke-AgentshCommand
```

#### 9.4.2 CMD Wrapper Executable

```go
// cmd/agentsh-cmd-shim/main_windows.go

package main

import (
    "os"
    "os/exec"
    "strings"
    "syscall"
)

func main() {
    // Check if we're being invoked as cmd.exe replacement
    args := os.Args[1:]
    
    server := os.Getenv("AGENTSH_SERVER")
    session := os.Getenv("AGENTSH_SESSION")
    
    if server == "" || session == "" {
        // Not in agentsh mode, passthrough to real cmd
        realCmd := `C:\Windows\System32\cmd.exe`
        cmd := exec.Command(realCmd, args...)
        cmd.Stdin = os.Stdin
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        cmd.Run()
        return
    }
    
    // Handle /c flag
    for i, arg := range args {
        if strings.EqualFold(arg, "/c") && i+1 < len(args) {
            command := strings.Join(args[i+1:], " ")
            executeViaAgentsh(server, session, command)
            return
        }
    }
    
    // Interactive mode
    attachInteractive(server, session)
}
```

#### 9.4.3 Windows Terminal Integration

```json
// %LOCALAPPDATA%\Packages\Microsoft.WindowsTerminal_*/LocalState/settings.json

{
    "profiles": {
        "list": [
            {
                "name": "agentsh",
                "commandline": "agentsh session attach --create",
                "icon": "🛡️",
                "startingDirectory": "%USERPROFILE%"
            },
            {
                "name": "PowerShell (agentsh)",
                "commandline": "agentsh exec --session auto -- powershell",
                "hidden": false
            }
        ]
    }
}
```

### 9.5 Platform Support Matrix

| Feature | Linux | macOS Native | macOS Lima | Windows |
|---------|:-----:|:------------:|:----------:|:-------:|
| Replace /bin/sh | ✅ | ❌ SIP | ✅ In VM | N/A |
| Replace /bin/bash | ✅ | ❌ SIP | ✅ In VM | N/A |
| PATH-based shim | ✅ | ✅ | ✅ | ✅ |
| Profile hooks | ✅ | ✅ | ✅ | ✅ |
| Terminal integration | ✅ | ✅ | ✅ | ✅ |
| Subprocess inheritance | ✅ | ⚠️ Partial | ✅ | ✅ Job Objects |
| Autostart server | ✅ | ✅ | ✅ | ✅ |

### 9.6 Installation Commands

```bash
# Linux - Full shell replacement (in container or with root)
agentsh shim install-shell \
    --root / \
    --bash --sh --zsh \
    --i-understand-this-modifies-the-host

# macOS - PATH-based (no root required)
agentsh shim install-path
echo 'export PATH="$HOME/.agentsh/bin:$PATH"' >> ~/.zshrc

# macOS - Profile hook
agentsh shim install-profile --zsh --bash

# Windows - PowerShell profile
agentsh shim install-psprofile

# Windows - Windows Terminal
agentsh shim install-terminal

# All platforms - Verify installation
agentsh shim verify
```

---

## 10. Command Interception & Redirect (Cross-Platform)

### 10.1 Overview

Beyond file and network operations, agentsh can intercept and **redirect commands** themselves. This enables:

1. **Blocking dangerous commands** - `rm -rf /`, `shutdown`, etc.
2. **Redirecting to safe alternatives** - `curl` → `agentsh-fetch`
3. **Auditing tool usage** - Track all `git`, `npm`, `pip` invocations
4. **Path redirection** - Writes outside workspace → workspace subdirectory

### 10.2 Command Interception Points

```
┌─────────────────────────────────────────────────────────────────┐
│                    Command Execution Flow                        │
│                                                                 │
│  User/Agent                                                     │
│      │                                                          │
│      ▼                                                          │
│  ┌─────────────────┐                                           │
│  │  Shell Shim     │◀── Intercept Point 1: Shell invocation    │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ Command Parser  │◀── Intercept Point 2: Command resolution  │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ Policy Engine   │◀── Intercept Point 3: Policy evaluation   │
│  └────────┬────────┘                                           │
│           │                                                     │
│     ┌─────┴─────┐                                              │
│     │           │                                               │
│     ▼           ▼                                               │
│  ┌──────┐  ┌────────┐                                          │
│  │ Deny │  │ Allow/ │                                          │
│  │      │  │Redirect│                                          │
│  └──────┘  └───┬────┘                                          │
│                │                                                │
│                ▼                                                │
│  ┌─────────────────┐                                           │
│  │   Executor      │◀── Intercept Point 4: Actual execution    │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │  FUSE / Proxy   │◀── Intercept Point 5: I/O operations      │
│  └─────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

### 10.3 Command Rule Engine

```go
// pkg/policy/command.go

package policy

type CommandRule struct {
    Name        string            `yaml:"name"`
    Commands    []string          `yaml:"commands"`      // Command names to match
    ArgsPattern []string          `yaml:"args_pattern"`  // Glob patterns for args
    Decision    Decision          `yaml:"decision"`
    Message     string            `yaml:"message"`
    
    // Redirect configuration
    RedirectTo  *CommandRedirect  `yaml:"redirect_to,omitempty"`
    
    // Environment modifications
    EnvSet      map[string]string `yaml:"env_set,omitempty"`
    EnvUnset    []string          `yaml:"env_unset,omitempty"`
}

type CommandRedirect struct {
    Command     string            `yaml:"command"`       // New command
    Args        []string          `yaml:"args"`          // Prepended args
    ArgsAppend  []string          `yaml:"args_append"`   // Appended args
    Environment map[string]string `yaml:"environment"`
}

type Decision string

const (
    DecisionAllow     Decision = "allow"
    DecisionDeny      Decision = "deny"
    DecisionApprove   Decision = "approve"
    DecisionRedirect  Decision = "redirect"
    DecisionAudit     Decision = "audit"      // Allow + enhanced logging
    DecisionSoftDelete Decision = "soft_delete" // For destructive ops
)

// Evaluate command against rules
func (e *PolicyEngine) EvaluateCommand(cmd string, args []string) *CommandDecision {
    for _, rule := range e.commandRules {
        if !matchCommand(rule.Commands, cmd) {
            continue
        }
        if len(rule.ArgsPattern) > 0 && !matchArgs(rule.ArgsPattern, args) {
            continue
        }
        
        return &CommandDecision{
            Rule:       rule.Name,
            Decision:   rule.Decision,
            Message:    expandTemplate(rule.Message, cmd, args),
            RedirectTo: rule.RedirectTo,
            EnvSet:     rule.EnvSet,
            EnvUnset:   rule.EnvUnset,
        }
    }
    
    // Default: allow
    return &CommandDecision{
        Rule:     "default",
        Decision: DecisionAllow,
    }
}
```

### 10.4 Command Redirect Examples

#### 10.4.1 Redirect Network Tools to Audited Wrapper

```yaml
# policies/network-audit.yaml

command_rules:
  - name: redirect-curl
    commands: [curl, wget, http, httpie]
    decision: redirect
    message: "Network requests routed through audited fetch"
    redirect_to:
      command: agentsh-fetch
      args: ["--audit", "--session", "${AGENTSH_SESSION}"]
      # Original args are appended automatically
      
  - name: redirect-git-clone
    commands: [git]
    args_pattern: ["clone*", "pull*", "fetch*", "push*"]
    decision: redirect
    redirect_to:
      command: agentsh-git
      args: ["--audit"]
```

#### 10.4.2 Redirect Writes Outside Workspace

```yaml
# policies/workspace-contain.yaml

file_rules:
  - name: redirect-outside-writes
    paths:
      - "/home/**"
      - "/tmp/**"
      - "/var/tmp/**"
    operations: [write, create]
    decision: redirect
    redirect_to: "${WORKSPACE}/.scratch"
    message: "Writes outside workspace redirected to ${WORKSPACE}/.scratch"
    
  - name: redirect-etc-writes
    paths: ["/etc/**"]
    operations: [write, create]
    decision: redirect
    redirect_to: "${WORKSPACE}/.fake-etc"
    message: "System config writes redirected to fake-etc"
```

### 10.5 Path Redirect Implementation

```go
// pkg/fs/redirect.go

package fs

import (
    "path/filepath"
    "strings"
)

type PathRedirector struct {
    rules []PathRedirectRule
}

type PathRedirectRule struct {
    SourcePattern string // Glob pattern for source path
    TargetBase    string // Base directory for redirected files
    Operations    []string
    PreserveTree  bool   // Preserve directory structure under target
}

func (r *PathRedirector) Redirect(path string, op string) (string, bool) {
    for _, rule := range r.rules {
        if !matchOperation(rule.Operations, op) {
            continue
        }
        if !matchGlob(rule.SourcePattern, path) {
            continue
        }
        
        // Calculate redirected path
        var newPath string
        if rule.PreserveTree {
            // /home/user/file.txt -> /workspace/.scratch/home/user/file.txt
            newPath = filepath.Join(rule.TargetBase, path)
        } else {
            // /home/user/file.txt -> /workspace/.scratch/file.txt
            newPath = filepath.Join(rule.TargetBase, filepath.Base(path))
        }
        
        return newPath, true
    }
    
    return path, false
}

// FUSE integration
func (fs *AgentFS) Create(name string, flags uint32, mode uint32) (nodefs.File, fuse.Status) {
    // Check for redirect
    if newPath, redirected := fs.redirector.Redirect(name, "create"); redirected {
        fs.emitEvent(EventFileRedirect{
            OriginalPath: name,
            RedirectPath: newPath,
            Operation:    "create",
        })
        name = newPath
        
        // Ensure parent directory exists
        os.MkdirAll(filepath.Dir(fs.realPath(name)), 0755)
    }
    
    // Proceed with creation at (possibly redirected) path
    return fs.createFile(name, flags, mode)
}
```

### 10.6 Audited Command Wrappers

```go
// cmd/agentsh-fetch/main.go
// Audited replacement for curl/wget

package main

import (
    "io"
    "net/http"
    "os"
)

func main() {
    session := os.Getenv("AGENTSH_SESSION")
    server := os.Getenv("AGENTSH_SERVER")
    
    // Parse curl-like arguments
    url, opts := parseArgs(os.Args[1:])
    
    // Log the request to agentsh
    client := NewAgentshClient(server)
    client.LogNetworkRequest(session, NetworkRequest{
        Type:   "http",
        URL:    url,
        Method: opts.Method,
    })
    
    // Perform the actual request
    resp, err := http.Get(url)
    if err != nil {
        client.LogNetworkError(session, url, err)
        os.Exit(1)
    }
    defer resp.Body.Close()
    
    // Log response metadata
    client.LogNetworkResponse(session, NetworkResponse{
        URL:        url,
        StatusCode: resp.StatusCode,
        Size:       resp.ContentLength,
        Headers:    resp.Header,
    })
    
    // Output response body
    io.Copy(os.Stdout, resp.Body)
}
```

### 10.7 Platform-Specific Considerations

| Feature | Linux | macOS | Windows |
|---------|:-----:|:-----:|:-------:|
| Command interception | ✅ Shell shim | ⚠️ PATH/Profile | ⚠️ Profile |
| Path redirect in FUSE | ✅ | ✅ FUSE-T | ✅ WinFsp |
| Wrapper commands | ✅ | ✅ | ✅ |
| execve interception | ✅ seccomp | ❌ | ❌ |
| Dynamic library hook | ✅ LD_PRELOAD | ⚠️ DYLD+SIP | ✅ Detours |

---

## 11. Resource Limits (Cross-Platform)

### 11.1 Overview

Resource limits prevent agents from consuming excessive CPU, memory, disk, or network resources. Each platform has different mechanisms:

| Platform | Primary Mechanism | Secondary |
|----------|-------------------|-----------|
| Linux | cgroups v2 | setrlimit, ulimit |
| macOS | setrlimit, process limits | launchd limits |
| Windows | Job Objects | Process quotas |

### 11.2 Unified Resource Limits Interface

```go
// pkg/resource/limits.go

package resource

import "time"

// ResourceLimits defines constraints for a session/command
type ResourceLimits struct {
    // Memory
    MaxMemoryMB      int64         `yaml:"max_memory_mb"`
    MaxSwapMB        int64         `yaml:"max_swap_mb"`
    
    // CPU
    CPUQuotaPercent  int           `yaml:"cpu_quota_percent"`  // % of one CPU
    CPUPeriodUS      int64         `yaml:"cpu_period_us"`      // Period in microseconds
    CPUShares        int64         `yaml:"cpu_shares"`         // Relative weight
    
    // Process
    MaxProcesses     int           `yaml:"max_processes"`      // pids.max
    MaxThreads       int           `yaml:"max_threads"`
    
    // I/O
    MaxDiskReadMBps  int64         `yaml:"max_disk_read_mbps"`
    MaxDiskWriteMBps int64         `yaml:"max_disk_write_mbps"`
    MaxDiskMB        int64         `yaml:"max_disk_mb"`        // Total disk quota
    
    // Network
    MaxNetSendMBps   int64         `yaml:"max_net_send_mbps"`
    MaxNetRecvMBps   int64         `yaml:"max_net_recv_mbps"`
    MaxNetMB         int64         `yaml:"max_net_mb"`         // Total transfer quota
    
    // Time
    CommandTimeout   time.Duration `yaml:"command_timeout"`
    SessionTimeout   time.Duration `yaml:"session_timeout"`
}

// ResourceLimiter applies limits to processes
type ResourceLimiter interface {
    // Apply limits to a process/session
    Apply(pid int, limits ResourceLimits) error
    
    // Get current resource usage
    Usage(pid int) (*ResourceUsage, error)
    
    // Check if limits exceeded
    CheckLimits(pid int) (*LimitViolation, error)
    
    // Clean up resources
    Cleanup(pid int) error
}

type ResourceUsage struct {
    MemoryMB       int64
    CPUPercent     float64
    DiskReadMB     int64
    DiskWriteMB    int64
    NetSentMB      int64
    NetReceivedMB  int64
    ProcessCount   int
    ThreadCount    int
}

type LimitViolation struct {
    Resource string
    Limit    int64
    Current  int64
    Action   string // "warn", "throttle", "kill"
}
```

### 11.3 Linux Implementation (cgroups v2)

```go
// pkg/resource/linux_cgroups.go
// +build linux

package resource

import (
    "fmt"
    "os"
    "path/filepath"
    "strconv"
)

type CgroupsV2Limiter struct {
    basePath string // e.g., /sys/fs/cgroup/agentsh
}

func NewCgroupsV2Limiter(basePath string) (*CgroupsV2Limiter, error) {
    // Ensure we're on cgroups v2
    if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); os.IsNotExist(err) {
        return nil, fmt.Errorf("cgroups v2 not available")
    }
    
    fullPath := filepath.Join("/sys/fs/cgroup", basePath)
    if err := os.MkdirAll(fullPath, 0755); err != nil {
        return nil, fmt.Errorf("create cgroup: %w", err)
    }
    
    // Enable controllers
    controllers := "+cpu +memory +io +pids"
    subtreeControl := filepath.Join(fullPath, "cgroup.subtree_control")
    if err := os.WriteFile(subtreeControl, []byte(controllers), 0644); err != nil {
        // May fail if not delegated - try individual controllers
    }
    
    return &CgroupsV2Limiter{basePath: fullPath}, nil
}

func (l *CgroupsV2Limiter) Apply(pid int, limits ResourceLimits) error {
    cgroupPath := filepath.Join(l.basePath, fmt.Sprintf("session-%d", pid))
    if err := os.MkdirAll(cgroupPath, 0755); err != nil {
        return err
    }
    
    // Memory limit
    if limits.MaxMemoryMB > 0 {
        memMax := filepath.Join(cgroupPath, "memory.max")
        memBytes := limits.MaxMemoryMB * 1024 * 1024
        if err := os.WriteFile(memMax, []byte(strconv.FormatInt(memBytes, 10)), 0644); err != nil {
            return fmt.Errorf("set memory.max: %w", err)
        }
        
        // Swap limit (memory.swap.max)
        if limits.MaxSwapMB >= 0 {
            swapMax := filepath.Join(cgroupPath, "memory.swap.max")
            swapBytes := limits.MaxSwapMB * 1024 * 1024
            _ = os.WriteFile(swapMax, []byte(strconv.FormatInt(swapBytes, 10)), 0644)
        }
    }
    
    // CPU limit (cpu.max: quota period)
    if limits.CPUQuotaPercent > 0 {
        cpuMax := filepath.Join(cgroupPath, "cpu.max")
        period := int64(100000) // 100ms default period
        if limits.CPUPeriodUS > 0 {
            period = limits.CPUPeriodUS
        }
        quota := period * int64(limits.CPUQuotaPercent) / 100
        value := fmt.Sprintf("%d %d", quota, period)
        if err := os.WriteFile(cpuMax, []byte(value), 0644); err != nil {
            return fmt.Errorf("set cpu.max: %w", err)
        }
    }
    
    // CPU shares (cpu.weight: 1-10000, default 100)
    if limits.CPUShares > 0 {
        cpuWeight := filepath.Join(cgroupPath, "cpu.weight")
        // Convert shares (2-262144) to weight (1-10000)
        weight := limits.CPUShares * 10000 / 262144
        if weight < 1 {
            weight = 1
        }
        _ = os.WriteFile(cpuWeight, []byte(strconv.FormatInt(weight, 10)), 0644)
    }
    
    // Process limit (pids.max)
    if limits.MaxProcesses > 0 {
        pidsMax := filepath.Join(cgroupPath, "pids.max")
        if err := os.WriteFile(pidsMax, []byte(strconv.Itoa(limits.MaxProcesses)), 0644); err != nil {
            return fmt.Errorf("set pids.max: %w", err)
        }
    }
    
    // I/O limits (io.max)
    if limits.MaxDiskReadMBps > 0 || limits.MaxDiskWriteMBps > 0 {
        // Need device major:minor - get root device
        device := l.getRootDevice()
        if device != "" {
            ioMax := filepath.Join(cgroupPath, "io.max")
            rbps := limits.MaxDiskReadMBps * 1024 * 1024
            wbps := limits.MaxDiskWriteMBps * 1024 * 1024
            value := fmt.Sprintf("%s rbps=%d wbps=%d", device, rbps, wbps)
            _ = os.WriteFile(ioMax, []byte(value), 0644)
        }
    }
    
    // Add process to cgroup
    procsFile := filepath.Join(cgroupPath, "cgroup.procs")
    if err := os.WriteFile(procsFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
        return fmt.Errorf("add to cgroup: %w", err)
    }
    
    return nil
}

func (l *CgroupsV2Limiter) Usage(pid int) (*ResourceUsage, error) {
    cgroupPath := filepath.Join(l.basePath, fmt.Sprintf("session-%d", pid))
    
    usage := &ResourceUsage{}
    
    // Memory usage
    memCurrent := filepath.Join(cgroupPath, "memory.current")
    if data, err := os.ReadFile(memCurrent); err == nil {
        if bytes, err := strconv.ParseInt(string(data[:len(data)-1]), 10, 64); err == nil {
            usage.MemoryMB = bytes / 1024 / 1024
        }
    }
    
    // CPU usage (from cpu.stat)
    cpuStat := filepath.Join(cgroupPath, "cpu.stat")
    if data, err := os.ReadFile(cpuStat); err == nil {
        // Parse usage_usec
        // ...
    }
    
    // Process count
    procsFile := filepath.Join(cgroupPath, "cgroup.procs")
    if data, err := os.ReadFile(procsFile); err == nil {
        usage.ProcessCount = len(strings.Split(string(data), "\n")) - 1
    }
    
    return usage, nil
}

func (l *CgroupsV2Limiter) Cleanup(pid int) error {
    cgroupPath := filepath.Join(l.basePath, fmt.Sprintf("session-%d", pid))
    
    // Move all processes out first
    procsFile := filepath.Join(cgroupPath, "cgroup.procs")
    if data, err := os.ReadFile(procsFile); err == nil {
        parentProcs := filepath.Join(l.basePath, "cgroup.procs")
        for _, pidStr := range strings.Split(string(data), "\n") {
            if pidStr != "" {
                _ = os.WriteFile(parentProcs, []byte(pidStr), 0644)
            }
        }
    }
    
    // Remove cgroup directory
    return os.Remove(cgroupPath)
}

func (l *CgroupsV2Limiter) getRootDevice() string {
    // Parse /proc/self/mountinfo to find root device
    // Returns "major:minor" format
    // ...
    return "8:0" // Default to sda
}
```

### 11.4 macOS Implementation (setrlimit + Process Limits)

```go
// pkg/resource/darwin_limits.go
// +build darwin

package resource

import (
    "fmt"
    "os/exec"
    "strconv"
    "syscall"
)

type DarwinLimiter struct {
    useLaunchd bool
}

func NewDarwinLimiter() *DarwinLimiter {
    return &DarwinLimiter{useLaunchd: false}
}

func (l *DarwinLimiter) Apply(pid int, limits ResourceLimits) error {
    // Use setrlimit for the process
    // Note: Must be called from the process itself or via launchd
    
    // For external process, we need to use launchctl or a helper
    if pid != 0 && pid != syscall.Getpid() {
        return l.applyExternal(pid, limits)
    }
    
    // Memory limit (RLIMIT_AS - address space)
    if limits.MaxMemoryMB > 0 {
        var rLimit syscall.Rlimit
        rLimit.Cur = uint64(limits.MaxMemoryMB) * 1024 * 1024
        rLimit.Max = rLimit.Cur
        if err := syscall.Setrlimit(syscall.RLIMIT_AS, &rLimit); err != nil {
            return fmt.Errorf("setrlimit AS: %w", err)
        }
    }
    
    // CPU time limit (RLIMIT_CPU) - in seconds
    if limits.CommandTimeout > 0 {
        var rLimit syscall.Rlimit
        rLimit.Cur = uint64(limits.CommandTimeout.Seconds())
        rLimit.Max = rLimit.Cur + 60 // Grace period
        if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &rLimit); err != nil {
            return fmt.Errorf("setrlimit CPU: %w", err)
        }
    }
    
    // File size limit (RLIMIT_FSIZE)
    if limits.MaxDiskMB > 0 {
        var rLimit syscall.Rlimit
        rLimit.Cur = uint64(limits.MaxDiskMB) * 1024 * 1024
        rLimit.Max = rLimit.Cur
        if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &rLimit); err != nil {
            return fmt.Errorf("setrlimit FSIZE: %w", err)
        }
    }
    
    // Process limit (RLIMIT_NPROC)
    if limits.MaxProcesses > 0 {
        var rLimit syscall.Rlimit
        rLimit.Cur = uint64(limits.MaxProcesses)
        rLimit.Max = rLimit.Cur
        if err := syscall.Setrlimit(syscall.RLIMIT_NPROC, &rLimit); err != nil {
            return fmt.Errorf("setrlimit NPROC: %w", err)
        }
    }
    
    // Open files limit (RLIMIT_NOFILE)
    // (Often needed for applications that open many files)
    
    return nil
}

func (l *DarwinLimiter) applyExternal(pid int, limits ResourceLimits) error {
    // For external process, use a helper or accept limitations
    // macOS doesn't have a way to apply rlimits to running processes
    
    // Alternative: Use process priority (nice)
    if limits.CPUShares > 0 {
        // Lower priority = less CPU (nice 0-20)
        nice := 20 - int(limits.CPUShares*20/100)
        exec.Command("renice", strconv.Itoa(nice), "-p", strconv.Itoa(pid)).Run()
    }
    
    return nil
}

func (l *DarwinLimiter) Usage(pid int) (*ResourceUsage, error) {
    usage := &ResourceUsage{}
    
    // Use ps to get process info
    out, err := exec.Command("ps", "-o", "rss=,pcpu=", "-p", strconv.Itoa(pid)).Output()
    if err != nil {
        return nil, err
    }
    
    // Parse output: RSS (KB), CPU%
    var rss int64
    var cpu float64
    fmt.Sscanf(string(out), "%d %f", &rss, &cpu)
    
    usage.MemoryMB = rss / 1024
    usage.CPUPercent = cpu
    
    return usage, nil
}

func (l *DarwinLimiter) Cleanup(pid int) error {
    // No persistent state to clean up
    return nil
}
```

### 11.5 Windows Implementation (Job Objects)

```go
// pkg/resource/windows_job.go
// +build windows

package resource

import (
    "fmt"
    "unsafe"
    
    "golang.org/x/sys/windows"
)

type WindowsJobLimiter struct {
    jobs map[int]windows.Handle
}

func NewWindowsJobLimiter() *WindowsJobLimiter {
    return &WindowsJobLimiter{
        jobs: make(map[int]windows.Handle),
    }
}

func (l *WindowsJobLimiter) Apply(pid int, limits ResourceLimits) error {
    // Create a Job Object
    job, err := windows.CreateJobObject(nil, nil)
    if err != nil {
        return fmt.Errorf("CreateJobObject: %w", err)
    }
    l.jobs[pid] = job
    
    // Set basic limits
    var basicInfo windows.JOBOBJECT_BASIC_LIMIT_INFORMATION
    var extendedInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    
    extendedInfo.BasicLimitInformation = basicInfo
    
    // Memory limit
    if limits.MaxMemoryMB > 0 {
        extendedInfo.JobMemoryLimit = uintptr(limits.MaxMemoryMB * 1024 * 1024)
        extendedInfo.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY
    }
    
    // Process memory limit
    if limits.MaxMemoryMB > 0 {
        extendedInfo.ProcessMemoryLimit = uintptr(limits.MaxMemoryMB * 1024 * 1024)
        extendedInfo.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
    }
    
    // CPU time limit (per process, in 100ns units)
    if limits.CommandTimeout > 0 {
        extendedInfo.BasicLimitInformation.PerProcessUserTimeLimit = 
            int64(limits.CommandTimeout.Nanoseconds() / 100)
        extendedInfo.BasicLimitInformation.LimitFlags |= 
            windows.JOB_OBJECT_LIMIT_PROCESS_TIME
    }
    
    // Active process limit
    if limits.MaxProcesses > 0 {
        extendedInfo.BasicLimitInformation.ActiveProcessLimit = uint32(limits.MaxProcesses)
        extendedInfo.BasicLimitInformation.LimitFlags |= 
            windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    }
    
    // Set the limits
    err = windows.SetInformationJobObject(
        job,
        windows.JobObjectExtendedLimitInformation,
        uintptr(unsafe.Pointer(&extendedInfo)),
        uint32(unsafe.Sizeof(extendedInfo)),
    )
    if err != nil {
        windows.CloseHandle(job)
        return fmt.Errorf("SetInformationJobObject: %w", err)
    }
    
    // CPU rate limit (Windows 8+)
    if limits.CPUQuotaPercent > 0 {
        var cpuRateInfo JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
        cpuRateInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | 
                                   JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        cpuRateInfo.CpuRate = uint32(limits.CPUQuotaPercent * 100) // In hundredths of percent
        
        windows.SetInformationJobObject(
            job,
            JobObjectCpuRateControlInformation,
            uintptr(unsafe.Pointer(&cpuRateInfo)),
            uint32(unsafe.Sizeof(cpuRateInfo)),
        )
    }
    
    // Assign process to job
    process, err := windows.OpenProcess(
        windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
        false,
        uint32(pid),
    )
    if err != nil {
        windows.CloseHandle(job)
        return fmt.Errorf("OpenProcess: %w", err)
    }
    defer windows.CloseHandle(process)
    
    if err := windows.AssignProcessToJobObject(job, process); err != nil {
        windows.CloseHandle(job)
        return fmt.Errorf("AssignProcessToJobObject: %w", err)
    }
    
    return nil
}

func (l *WindowsJobLimiter) Usage(pid int) (*ResourceUsage, error) {
    job, ok := l.jobs[pid]
    if !ok {
        return nil, fmt.Errorf("no job for pid %d", pid)
    }
    
    var info JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION
    err := windows.QueryInformationJobObject(
        job,
        JobObjectBasicAndIoAccountingInformation,
        uintptr(unsafe.Pointer(&info)),
        uint32(unsafe.Sizeof(info)),
        nil,
    )
    if err != nil {
        return nil, err
    }
    
    usage := &ResourceUsage{
        ProcessCount: int(info.BasicInfo.ActiveProcesses),
        // CPU time in 100ns units
        CPUPercent: float64(info.BasicInfo.TotalUserTime+info.BasicInfo.TotalKernelTime) / 
                    10000000.0, // Convert to seconds
        DiskReadMB:  int64(info.IoInfo.ReadTransferCount) / 1024 / 1024,
        DiskWriteMB: int64(info.IoInfo.WriteTransferCount) / 1024 / 1024,
    }
    
    return usage, nil
}

func (l *WindowsJobLimiter) Cleanup(pid int) error {
    if job, ok := l.jobs[pid]; ok {
        windows.TerminateJobObject(job, 0)
        windows.CloseHandle(job)
        delete(l.jobs, pid)
    }
    return nil
}

// Constants not in x/sys/windows
const (
    JOB_OBJECT_CPU_RATE_CONTROL_ENABLE   = 0x1
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4
    JobObjectCpuRateControlInformation   = 15
    JobObjectBasicAndIoAccountingInformation = 8
)

type JOBOBJECT_CPU_RATE_CONTROL_INFORMATION struct {
    ControlFlags uint32
    CpuRate      uint32
}

type JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION struct {
    BasicInfo windows.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    IoInfo    windows.IO_COUNTERS
}
```

### 11.6 Platform Feature Matrix

| Limit | Linux (cgroups) | macOS (rlimit) | Windows (Job) |
|-------|:---------------:|:--------------:|:-------------:|
| Memory (hard) | ✅ memory.max | ⚠️ RLIMIT_AS | ✅ JobMemoryLimit |
| Memory (soft) | ✅ memory.high | ❌ | ❌ |
| Swap | ✅ memory.swap.max | ❌ | ❌ |
| CPU quota | ✅ cpu.max | ❌ | ✅ CpuRate |
| CPU shares | ✅ cpu.weight | ⚠️ nice | ❌ |
| Process count | ✅ pids.max | ⚠️ RLIMIT_NPROC | ✅ ActiveProcessLimit |
| CPU time | ✅ cpu.max | ⚠️ RLIMIT_CPU | ✅ PerProcessUserTimeLimit |
| Disk I/O rate | ✅ io.max | ❌ | ❌ |
| Disk quota | ⚠️ Filesystem | ⚠️ RLIMIT_FSIZE | ❌ |
| Network rate | ⚠️ tc/netfilter | ❌ | ❌ |
| Child tracking | ✅ Automatic | ❌ Manual | ✅ Automatic |

---

## 12. Process Tree Tracking (Cross-Platform)

### 12.1 Overview

When an agent runs a command, that command may spawn subprocesses. Tracking the entire process tree is essential for:

1. **Policy inheritance** - Child processes inherit parent's restrictions
2. **Resource accounting** - Aggregate usage across all descendants
3. **Cleanup** - Kill entire tree when session ends
4. **Audit completeness** - Log all subprocess activity

### 12.2 Process Tree Interface

```go
// pkg/process/tree.go

package process

import (
    "context"
    "os"
    "sync"
    "time"
)

// ProcessTree tracks a process and all its descendants
type ProcessTree struct {
    Root      *ProcessNode
    mu        sync.RWMutex
    tracker   ProcessTracker
    onSpawn   func(*ProcessNode)
    onExit    func(*ProcessNode, int)
}

type ProcessNode struct {
    PID       int
    PPID      int
    Command   string
    Args      []string
    StartTime time.Time
    EndTime   *time.Time
    ExitCode  *int
    Children  []*ProcessNode
}

// ProcessTracker is platform-specific
type ProcessTracker interface {
    // Start tracking a process and its descendants
    Track(pid int) error
    
    // Get all PIDs in the tree
    ListPIDs() []int
    
    // Check if a PID is in the tracked tree
    Contains(pid int) bool
    
    // Kill all processes in the tree
    KillAll(signal os.Signal) error
    
    // Wait for all processes to exit
    Wait(ctx context.Context) error
    
    // Get process info
    Info(pid int) (*ProcessNode, error)
    
    // Register callbacks
    OnSpawn(func(pid int, ppid int))
    OnExit(func(pid int, exitCode int))
    
    // Stop tracking
    Stop() error
}

// NewProcessTree creates a tracker for the given root PID
func NewProcessTree(rootPID int) (*ProcessTree, error) {
    tracker := newPlatformTracker()
    
    tree := &ProcessTree{
        Root: &ProcessNode{
            PID:       rootPID,
            StartTime: time.Now(),
        },
        tracker: tracker,
    }
    
    tracker.OnSpawn(tree.handleSpawn)
    tracker.OnExit(tree.handleExit)
    
    if err := tracker.Track(rootPID); err != nil {
        return nil, err
    }
    
    return tree, nil
}

func (t *ProcessTree) handleSpawn(pid, ppid int) {
    t.mu.Lock()
    defer t.mu.Unlock()
    
    parent := t.findNode(ppid)
    if parent == nil {
        return
    }
    
    child := &ProcessNode{
        PID:       pid,
        PPID:      ppid,
        StartTime: time.Now(),
    }
    parent.Children = append(parent.Children, child)
    
    if t.onSpawn != nil {
        t.onSpawn(child)
    }
}

func (t *ProcessTree) handleExit(pid, exitCode int) {
    t.mu.Lock()
    defer t.mu.Unlock()
    
    node := t.findNode(pid)
    if node == nil {
        return
    }
    
    now := time.Now()
    node.EndTime = &now
    node.ExitCode = &exitCode
    
    if t.onExit != nil {
        t.onExit(node, exitCode)
    }
}
```

### 12.3 Linux Implementation (cgroups + /proc)

```go
// pkg/process/tree_linux.go
// +build linux

package process

import (
    "bufio"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "syscall"
    
    "golang.org/x/sys/unix"
)

type LinuxProcessTracker struct {
    cgroupPath  string
    rootPID     int
    spawnCb     func(pid, ppid int)
    exitCb      func(pid, exitCode int)
    
    // For netlink-based tracking
    netlinkFd   int
    done        chan struct{}
}

func newPlatformTracker() ProcessTracker {
    return &LinuxProcessTracker{
        done: make(chan struct{}),
    }
}

func (t *LinuxProcessTracker) Track(pid int) error {
    t.rootPID = pid
    
    // Method 1: Use cgroups (preferred - automatic child tracking)
    if cgroupPath, err := t.setupCgroup(pid); err == nil {
        t.cgroupPath = cgroupPath
        go t.watchCgroupEvents()
        return nil
    }
    
    // Method 2: Use netlink proc connector (requires CAP_NET_ADMIN)
    if err := t.setupNetlink(); err == nil {
        go t.watchNetlink()
        return nil
    }
    
    // Method 3: Poll /proc (fallback)
    go t.pollProc()
    return nil
}

func (t *LinuxProcessTracker) setupCgroup(pid int) (string, error) {
    cgroupBase := "/sys/fs/cgroup/agentsh"
    cgroupPath := filepath.Join(cgroupBase, fmt.Sprintf("session-%d", pid))
    
    if err := os.MkdirAll(cgroupPath, 0755); err != nil {
        return "", err
    }
    
    // Move process to cgroup
    procsFile := filepath.Join(cgroupPath, "cgroup.procs")
    if err := os.WriteFile(procsFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
        return "", err
    }
    
    // Enable notifications
    eventsFile := filepath.Join(cgroupPath, "cgroup.events")
    // Set up inotify on events file
    
    return cgroupPath, nil
}

func (t *LinuxProcessTracker) watchCgroupEvents() {
    // Watch cgroup.events for populated changes
    // Watch cgroup.procs for membership changes
    
    eventsPath := filepath.Join(t.cgroupPath, "cgroup.events")
    
    fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
    if err != nil {
        return
    }
    defer unix.Close(fd)
    
    _, err = unix.InotifyAddWatch(fd, eventsPath, unix.IN_MODIFY)
    if err != nil {
        return
    }
    
    buf := make([]byte, 4096)
    for {
        select {
        case <-t.done:
            return
        default:
        }
        
        n, err := unix.Read(fd, buf)
        if err != nil || n == 0 {
            continue
        }
        
        // Read current procs
        t.updateFromProcs()
    }
}

func (t *LinuxProcessTracker) setupNetlink() error {
    // Set up netlink socket for proc connector
    fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
    if err != nil {
        return err
    }
    
    // Bind to kernel connector
    addr := &unix.SockaddrNetlink{
        Family: unix.AF_NETLINK,
        Groups: 1, // CN_IDX_PROC
    }
    if err := unix.Bind(fd, addr); err != nil {
        unix.Close(fd)
        return err
    }
    
    // Subscribe to proc events
    // Send PROC_CN_MCAST_LISTEN message
    
    t.netlinkFd = fd
    return nil
}

func (t *LinuxProcessTracker) watchNetlink() {
    defer unix.Close(t.netlinkFd)
    
    buf := make([]byte, 4096)
    for {
        select {
        case <-t.done:
            return
        default:
        }
        
        n, _, err := unix.Recvfrom(t.netlinkFd, buf, 0)
        if err != nil {
            continue
        }
        
        // Parse proc_event from netlink message
        t.parseProcEvent(buf[:n])
    }
}

func (t *LinuxProcessTracker) pollProc() {
    known := make(map[int]bool)
    known[t.rootPID] = true
    
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()
    
    for {
        select {
        case <-t.done:
            return
        case <-ticker.C:
            t.scanProc(known)
        }
    }
}

func (t *LinuxProcessTracker) scanProc(known map[int]bool) {
    // Scan /proc for children of known processes
    files, _ := os.ReadDir("/proc")
    
    for _, f := range files {
        pid, err := strconv.Atoi(f.Name())
        if err != nil {
            continue
        }
        
        if known[pid] {
            continue
        }
        
        // Check if parent is known
        ppid := t.getPPID(pid)
        if ppid > 0 && known[ppid] {
            known[pid] = true
            if t.spawnCb != nil {
                t.spawnCb(pid, ppid)
            }
        }
    }
    
    // Check for exits
    for pid := range known {
        if pid == t.rootPID {
            continue
        }
        if !t.processExists(pid) {
            delete(known, pid)
            if t.exitCb != nil {
                // Get exit code from wait status if available
                t.exitCb(pid, 0)
            }
        }
    }
}

func (t *LinuxProcessTracker) getPPID(pid int) int {
    statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
    data, err := os.ReadFile(statPath)
    if err != nil {
        return 0
    }
    
    // Parse: pid (comm) state ppid ...
    fields := strings.Fields(string(data))
    if len(fields) < 4 {
        return 0
    }
    
    ppid, _ := strconv.Atoi(fields[3])
    return ppid
}

func (t *LinuxProcessTracker) processExists(pid int) bool {
    return unix.Kill(pid, 0) == nil
}

func (t *LinuxProcessTracker) ListPIDs() []int {
    if t.cgroupPath != "" {
        return t.listFromCgroup()
    }
    return t.listFromProc()
}

func (t *LinuxProcessTracker) listFromCgroup() []int {
    procsFile := filepath.Join(t.cgroupPath, "cgroup.procs")
    data, err := os.ReadFile(procsFile)
    if err != nil {
        return nil
    }
    
    var pids []int
    for _, line := range strings.Split(string(data), "\n") {
        if pid, err := strconv.Atoi(line); err == nil {
            pids = append(pids, pid)
        }
    }
    return pids
}

func (t *LinuxProcessTracker) KillAll(signal os.Signal) error {
    sig := signal.(syscall.Signal)
    
    if t.cgroupPath != "" {
        // Use cgroup.kill (Linux 5.14+) or iterate
        killFile := filepath.Join(t.cgroupPath, "cgroup.kill")
        if err := os.WriteFile(killFile, []byte("1"), 0644); err == nil {
            return nil
        }
    }
    
    // Iterate and kill
    for _, pid := range t.ListPIDs() {
        unix.Kill(pid, sig)
    }
    return nil
}

func (t *LinuxProcessTracker) Stop() error {
    close(t.done)
    
    // Clean up cgroup
    if t.cgroupPath != "" {
        // Move processes out and remove
        os.RemoveAll(t.cgroupPath)
    }
    
    return nil
}
```

### 12.4 macOS Implementation (proc_listchildpids)

```go
// pkg/process/tree_darwin.go
// +build darwin

package process

/*
#include <libproc.h>
#include <sys/sysctl.h>
*/
import "C"

import (
    "os"
    "syscall"
    "time"
    "unsafe"
)

type DarwinProcessTracker struct {
    rootPID  int
    known    map[int]bool
    spawnCb  func(pid, ppid int)
    exitCb   func(pid, exitCode int)
    done     chan struct{}
}

func newPlatformTracker() ProcessTracker {
    return &DarwinProcessTracker{
        known: make(map[int]bool),
        done:  make(chan struct{}),
    }
}

func (t *DarwinProcessTracker) Track(pid int) error {
    t.rootPID = pid
    t.known[pid] = true
    
    go t.pollChildren()
    return nil
}

func (t *DarwinProcessTracker) pollChildren() {
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()
    
    for {
        select {
        case <-t.done:
            return
        case <-ticker.C:
            t.scanChildren()
        }
    }
}

func (t *DarwinProcessTracker) scanChildren() {
    // Check for new children of all known processes
    for pid := range t.known {
        children := t.getChildPIDs(pid)
        for _, child := range children {
            if !t.known[child] {
                t.known[child] = true
                if t.spawnCb != nil {
                    t.spawnCb(child, pid)
                }
            }
        }
    }
    
    // Check for exits
    for pid := range t.known {
        if pid == t.rootPID {
            continue
        }
        if !t.processExists(pid) {
            delete(t.known, pid)
            if t.exitCb != nil {
                t.exitCb(pid, 0)
            }
        }
    }
}

func (t *DarwinProcessTracker) getChildPIDs(pid int) []int {
    // Use proc_listchildpids
    var count C.int
    count = C.proc_listchildpids(C.int(pid), nil, 0)
    if count <= 0 {
        return nil
    }
    
    pids := make([]C.int, count)
    count = C.proc_listchildpids(C.int(pid), unsafe.Pointer(&pids[0]), C.int(len(pids))*C.sizeof_int)
    if count <= 0 {
        return nil
    }
    
    result := make([]int, count)
    for i := 0; i < int(count); i++ {
        result[i] = int(pids[i])
    }
    return result
}

func (t *DarwinProcessTracker) processExists(pid int) bool {
    return syscall.Kill(pid, 0) == nil
}

func (t *DarwinProcessTracker) ListPIDs() []int {
    result := make([]int, 0, len(t.known))
    for pid := range t.known {
        result = append(result, pid)
    }
    return result
}

func (t *DarwinProcessTracker) KillAll(signal os.Signal) error {
    sig := signal.(syscall.Signal)
    
    // Kill in reverse order (children first)
    pids := t.ListPIDs()
    for i := len(pids) - 1; i >= 0; i-- {
        syscall.Kill(pids[i], sig)
    }
    return nil
}

func (t *DarwinProcessTracker) Contains(pid int) bool {
    return t.known[pid]
}

func (t *DarwinProcessTracker) OnSpawn(cb func(pid, ppid int)) {
    t.spawnCb = cb
}

func (t *DarwinProcessTracker) OnExit(cb func(pid, exitCode int)) {
    t.exitCb = cb
}

func (t *DarwinProcessTracker) Stop() error {
    close(t.done)
    return nil
}
```

### 12.5 Windows Implementation (Job Objects)

```go
// pkg/process/tree_windows.go
// +build windows

package process

import (
    "os"
    "syscall"
    "unsafe"
    
    "golang.org/x/sys/windows"
)

type WindowsProcessTracker struct {
    job      windows.Handle
    rootPID  int
    spawnCb  func(pid, ppid int)
    exitCb   func(pid, exitCode int)
    done     chan struct{}
    ioPort   windows.Handle
}

func newPlatformTracker() ProcessTracker {
    return &WindowsProcessTracker{
        done: make(chan struct{}),
    }
}

func (t *WindowsProcessTracker) Track(pid int) error {
    t.rootPID = pid
    
    // Create Job Object
    job, err := windows.CreateJobObject(nil, nil)
    if err != nil {
        return err
    }
    t.job = job
    
    // Create I/O completion port for notifications
    ioPort, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
    if err != nil {
        windows.CloseHandle(job)
        return err
    }
    t.ioPort = ioPort
    
    // Associate completion port with job
    var port JOBOBJECT_ASSOCIATE_COMPLETION_PORT
    port.CompletionKey = uintptr(job)
    port.CompletionPort = ioPort
    
    err = windows.SetInformationJobObject(
        job,
        windows.JobObjectAssociateCompletionPortInformation,
        uintptr(unsafe.Pointer(&port)),
        uint32(unsafe.Sizeof(port)),
    )
    if err != nil {
        windows.CloseHandle(ioPort)
        windows.CloseHandle(job)
        return err
    }
    
    // Configure job to track all child processes
    var extInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    extInfo.BasicLimitInformation.LimitFlags = 
        windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_BREAKAWAY_OK
    
    err = windows.SetInformationJobObject(
        job,
        windows.JobObjectExtendedLimitInformation,
        uintptr(unsafe.Pointer(&extInfo)),
        uint32(unsafe.Sizeof(extInfo)),
    )
    if err != nil {
        windows.CloseHandle(ioPort)
        windows.CloseHandle(job)
        return err
    }
    
    // Add root process to job
    process, err := windows.OpenProcess(
        windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
        false,
        uint32(pid),
    )
    if err != nil {
        windows.CloseHandle(ioPort)
        windows.CloseHandle(job)
        return err
    }
    defer windows.CloseHandle(process)
    
    if err := windows.AssignProcessToJobObject(job, process); err != nil {
        windows.CloseHandle(ioPort)
        windows.CloseHandle(job)
        return err
    }
    
    // Start notification watcher
    go t.watchNotifications()
    
    return nil
}

func (t *WindowsProcessTracker) watchNotifications() {
    var (
        bytesTransferred uint32
        completionKey    uintptr
        overlapped       *windows.Overlapped
    )
    
    for {
        select {
        case <-t.done:
            return
        default:
        }
        
        err := windows.GetQueuedCompletionStatus(
            t.ioPort,
            &bytesTransferred,
            &completionKey,
            &overlapped,
            100, // 100ms timeout
        )
        
        if err != nil {
            if err == syscall.WAIT_TIMEOUT {
                continue
            }
            return
        }
        
        // bytesTransferred contains the message type
        msgType := bytesTransferred
        // overlapped (as uintptr) contains the PID
        pid := int(uintptr(unsafe.Pointer(overlapped)))
        
        switch msgType {
        case JOB_OBJECT_MSG_NEW_PROCESS:
            if t.spawnCb != nil {
                // Get parent PID via NtQueryInformationProcess
                ppid := t.getParentPID(pid)
                t.spawnCb(pid, ppid)
            }
            
        case JOB_OBJECT_MSG_EXIT_PROCESS:
            if t.exitCb != nil {
                t.exitCb(pid, 0)
            }
            
        case JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS:
            if t.exitCb != nil {
                t.exitCb(pid, -1)
            }
        }
    }
}

func (t *WindowsProcessTracker) getParentPID(pid int) int {
    handle, err := windows.OpenProcess(
        windows.PROCESS_QUERY_LIMITED_INFORMATION,
        false,
        uint32(pid),
    )
    if err != nil {
        return 0
    }
    defer windows.CloseHandle(handle)
    
    var pbi PROCESS_BASIC_INFORMATION
    var returnLength uint32
    
    status := NtQueryInformationProcess(
        handle,
        ProcessBasicInformation,
        unsafe.Pointer(&pbi),
        uint32(unsafe.Sizeof(pbi)),
        &returnLength,
    )
    
    if status != 0 {
        return 0
    }
    
    return int(pbi.InheritedFromUniqueProcessId)
}

func (t *WindowsProcessTracker) ListPIDs() []int {
    var info JOBOBJECT_BASIC_PROCESS_ID_LIST
    info.NumberOfAssignedProcesses = 1000
    pids := make([]uintptr, 1000)
    info.ProcessIdList = pids
    
    err := windows.QueryInformationJobObject(
        t.job,
        JobObjectBasicProcessIdList,
        uintptr(unsafe.Pointer(&info)),
        uint32(unsafe.Sizeof(info)) + uint32(len(pids))*8,
        nil,
    )
    if err != nil {
        return nil
    }
    
    result := make([]int, info.NumberOfProcessIdsInList)
    for i := uint32(0); i < info.NumberOfProcessIdsInList; i++ {
        result[i] = int(pids[i])
    }
    return result
}

func (t *WindowsProcessTracker) KillAll(signal os.Signal) error {
    // Terminate all processes in the job
    return windows.TerminateJobObject(t.job, 1)
}

func (t *WindowsProcessTracker) Contains(pid int) bool {
    process, err := windows.OpenProcess(
        windows.PROCESS_QUERY_LIMITED_INFORMATION,
        false,
        uint32(pid),
    )
    if err != nil {
        return false
    }
    defer windows.CloseHandle(process)
    
    var inJob int32
    err = windows.IsProcessInJob(process, t.job, &inJob)
    return err == nil && inJob != 0
}

func (t *WindowsProcessTracker) OnSpawn(cb func(pid, ppid int)) {
    t.spawnCb = cb
}

func (t *WindowsProcessTracker) OnExit(cb func(pid, exitCode int)) {
    t.exitCb = cb
}

func (t *WindowsProcessTracker) Stop() error {
    close(t.done)
    windows.CloseHandle(t.ioPort)
    windows.CloseHandle(t.job)
    return nil
}

// Constants
const (
    JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
    JOB_OBJECT_MSG_NEW_PROCESS    = 6
    JOB_OBJECT_MSG_EXIT_PROCESS   = 7
    JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS = 8
    JobObjectBasicProcessIdList   = 3
    ProcessBasicInformation       = 0
)

type JOBOBJECT_ASSOCIATE_COMPLETION_PORT struct {
    CompletionKey  uintptr
    CompletionPort windows.Handle
}

type JOBOBJECT_BASIC_PROCESS_ID_LIST struct {
    NumberOfAssignedProcesses  uint32
    NumberOfProcessIdsInList   uint32
    ProcessIdList              []uintptr
}

type PROCESS_BASIC_INFORMATION struct {
    Reserved1                    uintptr
    PebBaseAddress               uintptr
    Reserved2                    [2]uintptr
    UniqueProcessId              uintptr
    InheritedFromUniqueProcessId uintptr
}

// NtQueryInformationProcess from ntdll.dll
var (
    ntdll                      = syscall.NewLazyDLL("ntdll.dll")
    procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
)

func NtQueryInformationProcess(handle windows.Handle, class int, info unsafe.Pointer, size uint32, returnLen *uint32) uint32 {
    r, _, _ := procNtQueryInformationProcess.Call(
        uintptr(handle),
        uintptr(class),
        uintptr(info),
        uintptr(size),
        uintptr(unsafe.Pointer(returnLen)),
    )
    return uint32(r)
}
```

### 12.6 Platform Feature Matrix

| Feature | Linux (cgroups) | Linux (netlink) | macOS | Windows (Job) |
|---------|:---------------:|:---------------:|:-----:|:-------------:|
| Auto child tracking | ✅ | ✅ | ❌ Poll | ✅ |
| Spawn notification | ✅ | ✅ | ❌ Poll | ✅ |
| Exit notification | ✅ | ✅ | ❌ Poll | ✅ |
| Exit code capture | ❌ | ✅ | ❌ | ✅ |
| Atomic kill all | ✅ cgroup.kill | ❌ | ❌ | ✅ TerminateJobObject |
| No root required | ⚠️ Delegated | ❌ CAP_NET_ADMIN | ✅ | ✅ |
| Performance | ✅ | ✅ | ⚠️ Polling | ✅ |

---

## 13. Unix Socket / IPC Monitoring (Cross-Platform)

### 13.1 Overview

Unix domain sockets and other IPC mechanisms (named pipes, shared memory) can be used to bypass network monitoring. Monitoring these is important for:

1. **Database connections** - Many databases use Unix sockets
2. **Docker socket** - `/var/run/docker.sock` is a common target
3. **X11 forwarding** - `/tmp/.X11-unix/*`
4. **D-Bus** - System and session bus access
5. **Agent communication** - Detecting covert channels

### 13.2 IPC Monitoring Interface

```go
// pkg/ipc/monitor.go

package ipc

import (
    "context"
    "net"
)

// IPCMonitor monitors inter-process communication
type IPCMonitor interface {
    // Start monitoring
    Start(ctx context.Context) error
    
    // Stop monitoring
    Stop() error
    
    // Register event handlers
    OnSocketConnect(func(event SocketEvent))
    OnSocketBind(func(event SocketEvent))
    OnPipeOpen(func(event PipeEvent))
    
    // Get active connections
    ListConnections() []Connection
}

type SocketEvent struct {
    Timestamp   time.Time
    PID         int
    Operation   string // "connect", "bind", "listen", "accept"
    SocketType  string // "unix", "abstract", "netlink"
    Path        string // Socket path (if filesystem-based)
    Address     string // Abstract name or other address
    Peer        *PeerInfo
    Decision    string
    PolicyRule  string
}

type PipeEvent struct {
    Timestamp   time.Time
    PID         int
    Operation   string // "open", "create", "write", "read"
    Path        string // Named pipe path
    Flags       int
    Decision    string
}

type PeerInfo struct {
    PID  int
    UID  int
    GID  int
    Comm string
}

type Connection struct {
    LocalPath   string
    RemotePath  string
    LocalPID    int
    RemotePID   int
    State       string
    BytesSent   int64
    BytesRecv   int64
}
```

### 13.3 Linux Implementation (seccomp user-notify)

```go
// pkg/ipc/monitor_linux.go
// +build linux

package ipc

import (
    "context"
    "fmt"
    "os"
    "syscall"
    "unsafe"
    
    "golang.org/x/sys/unix"
)

type LinuxIPCMonitor struct {
    notifyFd    int
    policyEngine *PolicyEngine
    
    onConnect   func(SocketEvent)
    onBind      func(SocketEvent)
    onPipe      func(PipeEvent)
    
    done        chan struct{}
}

func NewLinuxIPCMonitor(policy *PolicyEngine) (*LinuxIPCMonitor, error) {
    return &LinuxIPCMonitor{
        policyEngine: policy,
        done:         make(chan struct{}),
    }, nil
}

// SetupSeccompNotify configures seccomp user-notify for socket syscalls
func (m *LinuxIPCMonitor) SetupSeccompNotify() (int, error) {
    // Create seccomp filter with SECCOMP_RET_USER_NOTIF for:
    // - socket() when AF_UNIX
    // - connect() when sockaddr_un
    // - bind() when sockaddr_un
    
    filter := []unix.SockFilter{
        // Load syscall number
        unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
        
        // Check for connect
        unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, 
            K: uint32(unix.SYS_CONNECT), Jt: 0, Jf: 2},
        // Return user notify for connect
        unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, 
            K: uint32(unix.SECCOMP_RET_USER_NOTIF)},
        
        // Check for bind
        unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
            K: uint32(unix.SYS_BIND), Jt: 0, Jf: 2},
        // Return user notify for bind
        unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K,
            K: uint32(unix.SECCOMP_RET_USER_NOTIF)},
        
        // Default: allow
        unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K,
            K: uint32(unix.SECCOMP_RET_ALLOW)},
    }
    
    prog := unix.SockFprog{
        Len:    uint16(len(filter)),
        Filter: &filter[0],
    }
    
    // Install filter with SECCOMP_FILTER_FLAG_NEW_LISTENER
    fd, err := seccompUserNotify(&prog)
    if err != nil {
        return -1, err
    }
    
    m.notifyFd = fd
    return fd, nil
}

func (m *LinuxIPCMonitor) Start(ctx context.Context) error {
    if m.notifyFd <= 0 {
        // Fallback: audit-only mode using /proc/net/unix
        go m.pollProcNetUnix(ctx)
        return nil
    }
    
    go m.handleNotifications(ctx)
    return nil
}

func (m *LinuxIPCMonitor) handleNotifications(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        case <-m.done:
            return
        default:
        }
        
        // Read notification
        var req seccompNotifReq
        _, err := unix.Read(m.notifyFd, (*[unsafe.Sizeof(req)]byte)(unsafe.Pointer(&req))[:])
        if err != nil {
            continue
        }
        
        // Process the request
        resp := m.processNotification(&req)
        
        // Send response
        unix.Write(m.notifyFd, (*[unsafe.Sizeof(resp)]byte)(unsafe.Pointer(&resp))[:])
    }
}

func (m *LinuxIPCMonitor) processNotification(req *seccompNotifReq) seccompNotifResp {
    resp := seccompNotifResp{
        ID:    req.ID,
        Flags: 0,
    }
    
    // Read sockaddr from process memory
    sockaddr := m.readSockaddr(req.PID, req.Data.Args[1], req.Data.Args[2])
    if sockaddr == nil {
        // Can't read, allow
        resp.Flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
        return resp
    }
    
    // Check if Unix socket
    if sockaddr.Family != unix.AF_UNIX {
        resp.Flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
        return resp
    }
    
    // Create event
    event := SocketEvent{
        Timestamp:  time.Now(),
        PID:        int(req.PID),
        Operation:  m.syscallName(req.Data.Nr),
        SocketType: "unix",
        Path:       sockaddr.Path,
    }
    
    // Evaluate policy
    decision := m.policyEngine.EvaluateUnixSocket(event)
    event.Decision = string(decision.Action)
    event.PolicyRule = decision.Rule
    
    // Emit event
    if m.onConnect != nil && event.Operation == "connect" {
        m.onConnect(event)
    }
    if m.onBind != nil && event.Operation == "bind" {
        m.onBind(event)
    }
    
    // Set response based on decision
    if decision.Action == DecisionDeny {
        resp.Error = int32(unix.EACCES)
        resp.Val = 0
    } else {
        resp.Flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
    }
    
    return resp
}

func (m *LinuxIPCMonitor) readSockaddr(pid uint32, addr, length uint64) *unix.SockaddrUnix {
    // Read from /proc/[pid]/mem
    memPath := fmt.Sprintf("/proc/%d/mem", pid)
    f, err := os.Open(memPath)
    if err != nil {
        return nil
    }
    defer f.Close()
    
    buf := make([]byte, length)
    _, err = f.ReadAt(buf, int64(addr))
    if err != nil {
        return nil
    }
    
    // Parse as sockaddr_un
    if len(buf) < 2 {
        return nil
    }
    
    family := uint16(buf[0]) | uint16(buf[1])<<8
    if family != unix.AF_UNIX {
        return nil
    }
    
    // Extract path
    pathBytes := buf[2:]
    pathEnd := 0
    for i, b := range pathBytes {
        if b == 0 {
            pathEnd = i
            break
        }
    }
    
    return &unix.SockaddrUnix{
        Name: string(pathBytes[:pathEnd]),
    }
}

func (m *LinuxIPCMonitor) pollProcNetUnix(ctx context.Context) {
    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()
    
    known := make(map[string]bool)
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-m.done:
            return
        case <-ticker.C:
            m.scanProcNetUnix(known)
        }
    }
}

func (m *LinuxIPCMonitor) scanProcNetUnix(known map[string]bool) {
    data, err := os.ReadFile("/proc/net/unix")
    if err != nil {
        return
    }
    
    // Parse /proc/net/unix
    // Format: Num RefCount Protocol Flags Type St Inode Path
    lines := strings.Split(string(data), "\n")
    for _, line := range lines[1:] { // Skip header
        fields := strings.Fields(line)
        if len(fields) < 8 {
            continue
        }
        
        path := fields[7]
        if path == "" {
            continue
        }
        
        key := fmt.Sprintf("%s-%s", fields[0], path)
        if !known[key] {
            known[key] = true
            
            event := SocketEvent{
                Timestamp:  time.Now(),
                Operation:  "observed",
                SocketType: "unix",
                Path:       path,
            }
            
            if m.onConnect != nil {
                m.onConnect(event)
            }
        }
    }
}

func (m *LinuxIPCMonitor) Stop() error {
    close(m.done)
    if m.notifyFd > 0 {
        unix.Close(m.notifyFd)
    }
    return nil
}

// seccomp structures
type seccompNotifReq struct {
    ID    uint64
    PID   uint32
    Flags uint32
    Data  seccompData
}

type seccompData struct {
    Nr                 int32
    Arch               uint32
    InstructionPointer uint64
    Args               [6]uint64
}

type seccompNotifResp struct {
    ID    uint64
    Val   int64
    Error int32
    Flags uint32
}

const SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1

func seccompUserNotify(prog *unix.SockFprog) (int, error) {
    // syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 
    //         SECCOMP_FILTER_FLAG_NEW_LISTENER, prog)
    const SYS_seccomp = 317
    const SECCOMP_SET_MODE_FILTER = 1
    const SECCOMP_FILTER_FLAG_NEW_LISTENER = 8
    
    fd, _, errno := unix.Syscall(
        SYS_seccomp,
        SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_NEW_LISTENER,
        uintptr(unsafe.Pointer(prog)),
    )
    if errno != 0 {
        return -1, errno
    }
    return int(fd), nil
}
```

### 13.4 macOS Implementation (Network Extension or DTrace)

```go
// pkg/ipc/monitor_darwin.go
// +build darwin

package ipc

import (
    "context"
    "os/exec"
    "strings"
    "time"
)

type DarwinIPCMonitor struct {
    useNetworkExtension bool
    useDTrace           bool
    
    onConnect func(SocketEvent)
    onBind    func(SocketEvent)
    onPipe    func(PipeEvent)
    
    done      chan struct{}
    dtrace    *exec.Cmd
}

func NewDarwinIPCMonitor() *DarwinIPCMonitor {
    return &DarwinIPCMonitor{
        done: make(chan struct{}),
    }
}

func (m *DarwinIPCMonitor) Start(ctx context.Context) error {
    // Try Network Extension first (requires entitlements)
    if m.useNetworkExtension {
        return m.startNetworkExtension(ctx)
    }
    
    // Try DTrace (requires root or dtrace_proc entitlement)
    if m.useDTrace {
        return m.startDTrace(ctx)
    }
    
    // Fallback: poll lsof
    go m.pollLsof(ctx)
    return nil
}

func (m *DarwinIPCMonitor) startDTrace(ctx context.Context) error {
    // DTrace script to monitor Unix socket operations
    script := `
    syscall::connect:entry
    /arg1 != 0/
    {
        self->sockaddr = arg1;
    }
    
    syscall::connect:return
    /self->sockaddr && *(short *)copyin(self->sockaddr, 2) == AF_UNIX/
    {
        printf("connect|%d|%s\n", pid, 
            copyinstr(self->sockaddr + 2));
    }
    
    syscall::bind:entry
    /arg1 != 0/
    {
        self->sockaddr = arg1;
    }
    
    syscall::bind:return  
    /self->sockaddr && *(short *)copyin(self->sockaddr, 2) == AF_UNIX/
    {
        printf("bind|%d|%s\n", pid,
            copyinstr(self->sockaddr + 2));
    }
    `
    
    m.dtrace = exec.CommandContext(ctx, "dtrace", "-n", script)
    stdout, err := m.dtrace.StdoutPipe()
    if err != nil {
        return err
    }
    
    if err := m.dtrace.Start(); err != nil {
        return err
    }
    
    go func() {
        scanner := bufio.NewScanner(stdout)
        for scanner.Scan() {
            line := scanner.Text()
            parts := strings.Split(line, "|")
            if len(parts) != 3 {
                continue
            }
            
            event := SocketEvent{
                Timestamp:  time.Now(),
                Operation:  parts[0],
                PID:        parseInt(parts[1]),
                SocketType: "unix",
                Path:       parts[2],
            }
            
            if event.Operation == "connect" && m.onConnect != nil {
                m.onConnect(event)
            }
            if event.Operation == "bind" && m.onBind != nil {
                m.onBind(event)
            }
        }
    }()
    
    return nil
}

func (m *DarwinIPCMonitor) pollLsof(ctx context.Context) {
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    
    known := make(map[string]bool)
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-m.done:
            return
        case <-ticker.C:
            m.scanLsof(known)
        }
    }
}

func (m *DarwinIPCMonitor) scanLsof(known map[string]bool) {
    // lsof -U lists Unix domain sockets
    out, err := exec.Command("lsof", "-U", "-F", "pcn").Output()
    if err != nil {
        return
    }
    
    // Parse lsof output (field mode)
    // p<pid> c<command> n<name>
    var currentPID int
    var currentCmd string
    
    for _, line := range strings.Split(string(out), "\n") {
        if len(line) == 0 {
            continue
        }
        
        switch line[0] {
        case 'p':
            currentPID = parseInt(line[1:])
        case 'c':
            currentCmd = line[1:]
        case 'n':
            path := line[1:]
            key := fmt.Sprintf("%d-%s", currentPID, path)
            
            if !known[key] {
                known[key] = true
                
                event := SocketEvent{
                    Timestamp:  time.Now(),
                    PID:        currentPID,
                    Operation:  "observed",
                    SocketType: "unix",
                    Path:       path,
                }
                
                if m.onConnect != nil {
                    m.onConnect(event)
                }
            }
        }
    }
}

func (m *DarwinIPCMonitor) Stop() error {
    close(m.done)
    if m.dtrace != nil {
        m.dtrace.Process.Kill()
    }
    return nil
}
```

### 13.5 Windows Implementation (Named Pipes via ETW)

```go
// pkg/ipc/monitor_windows.go
// +build windows

package ipc

import (
    "context"
    "syscall"
    "unsafe"
    
    "golang.org/x/sys/windows"
)

type WindowsIPCMonitor struct {
    session   uintptr // ETW trace session
    consumer  uintptr
    
    onConnect func(SocketEvent)
    onPipe    func(PipeEvent)
    
    done      chan struct{}
}

func NewWindowsIPCMonitor() *WindowsIPCMonitor {
    return &WindowsIPCMonitor{
        done: make(chan struct{}),
    }
}

func (m *WindowsIPCMonitor) Start(ctx context.Context) error {
    // Start ETW trace for file I/O (includes named pipes)
    if err := m.startETWTrace(); err != nil {
        // Fallback: poll named pipes
        go m.pollNamedPipes(ctx)
        return nil
    }
    
    go m.processETWEvents(ctx)
    return nil
}

func (m *WindowsIPCMonitor) startETWTrace() error {
    // Enable Microsoft-Windows-Kernel-File provider
    // with FileIO keyword for named pipe operations
    
    const (
        EVENT_TRACE_REAL_TIME_MODE = 0x00000100
        WNODE_FLAG_TRACED_GUID     = 0x00020000
    )
    
    // Create trace session
    sessionName := "AgentshIPCMonitor"
    // ... ETW setup code
    
    return nil
}

func (m *WindowsIPCMonitor) processETWEvents(ctx context.Context) {
    // Process ETW events
    // Filter for \\.\pipe\* paths
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-m.done:
            return
        default:
            // Read next event
            // ...
        }
    }
}

func (m *WindowsIPCMonitor) pollNamedPipes(ctx context.Context) {
    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()
    
    known := make(map[string]bool)
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-m.done:
            return
        case <-ticker.C:
            m.scanNamedPipes(known)
        }
    }
}

func (m *WindowsIPCMonitor) scanNamedPipes(known map[string]bool) {
    // Enumerate \\.\pipe\*
    pipePath := `\\.\pipe\*`
    
    pattern, _ := syscall.UTF16PtrFromString(pipePath)
    var findData windows.Win32finddata
    
    handle, err := windows.FindFirstFile(pattern, &findData)
    if err != nil {
        return
    }
    defer windows.FindClose(handle)
    
    for {
        name := syscall.UTF16ToString(findData.FileName[:])
        fullPath := `\\.\pipe\` + name
        
        if !known[fullPath] {
            known[fullPath] = true
            
            event := PipeEvent{
                Timestamp: time.Now(),
                Operation: "observed",
                Path:      fullPath,
            }
            
            if m.onPipe != nil {
                m.onPipe(event)
            }
        }
        
        if err := windows.FindNextFile(handle, &findData); err != nil {
            break
        }
    }
}

// Monitor specific sensitive pipes
func (m *WindowsIPCMonitor) watchSensitivePipes() {
    sensitivePipes := []string{
        `\\.\pipe\docker_engine`,     // Docker
        `\\.\pipe\openssh-ssh-agent`, // SSH agent
        `\\.\pipe\*sqlquery*`,        // SQL connections
    }
    
    for _, pattern := range sensitivePipes {
        go m.watchPipe(pattern)
    }
}

func (m *WindowsIPCMonitor) watchPipe(pipePath string) {
    // Use minifilter or ETW to monitor specific pipe
    // ...
}

func (m *WindowsIPCMonitor) Stop() error {
    close(m.done)
    // Stop ETW trace
    // ...
    return nil
}
```

### 13.6 Common Sensitive Paths

```yaml
# policies/ipc-sensitive.yaml

ipc_rules:
  # Docker socket - high risk
  - name: docker-socket
    paths:
      - "/var/run/docker.sock"
      - "/run/docker.sock"
      - `\\.\pipe\docker_engine`
    decision: deny
    message: "Docker socket access blocked - container escape risk"
    
  # SSH agent
  - name: ssh-agent
    paths:
      - "/tmp/ssh-*/agent.*"
      - "/run/user/*/ssh-agent.*"
      - `\\.\pipe\openssh-ssh-agent`
    decision: approve
    message: "SSH agent access requires approval"
    
  # X11 (can be used for keylogging)
  - name: x11-socket
    paths:
      - "/tmp/.X11-unix/*"
    decision: deny
    message: "X11 socket access blocked"
    
  # D-Bus system bus
  - name: dbus-system
    paths:
      - "/var/run/dbus/system_bus_socket"
      - "/run/dbus/system_bus_socket"
    decision: deny
    message: "System D-Bus access blocked"
    
  # Databases
  - name: postgresql
    paths:
      - "/var/run/postgresql/.s.PGSQL.*"
      - "/tmp/.s.PGSQL.*"
    decision: allow  # Usually fine for dev
    
  - name: mysql
    paths:
      - "/var/run/mysqld/mysqld.sock"
      - "/tmp/mysql.sock"
    decision: allow
```

### 13.7 Platform Feature Matrix

| Feature | Linux (seccomp) | Linux (poll) | macOS (DTrace) | macOS (poll) | Windows (ETW) | Windows (poll) |
|---------|:---------------:|:------------:|:--------------:|:------------:|:-------------:|:--------------:|
| Real-time | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ |
| Enforcement | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| No root | ❌ | ✅ | ❌ | ✅ | ⚠️ Admin | ✅ |
| Process info | ✅ | ⚠️ | ✅ | ⚠️ | ✅ | ⚠️ |
| Abstract sockets | ✅ | ✅ | N/A | N/A | N/A | N/A |
| Named pipes | N/A | N/A | N/A | N/A | ✅ | ✅ |

---

## 14. Event Schema (Cross-Platform)

### 14.1 Overview

agentsh emits structured events for all intercepted operations. This section documents the complete event schema including new events introduced by cross-platform features (shell shim, command interception, resource limits, process tree tracking, and IPC monitoring).

### 14.2 Base Event Structure

All events share a comprehensive base structure that provides complete context for auditing, debugging, correlation, and analysis. Every event is self-contained with no reliance on session-level context events.

```go
// pkg/events/event.go

package events

import (
    "time"
)

// EventType identifies the type of event
type EventType string

// Base event types (existing)
const (
    // File operations
    EventFileOpen      EventType = "file_open"
    EventFileRead      EventType = "file_read"
    EventFileWrite     EventType = "file_write"
    EventFileCreate    EventType = "file_create"
    EventFileDelete    EventType = "file_delete"
    EventFileRename    EventType = "file_rename"
    EventFileStat      EventType = "file_stat"
    EventFileChmod     EventType = "file_chmod"
    EventDirCreate     EventType = "dir_create"
    EventDirDelete     EventType = "dir_delete"
    EventDirList       EventType = "dir_list"
    
    // Network operations
    EventDNSQuery      EventType = "dns_query"
    EventNetConnect    EventType = "net_connect"
    EventNetListen     EventType = "net_listen"
    EventNetAccept     EventType = "net_accept"
    
    // Process operations (existing)
    EventProcessStart  EventType = "process_start"
    EventProcessEnd    EventType = "process_end"
    
    // Environment operations
    EventEnvRead       EventType = "env_read"
    EventEnvWrite      EventType = "env_write"
    EventEnvList       EventType = "env_list"
    EventEnvBlocked    EventType = "env_blocked"
    
    // Soft delete operations
    EventSoftDelete    EventType = "soft_delete"
    EventTrashRestore  EventType = "trash_restore"
    EventTrashPurge    EventType = "trash_purge"
)

// BaseEvent contains fields common to ALL events
// Every event is self-contained for independent parsing and analysis
type BaseEvent struct {
    // ============================================================
    // IDENTITY & LOCATION
    // ============================================================
    
    // Machine hostname
    Hostname       string `json:"hostname"`
    
    // Unique machine identifier (survives reboots)
    // Linux: /etc/machine-id, macOS: IOPlatformUUID, Windows: MachineGuid
    MachineID      string `json:"machine_id"`
    
    // Container ID if running in container (null if not containerized)
    ContainerID    string `json:"container_id,omitempty"`
    
    // Container image if containerized
    ContainerImage string `json:"container_image,omitempty"`
    
    // Container runtime type
    ContainerRuntime string `json:"container_runtime,omitempty"` // "docker", "containerd", "podman"
    
    // Kubernetes context (if running in K8s)
    K8sNamespace   string `json:"k8s_namespace,omitempty"`
    K8sPod         string `json:"k8s_pod,omitempty"`
    K8sNode        string `json:"k8s_node,omitempty"`
    K8sCluster     string `json:"k8s_cluster,omitempty"`
    
    // ============================================================
    // NETWORK IDENTITY (configurable - included by default)
    // ============================================================
    
    // Machine's IP addresses
    IPv4Addresses  []string `json:"ipv4_addresses,omitempty"`
    IPv6Addresses  []string `json:"ipv6_addresses,omitempty"`
    
    // Primary interface
    PrimaryInterface string `json:"primary_interface,omitempty"` // "eth0", "en0", "Ethernet"
    
    // MAC address of primary interface (if configured to include)
    MACAddress     string `json:"mac_address,omitempty"`
    
    // ============================================================
    // TIMESTAMP (High Precision)
    // ============================================================
    
    // ISO 8601 timestamp with microsecond precision and timezone
    Timestamp      string `json:"timestamp"` // "2025-01-15T14:30:00.123456Z"
    
    // Unix timestamp in microseconds (for precise ordering/math)
    TimestampUnixUS int64 `json:"timestamp_unix_us"`
    
    // Monotonic clock in nanoseconds (for ordering events on same host)
    MonotonicNS    int64  `json:"monotonic_ns"`
    
    // Event sequence number within session (strictly increasing)
    Sequence       int64  `json:"sequence"`
    
    // ============================================================
    // OPERATING SYSTEM
    // ============================================================
    
    // OS family
    OS             string `json:"os"` // "linux", "darwin", "windows"
    
    // OS version (human-readable)
    OSVersion      string `json:"os_version"` // "Ubuntu 24.04 LTS", "macOS 14.2 Sonoma", "Windows 11 23H2"
    
    // OS distribution (Linux-specific)
    OSDistro       string `json:"os_distro,omitempty"` // "ubuntu", "debian", "fedora", "alpine"
    
    // Kernel/NT version
    KernelVersion  string `json:"kernel_version"` // "6.5.0-44-generic", "23.2.0", "10.0.22631"
    
    // CPU architecture
    Arch           string `json:"arch"` // "amd64", "arm64", "arm"
    
    // ============================================================
    // AGENTSH PLATFORM DETAILS
    // ============================================================
    
    // Which agentsh implementation variant is running
    PlatformVariant string `json:"platform_variant"` 
    // Values: "linux-native", "darwin-esf", "darwin-fuse-t", "darwin-network-extension",
    //         "darwin-lima", "windows-native", "windows-wsl2"
    
    // Filesystem interception backend
    FSBackend      string `json:"fs_backend"` 
    // Values: "fuse3", "fuse-t", "winfsp", "esf", "none"
    
    // Network interception backend
    NetBackend     string `json:"net_backend"`
    // Values: "iptables", "nftables", "ebpf", "nfqueue", "network-extension", 
    //         "pf", "wfp", "windivert", "none"
    
    // Process tracking backend
    ProcessBackend string `json:"process_backend"`
    // Values: "cgroups-v2", "cgroups-v1", "netlink", "job-objects", 
    //         "proc-poll", "dtrace", "etw", "none"
    
    // IPC monitoring backend
    IPCBackend     string `json:"ipc_backend,omitempty"`
    // Values: "seccomp", "dtrace", "etw", "poll", "none"
    
    // ============================================================
    // VERSIONING
    // ============================================================
    
    // agentsh binary version
    AgentshVersion    string `json:"agentsh_version"` // "1.2.3"
    
    // agentsh build info
    AgentshCommit     string `json:"agentsh_commit,omitempty"` // "abc123f"
    AgentshBuildTime  string `json:"agentsh_build_time,omitempty"` // "2025-01-15T10:00:00Z"
    
    // Event schema version (for forward/backward compatibility)
    EventSchemaVersion string `json:"event_schema_version"` // "1.0"
    
    // Policy version (name + hash for integrity)
    PolicyVersion     string `json:"policy_version,omitempty"` // "default@sha256:abc123"
    PolicyName        string `json:"policy_name,omitempty"`    // "default"
    
    // ============================================================
    // CORRELATION IDs
    // ============================================================
    
    // Unique event identifier
    EventID        string `json:"event_id"` // "evt-7f3a9b2c"
    
    // agentsh session ID
    SessionID      string `json:"session_id"` // "session-abc123"
    
    // Command ID that triggered this event
    CommandID      string `json:"command_id,omitempty"` // "cmd-xyz789"
    
    // OpenTelemetry trace context (if OTEL integration enabled)
    TraceID        string `json:"trace_id,omitempty"`       // W3C trace ID
    SpanID         string `json:"span_id,omitempty"`        // W3C span ID
    ParentSpanID   string `json:"parent_span_id,omitempty"` // Parent span
    TraceFlags     string `json:"trace_flags,omitempty"`    // "01" for sampled
    
    // Upstream request ID (from API call that started command)
    RequestID      string `json:"request_id,omitempty"` // "req-456"
    
    // Causation chain (parent event that caused this event)
    CausedByEventID string `json:"caused_by_event_id,omitempty"`
    
    // ============================================================
    // PROCESS CONTEXT
    // ============================================================
    
    // Process ID
    PID            int    `json:"pid"`
    
    // Parent process ID
    PPID           int    `json:"ppid"`
    
    // Process name (comm)
    ProcessName    string `json:"process_name"` // "node", "python3", "bash"
    
    // Full executable path (subject to sanitization)
    Executable     string `json:"executable,omitempty"` // "/usr/bin/node"
    
    // Command line arguments (subject to sanitization)
    Cmdline        []string `json:"cmdline,omitempty"` // ["node", "server.js"]
    
    // User ID
    UID            int    `json:"uid"`
    
    // Group ID
    GID            int    `json:"gid"`
    
    // Username (if resolvable)
    Username       string `json:"username,omitempty"` // "developer"
    
    // Group name (if resolvable)
    Groupname      string `json:"groupname,omitempty"` // "staff"
    
    // Current working directory (subject to sanitization)
    Cwd            string `json:"cwd,omitempty"` // "/workspace/src"
    
    // Process tree depth (1 = direct child of session root)
    TreeDepth      int    `json:"tree_depth,omitempty"`
    
    // Session root process ID
    RootPID        int    `json:"root_pid,omitempty"`
    
    // ============================================================
    // AGENT CONTEXT
    // ============================================================
    
    // AI agent identifier
    AgentID        string `json:"agent_id,omitempty"` // "claude-coder-1"
    
    // Type/model of agent
    AgentType      string `json:"agent_type,omitempty"` // "claude", "gpt", "gemini", "custom"
    
    // Agent framework/SDK
    AgentFramework string `json:"agent_framework,omitempty"` // "langchain", "autogen", "custom"
    
    // Human operator who started/owns the session
    OperatorID     string `json:"operator_id,omitempty"` // "user@example.com"
    
    // Multi-tenant organization identifier
    TenantID       string `json:"tenant_id,omitempty"` // "acme-corp"
    
    // Workspace/project identifier
    WorkspaceID    string `json:"workspace_id,omitempty"` // "project-xyz"
    
    // ============================================================
    // POLICY & DECISION
    // ============================================================
    
    // Policy decision
    Decision       string `json:"decision"` // "allow", "deny", "redirect", "approve", "audit", "soft_delete"
    
    // Rule that matched
    PolicyRule     string `json:"policy_rule,omitempty"` // "allow-workspace-read"
    
    // Risk assessment level
    RiskLevel      string `json:"risk_level,omitempty"` // "low", "medium", "high", "critical"
    
    // Risk factors identified
    RiskFactors    []string `json:"risk_factors,omitempty"` // ["sensitive_path", "network_egress"]
    
    // Was approval required?
    ApprovalRequired bool   `json:"approval_required,omitempty"`
    ApprovalID       string `json:"approval_id,omitempty"`
    ApprovedBy       string `json:"approved_by,omitempty"`
    
    // ============================================================
    // PERFORMANCE METRICS
    // ============================================================
    
    // Total operation latency in microseconds
    LatencyUS      int64 `json:"latency_us,omitempty"`
    
    // Time spent waiting in queue
    QueueTimeUS    int64 `json:"queue_time_us,omitempty"`
    
    // Time spent evaluating policy
    PolicyEvalUS   int64 `json:"policy_eval_us,omitempty"`
    
    // Time spent in interception layer (FUSE, eBPF, etc.)
    InterceptUS    int64 `json:"intercept_us,omitempty"`
    
    // Time spent in actual operation (backend I/O)
    BackendUS      int64 `json:"backend_us,omitempty"`
    
    // ============================================================
    // ERROR CONTEXT
    // ============================================================
    
    // Error message if operation failed
    Error          string `json:"error,omitempty"` // "ENOENT: file not found"
    
    // System error code
    ErrorCode      string `json:"error_code,omitempty"` // "ENOENT", "EACCES", "EPERM"
    
    // Numeric errno (platform-specific)
    Errno          int    `json:"errno,omitempty"` // 2
    
    // Error category
    ErrorCategory  string `json:"error_category,omitempty"` // "filesystem", "network", "policy", "resource"
    
    // Is this error retryable?
    Retryable      bool   `json:"retryable,omitempty"`
    
    // ============================================================
    // EVENT TYPE
    // ============================================================
    
    // Event type identifier
    Type           EventType `json:"type"`
    
    // Event category (derived from type)
    Category       string `json:"category"` // "file", "network", "process", "command", "resource", "ipc", "shell"
    
    // ============================================================
    // CUSTOM METADATA (User-defined fields)
    // ============================================================
    
    // Custom key-value metadata (configurable per deployment)
    Metadata       map[string]string `json:"metadata,omitempty"`
    
    // Custom tags for filtering/grouping
    Tags           []string `json:"tags,omitempty"`
    
    // Custom labels (K8s-style key=value)
    Labels         map[string]string `json:"labels,omitempty"`
    
    // ============================================================
    // SANITIZATION INFO
    // ============================================================
    
    // Fields that were sanitized in this event
    SanitizedFields []string `json:"sanitized_fields,omitempty"` // ["executable", "cwd", "cmdline"]
    
    // Sanitization reason
    SanitizationReason string `json:"sanitization_reason,omitempty"` // "sensitive_path_pattern"
}
```

#### 14.2.1 Runtime Context Detection

The static fields are populated once at startup:

```go
// pkg/events/context.go

package events

import (
    "net"
    "os"
    "runtime"
    "strings"
)

// RuntimeContext holds static information collected at startup
type RuntimeContext struct {
    // Identity
    Hostname        string
    MachineID       string
    ContainerID     string
    ContainerImage  string
    ContainerRuntime string
    K8sNamespace    string
    K8sPod          string
    K8sNode         string
    K8sCluster      string
    
    // Network
    IPv4Addresses   []string
    IPv6Addresses   []string
    PrimaryInterface string
    MACAddress      string
    
    // OS
    OS              string
    OSVersion       string
    OSDistro        string
    KernelVersion   string
    Arch            string
    
    // Platform
    PlatformVariant string
    FSBackend       string
    NetBackend      string
    ProcessBackend  string
    IPCBackend      string
    
    // Version
    AgentshVersion  string
    AgentshCommit   string
    AgentshBuildTime string
    EventSchemaVersion string
}

// DetectRuntimeContext collects all static context at startup
func DetectRuntimeContext() *RuntimeContext {
    ctx := &RuntimeContext{
        OS:                 runtime.GOOS,
        Arch:               runtime.GOARCH,
        EventSchemaVersion: "1.0",
    }
    
    // Hostname
    ctx.Hostname, _ = os.Hostname()
    
    // Machine ID
    ctx.MachineID = detectMachineID()
    
    // Container detection
    ctx.ContainerID, ctx.ContainerRuntime = detectContainer()
    ctx.ContainerImage = os.Getenv("AGENTSH_CONTAINER_IMAGE")
    
    // Kubernetes detection
    ctx.K8sNamespace = os.Getenv("KUBERNETES_NAMESPACE")
    if ctx.K8sNamespace == "" {
        ctx.K8sNamespace = os.Getenv("POD_NAMESPACE")
    }
    ctx.K8sPod = os.Getenv("KUBERNETES_POD_NAME")
    if ctx.K8sPod == "" {
        ctx.K8sPod = os.Getenv("HOSTNAME") // K8s sets HOSTNAME to pod name
    }
    ctx.K8sNode = os.Getenv("KUBERNETES_NODE_NAME")
    ctx.K8sCluster = os.Getenv("KUBERNETES_CLUSTER_NAME")
    
    // Network addresses
    ctx.IPv4Addresses, ctx.IPv6Addresses, ctx.PrimaryInterface, ctx.MACAddress = detectNetworkInfo()
    
    // OS details
    ctx.OSVersion, ctx.OSDistro = detectOSVersion()
    ctx.KernelVersion = detectKernelVersion()
    
    return ctx
}

func detectMachineID() string {
    switch runtime.GOOS {
    case "linux":
        // Try /etc/machine-id first, then /var/lib/dbus/machine-id
        if data, err := os.ReadFile("/etc/machine-id"); err == nil {
            return strings.TrimSpace(string(data))
        }
        if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
            return strings.TrimSpace(string(data))
        }
    case "darwin":
        // Use IOPlatformUUID via ioreg
        // ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID
        return execCommand("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
    case "windows":
        // HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid
        return readWindowsRegistry(`SOFTWARE\Microsoft\Cryptography`, "MachineGuid")
    }
    return ""
}

func detectContainer() (containerID, runtime string) {
    // Check for Docker
    if _, err := os.Stat("/.dockerenv"); err == nil {
        runtime = "docker"
    }
    
    // Check cgroup for container ID
    if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
        lines := strings.Split(string(data), "\n")
        for _, line := range lines {
            // Look for docker/containerd/podman container IDs
            if strings.Contains(line, "docker") || 
               strings.Contains(line, "containerd") ||
               strings.Contains(line, "crio") {
                parts := strings.Split(line, "/")
                if len(parts) > 0 {
                    containerID = parts[len(parts)-1]
                    if len(containerID) >= 12 {
                        containerID = containerID[:12] // Short ID
                    }
                }
            }
        }
    }
    
    // Check for containerd
    if runtime == "" && os.Getenv("CONTAINER_RUNTIME") != "" {
        runtime = os.Getenv("CONTAINER_RUNTIME")
    }
    
    // Check for Kubernetes
    if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
        if runtime == "" {
            runtime = "containerd" // Default for K8s
        }
    }
    
    return
}

func detectNetworkInfo() (ipv4, ipv6 []string, primaryIface, macAddr string) {
    interfaces, err := net.Interfaces()
    if err != nil {
        return
    }
    
    for _, iface := range interfaces {
        // Skip loopback and down interfaces
        if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
            continue
        }
        
        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }
        
        for _, addr := range addrs {
            ipNet, ok := addr.(*net.IPNet)
            if !ok {
                continue
            }
            
            ip := ipNet.IP
            if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
                continue
            }
            
            if ip.To4() != nil {
                ipv4 = append(ipv4, ip.String())
                if primaryIface == "" {
                    primaryIface = iface.Name
                    macAddr = iface.HardwareAddr.String()
                }
            } else {
                ipv6 = append(ipv6, ip.String())
            }
        }
    }
    
    return
}
```

#### 14.2.2 Event Factory

```go
// pkg/events/factory.go

package events

import (
    "fmt"
    "sync/atomic"
    "time"
)

// EventFactory creates events with pre-populated base fields
type EventFactory struct {
    ctx       *RuntimeContext
    sessionID string
    sequence  int64
    sanitizer *Sanitizer
    config    *EventConfig
}

// NewEventFactory creates a factory for a session
func NewEventFactory(ctx *RuntimeContext, sessionID string, config *EventConfig) *EventFactory {
    return &EventFactory{
        ctx:       ctx,
        sessionID: sessionID,
        config:    config,
        sanitizer: NewSanitizer(config.SanitizePatterns),
    }
}

// NewEvent creates a new event with all base fields populated
func (f *EventFactory) NewEvent(eventType EventType, pid int) *BaseEvent {
    now := time.Now()
    seq := atomic.AddInt64(&f.sequence, 1)
    
    event := &BaseEvent{
        // Identity
        Hostname:         f.ctx.Hostname,
        MachineID:        f.ctx.MachineID,
        ContainerID:      f.ctx.ContainerID,
        ContainerImage:   f.ctx.ContainerImage,
        ContainerRuntime: f.ctx.ContainerRuntime,
        K8sNamespace:     f.ctx.K8sNamespace,
        K8sPod:           f.ctx.K8sPod,
        K8sNode:          f.ctx.K8sNode,
        K8sCluster:       f.ctx.K8sCluster,
        
        // Network (if configured)
        IPv4Addresses:    f.conditionalField(f.config.IncludeNetworkInfo, f.ctx.IPv4Addresses),
        IPv6Addresses:    f.conditionalField(f.config.IncludeNetworkInfo, f.ctx.IPv6Addresses),
        PrimaryInterface: f.conditionalString(f.config.IncludeNetworkInfo, f.ctx.PrimaryInterface),
        MACAddress:       f.conditionalString(f.config.IncludeMACAddress, f.ctx.MACAddress),
        
        // Timestamp
        Timestamp:       now.Format("2006-01-02T15:04:05.000000Z07:00"),
        TimestampUnixUS: now.UnixMicro(),
        MonotonicNS:     monotonicNow(),
        Sequence:        seq,
        
        // OS
        OS:            f.ctx.OS,
        OSVersion:     f.ctx.OSVersion,
        OSDistro:      f.ctx.OSDistro,
        KernelVersion: f.ctx.KernelVersion,
        Arch:          f.ctx.Arch,
        
        // Platform
        PlatformVariant: f.ctx.PlatformVariant,
        FSBackend:       f.ctx.FSBackend,
        NetBackend:      f.ctx.NetBackend,
        ProcessBackend:  f.ctx.ProcessBackend,
        IPCBackend:      f.ctx.IPCBackend,
        
        // Version
        AgentshVersion:     f.ctx.AgentshVersion,
        AgentshCommit:      f.ctx.AgentshCommit,
        AgentshBuildTime:   f.ctx.AgentshBuildTime,
        EventSchemaVersion: f.ctx.EventSchemaVersion,
        
        // Correlation
        EventID:   generateEventID(),
        SessionID: f.sessionID,
        
        // Process
        PID: pid,
        
        // Type
        Type:     eventType,
        Category: EventCategory[eventType],
        
        // Custom metadata
        Metadata: f.config.DefaultMetadata,
        Tags:     f.config.DefaultTags,
        Labels:   f.config.DefaultLabels,
    }
    
    // Populate process info
    f.populateProcessInfo(event, pid)
    
    return event
}

func (f *EventFactory) populateProcessInfo(event *BaseEvent, pid int) {
    info := getProcessInfo(pid)
    if info == nil {
        return
    }
    
    event.PPID = info.PPID
    event.ProcessName = info.Comm
    event.UID = info.UID
    event.GID = info.GID
    event.Username = info.Username
    event.Groupname = info.Groupname
    
    // Apply sanitization if configured
    if f.config.SanitizePaths {
        event.Executable, event.SanitizedFields = f.sanitizer.SanitizePath(info.Executable)
        event.Cwd, _ = f.sanitizer.SanitizePath(info.Cwd)
        event.Cmdline = f.sanitizer.SanitizeCmdline(info.Cmdline)
        
        if len(event.SanitizedFields) > 0 {
            event.SanitizationReason = "sensitive_path_pattern"
        }
    } else {
        event.Executable = info.Executable
        event.Cwd = info.Cwd
        event.Cmdline = info.Cmdline
    }
}

func generateEventID() string {
    // Format: evt-{timestamp_hex}-{random}
    return fmt.Sprintf("evt-%x-%s", time.Now().UnixNano(), randomHex(4))
}
```

#### 14.2.3 Path and Content Sanitization

Sensitive paths and content can be automatically sanitized:

```go
// pkg/events/sanitizer.go

package events

import (
    "regexp"
    "strings"
)

// Sanitizer handles redaction of sensitive information in events
type Sanitizer struct {
    pathPatterns    []*regexp.Regexp
    contentPatterns []*regexp.Regexp
    envVarPatterns  []*regexp.Regexp
}

// Default patterns for sensitive content
var DefaultSensitivePatterns = SanitizePatterns{
    // Paths that should be sanitized
    PathPatterns: []string{
        `(?i)\.ssh`,
        `(?i)\.aws`,
        `(?i)\.kube`,
        `(?i)\.gnupg`,
        `(?i)/secrets?/`,
        `(?i)/credentials?/`,
        `(?i)/private/`,
        `(?i)\.env$`,
        `(?i)\.pem$`,
        `(?i)\.key$`,
        `(?i)\.p12$`,
        `(?i)password`,
        `(?i)token`,
        `(?i)api.?key`,
    },
    
    // Command line arguments to redact
    CmdlinePatterns: []string{
        `(?i)(--password[=\s]+)\S+`,
        `(?i)(--token[=\s]+)\S+`,
        `(?i)(--api-key[=\s]+)\S+`,
        `(?i)(-p\s+)\S+`,  // Common password flag
        `(?i)(PASS(WORD)?=)\S+`,
        `(?i)(TOKEN=)\S+`,
        `(?i)(API_KEY=)\S+`,
        `(?i)(SECRET=)\S+`,
    },
    
    // Environment variable names to never log
    EnvVarPatterns: []string{
        `(?i).*PASSWORD.*`,
        `(?i).*SECRET.*`,
        `(?i).*TOKEN.*`,
        `(?i).*API.?KEY.*`,
        `(?i).*PRIVATE.?KEY.*`,
        `(?i).*CREDENTIAL.*`,
        `(?i)AWS_.*`,
        `(?i)GITHUB_TOKEN`,
        `(?i)NPM_TOKEN`,
    },
}

type SanitizePatterns struct {
    PathPatterns    []string `yaml:"path_patterns"`
    CmdlinePatterns []string `yaml:"cmdline_patterns"`
    EnvVarPatterns  []string `yaml:"env_var_patterns"`
}

func NewSanitizer(patterns SanitizePatterns) *Sanitizer {
    s := &Sanitizer{}
    
    for _, p := range patterns.PathPatterns {
        if re, err := regexp.Compile(p); err == nil {
            s.pathPatterns = append(s.pathPatterns, re)
        }
    }
    
    for _, p := range patterns.CmdlinePatterns {
        if re, err := regexp.Compile(p); err == nil {
            s.contentPatterns = append(s.contentPatterns, re)
        }
    }
    
    for _, p := range patterns.EnvVarPatterns {
        if re, err := regexp.Compile(p); err == nil {
            s.envVarPatterns = append(s.envVarPatterns, re)
        }
    }
    
    return s
}

// SanitizePath checks if a path matches sensitive patterns
// Returns sanitized path and list of fields that were sanitized
func (s *Sanitizer) SanitizePath(path string) (string, []string) {
    for _, re := range s.pathPatterns {
        if re.MatchString(path) {
            // Redact sensitive part of path
            parts := strings.Split(path, "/")
            for i, part := range parts {
                if re.MatchString(part) {
                    parts[i] = "[REDACTED]"
                }
            }
            return strings.Join(parts, "/"), []string{"path"}
        }
    }
    return path, nil
}

// SanitizeCmdline redacts sensitive values in command line arguments
func (s *Sanitizer) SanitizeCmdline(cmdline []string) []string {
    result := make([]string, len(cmdline))
    for i, arg := range cmdline {
        result[i] = arg
        for _, re := range s.contentPatterns {
            result[i] = re.ReplaceAllString(result[i], "${1}[REDACTED]")
        }
    }
    return result
}

// ShouldSanitizeEnvVar checks if an environment variable should be redacted
func (s *Sanitizer) ShouldSanitizeEnvVar(name string) bool {
    for _, re := range s.envVarPatterns {
        if re.MatchString(name) {
            return true
        }
    }
    return false
}
```

#### 14.2.4 Event Configuration

```go
// pkg/events/config.go

package events

// EventConfig controls event generation behavior
type EventConfig struct {
    // ============================================================
    // NETWORK IDENTITY (configurable - included by default)
    // ============================================================
    
    // Include IP addresses in events (default: true)
    IncludeNetworkInfo bool `yaml:"include_network_info"`
    
    // Include MAC address in events (default: false - more sensitive)
    IncludeMACAddress bool `yaml:"include_mac_address"`
    
    // ============================================================
    // SANITIZATION
    // ============================================================
    
    // Enable path/content sanitization (default: true)
    SanitizePaths bool `yaml:"sanitize_paths"`
    
    // Custom sanitization patterns
    SanitizePatterns SanitizePatterns `yaml:"sanitize_patterns"`
    
    // ============================================================
    // CUSTOM METADATA
    // ============================================================
    
    // Default metadata added to all events
    DefaultMetadata map[string]string `yaml:"default_metadata"`
    
    // Default tags added to all events
    DefaultTags []string `yaml:"default_tags"`
    
    // Default labels added to all events
    DefaultLabels map[string]string `yaml:"default_labels"`
    
    // ============================================================
    // COMPRESSION
    // ============================================================
    
    // Compression algorithm for event output
    Compression string `yaml:"compression"` // "none", "gzip", "lz4", "zstd"
    
    // Compression level (algorithm-specific)
    CompressionLevel int `yaml:"compression_level"`
}

// DefaultEventConfig returns sensible defaults
func DefaultEventConfig() *EventConfig {
    return &EventConfig{
        IncludeNetworkInfo: true,
        IncludeMACAddress:  false,
        SanitizePaths:      true,
        SanitizePatterns:   DefaultSensitivePatterns,
        DefaultMetadata:    map[string]string{},
        DefaultTags:        []string{},
        DefaultLabels:      map[string]string{},
        Compression:        "gzip",
        CompressionLevel:   6,
    }
}
```

#### 14.2.5 YAML Configuration Example

```yaml
# In agentsh.yaml

events:
  # Enable/disable event emission
  enabled: true
  
  # Schema version (for compatibility)
  schema_version: "1.0"
  
  # ============================================================
  # NETWORK IDENTITY
  # ============================================================
  
  # Include IP addresses in all events (default: true)
  include_network_info: true
  
  # Include MAC address (more sensitive, default: false)
  include_mac_address: false
  
  # ============================================================
  # SANITIZATION
  # ============================================================
  
  # Enable automatic sanitization of sensitive paths/content
  sanitize_paths: true
  
  # Custom patterns to sanitize (extends defaults)
  sanitize_patterns:
    path_patterns:
      - '(?i)\.ssh'
      - '(?i)\.aws'
      - '(?i)\.kube'
      - '(?i)/secrets?/'
      - '(?i)/credentials?/'
      - '(?i)\.env$'
      - '(?i)\.pem$'
      - '(?i)\.key$'
      # Add custom patterns
      - '(?i)/internal-keys/'
      - '(?i)/company-secrets/'
      
    cmdline_patterns:
      - '(?i)(--password[=\s]+)\S+'
      - '(?i)(--token[=\s]+)\S+'
      - '(?i)(--api-key[=\s]+)\S+'
      # Add custom patterns
      - '(?i)(--db-password[=\s]+)\S+'
      
    env_var_patterns:
      - '(?i).*PASSWORD.*'
      - '(?i).*SECRET.*'
      - '(?i).*TOKEN.*'
      - '(?i)AWS_.*'
      # Add custom patterns
      - '(?i)INTERNAL_.*'
  
  # ============================================================
  # CUSTOM METADATA
  # ============================================================
  
  # Default metadata added to every event
  default_metadata:
    environment: "production"
    region: "us-east-1"
    cost_center: "engineering"
    
  # Default tags for filtering
  default_tags:
    - "ai-agent"
    - "monitored"
    
  # Default labels (K8s-style)
  default_labels:
    app.kubernetes.io/name: "agentsh"
    app.kubernetes.io/component: "sandbox"
    team: "platform"
  
  # ============================================================
  # COMPRESSION
  # ============================================================
  
  # Compression for event output streams/files
  compression: "gzip"  # none, gzip, lz4, zstd
  compression_level: 6
  
  # ============================================================
  # OUTPUT DESTINATIONS
  # ============================================================
  
  outputs:
    # Real-time streaming to connected clients
    - type: "stream"
      format: "jsonl"
      
    # File output with rotation
    - type: "file"
      path: "/var/log/agentsh/events.jsonl.gz"
      format: "jsonl"
      compress: true
      rotate:
        max_size_mb: 100
        max_files: 10
        max_age_days: 30
        
    # Webhook for SIEM integration
    - type: "webhook"
      url: "https://siem.example.com/api/v1/events"
      format: "jsonl"
      batch_size: 100
      batch_timeout_ms: 1000
      headers:
        Authorization: "Bearer ${SIEM_TOKEN}"
        
    # Kafka for high-volume ingestion
    - type: "kafka"
      brokers:
        - "kafka-1.example.com:9092"
        - "kafka-2.example.com:9092"
      topic: "agentsh-events"
      format: "json"
      compress: true
```

#### 14.2.6 Complete Event Example

```json
{
  "hostname": "dev-macbook-pro.local",
  "machine_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "container_id": null,
  "container_image": null,
  "container_runtime": null,
  "k8s_namespace": null,
  "k8s_pod": null,
  "k8s_node": null,
  "k8s_cluster": null,
  
  "ipv4_addresses": ["192.168.1.100", "10.0.0.50"],
  "ipv6_addresses": ["fe80::1"],
  "primary_interface": "en0",
  "mac_address": "a1:b2:c3:d4:e5:f6",
  
  "timestamp": "2025-01-15T14:30:00.123456Z",
  "timestamp_unix_us": 1736951400123456,
  "monotonic_ns": 98765432100,
  "sequence": 42,
  
  "os": "darwin",
  "os_version": "macOS 14.2 (Sonoma)",
  "os_distro": null,
  "kernel_version": "23.2.0",
  "arch": "arm64",
  
  "platform_variant": "darwin-fuse-t",
  "fs_backend": "fuse-t",
  "net_backend": "pf",
  "process_backend": "proc-poll",
  "ipc_backend": "poll",
  
  "agentsh_version": "1.2.3",
  "agentsh_commit": "abc123f",
  "agentsh_build_time": "2025-01-10T10:00:00Z",
  "event_schema_version": "1.0",
  "policy_version": "default@sha256:abc123def456",
  "policy_name": "default",
  
  "event_id": "evt-18d5f3a2b7c9-a1b2",
  "session_id": "session-abc123",
  "command_id": "cmd-xyz789",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "parent_span_id": null,
  "trace_flags": "01",
  "request_id": "req-456",
  "caused_by_event_id": null,
  
  "pid": 12345,
  "ppid": 12340,
  "process_name": "node",
  "executable": "/opt/homebrew/bin/node",
  "cmdline": ["node", "server.js", "--port", "3000"],
  "uid": 501,
  "gid": 20,
  "username": "developer",
  "groupname": "staff",
  "cwd": "/Users/developer/project/src",
  "tree_depth": 2,
  "root_pid": 12300,
  
  "agent_id": "claude-coder-1",
  "agent_type": "claude",
  "agent_framework": "agentsh-native",
  "operator_id": "user@example.com",
  "tenant_id": "acme-corp",
  "workspace_id": "project-xyz",
  
  "decision": "allow",
  "policy_rule": "allow-workspace-read",
  "risk_level": "low",
  "risk_factors": null,
  "approval_required": false,
  "approval_id": null,
  "approved_by": null,
  
  "latency_us": 234,
  "queue_time_us": 12,
  "policy_eval_us": 45,
  "intercept_us": 89,
  "backend_us": 88,
  
  "error": null,
  "error_code": null,
  "errno": null,
  "error_category": null,
  "retryable": null,
  
  "type": "file_read",
  "category": "file",
  
  "metadata": {
    "environment": "production",
    "region": "us-east-1",
    "cost_center": "engineering"
  },
  "tags": ["ai-agent", "monitored"],
  "labels": {
    "app.kubernetes.io/name": "agentsh",
    "team": "platform"
  },
  
  "sanitized_fields": null,
  "sanitization_reason": null,
  
  "path": "/workspace/src/index.ts",
  "bytes": 4096,
  "offset": 0
}
```

### 14.3 Shell Shim Events

Events emitted by the shell shim layer:

```go
// New shell shim event types
const (
    EventShellInvoke      EventType = "shell_invoke"
    EventShellPassthrough EventType = "shell_passthrough"
    EventSessionAutostart EventType = "session_autostart"
)

// ShellInvokeEvent - Shell shim intercepted a shell call
type ShellInvokeEvent struct {
    BaseEvent
    
    // Which shell was invoked
    Shell       string   `json:"shell"`        // "sh", "bash", "zsh", "powershell", "cmd"
    
    // How it was invoked
    InvokedAs   string   `json:"invoked_as"`   // Actual binary name used
    
    // Arguments passed
    Args        []string `json:"args"`
    
    // Execution mode
    Mode        string   `json:"mode"`         // "command" (-c), "script", "interactive"
    
    // Command string (if -c mode)
    Command     string   `json:"command,omitempty"`
    
    // Script path (if script mode)
    Script      string   `json:"script,omitempty"`
    
    // Was this routed through agentsh?
    Intercepted bool     `json:"intercepted"`
    
    // Shim strategy used
    Strategy    string   `json:"strategy"`     // "binary_replace", "path", "profile", "terminal"
}

// ShellPassthroughEvent - Shell shim bypassed (not in agentsh mode)
type ShellPassthroughEvent struct {
    BaseEvent
    
    Shell       string   `json:"shell"`
    Reason      string   `json:"reason"`       // "no_session", "no_server", "disabled"
    RealShell   string   `json:"real_shell"`   // Path to actual shell used
}

// SessionAutostartEvent - Server auto-started by shim
type SessionAutostartEvent struct {
    BaseEvent
    
    // How the server was started
    StartMethod string   `json:"start_method"` // "fork", "systemd", "launchd", "service"
    
    // Server configuration used
    ConfigPath  string   `json:"config_path"`
    
    // New session created
    NewSession  string   `json:"new_session_id"`
    
    // Workspace path
    Workspace   string   `json:"workspace"`
    
    // Time to start
    StartupMS   int64    `json:"startup_ms"`
}
```

**Example Events:**

```json
{
  "id": "evt-shell-001",
  "type": "shell_invoke",
  "timestamp": "2025-01-15T14:30:00.123Z",
  "session_id": "session-abc123",
  "pid": 12345,
  "platform": "linux",
  "decision": "allow",
  "shell": "bash",
  "invoked_as": "/bin/bash",
  "args": ["-c", "npm install"],
  "mode": "command",
  "command": "npm install",
  "intercepted": true,
  "strategy": "binary_replace"
}
```

```json
{
  "id": "evt-autostart-001",
  "type": "session_autostart",
  "timestamp": "2025-01-15T14:29:55.000Z",
  "session_id": "session-abc123",
  "pid": 12340,
  "platform": "darwin",
  "decision": "allow",
  "start_method": "fork",
  "config_path": "/Users/dev/.agentsh/config.yaml",
  "new_session_id": "session-abc123",
  "workspace": "/Users/dev/project",
  "startup_ms": 245
}
```

### 14.4 Command Interception Events

Events emitted when commands are intercepted, redirected, or blocked:

```go
// Command interception event types
const (
    EventCommandIntercept EventType = "command_intercept"
    EventCommandRedirect  EventType = "command_redirect"
    EventCommandBlocked   EventType = "command_blocked"
    EventPathRedirect     EventType = "path_redirect"
)

// CommandInterceptEvent - Command evaluated by policy engine
type CommandInterceptEvent struct {
    BaseEvent
    
    // Original command
    Command     string            `json:"command"`
    Args        []string          `json:"args"`
    
    // Resolved executable path
    Executable  string            `json:"executable"`
    
    // Working directory
    WorkingDir  string            `json:"working_dir"`
    
    // Environment modifications
    EnvSet      map[string]string `json:"env_set,omitempty"`
    EnvUnset    []string          `json:"env_unset,omitempty"`
    
    // Risk assessment
    RiskLevel   string            `json:"risk_level"` // "low", "medium", "high", "critical"
    RiskFactors []string          `json:"risk_factors,omitempty"`
}

// CommandRedirectEvent - Command redirected to different binary
type CommandRedirectEvent struct {
    BaseEvent
    
    // Original command
    OriginalCommand string   `json:"original_command"`
    OriginalArgs    []string `json:"original_args"`
    
    // Redirected to
    NewCommand      string   `json:"new_command"`
    NewArgs         []string `json:"new_args"`
    
    // Why redirected
    Reason          string   `json:"reason"`
    Message         string   `json:"message"`
    
    // Redirect rule that matched
    RedirectRule    string   `json:"redirect_rule"`
}

// CommandBlockedEvent - Command denied by policy
type CommandBlockedEvent struct {
    BaseEvent
    
    // Blocked command
    Command     string   `json:"command"`
    Args        []string `json:"args"`
    
    // Why blocked
    Reason      string   `json:"reason"`
    Message     string   `json:"message"`
    
    // Suggestions for user
    Suggestions []string `json:"suggestions,omitempty"`
    
    // Alternative commands allowed
    Alternatives []string `json:"alternatives,omitempty"`
}

// PathRedirectEvent - File path redirected to different location
type PathRedirectEvent struct {
    BaseEvent
    
    // Original requested path
    OriginalPath string `json:"original_path"`
    
    // Redirected to
    RedirectPath string `json:"redirect_path"`
    
    // Operation being performed
    Operation    string `json:"operation"` // "write", "create", "mkdir"
    
    // Redirect rule that matched
    RedirectRule string `json:"redirect_rule"`
    
    // Was parent directory created?
    ParentCreated bool  `json:"parent_created"`
}
```

**Example Events:**

```json
{
  "id": "evt-cmd-001",
  "type": "command_redirect",
  "timestamp": "2025-01-15T14:30:05.456Z",
  "session_id": "session-abc123",
  "command_id": "cmd-xyz789",
  "pid": 12346,
  "platform": "linux",
  "decision": "redirect",
  "policy_rule": "redirect-curl",
  "original_command": "curl",
  "original_args": ["https://example.com/file.zip"],
  "new_command": "agentsh-fetch",
  "new_args": ["--audit", "--session", "session-abc123", "https://example.com/file.zip"],
  "reason": "Network tools redirected through audited wrapper",
  "message": "Downloads routed through audited fetch",
  "redirect_rule": "redirect-curl"
}
```

```json
{
  "id": "evt-path-001",
  "type": "path_redirect",
  "timestamp": "2025-01-15T14:30:10.789Z",
  "session_id": "session-abc123",
  "command_id": "cmd-xyz790",
  "pid": 12347,
  "platform": "linux",
  "decision": "redirect",
  "policy_rule": "redirect-outside-writes",
  "original_path": "/tmp/output.log",
  "redirect_path": "/workspace/.scratch/tmp/output.log",
  "operation": "create",
  "redirect_rule": "redirect-outside-writes",
  "parent_created": true
}
```

### 14.5 Resource Limit Events

Events related to resource limits and usage:

```go
// Resource limit event types
const (
    EventResourceLimitSet      EventType = "resource_limit_set"
    EventResourceLimitWarning  EventType = "resource_limit_warning"
    EventResourceLimitExceeded EventType = "resource_limit_exceeded"
    EventResourceUsage         EventType = "resource_usage_snapshot"
)

// ResourceLimitSetEvent - Limits applied to process/session
type ResourceLimitSetEvent struct {
    BaseEvent
    
    // Target of limits
    TargetPID   int    `json:"target_pid"`
    TargetType  string `json:"target_type"` // "session", "command", "process"
    
    // Limits applied
    Limits      ResourceLimits `json:"limits"`
    
    // Platform-specific info
    LinuxCgroup   *LinuxCgroupInfo   `json:"linux_cgroup,omitempty"`
    DarwinRlimit  *DarwinRlimitInfo  `json:"darwin_rlimit,omitempty"`
    WindowsJob    *WindowsJobInfo    `json:"windows_job,omitempty"`
}

type ResourceLimits struct {
    MaxMemoryMB      int64  `json:"max_memory_mb,omitempty"`
    MaxSwapMB        int64  `json:"max_swap_mb,omitempty"`
    CPUQuotaPercent  int    `json:"cpu_quota_percent,omitempty"`
    MaxProcesses     int    `json:"max_processes,omitempty"`
    MaxDiskReadMBps  int64  `json:"max_disk_read_mbps,omitempty"`
    MaxDiskWriteMBps int64  `json:"max_disk_write_mbps,omitempty"`
    CommandTimeoutS  int    `json:"command_timeout_s,omitempty"`
}

type LinuxCgroupInfo struct {
    Path        string   `json:"path"`
    Controllers []string `json:"controllers"` // ["cpu", "memory", "io", "pids"]
    Version     int      `json:"version"`     // 1 or 2
}

type DarwinRlimitInfo struct {
    LimitsSet []string `json:"limits_set"` // ["RLIMIT_AS", "RLIMIT_CPU", ...]
    NiceValue int      `json:"nice_value,omitempty"`
}

type WindowsJobInfo struct {
    JobHandle    uint64 `json:"job_handle"`
    LimitFlags   uint32 `json:"limit_flags"`
    CPURateFlags uint32 `json:"cpu_rate_flags,omitempty"`
}

// ResourceLimitWarningEvent - Usage approaching threshold
type ResourceLimitWarningEvent struct {
    BaseEvent
    
    // Which resource
    Resource    string  `json:"resource"` // "memory", "cpu", "disk", "processes"
    
    // Current usage
    Current     int64   `json:"current"`
    CurrentUnit string  `json:"current_unit"` // "MB", "percent", "count"
    
    // Limit
    Limit       int64   `json:"limit"`
    
    // Percentage of limit
    Percentage  float64 `json:"percentage"`
    
    // Warning threshold
    Threshold   float64 `json:"threshold"` // e.g., 0.8 for 80%
}

// ResourceLimitExceededEvent - Limit hit
type ResourceLimitExceededEvent struct {
    BaseEvent
    
    // Which resource
    Resource    string `json:"resource"`
    
    // Values at time of violation
    Current     int64  `json:"current"`
    Limit       int64  `json:"limit"`
    Unit        string `json:"unit"`
    
    // Action taken
    Action      string `json:"action"` // "throttle", "kill", "deny", "warn"
    
    // Was process/session terminated?
    Terminated  bool   `json:"terminated"`
    TermSignal  int    `json:"term_signal,omitempty"`
}

// ResourceUsageEvent - Periodic usage snapshot
type ResourceUsageEvent struct {
    BaseEvent
    
    // Current usage
    MemoryMB       int64   `json:"memory_mb"`
    MemoryPercent  float64 `json:"memory_percent"`
    CPUPercent     float64 `json:"cpu_percent"`
    DiskReadMB     int64   `json:"disk_read_mb"`
    DiskWriteMB    int64   `json:"disk_write_mb"`
    NetSentMB      int64   `json:"net_sent_mb"`
    NetReceivedMB  int64   `json:"net_received_mb"`
    ProcessCount   int     `json:"process_count"`
    ThreadCount    int     `json:"thread_count"`
    OpenFiles      int     `json:"open_files"`
    
    // Interval this covers
    IntervalMS     int64   `json:"interval_ms"`
}
```

**Example Events:**

```json
{
  "id": "evt-limit-001",
  "type": "resource_limit_set",
  "timestamp": "2025-01-15T14:30:00.000Z",
  "session_id": "session-abc123",
  "pid": 12345,
  "platform": "linux",
  "decision": "allow",
  "target_pid": 12345,
  "target_type": "session",
  "limits": {
    "max_memory_mb": 2048,
    "cpu_quota_percent": 80,
    "max_processes": 100
  },
  "linux_cgroup": {
    "path": "/sys/fs/cgroup/agentsh/session-12345",
    "controllers": ["cpu", "memory", "pids"],
    "version": 2
  }
}
```

```json
{
  "id": "evt-limit-002",
  "type": "resource_limit_exceeded",
  "timestamp": "2025-01-15T14:35:22.456Z",
  "session_id": "session-abc123",
  "command_id": "cmd-xyz800",
  "pid": 12350,
  "platform": "linux",
  "decision": "deny",
  "policy_rule": "resource-limits",
  "resource": "memory",
  "current": 2100,
  "limit": 2048,
  "unit": "MB",
  "action": "kill",
  "terminated": true,
  "term_signal": 9
}
```

### 14.6 Process Tree Events

Events for process tree tracking:

```go
// Process tree event types
const (
    EventProcessSpawn    EventType = "process_spawn"
    EventProcessExit     EventType = "process_exit"
    EventProcessTreeKill EventType = "process_tree_kill"
)

// ProcessSpawnEvent - Child process created
type ProcessSpawnEvent struct {
    BaseEvent
    
    // New process
    ChildPID    int      `json:"child_pid"`
    ChildComm   string   `json:"child_comm"`   // Process name
    ChildExe    string   `json:"child_exe"`    // Executable path
    ChildArgs   []string `json:"child_args"`
    
    // Parent process
    ParentPID   int      `json:"parent_pid"`
    ParentComm  string   `json:"parent_comm"`
    
    // Full ancestry (root to child)
    Ancestry    []ProcessInfo `json:"ancestry"`
    
    // Tree depth (1 = direct child of root)
    Depth       int      `json:"depth"`
    
    // Platform-specific tracking info
    LinuxCgroupPath string `json:"linux_cgroup_path,omitempty"`
    WindowsJobHandle uint64 `json:"windows_job_handle,omitempty"`
    
    // Was this expected (from known command)?
    Expected    bool     `json:"expected"`
}

type ProcessInfo struct {
    PID  int    `json:"pid"`
    Comm string `json:"comm"`
}

// ProcessExitEvent - Process exited
type ProcessExitEvent struct {
    BaseEvent
    
    // Exited process
    ExitPID     int    `json:"exit_pid"`
    ExitComm    string `json:"exit_comm"`
    
    // Exit status
    ExitCode    int    `json:"exit_code"`
    ExitSignal  int    `json:"exit_signal,omitempty"`  // If killed by signal
    ExitReason  string `json:"exit_reason"`            // "normal", "signal", "oom", "timeout"
    
    // Runtime
    RuntimeMS   int64  `json:"runtime_ms"`
    
    // Resource usage during lifetime
    CPUTimeMS   int64  `json:"cpu_time_ms"`
    MaxMemoryMB int64  `json:"max_memory_mb"`
    
    // Remaining children
    OrphanedChildren []int `json:"orphaned_children,omitempty"`
}

// ProcessTreeKillEvent - Entire tree terminated
type ProcessTreeKillEvent struct {
    BaseEvent
    
    // Why the tree was killed
    Reason      string `json:"reason"` // "timeout", "limit_exceeded", "session_end", "manual", "policy"
    
    // Signal used
    Signal      int    `json:"signal"`
    
    // Processes killed
    ProcessesKilled []ProcessKillInfo `json:"processes_killed"`
    TotalKilled     int               `json:"total_killed"`
    
    // Any processes that didn't die
    Survivors       []int             `json:"survivors,omitempty"`
    
    // Time to kill all
    KillDurationMS  int64             `json:"kill_duration_ms"`
}

type ProcessKillInfo struct {
    PID      int    `json:"pid"`
    Comm     string `json:"comm"`
    ExitCode int    `json:"exit_code"`
}
```

**Example Events:**

```json
{
  "id": "evt-spawn-001",
  "type": "process_spawn",
  "timestamp": "2025-01-15T14:30:01.234Z",
  "session_id": "session-abc123",
  "command_id": "cmd-xyz789",
  "pid": 12346,
  "platform": "linux",
  "decision": "allow",
  "child_pid": 12346,
  "child_comm": "node",
  "child_exe": "/usr/bin/node",
  "child_args": ["node_modules/.bin/esbuild", "src/index.ts"],
  "parent_pid": 12345,
  "parent_comm": "npm",
  "ancestry": [
    {"pid": 12340, "comm": "bash"},
    {"pid": 12345, "comm": "npm"},
    {"pid": 12346, "comm": "node"}
  ],
  "depth": 2,
  "linux_cgroup_path": "/sys/fs/cgroup/agentsh/session-abc123",
  "expected": true
}
```

```json
{
  "id": "evt-treekill-001",
  "type": "process_tree_kill",
  "timestamp": "2025-01-15T14:40:00.000Z",
  "session_id": "session-abc123",
  "pid": 12340,
  "platform": "linux",
  "decision": "allow",
  "reason": "timeout",
  "signal": 9,
  "processes_killed": [
    {"pid": 12346, "comm": "node", "exit_code": 137},
    {"pid": 12345, "comm": "npm", "exit_code": 137},
    {"pid": 12340, "comm": "bash", "exit_code": 137}
  ],
  "total_killed": 3,
  "kill_duration_ms": 15
}
```

### 14.7 IPC / Unix Socket Events

Events for inter-process communication monitoring:

```go
// IPC event types
const (
    EventUnixSocketConnect EventType = "unix_socket_connect"
    EventUnixSocketBind    EventType = "unix_socket_bind"
    EventUnixSocketBlocked EventType = "unix_socket_blocked"
    EventNamedPipeOpen     EventType = "named_pipe_open"
    EventNamedPipeBlocked  EventType = "named_pipe_blocked"
    EventIPCObserved       EventType = "ipc_observed"
)

// UnixSocketEvent - Unix domain socket operation
type UnixSocketEvent struct {
    BaseEvent
    
    // Operation
    Operation   string `json:"operation"` // "connect", "bind", "listen", "accept"
    
    // Socket type
    SocketType  string `json:"socket_type"` // "stream", "dgram", "seqpacket"
    
    // Socket path (filesystem sockets)
    Path        string `json:"path,omitempty"`
    
    // Abstract socket name (Linux only)
    AbstractName string `json:"abstract_name,omitempty"`
    IsAbstract   bool   `json:"is_abstract"`
    
    // Peer information (if available)
    PeerPID     int    `json:"peer_pid,omitempty"`
    PeerUID     int    `json:"peer_uid,omitempty"`
    PeerGID     int    `json:"peer_gid,omitempty"`
    PeerComm    string `json:"peer_comm,omitempty"`
    
    // Known service
    Service     string `json:"service,omitempty"` // "docker", "ssh-agent", "dbus", etc.
    
    // Interception method
    Method      string `json:"method"` // "seccomp", "dtrace", "poll"
}

// NamedPipeEvent - Windows named pipe operation
type NamedPipeEvent struct {
    BaseEvent
    
    // Operation
    Operation   string `json:"operation"` // "open", "create", "connect"
    
    // Pipe path (\\.\pipe\NAME)
    Path        string `json:"path"`
    
    // Pipe mode
    PipeMode    string `json:"pipe_mode"` // "byte", "message"
    
    // Access requested
    AccessMode  string `json:"access_mode"` // "read", "write", "readwrite"
    
    // Server or client side
    IsServer    bool   `json:"is_server"`
    
    // Known service
    Service     string `json:"service,omitempty"` // "docker", "ssh-agent", etc.
    
    // Interception method
    Method      string `json:"method"` // "etw", "minifilter", "poll"
}

// IPCObservedEvent - Audit-only detection (no enforcement)
type IPCObservedEvent struct {
    BaseEvent
    
    // What was observed
    IPCType     string `json:"ipc_type"` // "unix_socket", "named_pipe", "shm", "mqueue"
    Path        string `json:"path"`
    
    // Detection method (typically polling)
    Method      string `json:"method"` // "proc_net_unix", "lsof", "pipe_enum"
    
    // Why we couldn't enforce
    Limitation  string `json:"limitation"` // "no_seccomp", "no_root", "audit_only"
    
    // Processes involved (if known)
    Endpoints   []IPCEndpoint `json:"endpoints,omitempty"`
}

type IPCEndpoint struct {
    PID  int    `json:"pid"`
    Comm string `json:"comm"`
    Role string `json:"role"` // "server", "client", "unknown"
}
```

**Example Events:**

```json
{
  "id": "evt-unix-001",
  "type": "unix_socket_blocked",
  "timestamp": "2025-01-15T14:30:15.789Z",
  "session_id": "session-abc123",
  "command_id": "cmd-xyz791",
  "pid": 12348,
  "platform": "linux",
  "decision": "deny",
  "policy_rule": "docker-socket",
  "operation": "connect",
  "socket_type": "stream",
  "path": "/var/run/docker.sock",
  "is_abstract": false,
  "service": "docker",
  "method": "seccomp"
}
```

```json
{
  "id": "evt-pipe-001",
  "type": "named_pipe_open",
  "timestamp": "2025-01-15T14:30:20.123Z",
  "session_id": "session-abc123",
  "command_id": "cmd-xyz792",
  "pid": 12349,
  "platform": "windows",
  "decision": "allow",
  "policy_rule": "allow-sql",
  "operation": "connect",
  "path": "\\\\.\\pipe\\sql\\query",
  "pipe_mode": "message",
  "access_mode": "readwrite",
  "is_server": false,
  "service": "mssql",
  "method": "etw"
}
```

### 14.8 Enhanced Existing Events

Several existing events need additional fields for cross-platform support:

```go
// Enhanced FileEvent - adds redirect info
type FileEvent struct {
    BaseEvent
    
    // Standard fields
    Path        string `json:"path"`
    RealPath    string `json:"real_path"`
    Operation   string `json:"operation"`
    
    // NEW: Redirect info
    RedirectedFrom string `json:"redirected_from,omitempty"`
    RedirectRule   string `json:"redirect_rule,omitempty"`
    
    // Operation details
    Bytes       int64    `json:"bytes,omitempty"`
    Offset      int64    `json:"offset,omitempty"`
    Flags       []string `json:"flags,omitempty"`
    
    // File metadata
    FileType    string `json:"file_type,omitempty"`
    FileSize    int64  `json:"file_size,omitempty"`
}

// Enhanced ProcessStartEvent - adds tree tracking info
type ProcessStartEvent struct {
    BaseEvent
    
    // Standard fields
    Command     string   `json:"command"`
    Args        []string `json:"args"`
    Executable  string   `json:"executable"`
    WorkingDir  string   `json:"working_dir"`
    
    // NEW: Tree tracking
    ParentPID   int      `json:"parent_pid"`
    TreeDepth   int      `json:"tree_depth"`
    RootPID     int      `json:"root_pid"` // Session root process
    
    // NEW: Platform-specific tracking
    LinuxCgroupPath  string `json:"linux_cgroup_path,omitempty"`
    WindowsJobHandle uint64 `json:"windows_job_handle,omitempty"`
    
    // NEW: Resource limits applied
    LimitsApplied bool           `json:"limits_applied"`
    Limits        *ResourceLimits `json:"limits,omitempty"`
    
    // Environment
    Environment map[string]string `json:"environment,omitempty"`
}

// Enhanced NetConnectEvent - adds interception method
type NetConnectEvent struct {
    BaseEvent
    
    // Standard fields
    RemoteAddr  string `json:"remote_addr"`
    RemotePort  int    `json:"remote_port"`
    LocalPort   int    `json:"local_port"`
    Protocol    string `json:"protocol"`
    
    // DNS info
    Domain      string `json:"domain,omitempty"`
    
    // NEW: Interception method
    InterceptedBy string `json:"intercepted_by"` // "proxy", "ebpf", "nfqueue", "wfp", "pf"
    
    // NEW: Was this redirected?
    Redirected    bool   `json:"redirected"`
    OriginalDest  string `json:"original_dest,omitempty"`
    
    // TLS info
    TLS         *TLSInfo `json:"tls,omitempty"`
}

type TLSInfo struct {
    SNI     string `json:"sni,omitempty"`
    Version string `json:"version,omitempty"`
    ALPN    string `json:"alpn,omitempty"`
}
```

### 14.9 Event Type Registry

Complete registry of all event types:

```go
// AllEventTypes lists every event type for documentation/validation
var AllEventTypes = []EventType{
    // File operations
    EventFileOpen, EventFileRead, EventFileWrite, EventFileCreate,
    EventFileDelete, EventFileRename, EventFileStat, EventFileChmod,
    EventDirCreate, EventDirDelete, EventDirList,
    
    // Network operations
    EventDNSQuery, EventNetConnect, EventNetListen, EventNetAccept,
    
    // Process operations (legacy)
    EventProcessStart, EventProcessEnd,
    
    // Environment operations
    EventEnvRead, EventEnvWrite, EventEnvList, EventEnvBlocked,
    
    // Soft delete operations
    EventSoftDelete, EventTrashRestore, EventTrashPurge,
    
    // Shell shim events (NEW)
    EventShellInvoke, EventShellPassthrough, EventSessionAutostart,
    
    // Command interception events (NEW)
    EventCommandIntercept, EventCommandRedirect, EventCommandBlocked, EventPathRedirect,
    
    // Resource limit events (NEW)
    EventResourceLimitSet, EventResourceLimitWarning, 
    EventResourceLimitExceeded, EventResourceUsage,
    
    // Process tree events (NEW)
    EventProcessSpawn, EventProcessExit, EventProcessTreeKill,
    
    // IPC events (NEW)
    EventUnixSocketConnect, EventUnixSocketBind, EventUnixSocketBlocked,
    EventNamedPipeOpen, EventNamedPipeBlocked, EventIPCObserved,
}

// EventCategory groups events by category
var EventCategory = map[EventType]string{
    EventFileOpen:      "file",
    EventFileRead:      "file",
    EventFileWrite:     "file",
    // ... etc
    
    EventShellInvoke:      "shell",
    EventShellPassthrough: "shell",
    EventSessionAutostart: "shell",
    
    EventCommandIntercept: "command",
    EventCommandRedirect:  "command",
    EventCommandBlocked:   "command",
    EventPathRedirect:     "command",
    
    EventResourceLimitSet:      "resource",
    EventResourceLimitWarning:  "resource",
    EventResourceLimitExceeded: "resource",
    EventResourceUsage:         "resource",
    
    EventProcessSpawn:    "process",
    EventProcessExit:     "process",
    EventProcessTreeKill: "process",
    
    EventUnixSocketConnect: "ipc",
    EventUnixSocketBind:    "ipc",
    EventUnixSocketBlocked: "ipc",
    EventNamedPipeOpen:     "ipc",
    EventNamedPipeBlocked:  "ipc",
    EventIPCObserved:       "ipc",
}
```

### 14.10 Platform Event Support Matrix

Not all events are available on all platforms:

| Event Type | Linux | macOS Native | macOS Lima | Windows |
|------------|:-----:|:------------:|:----------:|:-------:|
| **Shell Events** |
| `shell_invoke` | ✅ | ✅ | ✅ | ✅ |
| `shell_passthrough` | ✅ | ✅ | ✅ | ✅ |
| `session_autostart` | ✅ | ✅ | ✅ | ✅ |
| **Command Events** |
| `command_intercept` | ✅ | ✅ | ✅ | ✅ |
| `command_redirect` | ✅ | ✅ | ✅ | ✅ |
| `command_blocked` | ✅ | ✅ | ✅ | ✅ |
| `path_redirect` | ✅ | ✅ | ✅ | ✅ |
| **Resource Events** |
| `resource_limit_set` | ✅ | ⚠️ Partial | ✅ | ✅ |
| `resource_limit_warning` | ✅ | ⚠️ Partial | ✅ | ✅ |
| `resource_limit_exceeded` | ✅ | ⚠️ Partial | ✅ | ✅ |
| `resource_usage_snapshot` | ✅ | ✅ | ✅ | ✅ |
| **Process Tree Events** |
| `process_spawn` | ✅ | ⚠️ Polling | ✅ | ✅ |
| `process_exit` | ✅ | ⚠️ Polling | ✅ | ✅ |
| `process_tree_kill` | ✅ | ✅ | ✅ | ✅ |
| **IPC Events** |
| `unix_socket_connect` | ✅ | ⚠️ DTrace/Poll | ✅ | N/A |
| `unix_socket_bind` | ✅ | ⚠️ DTrace/Poll | ✅ | N/A |
| `unix_socket_blocked` | ✅ seccomp | ❌ | ✅ | N/A |
| `named_pipe_open` | N/A | N/A | N/A | ✅ |
| `named_pipe_blocked` | N/A | N/A | N/A | ⚠️ ETW |
| `ipc_observed` | ✅ | ✅ | ✅ | ✅ |

Legend:
- ✅ Full support
- ⚠️ Partial/limited support (see notes)
- ❌ Not supported
- N/A Not applicable to platform

### 14.11 Event Filtering Configuration

Configure which events to emit:

```yaml
# In agentsh.yaml

events:
  # Global enable/disable
  enabled: true
  
  # Events to emit (default: all)
  include:
    - "file_*"
    - "net_*"
    - "process_*"
    - "command_*"
    - "resource_*"
    - "ipc_*"
    - "shell_*"
    
  # Events to suppress
  exclude:
    - "file_stat"       # Too noisy
    - "resource_usage_snapshot"  # Use metrics instead
    
  # Category-level control
  categories:
    file: true
    network: true
    process: true
    command: true
    resource: true
    ipc: true
    shell: true
    
  # Sampling for high-volume events
  sampling:
    resource_usage_snapshot:
      rate: 0.1  # 10% sampling
    file_read:
      rate: 1.0  # 100% (no sampling)
      
  # Minimum severity to emit
  min_severity: "info"  # "debug", "info", "warn", "error"
  
  # Include full ancestry in process events
  include_ancestry: true
  max_ancestry_depth: 10
  
  # Include environment in process start events
  include_environment: false  # Can be verbose
  
  # Batch settings
  batch:
    size: 100
    delay_ms: 10
    
  # Output destinations
  outputs:
    - type: "stream"      # SSE to clients
    - type: "file"
      path: "/var/log/agentsh/events.jsonl"
      rotate_size_mb: 100
    - type: "webhook"
      url: "https://siem.example.com/events"
      batch_size: 50
```

---

## 15. Unified Configuration

### 15.1 Configuration File

```yaml
# agentsh.yaml - Cross-platform configuration

# Platform selection
platform:
  # auto, linux, darwin, darwin-lima, windows, windows-wsl2
  mode: auto
  
  # Fallback behavior when preferred mode unavailable
  fallback:
    enabled: true
    order:
      - windows-wsl2
      - windows
      - darwin-lima
      - darwin

# Filesystem interception
filesystem:
  enabled: true
  # Platform-specific mount points
  mount_point:
    linux: "/tmp/agentsh/workspace"
    darwin: "/tmp/agentsh/workspace"
    windows: "X:"
    windows_wsl2: "/tmp/agentsh/workspace"

# Network interception
network:
  enabled: true
  proxy_port: 9080
  dns_port: 9053
  intercept_mode: all # all, tcp_only, monitor
  
  # TLS inspection (requires CA cert)
  tls_inspection:
    enabled: false
    ca_cert: ""
    ca_key: ""

# Sandbox/Isolation
sandbox:
  enabled: true
  # Degrade gracefully on platforms without full isolation
  allow_degraded: true
  
  # Resource limits
  limits:
    max_memory_mb: 2048
    max_cpu_percent: 50
    max_processes: 100
    max_disk_io_mbps: 100
    max_network_mbps: 50

# Policy engine
policy:
  default_action: allow # allow, deny, redirect, approve
  
  # Approval settings for manual review
  approval:
    enabled: true
    timeout_seconds: 300        # 5 minutes to approve
    notify_url: "https://hooks.slack.com/..."
    ui_port: 9090               # Local approval UI
    
  file_rules:
    - name: workspace
      paths: ["${WORKSPACE}/**"]
      operations: [read, write, create]
      action: allow
      
    - name: sensitive
      paths: ["/etc/**", "**/.env", "**/secrets/**"]
      action: deny
      
    # Redirect: intercept reads of real files, serve fake content
    - name: honeypot-passwd
      paths: ["/etc/passwd", "/etc/shadow"]
      operations: [read]
      action: redirect
      redirect:
        file_path: "/opt/agentsh/honeypot/fake-passwd"
        
    # Redirect: capture writes to /dev/null
    - name: protect-ssh
      paths: ["~/.ssh/**"]
      operations: [write, create]
      action: redirect
      redirect:
        file_path: "/opt/agentsh/captures/${TIMESTAMP}-ssh-write"
        
    # Manual approval for destructive operations
    - name: require-approval-delete
      paths: ["${WORKSPACE}/**"]
      operations: [delete]
      action: approve
      
  network_rules:
    - name: package-registries
      domains: ["npmjs.org", "pypi.org", "github.com"]
      action: allow
      
    - name: internal
      cidrs: ["10.0.0.0/8", "192.168.0.0/16"]
      action: deny
      
    # Redirect: send all OpenAI requests to local mock
    - name: redirect-openai
      domains: ["api.openai.com"]
      action: redirect
      redirect:
        host: "localhost"
        port: 8080
        
    # Manual approval for unknown external hosts
    - name: unknown-external
      cidrs: ["0.0.0.0/0"]
      action: approve
      
  dns_rules:
    # Redirect: resolve C2 domains to localhost
    - name: block-c2
      patterns: ["*.malware.com", "*.evil.net"]
      action: redirect
      redirect:
        ip_address: "127.0.0.1"
        
    # Redirect: all external DNS to safe resolver
    - name: force-safe-dns
      patterns: ["*"]
      action: redirect
      redirect:
        ip_address: "1.1.1.2"  # Cloudflare malware blocking
        
  env_rules:
    # Redirect: return fake API key
    - name: fake-openai-key
      variables: ["OPENAI_API_KEY"]
      action: redirect
      redirect:
        value: "sk-fake-key-for-testing-only"
        
    - name: block-secrets
      patterns: ["*_SECRET*", "*_TOKEN*", "*_KEY*"]
      action: deny

  # Windows registry rules (requires minifilter driver)
  registry_rules:
    # Block writes to sensitive keys
    - name: protect-run-keys
      paths: 
        - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*"
        - "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*"
      operations: [write, create, delete]
      action: deny
      
    # Redirect: honeypot for credential reads
    - name: honeypot-credentials
      paths: ["HKLM\\SAM\\*", "HKLM\\SECURITY\\*"]
      operations: [read]
      action: redirect
      redirect:
        value: ""  # Return empty/fake data
        
    # Require approval for service installation
    - name: approve-services
      paths: ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\*"]
      operations: [create, write]
      action: approve
      
    # Monitor but allow normal software keys
    - name: monitor-software
      paths: ["HKLM\\SOFTWARE\\*", "HKCU\\SOFTWARE\\*"]
      operations: [read, write]
      action: allow
      log: true

# Logging
logging:
  level: info
  format: json
  output: stderr
  
  # Audit log for security events
  audit:
    enabled: true
    path: "${DATA_DIR}/audit.log"
```

### 15.2 Sample Policy Files

agentsh uses policy files for all rules - **there are no hardcoded defaults**. You must provide policy configuration for the features you want to use.

#### 15.2.1 Environment Variable Policy

Create `/etc/agentsh/policies/env.yaml`:

```yaml
# Environment Variable Protection Policy
# All rules must be explicitly configured - no hardcoded defaults

env_protection:
  enabled: true
  mode: allowlist  # "allowlist" or "blocklist"
  
  # Allowlist: Only these variables are visible to the agent
  # Required when mode is "allowlist"
  allowlist:
    # Essential system vars
    - "PATH"
    - "HOME"
    - "USER"
    - "SHELL"
    - "TERM"
    - "LANG"
    - "LC_*"
    - "TZ"
    - "PWD"
    - "TMPDIR"
    # Development tools
    - "EDITOR"
    - "VISUAL"
    - "PAGER"
    # agentsh-specific
    - "AGENTSH_*"
    
  # Blocklist: These are always blocked, even if in allowlist
  blocklist:
    - "*_KEY"
    - "*_TOKEN"
    - "*_SECRET"
    - "*_PASSWORD"
    - "*_CREDENTIAL*"
    - "AWS_*"
    - "AZURE_*"
    - "GCP_*"
    - "OPENAI_*"
    - "ANTHROPIC_*"
    - "DATABASE_URL"
    - "SSH_*"
    
  # Patterns to detect sensitive variables (regex)
  sensitive_patterns:
    - "(?i)api[_-]?key"
    - "(?i)secret"
    - "(?i)token"
    - "(?i)password"
    - "(?i)credential"
    
  # Options
  redact_instead_of_remove: false
  redact_placeholder: "[REDACTED]"
  log_access: true
  alert_on_sensitive: true
```

#### 15.2.2 File Policy

Create `/etc/agentsh/policies/files.yaml`:

```yaml
# File Access Policy

file_policy:
  default_action: deny  # deny, allow, or approve
  
  rules:
    # Workspace - full access
    - name: workspace
      paths:
        - "${WORKSPACE}/**"
      operations: [read, write, create, delete, rename]
      action: allow
      
    # Read-only system files
    - name: system-read
      paths:
        - "/usr/share/**"
        - "/etc/timezone"
        - "/etc/localtime"
      operations: [read, stat]
      action: allow
      
    # Block sensitive paths
    - name: sensitive-block
      paths:
        - "/etc/shadow"
        - "/etc/passwd"
        - "**/.ssh/**"
        - "**/.gnupg/**"
        - "**/.aws/**"
        - "**/.env"
        - "**/.env.*"
        - "**/secrets/**"
      operations: [read, write, create, delete]
      action: deny
      
    # Require approval for destructive operations
    - name: approve-delete
      paths:
        - "${WORKSPACE}/**"
      operations: [delete]
      action: approve
      timeout_seconds: 300
```

#### 15.2.3 Network Policy

Create `/etc/agentsh/policies/network.yaml`:

```yaml
# Network Access Policy

network_policy:
  default_action: deny
  
  rules:
    # Allow package registries
    - name: package-registries
      domains:
        - "npmjs.org"
        - "registry.npmjs.org"
        - "pypi.org"
        - "files.pythonhosted.org"
        - "github.com"
        - "api.github.com"
        - "crates.io"
      action: allow
      
    # Allow documentation sites
    - name: documentation
      domains:
        - "*.readthedocs.io"
        - "docs.python.org"
        - "docs.rs"
        - "developer.mozilla.org"
      action: allow
      
    # Block internal networks
    - name: internal-block
      cidrs:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
      action: deny
      
    # Require approval for unknown external hosts
    - name: unknown-external
      domains:
        - "*"
      action: approve
      timeout_seconds: 60

dns_policy:
  # Block known malicious patterns
  rules:
    - name: block-suspicious
      patterns:
        - "*.ru"
        - "*.cn"
        - "*malware*"
        - "*phishing*"
      action: deny
```

#### 15.2.4 Registry Policy (Windows)

Create `C:\ProgramData\agentsh\policies\registry.yaml`:

```yaml
# Windows Registry Policy

registry_policy:
  default_action: allow
  log_all: true
  
  rules:
    # Block persistence mechanisms
    - name: block-autorun
      paths:
        - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*"
        - "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*"
        - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
      operations: [write, create, delete]
      action: deny
      
    # Require approval for service installation
    - name: approve-services
      paths:
        - "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*"
      operations: [create, write]
      action: approve
      timeout_seconds: 300
      
    # Block credential access
    - name: block-credentials
      paths:
        - "HKLM\\SAM\\*"
        - "HKLM\\SECURITY\\*"
        - "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\*"
      operations: [read, write]
      action: deny
```

#### 15.2.5 Minimal Starter Policy

For quick setup, create `/etc/agentsh/policies/minimal.yaml`:

```yaml
# Minimal starter policy - customize for your needs

env_protection:
  enabled: true
  mode: allowlist
  allowlist: [PATH, HOME, USER, SHELL, TERM, PWD, TMPDIR]
  blocklist: ["*_KEY", "*_TOKEN", "*_SECRET", "*_PASSWORD"]
  sensitive_patterns: ["(?i)secret", "(?i)password", "(?i)token"]

file_policy:
  default_action: deny
  rules:
    - name: workspace
      paths: ["${WORKSPACE}/**"]
      operations: [read, write, create, delete]
      action: allow

network_policy:
  default_action: deny
  rules:
    - name: allow-all-https
      ports: [443]
      action: allow
```

**Important:** Without policy files, agentsh will refuse to start. This ensures you consciously configure security rules rather than relying on potentially insecure defaults.

### 15.3 Platform Detection and Initialization

```go
// pkg/config/platform.go

package config

func InitializePlatform(cfg *Config) (Platform, error) {
    mode := cfg.Platform.Mode
    
    if mode == "auto" {
        mode = detectBestMode()
    }
    
    platform, err := platform.NewWithMode(parseMode(mode))
    if err != nil {
        if cfg.Platform.Fallback.Enabled {
            return tryFallbacks(cfg.Platform.Fallback.Order)
        }
        return nil, err
    }
    
    // Validate platform capabilities meet requirements
    caps := platform.Capabilities()
    
    if cfg.Sandbox.Enabled && !cfg.Sandbox.AllowDegraded {
        if caps.IsolationLevel < IsolationFull {
            return nil, fmt.Errorf(
                "platform %s has degraded isolation (level %d), "+
                "set sandbox.allow_degraded=true to continue",
                platform.Name(), caps.IsolationLevel,
            )
        }
    }
    
    return platform, nil
}

func detectBestMode() string {
    switch runtime.GOOS {
    case "linux":
        return "linux"
    case "darwin":
        if hasLima() {
            return "darwin-lima"
        }
        return "darwin"
    case "windows":
        if hasWSL2() {
            return "windows-wsl2"
        }
        return "windows"
    default:
        return "unsupported"
    }
}
```

---

## 16. Installation & Deployment

### 16.1 Linux Installation

```bash
#!/bin/bash
# install-linux.sh

set -e

# Check prerequisites
check_fuse() {
    if ! command -v fusermount3 &> /dev/null; then
        echo "Installing FUSE3..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y fuse3 libfuse3-dev
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y fuse3 fuse3-devel
        elif command -v pacman &> /dev/null; then
            sudo pacman -S fuse3
        fi
    fi
}

check_iptables() {
    if ! command -v iptables &> /dev/null; then
        echo "Installing iptables..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y iptables
        fi
    fi
}

# Download and install
install_agentsh() {
    local version="${1:-latest}"
    local arch=$(uname -m)
    
    case $arch in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
    esac
    
    curl -fsSL "https://github.com/agentsh/agentsh/releases/download/${version}/agentsh-linux-${arch}" \
        -o /tmp/agentsh
    chmod +x /tmp/agentsh
    sudo mv /tmp/agentsh /usr/local/bin/agentsh
}

check_fuse
check_iptables
install_agentsh "$@"

echo "agentsh installed successfully!"
echo "Run 'agentsh server' to start the server."
```

### 16.2 macOS Installation

```bash
#!/bin/bash
# install-macos.sh

set -e

echo "agentsh macOS Installer"
echo "======================="

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install FUSE-T (recommended - no kernel extension)
install_fuse_t() {
    echo "Installing FUSE-T (recommended)..."
    brew install fuse-t
    echo "✅ FUSE-T installed - no restart required!"
}

# Install Lima for full Linux security
install_lima() {
    echo "Installing Lima for full isolation..."
    brew install lima
    
    # Create agentsh VM
    if ! limactl list 2>/dev/null | grep -q "agentsh"; then
        limactl create --name=agentsh template://ubuntu-lts
        limactl start agentsh
        limactl shell agentsh -- bash -c 'curl -fsSL https://get.agentsh.dev | bash'
    fi
    echo "✅ Lima VM ready with full Linux security"
}

# Download and install agentsh binary
install_agentsh() {
    local version="${1:-latest}"
    local arch=$(uname -m)
    
    case $arch in
        x86_64) arch="amd64" ;;
        arm64) arch="arm64" ;;
    esac
    
    echo "Installing agentsh binary..."
    curl -fsSL "https://github.com/agentsh/agentsh/releases/download/${version}/agentsh-darwin-${arch}" \
        -o /tmp/agentsh
    chmod +x /tmp/agentsh
    sudo mv /tmp/agentsh /usr/local/bin/agentsh
    echo "✅ agentsh installed to /usr/local/bin/"
}

echo ""
echo "Select installation mode:"
echo ""
echo "  1) FUSE-T + pf (Recommended for development)"
echo "     - No kernel extension required"
echo "     - Works on Apple Silicon without reduced security"
echo "     - File + Network interception (no isolation)"
echo "     - Security: 70%"
echo ""
echo "  2) Lima VM (Recommended for production)"
echo "     - Full Linux isolation in VM"
echo "     - All security features available"
echo "     - Slight performance overhead"
echo "     - Security: 85%"
echo ""
echo "  3) Network only (minimal setup)"
echo "     - pf for network interception"
echo "     - FSEvents for file monitoring (observe only)"
echo "     - No FUSE installation needed"
echo "     - Security: 50%"
echo ""

read -p "Choice [1/2/3]: " choice

case $choice in
    1)
        install_fuse_t
        install_agentsh "$@"
        echo ""
        echo "Run with: sudo agentsh server"
        ;;
    2)
        install_lima
        install_agentsh "$@"
        echo ""
        echo "Run with: limactl shell agentsh -- agentsh server"
        ;;
    3)
        install_agentsh "$@"
        echo ""
        echo "Run with: sudo agentsh server"
        echo "Note: File monitoring is observation-only without FUSE-T"
        ;;
    *)
        echo "Invalid choice, installing FUSE-T (recommended)"
        install_fuse_t
        install_agentsh "$@"
        ;;
esac

echo ""
echo "Installation complete!"
echo "Check status with: agentsh status"
```

### 16.3 Windows Installation

```powershell
# install-windows.ps1

param(
    [ValidateSet('native', 'wsl2', 'auto')]
    [string]$Mode = 'auto',
    [string]$Version = 'latest'
)

$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-WSL2 {
    try {
        $wslStatus = wsl --status 2>&1
        return $wslStatus -match "Default Version: 2" -or $wslStatus -match "WSL version"
    } catch {
        return $false
    }
}

function Install-WinFsp {
    Write-Host "Installing WinFsp..."
    winget install WinFsp.WinFsp --accept-source-agreements --accept-package-agreements
}

function Install-WinDivert {
    Write-Host "Installing WinDivert..."
    $url = "https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip"
    $zipPath = "$env:TEMP\windivert.zip"
    $extractPath = "$env:ProgramFiles\WinDivert"
    
    Invoke-WebRequest -Uri $url -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    
    # Add to PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notlike "*WinDivert*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$extractPath", "Machine")
    }
}

function Install-WSL2 {
    Write-Host "Setting up WSL2..."
    wsl --install -d Ubuntu-24.04
    
    Write-Host "Installing agentsh in WSL2..."
    wsl -d Ubuntu-24.04 -- bash -c 'curl -fsSL https://get.agentsh.dev | bash'
}

function Install-AgentshNative {
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    $url = "https://github.com/agentsh/agentsh/releases/download/$Version/agentsh-windows-$arch.exe"
    
    $installPath = "$env:LOCALAPPDATA\agentsh"
    New-Item -ItemType Directory -Force -Path $installPath | Out-Null
    
    Invoke-WebRequest -Uri $url -OutFile "$installPath\agentsh.exe"
    
    # Add to PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($currentPath -notlike "*agentsh*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$installPath", "User")
    }
}

# Check admin for native mode
if ($Mode -ne 'wsl2' -and -not (Test-Administrator)) {
    Write-Host "Native mode requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Auto-detect mode
if ($Mode -eq 'auto') {
    if (Test-WSL2) {
        $Mode = 'wsl2'
        Write-Host "WSL2 detected. Using WSL2 mode for full security."
    } else {
        $Mode = 'native'
        Write-Host "WSL2 not available. Using native Windows mode."
    }
}

switch ($Mode) {
    'native' {
        Install-WinFsp
        Install-WinDivert
        Install-AgentshNative
        
        Write-Host ""
        Write-Host "agentsh installed in native Windows mode."
        Write-Host "Note: Native mode provides partial isolation. Use WSL2 for full security."
    }
    'wsl2' {
        Install-WSL2
        Install-AgentshNative  # Also install native wrapper
        
        Write-Host ""
        Write-Host "agentsh installed with WSL2 backend."
        Write-Host "Full Linux security features are available."
    }
}

Write-Host ""
Write-Host "Installation complete! Run 'agentsh server' to start."
```

---

## 17. Testing Strategy

### 17.1 Cross-Platform Test Suite

```go
// test/platform_test.go

package test

import (
    "context"
    "testing"
    "time"
    
    "agentsh/pkg/platform"
)

// TestPlatformCapabilities verifies platform detection
func TestPlatformCapabilities(t *testing.T) {
    p, err := platform.New()
    if err != nil {
        t.Fatalf("failed to create platform: %v", err)
    }
    
    caps := p.Capabilities()
    t.Logf("Platform: %s", p.Name())
    t.Logf("Capabilities: %+v", caps)
    
    // Basic requirements - all platforms must have filesystem and network
    if !caps.HasFUSE {
        t.Error("Platform must have FUSE support")
    }
    if !caps.HasNetworkIntercept {
        t.Error("Platform must have network interception")
    }
}

// TestFilesystemInterception verifies FUSE works
func TestFilesystemInterception(t *testing.T) {
    p, _ := platform.New()
    fs := p.Filesystem()
    
    if !fs.Available() {
        t.Skip("FUSE not available on this platform")
    }
    
    events := make(chan IOEvent, 100)
    mount, err := fs.Mount(FSConfig{
        SourcePath:   t.TempDir(),
        MountPoint:   getMountPoint(t),
        EventChannel: events,
    })
    if err != nil {
        t.Fatalf("mount failed: %v", err)
    }
    defer mount.Close()
    
    // Create a file and verify event
    // ... test implementation
}

// TestNetworkInterception verifies network capture works
func TestNetworkInterception(t *testing.T) {
    p, _ := platform.New()
    net := p.Network()
    
    if !net.Available() {
        t.Skip("Network interception not available")
    }
    
    events := make(chan IOEvent, 100)
    err := net.Setup(NetConfig{
        ProxyPort:    19080,
        DNSPort:      19053,
        EventChannel: events,
    })
    if err != nil {
        t.Fatalf("network setup failed: %v", err)
    }
    defer net.Teardown()
    
    // Make a connection and verify event
    // ... test implementation
}

// TestSandboxIsolation verifies process isolation
func TestSandboxIsolation(t *testing.T) {
    p, _ := platform.New()
    sm := p.Sandbox()
    
    caps := p.Capabilities()
    t.Logf("Isolation level: %d", caps.IsolationLevel)
    
    if caps.IsolationLevel == IsolationNone {
        t.Skip("No isolation available on this platform")
    }
    
    sandbox, err := sm.Create(SandboxConfig{
        Name:          "test-sandbox",
        WorkspacePath: t.TempDir(),
    })
    if err != nil {
        t.Fatalf("sandbox creation failed: %v", err)
    }
    defer sandbox.Close()
    
    // Test that sandbox restricts access
    // ... test implementation
}

// TestResourceLimits verifies resource limiting
func TestResourceLimits(t *testing.T) {
    p, _ := platform.New()
    rl := p.Resources()
    
    if !rl.Available() {
        t.Skip("Resource limits not available")
    }
    
    supported := rl.SupportedLimits()
    t.Logf("Supported limits: %v", supported)
    
    handle, err := rl.Apply(ResourceConfig{
        MaxMemoryMB:   512,
        MaxCPUPercent: 25,
    })
    if err != nil {
        t.Fatalf("resource limit apply failed: %v", err)
    }
    defer handle.Release()
    
    // Test that limits are enforced
    // ... test implementation
}
```

### 17.2 CI/CD Matrix

```yaml
# .github/workflows/test.yml

name: Cross-Platform Tests

on: [push, pull_request]

jobs:
  test-linux:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y fuse3 libfuse3-dev
      - name: Run tests
        run: go test -v ./...
        
  test-macos:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Install FUSE-T
        run: brew install fuse-t
      - name: Run tests
        run: go test -v ./...
        
  test-windows-native:
    runs-on: windows-2022
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Install WinFsp
        run: choco install winfsp -y
      - name: Run tests
        run: go test -v ./...
        
  test-windows-wsl2:
    runs-on: windows-2022
    steps:
      - uses: actions/checkout@v4
      - name: Setup WSL2
        run: |
          wsl --install -d Ubuntu-24.04 --no-launch
          wsl -d Ubuntu-24.04 -- bash -c 'sudo apt-get update && sudo apt-get install -y golang-go fuse3'
      - name: Run tests in WSL2
        run: |
          wsl -d Ubuntu-24.04 -- bash -c 'cd /mnt/c/$(pwd) && go test -v ./...'
```

---

## 18. Platform Comparison Matrix

### 17.1 Feature Support Matrix (All Platform Variants)

| Feature | Linux | macOS ESF+NE | macOS FUSE-T | macOS Lima | Win Native | Win WSL2 |
|---------|:-----:|:------------:|:------------:|:----------:|:----------:|:--------:|
| **Filesystem Interception** |
| Implementation | FUSE3 | Endpoint Security | FUSE-T (NFS) | FUSE3 | WinFsp | FUSE3 |
| File read monitoring | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block |
| File write monitoring | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block |
| File create/delete | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block |
| File policy enforcement | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Network Interception** |
| Implementation | iptables | Network Extension | pf | iptables | WinDivert | iptables |
| TCP interception | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block |
| UDP interception | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block |
| DNS interception | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block | ✅ Block |
| TLS inspection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Per-app filtering | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Synchronous Interception (Block/Redirect/Approve)** |
| File operations hold | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network operations hold | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DNS hold | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Env var hold | ✅ | ✅ Spawn | ⚠️ Partial | ✅ | ⚠️ Partial | ✅ |
| Registry hold | N/A | N/A | N/A | N/A | ⚠️ Driver | N/A |
| File redirect | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network redirect | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DNS redirect | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Env var redirect | ✅ | ✅ Spawn | ⚠️ Partial | ✅ | ⚠️ Partial | ✅ |
| Registry redirect | N/A | N/A | N/A | N/A | ⚠️ Driver | N/A |
| Manual approval | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Environment Variable Protection** |
| Spawn-time filtering | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Runtime interception | ✅ LD_PRELOAD | ❌ | ⚠️ DYLD* | ✅ LD_PRELOAD | ⚠️ Detours | ✅ LD_PRELOAD |
| env_read events | ✅ | ✅ Spawn | ⚠️ Partial | ✅ | ⚠️ Partial | ✅ |
| env_list events | ✅ | ✅ Spawn | ⚠️ Partial | ✅ | ⚠️ Partial | ✅ |
| env_write events | ✅ | ✅ Spawn | ⚠️ Partial | ✅ | ⚠️ Partial | ✅ |
| environ blocking | ✅ | ✅ | ⚠️ Non-SIP | ✅ | ⚠️ | ✅ |
| **Process Isolation** |
| Mount namespace | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| Network namespace | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| PID namespace | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| User namespace | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| AppContainer | N/A | N/A | N/A | N/A | ✅ Partial | N/A |
| **Syscall Filtering** |
| seccomp-bpf | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| Process exec blocking | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| Syscall allowlist | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| **Resource Limits** |
| CPU limit | ✅ | ❌ | ❌ | ✅ | ✅ Job | ✅ |
| Memory limit | ✅ | ❌ | ❌ | ✅ | ✅ Job | ✅ |
| Disk I/O limit | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| Network BW limit | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| Process count | ✅ | ❌ | ❌ | ✅ | ✅ Job | ✅ |
| **Platform-Specific** |
| Registry monitoring | N/A | N/A | N/A | N/A | ✅ | N/A |
| Registry blocking | N/A | N/A | N/A | N/A | ⚠️ Driver | N/A |
| Registry redirect | N/A | N/A | N/A | N/A | ⚠️ Driver | N/A |
| Kernel events | ✅ eBPF | ✅ ESF | ❌ | ✅ eBPF | ❌ | ✅ eBPF |
| **Requirements** |
| Special permissions | root | Apple entitlements | root + brew | Lima VM | Admin | WSL2 |
| Installation complexity | Low | High (Apple approval) | Low | Medium | Medium | Low |

### 17.2 Security Score Comparison

| Platform | Security Score | File Block | Net Block | Isolation | Syscall Filter | Resources |
|----------|:-------------:|:----------:|:---------:|:---------:|:--------------:|:---------:|
| **Linux Native** | 100% | ✅ | ✅ | ✅ Full | ✅ | ✅ Full |
| **Windows WSL2** | 100% | ✅ | ✅ | ✅ Full | ✅ | ✅ Full |
| **macOS ESF+NE** | 90% | ✅ | ✅ | ❌ None | ⚠️ Exec only | ❌ None |
| **macOS + Lima** | 85% | ✅ | ✅ | ✅ Full | ✅ | ✅ Full |
| **macOS FUSE-T** | 70% | ✅ | ✅ | ❌ None | ❌ | ❌ None |
| **Windows Native** | 55% | ✅ | ✅ | ⚠️ Partial | ❌ | ⚠️ Partial |

### 17.3 Detailed Security Breakdown

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     Security Feature Coverage by Platform                     │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│ Platform               File    Network  Isolation  Syscall  Resources  Score │
│ ──────────────────────────────────────────────────────────────────────────── │
│                                                                               │
│ Linux Native          ████████████████████████████████████████████████  100% │
│                       File✓   Net✓    Iso✓      Sys✓     Res✓               │
│                                                                               │
│ Windows WSL2          ████████████████████████████████████████████████  100% │
│                       File✓   Net✓    Iso✓      Sys✓     Res✓               │
│                                                                               │
│ macOS ESF+NE          ████████████████████████████████████████░░░░░░░░   90% │
│                       File✓   Net✓    Iso✗      Sys⚠     Res✗               │
│                       (Apple entitlements required)                          │
│                                                                               │
│ macOS + Lima          ██████████████████████████████████████░░░░░░░░░░   85% │
│                       File✓   Net✓    Iso✓      Sys✓     Res✓               │
│                       (VM overhead, file I/O slightly slower)                │
│                                                                               │
│ macOS FUSE-T + pf     ██████████████████████████████░░░░░░░░░░░░░░░░░░   70% │
│                       File✓   Net✓    Iso✗      Sys✗     Res✗               │
│                       (No isolation, no syscall filter, no resource limits)  │
│                                                                               │
│ Windows Native        ████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░   55% │
│                       File✓   Net✓    Iso⚠      Sys✗     Res⚠               │
│                       (AppContainer partial, Job Objects partial)            │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘

Legend: ✓ = Full support  ⚠ = Partial support  ✗ = Not supported
        ████ = Capability coverage
```

### 17.4 Performance Impact Analysis

Understanding the performance overhead of each interception mechanism is critical for production deployments.

#### 18.4.1 File Operations Performance

| Mechanism | Overhead | Latency Added | Throughput Impact | Notes |
|-----------|:--------:|:-------------:|:-----------------:|-------|
| **FUSE3 (Linux)** | Low | 5-20µs | 3-8% | Kernel-userspace context switch |
| **FUSE-T (macOS)** | Medium | 50-200µs | 10-25% | NFS protocol overhead |
| **ESF (macOS)** | Very Low | 1-5µs | <2% | In-kernel, no context switch for observe |
| **WinFsp (Windows)** | Low | 10-30µs | 5-10% | Similar to FUSE3 |
| **Lima VM** | Medium | 20-100µs | 15-30% | VM boundary + 9p/virtiofs |

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 File I/O Overhead Comparison (relative to native)           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Sequential Read (large files):                                              │
│  Native          ████████████████████████████████████████  100% baseline    │
│  FUSE3           ████████████████████████████████████░░░░   92%             │
│  ESF             ████████████████████████████████████████   98%             │
│  FUSE-T          ████████████████████████████████░░░░░░░░   80%             │
│  WinFsp          ████████████████████████████████████░░░░   90%             │
│  Lima/virtiofs   ████████████████████████████░░░░░░░░░░░░   70%             │
│                                                                              │
│  Random I/O (many small files):                                              │
│  Native          ████████████████████████████████████████  100% baseline    │
│  FUSE3           ████████████████████████████████░░░░░░░░   85%             │
│  ESF             ████████████████████████████████████████   99%             │
│  FUSE-T          ████████████████████████████░░░░░░░░░░░░   75%             │
│  WinFsp          ████████████████████████████████░░░░░░░░   82%             │
│  Lima/virtiofs   ██████████████████████████░░░░░░░░░░░░░░   65%             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Findings:**
- ESF has minimal overhead because it's observation-only in AUTH mode for most events
- FUSE-T's NFS protocol adds measurable latency, especially for metadata operations
- Lima's virtiofs is fast for sequential I/O but suffers on random small file access
- For build/compile workloads (many small file reads), FUSE3/WinFsp perform best

#### 18.4.2 Network Operations Performance

| Mechanism | Overhead | Latency Added | Connection Overhead | Notes |
|-----------|:--------:|:-------------:|:-------------------:|-------|
| **iptables + proxy** | Low | 0.1-1ms | Per-connection | Single hop through localhost |
| **Network Extension** | Very Low | 0.05-0.2ms | Per-packet capable | In-kernel packet processing |
| **pf + proxy** | Low | 0.1-1ms | Per-connection | Similar to iptables |
| **WinDivert** | Low | 0.1-0.5ms | Per-packet | Kernel-mode redirection |

```
Network Latency Impact (HTTP request to localhost):

                    Without agentsh     With agentsh       Overhead
iptables proxy:          0.5ms              1.2ms           +0.7ms
Network Extension:       0.5ms              0.6ms           +0.1ms  
pf proxy:                0.5ms              1.3ms           +0.8ms
WinDivert:               0.5ms              0.9ms           +0.4ms
```

**TLS Inspection Impact:**
- Certificate verification: +2-5ms first connection (cached afterward)
- TLS decrypt/re-encrypt: +0.5-2ms per request depending on cipher
- Total TLS inspection overhead: 5-15% throughput reduction

#### 18.4.3 Environment Variable Operations Performance

| Mechanism | Overhead | Latency Added | Notes |
|-----------|:--------:|:-------------:|-------|
| **Spawn-time filtering** | None at runtime | 1-5ms at spawn | One-time cost per process |
| **LD_PRELOAD sync** | Medium | 50-500µs | IPC to daemon per getenv() |
| **LD_PRELOAD cached** | Very Low | 1-5µs | Policy cached in shim |
| **Detours (Windows)** | Low | 10-50µs | In-process hook |

**Recommendation:** Use spawn-time filtering by default. Enable runtime interception only when you need to intercept getenv() calls made after process start or need env_read events.

#### 18.4.4 Registry Operations Performance (Windows)

| Mechanism | Overhead | Latency Added | Notes |
|-----------|:--------:|:-------------:|-------|
| **Observation only** | Very Low | <10µs | ETW-based, async |
| **Minifilter blocking** | Medium | 100-500µs | Kernel-user IPC |
| **Minifilter + approval** | High | 100ms-5min | Depends on approval time |

#### 18.4.5 Synchronous Hold Impact

When operations are held for policy decisions or manual approval:

| Hold Type | Typical Latency | Impact |
|-----------|:---------------:|--------|
| **Policy lookup (cached)** | 1-10µs | Negligible |
| **Policy lookup (IPC)** | 50-200µs | Low, acceptable |
| **Redirect (file)** | Same as normal I/O | None beyond redirect target |
| **Redirect (network)** | +0.1-1ms | Connection setup to new target |
| **Manual approval** | 1s - 5min | **Process blocked** - use timeouts |

**Best Practices for Approval Workflows:**
1. Set reasonable timeouts (30s-5min)
2. Use async notification (Slack/webhook) not polling
3. Default-deny on timeout for destructive operations
4. Cache approval decisions for similar operations

#### 18.4.6 Performance Recommendations by Workload

| Workload | Recommended Config | Expected Overhead |
|----------|-------------------|:-----------------:|
| **CI/CD builds** | FUSE3 + iptables, no TLS inspection | 5-10% |
| **Development** | FUSE-T + pf (macOS) or FUSE3 | 10-15% |
| **AI agent tasks** | Full interception, TLS inspection | 15-25% |
| **Data processing** | Lima with virtiofs batch mode | 15-30% |
| **Security-critical** | ESF + NE (macOS) or full Linux | 2-10% |

#### 18.4.7 Optimization Strategies

```yaml
# agentsh.yaml - Performance-optimized configuration

performance:
  # Cache policy decisions
  policy_cache:
    enabled: true
    ttl_seconds: 300
    max_entries: 10000
    
  # Batch event emission
  event_batching:
    enabled: true
    batch_size: 100
    flush_interval_ms: 100
    
  # Async logging (don't block operations)
  async_logging:
    enabled: true
    buffer_size: 10000
    
  # Skip interception for known-safe paths
  bypass_paths:
    - "/usr/lib/*"
    - "/lib/*"
    - "*.so"
    - "*.pyc"
    
  # Skip interception for known-safe hosts
  bypass_hosts:
    - "127.0.0.1"
    - "localhost"
    - "*.internal.company.com"
    
  # Reduce syscall overhead
  fuse:
    # Enable kernel caching
    kernel_cache: true
    # Batch attribute lookups
    batch_forget: true
    # Increase read-ahead
    max_readahead_kb: 1024
```

### 17.5 Platform Selection Guide

```
                    ┌─────────────────────────────┐
                    │  What's your primary OS?    │
                    └──────────────┬──────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
         ▼                         ▼                         ▼
   ┌───────────┐             ┌───────────┐             ┌───────────┐
   │   Linux   │             │   macOS   │             │  Windows  │
   └─────┬─────┘             └─────┬─────┘             └─────┬─────┘
         │                         │                         │
         ▼                         ▼                         ▼
┌─────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  Linux Native   │    │ Need full isolation │    │  Need registry      │
│                 │    │ & resource limits?  │    │  monitoring?        │
│  ✅ 100%        │    └──────────┬──────────┘    └──────────┬──────────┘
│  Best choice    │          Yes  │  No                 Yes  │  No
└─────────────────┘               │                          │
                                  ▼                          ▼
                    ┌─────────────────────┐    ┌─────────────────────┐
                    │    macOS + Lima     │    │   Windows Native    │
                    │                     │    │                     │
                    │    ✅ 85%           │    │   ✅ 55% + Registry │
                    │    Full isolation   │    │   monitoring        │
                    └─────────────────────┘    └─────────────────────┘
                                  │
                                  │ If Lima not acceptable
                                  ▼
                    ┌─────────────────────┐    ┌─────────────────────┐
                    │ Have Apple          │    │   Windows WSL2      │
                    │ entitlements?       │    │                     │
                    └──────────┬──────────┘    │   ✅ 100%           │
                          Yes  │  No           │   Full Linux        │
                               │               └─────────────────────┘
              ┌────────────────┴────────────────┐
              ▼                                 ▼
┌─────────────────────┐           ┌─────────────────────┐
│   macOS ESF+NE      │           │   macOS FUSE-T      │
│                     │           │                     │
│   ✅ 90%            │           │   ✅ 70%            │
│   Best native macOS │           │   Easy setup        │
│   (requires Apple   │           │   brew install      │
│    approval)        │           │   fuse-t            │
└─────────────────────┘           └─────────────────────┘
```

### 17.6 Recommended Configuration by Use Case

| Use Case | Recommended Platform | Security | Notes |
|----------|---------------------|:--------:|-------|
| **Production - Maximum Security** | Linux Native | 100% | Full isolation, all features |
| **Production - Windows Server** | Windows WSL2 | 100% | Full Linux security in VM |
| **Production - macOS** | macOS + Lima | 85% | Full isolation via VM |
| **Enterprise Security Product** | macOS ESF+NE | 90% | Requires Apple approval |
| **Development - macOS** | macOS FUSE-T | 70% | Easy setup, good monitoring |
| **Development - Windows** | Windows Native | 55% | Registry monitoring included |
| **CI/CD Pipeline** | Linux Native | 100% | Containers supported |
| **Air-gapped/Offline** | Linux Native | 100% | No external dependencies |

### 17.7 Windows-Specific Features

| Feature | Native | WSL2 | Notes |
|---------|:------:|:----:|-------|
| **Registry Monitoring** |
| Read monitoring | ✅ | N/A | Via RegNotifyChangeKeyValue |
| Write monitoring | ✅ | N/A | Via RegNotifyChangeKeyValue |
| Create key monitoring | ✅ | N/A | Via RegNotifyChangeKeyValue |
| Delete key monitoring | ✅ | N/A | Via RegNotifyChangeKeyValue |
| Registry blocking | ⚠️ | N/A | Requires signed kernel driver |
| **High-Risk Path Alerts** |
| Run keys (persistence) | ✅ | N/A | HKLM/HKCU Run, RunOnce |
| Services | ✅ | N/A | HKLM\SYSTEM\Services |
| Winlogon | ✅ | N/A | Shell, Userinit hijacking |
| Image File Exec Options | ✅ | N/A | Debugger hijacking |
| COM objects | ✅ | N/A | CLSID hijacking |
| Windows Defender | ✅ | N/A | Policy modifications |
| LSA settings | ✅ | N/A | Credential access |

### 17.8 macOS Configuration Options

| Configuration | File Interception | Network | Isolation | Ease of Setup | Security |
|---------------|:-----------------:|:-------:|:---------:|:-------------:|:--------:|
| **ESF + NE** | Endpoint Security | Network Extension | ❌ | Hard (Apple approval) | 90% |
| **FUSE-T + pf** | FUSE-T (NFS) | pf packet filter | ❌ | Easy (`brew install`) | 70% |
| **Lima VM** | FUSE3 in VM | iptables in VM | ✅ Full | Medium | 85% |
| **Degraded** | FSEvents (observe) | pcap (observe) | ❌ | None required | 25% |

**When to use each:**
- **ESF + NE**: Building a commercial security product, have Apple Developer relationship
- **FUSE-T + pf**: Development, testing, personal use - best balance of features/simplicity
- **Lima VM**: Need full isolation and resource limits on macOS
- **Degraded**: Quick testing, observation-only use cases

### 17.9 Known Limitations by Platform

#### Linux Native
- No significant limitations
- Requires root or CAP_SYS_ADMIN for namespaces
- eBPF requires kernel 5.x+ for full features

#### macOS ESF+NE
- **Requires Apple approval** - must apply for entitlements with business justification
- **No process isolation** - macOS has no namespace equivalent
- **No resource limits** - no cgroups equivalent
- **No syscall filtering** - except exec blocking via ESF
- Best option for commercial security products

#### macOS FUSE-T + pf
- **No process isolation** - agents can see all processes
- **No resource limits** - cannot enforce CPU/memory limits
- **No syscall filtering** - cannot block dangerous syscalls
- **Requires root for pf** - network interception needs sudo
- Best option for development and personal use

#### macOS + Lima
- Adds VM overhead (~200-500MB RAM)
- File access through virtiofs slightly slower
- Some edge cases with file permissions
- Requires maintaining Lima VM
- Best option for production on macOS

#### Windows Native
- **Partial isolation** - AppContainer provides file/registry isolation but not full namespace isolation
- **No syscall filtering** - no seccomp equivalent
- **No disk I/O limits** - Job Objects don't support this
- **No network bandwidth limits** - Job Objects don't support this
- **WinDivert requires admin** - Administrator privileges needed
- **Registry blocking requires driver** - Monitoring works without driver, blocking needs signed kernel driver

#### Windows WSL2
- Slight overhead from VM layer
- Network goes through Windows NAT
- File I/O to Windows drives slower than native
- Some Windows integration edge cases
- **No registry monitoring** - WSL2 runs Linux, Windows registry not accessible

### 17.10 Installation Quick Reference

| Platform | Command | Requirements |
|----------|---------|--------------|
| **Linux** | `curl -fsSL https://get.agentsh.dev \| bash` | root for full features |
| **macOS FUSE-T** | `brew install fuse-t && brew install agentsh` | root for pf network |
| **macOS Lima** | `brew install lima && limactl start agentsh` | Lima VM |
| **Windows Native** | `winget install agentsh` | Admin, WinFsp, WinDivert |
| **Windows WSL2** | `wsl --install -d Ubuntu && ...` | WSL2 enabled |

---

## 19. Session Management & Agent Lifecycle

### 19.1 Session Model

Each agent execution runs within a **session** that tracks all state and provides isolation.

```go
// pkg/session/session.go

package session

type Session struct {
    ID              string            `json:"id"`
    AgentID         string            `json:"agent_id"`         // Identity of the agent
    ParentSessionID string            `json:"parent_session,omitempty"` // For nested agents
    
    // Lifecycle
    State           SessionState      `json:"state"`
    CreatedAt       time.Time         `json:"created_at"`
    StartedAt       *time.Time        `json:"started_at,omitempty"`
    EndedAt         *time.Time        `json:"ended_at,omitempty"`
    ExitCode        *int              `json:"exit_code,omitempty"`
    
    // Configuration
    PolicySet       string            `json:"policy_set"`       // Which policies apply
    WorkspaceRoot   string            `json:"workspace_root"`
    ResourceLimits  ResourceLimits    `json:"resource_limits"`
    Timeout         time.Duration     `json:"timeout"`
    
    // Runtime state
    ProcessID       int               `json:"pid,omitempty"`
    Checkpoints     []Checkpoint      `json:"checkpoints,omitempty"`
    
    // Metrics
    Stats           SessionStats      `json:"stats"`
}

type SessionState string

const (
    SessionPending    SessionState = "pending"     // Created, not started
    SessionStarting   SessionState = "starting"    // Initializing sandbox
    SessionRunning    SessionState = "running"     // Agent is executing
    SessionPaused     SessionState = "paused"      // Awaiting approval
    SessionTerminating SessionState = "terminating" // Graceful shutdown
    SessionCompleted  SessionState = "completed"   // Normal exit
    SessionFailed     SessionState = "failed"      // Error/crash
    SessionTimedOut   SessionState = "timed_out"   // Exceeded timeout
    SessionKilled     SessionState = "killed"      // Force terminated
)

type SessionStats struct {
    FileReads       int64         `json:"file_reads"`
    FileWrites      int64         `json:"file_writes"`
    BytesRead       int64         `json:"bytes_read"`
    BytesWritten    int64         `json:"bytes_written"`
    NetworkConns    int64         `json:"network_conns"`
    NetworkBytesTx  int64         `json:"network_bytes_tx"`
    NetworkBytesRx  int64         `json:"network_bytes_rx"`
    DNSQueries      int64         `json:"dns_queries"`
    EnvReads        int64         `json:"env_reads"`
    BlockedOps      int64         `json:"blocked_ops"`
    ApprovalsPending int          `json:"approvals_pending"`
    ApprovalsGranted int          `json:"approvals_granted"`
    ApprovalsDenied  int          `json:"approvals_denied"`
    CPUTimeMs       int64         `json:"cpu_time_ms"`
    PeakMemoryMB    int64         `json:"peak_memory_mb"`
}
```

### 19.2 Lifecycle Hooks

```go
// pkg/session/hooks.go

type LifecycleHooks struct {
    // Called before session starts
    OnBeforeStart  func(session *Session) error
    
    // Called when session enters running state
    OnStart        func(session *Session)
    
    // Called on every intercepted operation (high frequency)
    OnOperation    func(session *Session, event *IOEvent)
    
    // Called when operation is blocked
    OnBlocked      func(session *Session, event *IOEvent)
    
    // Called when approval is needed
    OnApprovalNeeded func(session *Session, op *InterceptedOperation)
    
    // Called periodically for stats collection
    OnHeartbeat    func(session *Session)
    
    // Called when session is pausing
    OnPause        func(session *Session)
    
    // Called when session is resuming
    OnResume       func(session *Session)
    
    // Called before session terminates
    OnBeforeEnd    func(session *Session)
    
    // Called after session ends
    OnEnd          func(session *Session, result SessionResult)
    
    // Called on crash/error
    OnError        func(session *Session, err error)
}

// Integration example: send to SIEM
func NewSIEMHooks(siemClient *SIEMClient) LifecycleHooks {
    return LifecycleHooks{
        OnBlocked: func(s *Session, e *IOEvent) {
            siemClient.SendAlert(Alert{
                Severity: "medium",
                Type:     "agent_blocked_operation",
                Session:  s.ID,
                Event:    e,
            })
        },
        OnEnd: func(s *Session, r SessionResult) {
            siemClient.SendSessionSummary(s, r)
        },
    }
}
```

### 19.3 Graceful Shutdown

```go
// Graceful shutdown sequence
func (s *Session) Shutdown(ctx context.Context, reason string) error {
    s.State = SessionTerminating
    
    // 1. Stop accepting new operations (drain mode)
    s.interceptor.SetDrainMode(true)
    
    // 2. Wait for pending approvals (with timeout)
    approvalCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()
    s.waitPendingApprovals(approvalCtx)
    
    // 3. Flush event buffer
    s.eventBuffer.Flush()
    
    // 4. Send SIGTERM to agent process
    s.process.Signal(syscall.SIGTERM)
    
    // 5. Wait for graceful exit (with timeout)
    exitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    
    select {
    case <-s.process.Done():
        s.State = SessionCompleted
    case <-exitCtx.Done():
        // Force kill
        s.process.Signal(syscall.SIGKILL)
        s.State = SessionKilled
    }
    
    // 6. Cleanup resources
    s.cleanup()
    
    // 7. Final audit log
    s.auditLog.SessionEnd(s, reason)
    
    return nil
}
```

### 19.4 Checkpoint & Recovery

```go
// pkg/session/checkpoint.go

type Checkpoint struct {
    ID          string    `json:"id"`
    SessionID   string    `json:"session_id"`
    CreatedAt   time.Time `json:"created_at"`
    
    // Snapshot of session state
    Stats       SessionStats `json:"stats"`
    
    // File system state (for recovery)
    WorkspaceHash string    `json:"workspace_hash"`
    ModifiedFiles []string  `json:"modified_files"`
    
    // Can be used for rollback
    CanRollback   bool      `json:"can_rollback"`
}

// Create checkpoint before risky operation
func (s *Session) CreateCheckpoint(reason string) (*Checkpoint, error) {
    cp := &Checkpoint{
        ID:        uuid.New().String(),
        SessionID: s.ID,
        CreatedAt: time.Now(),
        Stats:     s.Stats,
    }
    
    // Hash current workspace state
    cp.WorkspaceHash = s.hashWorkspace()
    cp.ModifiedFiles = s.getModifiedFiles()
    
    // Store checkpoint
    s.checkpoints = append(s.checkpoints, *cp)
    s.storage.SaveCheckpoint(cp)
    
    return cp, nil
}

// Rollback to checkpoint (if supported)
func (s *Session) Rollback(checkpointID string) error {
    // Find checkpoint
    cp := s.findCheckpoint(checkpointID)
    if cp == nil {
        return ErrCheckpointNotFound
    }
    if !cp.CanRollback {
        return ErrRollbackNotSupported
    }
    
    // Pause session
    s.State = SessionPaused
    
    // Restore workspace
    if err := s.restoreWorkspace(cp); err != nil {
        return err
    }
    
    // Resume
    s.State = SessionRunning
    return nil
}
```

---

## 20. Multi-Agent & Multi-Tenant Support

### 20.1 Agent Identity

```go
// pkg/identity/agent.go

type AgentIdentity struct {
    // Unique identifier
    AgentID     string `json:"agent_id"`
    
    // Human-readable name
    Name        string `json:"name"`
    
    // Tenant/organization
    TenantID    string `json:"tenant_id"`
    
    // Authentication
    AuthMethod  AuthMethod `json:"auth_method"`
    APIKey      string     `json:"-"` // Never serialized
    JWTSubject  string     `json:"jwt_subject,omitempty"`
    
    // Capabilities/roles
    Roles       []string   `json:"roles"`
    
    // Trust level affects default policies
    TrustLevel  TrustLevel `json:"trust_level"`
}

type AuthMethod string

const (
    AuthAPIKey  AuthMethod = "api_key"
    AuthJWT     AuthMethod = "jwt"
    AuthMTLS    AuthMethod = "mtls"
    AuthOIDC    AuthMethod = "oidc"
)

type TrustLevel string

const (
    TrustUntrusted TrustLevel = "untrusted"  // Strictest policies
    TrustLimited   TrustLevel = "limited"    // Standard policies
    TrustTrusted   TrustLevel = "trusted"    // Relaxed policies
    TrustInternal  TrustLevel = "internal"   // Minimal restrictions
)
```

### 20.2 Multi-Tenant Isolation

```go
// pkg/tenant/isolation.go

type TenantConfig struct {
    TenantID        string `yaml:"tenant_id"`
    
    // Isolation settings
    Isolation       IsolationConfig `yaml:"isolation"`
    
    // Resource quotas (per tenant)
    Quotas          TenantQuotas    `yaml:"quotas"`
    
    // Policy overrides
    PolicyOverrides map[string]any  `yaml:"policy_overrides"`
}

type IsolationConfig struct {
    // Filesystem isolation
    WorkspaceRoot   string `yaml:"workspace_root"`   // e.g., /var/agentsh/tenants/{tenant_id}
    SharedReadOnly  []string `yaml:"shared_readonly"` // Paths readable by all tenants
    
    // Network isolation
    NetworkNamespace bool   `yaml:"network_namespace"` // Separate network namespace per tenant
    AllowedEgress   []string `yaml:"allowed_egress"`   // Tenant-specific allowed hosts
    
    // Process isolation
    UIDRange        [2]int `yaml:"uid_range"`  // e.g., [100000, 100999]
    MaxProcesses    int    `yaml:"max_processes"`
}

type TenantQuotas struct {
    MaxConcurrentSessions int           `yaml:"max_concurrent_sessions"`
    MaxSessionDuration    time.Duration `yaml:"max_session_duration"`
    MaxStorageBytes       int64         `yaml:"max_storage_bytes"`
    MaxNetworkBytesPerDay int64         `yaml:"max_network_bytes_per_day"`
    MaxAPICallsPerHour    int           `yaml:"max_api_calls_per_hour"`
}
```

### 20.3 Concurrent Agent Management

```go
// pkg/session/manager.go

type SessionManager struct {
    sessions     map[string]*Session
    byAgent      map[string][]*Session  // AgentID -> Sessions
    byTenant     map[string][]*Session  // TenantID -> Sessions
    
    maxConcurrent int
    mu            sync.RWMutex
    
    // Scheduling
    queue        *PriorityQueue
    scheduler    Scheduler
}

// Start a new session with resource checks
func (m *SessionManager) StartSession(ctx context.Context, req StartSessionRequest) (*Session, error) {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // Check tenant quotas
    tenantSessions := m.byTenant[req.TenantID]
    if len(tenantSessions) >= m.getTenantLimit(req.TenantID) {
        return nil, ErrTenantQuotaExceeded
    }
    
    // Check global limit
    if len(m.sessions) >= m.maxConcurrent {
        // Queue the request
        return m.queueSession(req)
    }
    
    // Create and start session
    session := m.createSession(req)
    if err := session.Start(ctx); err != nil {
        return nil, err
    }
    
    m.sessions[session.ID] = session
    m.byAgent[req.AgentID] = append(m.byAgent[req.AgentID], session)
    m.byTenant[req.TenantID] = append(m.byTenant[req.TenantID], session)
    
    return session, nil
}
```

---

## 21. Control API

### 21.1 HTTP/gRPC API

```protobuf
// api/agentsh.proto

syntax = "proto3";
package agentsh.v1;

service AgentshService {
    // Session management
    rpc CreateSession(CreateSessionRequest) returns (Session);
    rpc GetSession(GetSessionRequest) returns (Session);
    rpc ListSessions(ListSessionsRequest) returns (ListSessionsResponse);
    rpc TerminateSession(TerminateSessionRequest) returns (Empty);
    
    // Real-time streaming
    rpc StreamEvents(StreamEventsRequest) returns (stream IOEvent);
    rpc StreamLogs(StreamLogsRequest) returns (stream LogEntry);
    
    // Approvals
    rpc ListPendingApprovals(ListApprovalsRequest) returns (ListApprovalsResponse);
    rpc Approve(ApproveRequest) returns (ApproveResponse);
    rpc Deny(DenyRequest) returns (DenyResponse);
    
    // Policy management
    rpc GetPolicy(GetPolicyRequest) returns (Policy);
    rpc UpdatePolicy(UpdatePolicyRequest) returns (Policy);
    rpc ValidatePolicy(ValidatePolicyRequest) returns (ValidationResult);
    
    // Metrics
    rpc GetMetrics(GetMetricsRequest) returns (Metrics);
    rpc GetSessionStats(GetSessionStatsRequest) returns (SessionStats);
}
```

### 21.2 REST API Endpoints

```yaml
# OpenAPI spec summary

paths:
  # Sessions
  /api/v1/sessions:
    post:
      summary: Create new session
    get:
      summary: List sessions
      
  /api/v1/sessions/{session_id}:
    get:
      summary: Get session details
    delete:
      summary: Terminate session
      
  /api/v1/sessions/{session_id}/events:
    get:
      summary: Get session events (with pagination)
      
  /api/v1/sessions/{session_id}/events/stream:
    get:
      summary: Stream events (SSE/WebSocket)
      
  # Approvals
  /api/v1/approvals:
    get:
      summary: List pending approvals
      
  /api/v1/approvals/{approval_id}:
    post:
      summary: Submit approval decision
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                decision: { enum: [approve, deny] }
                reason: { type: string }
                redirect: { $ref: '#/components/schemas/RedirectTarget' }
                
  # Policies
  /api/v1/policies:
    get:
      summary: List policies
    post:
      summary: Create policy
      
  /api/v1/policies/{policy_id}:
    put:
      summary: Update policy
    delete:
      summary: Delete policy
      
  /api/v1/policies/validate:
    post:
      summary: Validate policy without applying
      
  # Metrics
  /api/v1/metrics:
    get:
      summary: Prometheus-format metrics
      
  /api/v1/health:
    get:
      summary: Health check
```

### 21.3 Webhook Integration

```yaml
# agentsh.yaml

webhooks:
  # Approval notifications
  approval_required:
    url: "https://hooks.slack.com/services/XXX"
    method: POST
    headers:
      Content-Type: application/json
    template: |
      {
        "text": "🔔 Approval required for {{.Session.AgentID}}",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*{{.Operation.Type}}*: `{{.Operation.Path}}`\n*Agent*: {{.Session.AgentID}}"
            }
          },
          {
            "type": "actions",
            "elements": [
              {"type": "button", "text": {"type": "plain_text", "text": "Approve"}, "url": "{{.ApprovalURL}}&action=approve"},
              {"type": "button", "text": {"type": "plain_text", "text": "Deny"}, "url": "{{.ApprovalURL}}&action=deny"}
            ]
          }
        ]
      }
    
  # Security alerts
  security_alert:
    url: "https://api.pagerduty.com/incidents"
    method: POST
    headers:
      Authorization: "Token token={{.Env.PAGERDUTY_TOKEN}}"
    events:
      - blocked_sensitive_file
      - blocked_network_internal
      - approval_timeout
      - session_killed
      
  # Audit log shipping
  audit_events:
    url: "https://logs.example.com/ingest"
    method: POST
    batch_size: 100
    flush_interval: 5s
    events:
      - "*"  # All events
```

---

## 22. Observability

### 22.1 Prometheus Metrics

```go
// pkg/metrics/prometheus.go

var (
    // Session metrics
    sessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "agentsh_sessions_active",
        Help: "Number of currently active sessions",
    })
    
    sessionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "agentsh_sessions_total",
        Help: "Total sessions by state",
    }, []string{"state", "tenant_id"})
    
    sessionDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
        Name:    "agentsh_session_duration_seconds",
        Help:    "Session duration in seconds",
        Buckets: []float64{1, 10, 60, 300, 900, 3600},
    }, []string{"tenant_id", "exit_state"})
    
    // Operation metrics
    operationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "agentsh_operations_total",
        Help: "Total operations by type and decision",
    }, []string{"type", "decision"})
    
    operationLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
        Name:    "agentsh_operation_latency_seconds",
        Help:    "Operation interception latency",
        Buckets: []float64{0.0001, 0.001, 0.01, 0.1, 1, 10},
    }, []string{"type"})
    
    // Approval metrics
    approvalsPending = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "agentsh_approvals_pending",
        Help: "Number of pending approvals",
    })
    
    approvalLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "agentsh_approval_latency_seconds",
        Help:    "Time to receive approval decision",
        Buckets: []float64{1, 5, 10, 30, 60, 300},
    })
    
    // Resource metrics
    policyEvalLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "agentsh_policy_eval_latency_seconds",
        Help:    "Policy evaluation latency",
        Buckets: []float64{0.00001, 0.0001, 0.001, 0.01},
    })
)
```

### 22.2 OpenTelemetry Tracing

```go
// pkg/tracing/otel.go

func TraceOperation(ctx context.Context, op *InterceptedOperation) (context.Context, trace.Span) {
    tracer := otel.Tracer("agentsh")
    
    ctx, span := tracer.Start(ctx, op.Type.String(),
        trace.WithAttributes(
            attribute.String("session.id", op.SessionID),
            attribute.String("agent.id", op.AgentID),
            attribute.String("operation.path", op.Request.Path),
            attribute.String("operation.type", string(op.Type)),
        ),
    )
    
    return ctx, span
}

// Usage in interceptor
func (m *InterceptionManager) Intercept(ctx context.Context, op *InterceptedOperation) DecisionResponse {
    ctx, span := TraceOperation(ctx, op)
    defer span.End()
    
    // Policy evaluation
    policySpan := trace.SpanFromContext(ctx)
    policySpan.AddEvent("policy_eval_start")
    decision := m.policyEngine.Evaluate(op.Request)
    policySpan.AddEvent("policy_eval_end", trace.WithAttributes(
        attribute.String("decision", string(decision.Action)),
    ))
    
    // Record decision
    span.SetAttributes(attribute.String("decision", string(decision.Action)))
    
    if decision.Action == DecisionPending {
        span.AddEvent("awaiting_approval")
        // ... approval flow with child spans
    }
    
    return decision
}
```

### 22.3 Structured Logging

```go
// pkg/logging/structured.go

type AuditLogger struct {
    logger    *zap.Logger
    sessionID string
    agentID   string
}

func (l *AuditLogger) LogOperation(event *IOEvent, decision Decision) {
    l.logger.Info("operation",
        zap.String("session_id", l.sessionID),
        zap.String("agent_id", l.agentID),
        zap.String("type", string(event.Type)),
        zap.String("path", event.Path),
        zap.String("decision", string(decision)),
        zap.Int64("latency_us", event.Latency.Microseconds()),
        zap.Time("timestamp", event.Timestamp),
        // Correlation
        zap.String("trace_id", trace.SpanFromContext(ctx).SpanContext().TraceID().String()),
    )
}

// Log format for SIEM ingestion
// {"level":"info","ts":"2025-01-15T14:30:00Z","msg":"operation",
//  "session_id":"sess_123","agent_id":"agent_456","type":"file_read",
//  "path":"/etc/passwd","decision":"deny","latency_us":150,"trace_id":"abc123"}
```

---

## 23. Rate Limiting & Quotas

### 23.1 Rate Limit Configuration

```yaml
# agentsh.yaml

rate_limits:
  # Per-session limits
  session:
    # Operations per second
    file_ops_per_second: 1000
    network_conns_per_second: 100
    dns_queries_per_second: 50
    
    # Burst allowance
    burst_multiplier: 5
    
  # Per-agent limits (across all sessions)
  agent:
    max_concurrent_sessions: 10
    max_total_operations_per_hour: 1000000
    
  # Per-tenant limits
  tenant:
    max_concurrent_sessions: 100
    max_storage_bytes: 10737418240  # 10GB
    max_network_bytes_per_day: 107374182400  # 100GB
    
  # Global limits
  global:
    max_concurrent_sessions: 1000
    max_pending_approvals: 100

# Actions when limit exceeded
rate_limit_actions:
  file_ops:
    action: throttle  # throttle, block, or alert
    delay_ms: 100
  network_conns:
    action: block
    message: "Connection rate limit exceeded"
  dns_queries:
    action: throttle
    delay_ms: 50
```

### 23.2 Quota Enforcement

```go
// pkg/quota/manager.go

type QuotaManager struct {
    storage   QuotaStorage
    limiters  map[string]*rate.Limiter
}

type ResourceQuota struct {
    Resource    string    `json:"resource"`
    Limit       int64     `json:"limit"`
    Used        int64     `json:"used"`
    ResetAt     time.Time `json:"reset_at"`
    Percentage  float64   `json:"percentage"`
}

func (q *QuotaManager) CheckAndConsume(ctx context.Context, sessionID string, resource string, amount int64) error {
    quota := q.getQuota(sessionID, resource)
    
    if quota.Used + amount > quota.Limit {
        return &QuotaExceededError{
            Resource:  resource,
            Limit:     quota.Limit,
            Used:      quota.Used,
            Requested: amount,
        }
    }
    
    // Consume quota
    q.consume(sessionID, resource, amount)
    
    // Alert if approaching limit
    newPct := float64(quota.Used + amount) / float64(quota.Limit) * 100
    if newPct > 80 && quota.Percentage <= 80 {
        q.alertQuotaWarning(sessionID, resource, newPct)
    }
    
    return nil
}
```

---

## 24. Testing & Simulation Modes

### 24.1 Dry-Run Mode

```yaml
# agentsh.yaml

modes:
  # Dry-run: log what would happen without enforcing
  dry_run:
    enabled: false
    log_decisions: true
    
  # Simulation: run against recorded session
  simulation:
    enabled: false
    replay_file: ""
    
  # Permissive: allow all but log everything
  permissive:
    enabled: false
    
  # Strict: deny by default
  strict:
    enabled: true
```

### 24.2 Policy Testing

```go
// pkg/policy/testing.go

type PolicyTestCase struct {
    Name        string          `yaml:"name"`
    Description string          `yaml:"description"`
    
    // Input
    Operation   TestOperation   `yaml:"operation"`
    
    // Expected output
    Expected    ExpectedResult  `yaml:"expected"`
}

type TestOperation struct {
    Type        string            `yaml:"type"`
    Path        string            `yaml:"path,omitempty"`
    Domain      string            `yaml:"domain,omitempty"`
    Variable    string            `yaml:"variable,omitempty"`
    ProcessName string            `yaml:"process_name,omitempty"`
    Metadata    map[string]string `yaml:"metadata,omitempty"`
}

type ExpectedResult struct {
    Decision    string `yaml:"decision"`
    PolicyRule  string `yaml:"policy_rule,omitempty"`
    RedirectTo  string `yaml:"redirect_to,omitempty"`
}

// Example test file: policies/tests/file_policy_test.yaml
/*
tests:
  - name: allow_workspace_read
    operation:
      type: file_read
      path: /workspace/src/main.go
    expected:
      decision: allow
      policy_rule: workspace
      
  - name: block_ssh_key_read
    operation:
      type: file_read
      path: /home/user/.ssh/id_rsa
    expected:
      decision: deny
      policy_rule: sensitive-block
      
  - name: redirect_passwd
    operation:
      type: file_read
      path: /etc/passwd
    expected:
      decision: redirect
      redirect_to: /opt/agentsh/honeypot/fake-passwd
*/

// Run tests
func TestPolicies(policyDir string, testDir string) (*TestResults, error) {
    engine := policy.LoadFromDir(policyDir)
    tests := loadTests(testDir)
    
    results := &TestResults{}
    for _, test := range tests {
        result := engine.Evaluate(test.Operation.ToRequest())
        if result.Decision != test.Expected.Decision {
            results.Failed = append(results.Failed, TestFailure{
                Test:     test,
                Got:      result,
                Expected: test.Expected,
            })
        } else {
            results.Passed++
        }
    }
    return results, nil
}
```

### 24.3 Session Recording & Replay

```go
// pkg/recording/recorder.go

type SessionRecorder struct {
    sessionID   string
    outputFile  *os.File
    encoder     *json.Encoder
}

type RecordedEvent struct {
    Timestamp   time.Time       `json:"ts"`
    Type        string          `json:"type"`
    Request     json.RawMessage `json:"request"`
    Decision    string          `json:"decision"`
    Latency     time.Duration   `json:"latency"`
}

func (r *SessionRecorder) Record(event *IOEvent, decision Decision) {
    r.encoder.Encode(RecordedEvent{
        Timestamp: event.Timestamp,
        Type:      string(event.Type),
        Request:   marshalRequest(event),
        Decision:  string(decision),
        Latency:   event.Latency,
    })
}

// Replay for testing
type SessionReplayer struct {
    recording   string
    policyDir   string
}

func (r *SessionReplayer) Replay() (*ReplayResults, error) {
    engine := policy.LoadFromDir(r.policyDir)
    events := r.loadRecording()
    
    results := &ReplayResults{}
    for _, event := range events {
        newDecision := engine.Evaluate(event.Request)
        if string(newDecision) != event.Decision {
            results.Differences = append(results.Differences, Difference{
                Event:       event,
                OldDecision: event.Decision,
                NewDecision: string(newDecision),
            })
        }
    }
    return results, nil
}
```

---

## 25. Hot-Reload & Dynamic Configuration

### 25.1 Policy Hot-Reload

```go
// pkg/policy/watcher.go

type PolicyWatcher struct {
    policyDir   string
    engine      *PolicyEngine
    watcher     *fsnotify.Watcher
    reloadChan  chan struct{}
}

func (w *PolicyWatcher) Start(ctx context.Context) error {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return err
    }
    w.watcher = watcher
    
    // Watch policy directory
    watcher.Add(w.policyDir)
    
    go func() {
        for {
            select {
            case event := <-watcher.Events:
                if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
                    w.handleReload(event.Name)
                }
            case err := <-watcher.Errors:
                log.Error("watcher error", zap.Error(err))
            case <-ctx.Done():
                return
            }
        }
    }()
    
    return nil
}

func (w *PolicyWatcher) handleReload(filename string) {
    log.Info("Policy file changed, reloading", zap.String("file", filename))
    
    // Validate before applying
    newEngine, err := policy.LoadFromDir(w.policyDir)
    if err != nil {
        log.Error("Invalid policy, keeping current", zap.Error(err))
        metrics.PolicyReloadErrors.Inc()
        return
    }
    
    // Atomic swap
    w.engine.Swap(newEngine)
    metrics.PolicyReloads.Inc()
    log.Info("Policy reloaded successfully")
}
```

### 25.2 Runtime Configuration Updates

```go
// pkg/config/runtime.go

type RuntimeConfig struct {
    mu sync.RWMutex
    
    // Dynamically updatable
    LogLevel        string
    RateLimits      RateLimitConfig
    FeatureFlags    map[string]bool
    
    // Require restart
    readonly struct {
        Platform    string
        ListenAddr  string
    }
}

// API endpoint for runtime config
func (c *RuntimeConfig) UpdateHandler(w http.ResponseWriter, r *http.Request) {
    var update RuntimeConfigUpdate
    json.NewDecoder(r.Body).Decode(&update)
    
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if update.LogLevel != "" {
        c.LogLevel = update.LogLevel
        c.applyLogLevel()
    }
    
    if update.RateLimits != nil {
        c.RateLimits = *update.RateLimits
        c.applyRateLimits()
    }
    
    w.WriteHeader(http.StatusOK)
}
```

---

## 26. Break-Glass & Emergency Override

### 26.1 Emergency Access

```yaml
# agentsh.yaml

emergency:
  # Break-glass allows bypassing all policies temporarily
  break_glass:
    enabled: true
    
    # Who can activate
    authorized_users:
      - "admin@example.com"
      - "oncall@example.com"
      
    # Require MFA
    require_mfa: true
    
    # Maximum duration
    max_duration: 1h
    
    # Audit requirements
    require_reason: true
    notify_channels:
      - security@example.com
      - "#security-alerts"
      
  # Auto-disable after time
  auto_expire: true
  
  # What's allowed during break-glass
  permissions:
    allow_all_files: true
    allow_all_network: true
    allow_sensitive_env: false  # Still protect secrets
    log_everything: true
```

### 26.2 Emergency Commands

```bash
# Activate break-glass
$ agentsh emergency activate \
    --reason "Production incident INC-12345" \
    --duration 30m \
    --mfa-token 123456

⚠️  BREAK-GLASS ACTIVATED
Duration: 30 minutes
Reason: Production incident INC-12345
Activated by: admin@example.com
Audit ID: bg_20250115_143000_abc123

All policies suspended. All operations will be logged.
Security team has been notified.

# Check status
$ agentsh emergency status
Break-glass: ACTIVE
Remaining: 28m 15s
Activated by: admin@example.com
Operations since activation: 1,247

# Deactivate early
$ agentsh emergency deactivate
Break-glass deactivated. Normal policies restored.
```

### 26.3 Kill Switch

```go
// pkg/emergency/killswitch.go

type KillSwitch struct {
    activated   atomic.Bool
    sessionMgr  *SessionManager
}

// Immediately terminate all sessions
func (k *KillSwitch) Activate(reason string, actor string) error {
    if !k.activated.CompareAndSwap(false, true) {
        return ErrAlreadyActivated
    }
    
    log.Critical("KILL SWITCH ACTIVATED",
        zap.String("reason", reason),
        zap.String("actor", actor),
    )
    
    // Terminate all sessions immediately
    sessions := k.sessionMgr.ListAll()
    for _, session := range sessions {
        session.Kill("kill_switch: " + reason)
    }
    
    // Prevent new sessions
    k.sessionMgr.Disable()
    
    // Alert
    k.sendAlerts(reason, actor, len(sessions))
    
    return nil
}
```

---

## 27. Container & Kubernetes Integration

### 27.1 Container Sidecar Mode

```yaml
# Kubernetes deployment with agentsh sidecar

apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-agent
spec:
  template:
    spec:
      containers:
        # Main agent container
        - name: agent
          image: my-ai-agent:latest
          env:
            - name: AGENTSH_SOCKET
              value: /var/run/agentsh/agent.sock
          volumeMounts:
            - name: agentsh-socket
              mountPath: /var/run/agentsh
            - name: workspace
              mountPath: /workspace
              
        # agentsh sidecar
        - name: agentsh
          image: agentsh/agentsh:latest
          securityContext:
            privileged: true  # Required for FUSE
            capabilities:
              add: [SYS_ADMIN, NET_ADMIN]
          volumeMounts:
            - name: agentsh-socket
              mountPath: /var/run/agentsh
            - name: workspace
              mountPath: /workspace
            - name: policies
              mountPath: /etc/agentsh/policies
              readOnly: true
          ports:
            - containerPort: 9090
              name: api
            - containerPort: 9091
              name: metrics
              
      volumes:
        - name: agentsh-socket
          emptyDir: {}
        - name: workspace
          emptyDir: {}
        - name: policies
          configMap:
            name: agentsh-policies
```

### 27.2 Kubernetes Operator

```yaml
# Custom Resource Definition

apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: agentshsessions.agentsh.io
spec:
  group: agentsh.io
  names:
    kind: AgentshSession
    plural: agentshsessions
    singular: agentshsession
    shortNames: [as]
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                agentImage:
                  type: string
                policyRef:
                  type: string
                timeout:
                  type: string
                resources:
                  type: object
            status:
              type: object
              properties:
                state:
                  type: string
                startTime:
                  type: string
                stats:
                  type: object

---
# Example session

apiVersion: agentsh.io/v1
kind: AgentshSession
metadata:
  name: coding-task-123
spec:
  agentImage: my-coding-agent:v2
  policyRef: strict-coding-policy
  timeout: 1h
  resources:
    limits:
      cpu: "2"
      memory: 4Gi
    requests:
      cpu: "1"
      memory: 2Gi
```

### 27.3 Helm Chart Values

```yaml
# values.yaml

replicaCount: 3

image:
  repository: agentsh/agentsh
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  apiPort: 9090
  metricsPort: 9091

# Policy ConfigMap
policies:
  create: true
  files:
    env.yaml: |
      env_protection:
        enabled: true
        mode: allowlist
        allowlist: [PATH, HOME, USER, SHELL]
    files.yaml: |
      file_policy:
        default_action: deny

# Resource limits
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

# Prometheus ServiceMonitor
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 15s

# RBAC
rbac:
  create: true
  
# Pod Security
podSecurityContext:
  fsGroup: 1000
  
securityContext:
  capabilities:
    add: [SYS_ADMIN, NET_ADMIN]
  privileged: true
```

---

## 28. CLI Tools & Debugging

### 28.1 CLI Commands

```bash
# Session management
agentsh session list [--tenant TENANT] [--state STATE]
agentsh session get SESSION_ID
agentsh session logs SESSION_ID [--follow]
agentsh session events SESSION_ID [--type TYPE] [--since TIME]
agentsh session terminate SESSION_ID [--force] [--reason REASON]

# Policy management
agentsh policy validate POLICY_FILE
agentsh policy test POLICY_DIR --tests TEST_DIR
agentsh policy diff OLD_POLICY NEW_POLICY
agentsh policy lint POLICY_FILE

# Debugging
agentsh debug trace SESSION_ID [--duration 30s]
agentsh debug intercept --file /path/to/file --action log
agentsh debug simulate --recording RECORDING_FILE --policy POLICY_DIR

# Status
agentsh status
agentsh status --json
agentsh metrics

# Configuration
agentsh config validate
agentsh config show [--effective]
agentsh config set KEY VALUE

# Emergency
agentsh emergency status
agentsh emergency activate --reason REASON --duration DURATION
agentsh emergency deactivate
agentsh emergency kill-all --reason REASON
```

### 28.2 Interactive Debugger

```bash
$ agentsh debug attach SESSION_ID

agentsh debugger v1.0.0
Session: sess_abc123
Agent: my-coding-agent
State: running

Commands:
  events    - Show recent events
  pending   - Show pending approvals
  stats     - Show session statistics
  policy    - Test policy against operation
  pause     - Pause session
  resume    - Resume session
  trace     - Enable detailed tracing
  quit      - Detach from session

(agentsh) events --last 10
TYPE         PATH                      DECISION  LATENCY
file_read    /workspace/src/main.go    allow     0.2ms
file_write   /workspace/src/main.go    allow     0.5ms
net_connect  api.github.com:443        allow     1.2ms
file_read    /etc/passwd               deny      0.1ms

(agentsh) policy test
Operation type: file_read
Path: /home/user/.ssh/id_rsa

Result:
  Decision: deny
  Rule: sensitive-block
  Reason: Path matches "**/.ssh/**"

(agentsh) trace on
Tracing enabled. All operations will be logged in detail.
```

### 28.3 Diagnostic Report

```bash
$ agentsh diagnostic report --output report.tar.gz

Collecting diagnostic information...
  ✓ System information
  ✓ agentsh configuration (secrets redacted)
  ✓ Active policies
  ✓ Recent logs (last 1000 lines)
  ✓ Metrics snapshot
  ✓ Active sessions summary
  ✓ Pending approvals
  ✓ Resource usage
  
Report saved to: report.tar.gz
Size: 2.3 MB

WARNING: Review report before sharing. May contain sensitive paths.
```

---

## 29. Secret Manager Integration

### 29.1 Controlled Secret Access

```yaml
# agentsh.yaml

secret_managers:
  # HashiCorp Vault
  vault:
    enabled: true
    address: "https://vault.example.com"
    auth_method: kubernetes  # or token, approle, aws
    
    # Paths the agent can request
    allowed_paths:
      - "secret/data/agent/*"
      - "database/creds/readonly"
      
    # Automatic secret injection (agent never sees raw secret)
    inject:
      - vault_path: "secret/data/agent/openai"
        env_var: "OPENAI_API_KEY"
        
  # AWS Secrets Manager
  aws:
    enabled: true
    region: us-west-2
    allowed_secrets:
      - "agent/*"
      
  # Azure Key Vault
  azure:
    enabled: false
```

### 29.2 Just-In-Time Secret Access

```go
// pkg/secrets/jit.go

type JITSecretProvider struct {
    vault       *vault.Client
    approvals   *ApprovalService
    auditLog    *AuditLogger
}

// Agent requests a secret - requires approval
func (p *JITSecretProvider) RequestSecret(ctx context.Context, req SecretRequest) (*SecretResponse, error) {
    // Check if path is allowed
    if !p.isAllowedPath(req.Path) {
        return nil, ErrSecretPathNotAllowed
    }
    
    // Create approval request
    approval := &ApprovalRequest{
        Type:        "secret_access",
        Resource:    req.Path,
        Requester:   req.AgentID,
        Justification: req.Reason,
        TTL:         req.TTL,
    }
    
    // Wait for approval
    decision := p.approvals.Request(ctx, approval)
    if decision != Approved {
        return nil, ErrSecretAccessDenied
    }
    
    // Fetch from vault with short TTL
    secret, err := p.vault.Read(ctx, req.Path)
    if err != nil {
        return nil, err
    }
    
    // Wrap secret with automatic expiry
    wrapped := p.wrapSecret(secret, req.TTL)
    
    // Audit log
    p.auditLog.SecretAccessed(req, wrapped.ID)
    
    return wrapped, nil
}
```

---

## 30. Upgrade & Migration

### 30.1 Version Compatibility

```yaml
# agentsh.yaml

compatibility:
  # Minimum supported client version
  min_client_version: "1.0.0"
  
  # Supported API versions
  api_versions:
    - v1
    - v1beta1  # deprecated, remove in 2.0
    
  # Policy format version
  policy_version: "2"
  
  # Feature flags for gradual rollout
  features:
    new_approval_ui: false
    async_policy_eval: true
```

### 30.2 Zero-Downtime Upgrade

```bash
# Rolling upgrade process

# 1. Deploy new version alongside old
$ agentsh upgrade prepare --version 1.2.0

# 2. Validate new version with canary traffic
$ agentsh upgrade canary --percentage 10

# 3. Monitor for errors
$ agentsh upgrade status
Canary: 10% traffic
Old version: 1.1.0 (90% traffic, 450 sessions)
New version: 1.2.0 (10% traffic, 50 sessions)
Errors: 0

# 4. Gradually increase
$ agentsh upgrade canary --percentage 50
$ agentsh upgrade canary --percentage 100

# 5. Complete upgrade
$ agentsh upgrade complete

# Rollback if needed
$ agentsh upgrade rollback
```

### 30.3 Policy Migration

```go
// pkg/policy/migrate.go

type PolicyMigration struct {
    FromVersion string
    ToVersion   string
    Transform   func(old Policy) (Policy, error)
}

var migrations = []PolicyMigration{
    {
        FromVersion: "1",
        ToVersion:   "2",
        Transform: func(old Policy) (Policy, error) {
            new := old
            // v2 split file_rules into separate file
            new.Version = "2"
            // ... transformation logic
            return new, nil
        },
    },
}

func MigratePolicy(policy Policy, targetVersion string) (Policy, error) {
    current := policy
    for _, m := range migrations {
        if current.Version == m.FromVersion && m.ToVersion <= targetVersion {
            var err error
            current, err = m.Transform(current)
            if err != nil {
                return Policy{}, err
            }
        }
    }
    return current, nil
}
```

---

## 31. Appendix: Go Dependencies

```go
// go.mod

module github.com/agentsh/agentsh

go 1.22

require (
    // Cross-platform FUSE
    github.com/winfsp/cgofuse v1.5.0
    
    // Windows-specific
    golang.org/x/sys v0.20.0
    inet.af/wf v0.0.0-20240401190028-78c1f6d4cfb4
    github.com/williamfhe/godivert v0.0.0-20210101000000-abcdef123456
    
    // Linux-specific  
    github.com/hanwen/go-fuse/v2 v2.5.0
    github.com/seccomp/libseccomp-golang v0.10.0
    
    // Common
    github.com/spf13/cobra v1.8.0
    github.com/spf13/viper v1.18.0
    go.uber.org/zap v1.27.0
    github.com/gobwas/glob v0.2.3
    google.golang.org/grpc v1.63.0
    google.golang.org/protobuf v1.33.0
    gopkg.in/yaml.v3 v3.0.1
    
    // Testing
    github.com/stretchr/testify v1.9.0
)
```

---

## 32. Conclusion

This specification provides a comprehensive framework for running agentsh across all major platforms while clearly documenting security trade-offs:

1. **Linux** and **Windows WSL2** provide full security with all features
2. **macOS + Lima** provides near-full security (85%) with a VM layer
3. **macOS FUSE-T** provides good security (70%) with native feel
4. **Windows Native** provides partial security (55%) suitable for development

The cross-platform abstraction layer ensures API compatibility while allowing each platform to leverage its native capabilities. Users can make informed decisions about which deployment mode to use based on their security requirements.
