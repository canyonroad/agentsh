# Parent-Conditional Process Policies Design

**Date:** 2026-01-18
**Status:** Draft

## Overview

Control command execution based on process ancestry. When a process is spawned by an AI tool (Cursor, Claude Desktop, VS Code with Copilot), apply different policies than for user-initiated commands. Enables "sandbox within sandbox" for AI agents while preserving normal functionality for editor features and user terminals.

### Goals

- Block or restrict commands spawned by AI agents while allowing user-initiated commands
- Distinguish between editor features (LSP, git integration) and AI agent actions
- Support ancestry chain analysis to detect shell laundering and escape attempts
- Cross-platform support: Linux, macOS, Windows
- Minimal performance overhead via taint propagation caching

### Non-Goals

- Real-time behavioral analysis of what constitutes "AI behavior" (too complex, too many false positives)
- Blocking at the syscall level (rely on existing command interception)
- Perfect detection of all AI agents (defense in depth, not impenetrable)

## Core Concepts

### 1. Process Identity

Cross-platform process identification:

| Platform | Identifiers |
|----------|-------------|
| Linux | `comm` (15 char), `/proc/PID/exe` path, `/proc/PID/cmdline`, cgroup |
| macOS | `comm`, bundle ID (via `lsappinfo`), app path, code signature |
| Windows | `ExeFile` (from toolhelp), full exe path, AppContainer name |

### 2. Taint Propagation

When a process matching an AI tool spawns children, those children are "tainted" with the parent's identity. The taint propagates through the entire process tree.

```
Cursor (PID 1000) ← taint source
└── bash (PID 1001) ← inherits taint {source: "cursor", via: ["bash"]}
    └── git (PID 1002) ← inherits taint {source: "cursor", via: ["bash", "git"]}
```

### 3. Chain Analysis

The "via" chain tracks intermediate processes between the taint source and current process. This enables:

- **Escape hatch detection**: If a shell is the first child, user likely opened a terminal
- **Shell laundering prevention**: Detect `agent → bash → bash → bash → malicious` patterns
- **Semantic classification**: Distinguish shells, build tools, language runtimes

### 4. Agent vs Editor Detection

Not all processes spawned by Cursor are AI agents:

| Process | Classification | Policy |
|---------|---------------|--------|
| TypeScript LSP | Editor feature | Allow normal |
| Git integration | Editor feature | Allow normal |
| Integrated terminal (bash) | User shell | Allow normal |
| Claude extension (node) | AI agent | Restricted |
| Agent-spawned curl | Agent action | Restricted/Deny |

## Configuration Schema

### Process Identities (Reusable Definitions)

```yaml
# Define once, use in multiple rules
process_identities:
  ai-coding-tools:
    description: "AI-powered coding assistants and IDEs with AI features"
    linux:
      comm: ["cursor", "code", "claude-desktop"]
      exe_path:
        - "**/cursor/**"
        - "**/claude-desktop/**"
        - "**/Code/**"
    darwin:
      bundle_id:
        - "com.todesktop.230313mzl4w4u92"  # Cursor
        - "com.anthropic.claude-desktop"
        - "com.microsoft.VSCode"
      exe_path:
        - "**/Cursor.app/**"
        - "**/Claude.app/**"
        - "**/Visual Studio Code.app/**"
    windows:
      exe_name: ["Cursor.exe", "Claude.exe", "Code.exe"]
      exe_path:
        - "*\\Cursor\\**"
        - "*\\Claude\\**"
        - "*\\Microsoft VS Code\\**"

  shells:
    description: "Interactive shells"
    linux:
      comm: ["bash", "zsh", "fish", "sh", "dash", "ksh"]
    darwin:
      comm: ["bash", "zsh", "fish", "sh"]
    windows:
      exe_name: ["cmd.exe", "powershell.exe", "pwsh.exe"]

  build-tools:
    description: "Build systems and package managers"
    all_platforms:
      comm: ["npm", "yarn", "pnpm", "cargo", "go", "make", "gradle", "mvn"]

  language-servers:
    description: "LSP servers (editor features)"
    all_platforms:
      comm_patterns:
        - "*-language-server"
        - "tsserver"
        - "gopls"
        - "rust-analyzer"
        - "pylsp"
        - "clangd"
```

### Process Contexts (Policy Application)

```yaml
process_contexts:
  - name: ai-tools-sandbox
    description: "Restrict commands spawned by AI coding tools"

    # Which processes trigger this context
    parent_match:
      identity: ai-coding-tools  # Reference to process_identities
      # Or inline:
      # names: ["Cursor", "cursor", "claude-desktop"]

    # Chain analysis rules (evaluated in priority order)
    chain_rules:
      # Rule 1: User opened integrated terminal - allow normal policy
      - name: user-terminal
        priority: 100
        condition:
          via_index_0:
            identity: shells  # First child is a shell
          via_not_contains:
            identity: ai-agents  # No agent in chain
        action: allow_normal_policy

      # Rule 2: Editor features (LSP, etc) - allow normal policy
      - name: editor-features
        priority: 90
        condition:
          via_contains:
            identity: language-servers
        action: allow_normal_policy

      # Rule 3: Detect shell laundering - deny
      - name: shell-laundering
        priority: 80
        condition:
          consecutive_matches:
            identity: shells
            count_gte: 3  # bash → bash → bash
        action: deny
        message: "Suspicious shell nesting pattern detected"

      # Rule 4: Depth limit - deny
      - name: max-depth
        priority: 70
        condition:
          depth_gt: 8
        action: deny
        message: "Exceeded maximum process depth from AI tool"

      # Rule 5: Detect agent processes - mark and apply restrictions
      - name: agent-detection
        priority: 60
        condition:
          or:
            - env_contains: ["CLAUDE_AGENT=*", "COPILOT_AGENT_MODE=*"]
            - args_contain: ["--agent-mode", "--autonomous"]
            - via_matches: ["*claude*", "*copilot*", "*agent*"]
        action: mark_as_agent
        continue: true  # Keep evaluating rules

      # Rule 6: Apply agent policy (fallback for tainted processes)
      - name: agent-restrictions
        priority: 50
        condition:
          is_tainted: true  # Descended from AI tool
        action: apply_context_policy

    # Policy for agent-tainted processes (when apply_context_policy triggers)
    default_decision: deny

    allowed_commands:
      # Safe read operations
      - ls
      - cat
      - head
      - tail
      - grep
      - find
      - file
      - wc

      # Version control (read)
      - git status
      - git diff
      - git log
      - git show
      - git branch

      # Build tools
      - npm install
      - npm run
      - npm test
      - cargo build
      - cargo test
      - go build
      - go test
      - make

      # Language runtimes
      - node
      - python
      - go

    denied_commands:
      # Dangerous git operations
      - git push
      - git remote add
      - git remote set-url

      # Package publishing
      - npm publish
      - cargo publish

      # System modification
      - rm -rf
      - chmod
      - chown
      - sudo

      # Network tools (require approval instead)
      # - curl
      # - wget

    require_approval:
      - curl
      - wget
      - ssh
      - scp
      - git push

    # Per-command overrides within this context
    command_overrides:
      git:
        # Allow read operations
        args_allow: ["status", "diff", "log", "show", "branch", "stash list"]
        # Deny write operations
        args_deny: ["push", "remote add", "remote set-url", "reset --hard"]
        # Require approval for others
        default: approve
```

### Pattern Syntax

```yaml
# Pattern syntax:
#
# Glob (default):
#   *        - matches any characters
#   ?        - matches single character
#   [abc]    - matches a, b, or c
#   {a,b,c}  - matches a or b or c
#
# Regex (opt-in with "re:" prefix):
#   re:^node(?!mon)  - node but not nodemon
#
# Built-in classes (opt-in with "@" prefix):
#   @shell   - common shells
#   @editor  - common editors
#   @agent   - known AI agents
#   @build   - build tools

# Examples:
parent_match:
  names:
    - "Cursor"              # Exact match
    - "cursor-*"            # Glob
    - "@editor"             # Built-in class
    - "re:^code(-server)?$" # Regex
```

## Implementation Architecture

### Package Structure

```
internal/policy/
├── ancestry/
│   ├── taint.go           # ProcessTaint struct, TaintCache
│   ├── taint_test.go
│   ├── propagation.go     # Taint propagation logic
│   ├── propagation_test.go
│   ├── chain.go           # Via chain analysis
│   ├── chain_test.go
│   ├── detector.go        # Agent detection (signatures, behavior)
│   └── detector_test.go
├── identity/
│   ├── matcher.go         # Process identity matching
│   ├── matcher_test.go
│   ├── platform_linux.go  # Linux-specific detection
│   ├── platform_darwin.go # macOS-specific detection
│   ├── platform_windows.go
│   └── builtin.go         # @shell, @editor, etc.
├── context/
│   ├── context.go         # ProcessContext evaluation
│   ├── context_test.go
│   ├── rules.go           # Chain rule evaluation
│   └── rules_test.go
└── pattern/
    ├── pattern.go         # Glob/regex/class pattern matching
    └── pattern_test.go
```

### Core Types

```go
// ProcessTaint tracks ancestry from AI tools
type ProcessTaint struct {
    SourcePID       int             // Original AI tool PID
    SourceName      string          // "cursor", "claude-desktop", etc.
    ContextName     string          // Matches process_contexts name
    IsAgent         bool            // Detected as AI agent (not just editor)
    Via             []string        // Intermediate process names
    ViaClasses      []ProcessClass  // Classifications: shell, build, agent, etc.
    Depth           int             // Hops from source
    InheritedAt     time.Time
    SourceSnapshot  ProcessSnapshot // Captured at taint creation
}

// ProcessSnapshot captures process info at a point in time (race protection)
type ProcessSnapshot struct {
    Comm      string
    ExePath   string
    Cmdline   []string
    StartTime uint64  // Unique with PID, prevents PID reuse confusion
}

// TaintCache provides O(1) taint lookup
type TaintCache struct {
    mu     sync.RWMutex
    taints map[int]*ProcessTaint
    ttl    time.Duration
}

// ProcessClass categorizes processes for chain analysis
type ProcessClass int

const (
    ClassUnknown ProcessClass = iota
    ClassShell
    ClassEditor
    ClassAgent
    ClassBuildTool
    ClassLanguageServer
    ClassLanguageRuntime
)

// ChainCondition represents a condition for chain_rules
type ChainCondition struct {
    ViaIndex          *int           // Check specific position in via chain
    ViaContains       []string       // Any of these in via chain
    ViaNotContains    []string       // None of these in via chain
    ViaMatches        []string       // Patterns to match against via
    ConsecutiveShells *int           // Detect shell laundering
    DepthGT           *int           // Depth greater than
    DepthLT           *int           // Depth less than
    IsTainted         *bool          // Is descended from AI tool
    IsAgent           *bool          // Is detected as agent
    EnvContains       []string       // Environment variable patterns
    ArgsContain       []string       // Argument patterns
    Or                []ChainCondition // OR of sub-conditions
    And               []ChainCondition // AND of sub-conditions
}

// ChainAction specifies what to do when condition matches
type ChainAction string

const (
    ActionAllowNormalPolicy ChainAction = "allow_normal_policy"
    ActionApplyContextPolicy ChainAction = "apply_context_policy"
    ActionDeny              ChainAction = "deny"
    ActionApprove           ChainAction = "approve"
    ActionMarkAsAgent       ChainAction = "mark_as_agent"
)
```

### Taint Cache Implementation

```go
// NewTaintCache creates a cache with the given TTL for stale entries
func NewTaintCache(ttl time.Duration) *TaintCache {
    c := &TaintCache{
        taints: make(map[int]*ProcessTaint),
        ttl:    ttl,
    }
    go c.cleanupLoop()
    return c
}

// OnSpawn handles new process detection
func (c *TaintCache) OnSpawn(pid, ppid int, info *ProcessInfo) {
    c.mu.Lock()
    defer c.mu.Unlock()

    // Check if parent is tainted
    if parentTaint, ok := c.taints[ppid]; ok {
        // Propagate taint to child
        c.taints[pid] = &ProcessTaint{
            SourcePID:      parentTaint.SourcePID,
            SourceName:     parentTaint.SourceName,
            ContextName:    parentTaint.ContextName,
            IsAgent:        parentTaint.IsAgent,
            Via:            append(append([]string{}, parentTaint.Via...), info.Comm),
            ViaClasses:     append(append([]ProcessClass{}, parentTaint.ViaClasses...), classifyProcess(info.Comm)),
            Depth:          parentTaint.Depth + 1,
            InheritedAt:    time.Now(),
            SourceSnapshot: parentTaint.SourceSnapshot,
        }
        return
    }

    // Check if this process IS an AI tool (new taint source)
    if ctx := c.matchesAITool(info); ctx != nil {
        c.taints[pid] = &ProcessTaint{
            SourcePID:   pid,
            SourceName:  info.Comm,
            ContextName: ctx.Name,
            Depth:       0,
            InheritedAt: time.Now(),
            SourceSnapshot: ProcessSnapshot{
                Comm:      info.Comm,
                ExePath:   info.ExePath,
                Cmdline:   info.Cmdline,
                StartTime: info.StartTime,
            },
        }
    }
}

// IsTainted returns taint info for a PID (O(1) lookup)
func (c *TaintCache) IsTainted(pid int) *ProcessTaint {
    c.mu.RLock()
    defer c.mu.RUnlock()
    return c.taints[pid]
}

// OnExit removes taint when process exits
func (c *TaintCache) OnExit(pid int) {
    c.mu.Lock()
    defer c.mu.Unlock()
    delete(c.taints, pid)
}
```

### Policy Evaluation Flow

```go
func (e *PolicyEngine) EvaluateCommand(ctx context.Context, pid int, cmd string, args []string) Decision {
    // 1. Check taint cache
    taint := e.taintCache.IsTainted(pid)

    if taint == nil {
        // Not tainted - apply normal policy
        return e.evaluateNormalPolicy(cmd, args)
    }

    // 2. Validate taint is still accurate (race protection)
    if !e.validateTaint(taint) {
        return e.handleRaceCondition(taint, cmd, args)
    }

    // 3. Find matching process context
    context := e.findContext(taint.ContextName)
    if context == nil {
        // Context not found - fall back to normal
        return e.evaluateNormalPolicy(cmd, args)
    }

    // 4. Evaluate chain rules in priority order
    for _, rule := range context.ChainRules {
        if e.evaluateChainCondition(rule.Condition, taint, cmd, args) {
            switch rule.Action {
            case ActionAllowNormalPolicy:
                return e.evaluateNormalPolicy(cmd, args)
            case ActionDeny:
                return Decision{Action: Deny, Reason: rule.Message}
            case ActionApprove:
                return Decision{Action: Approve, Message: rule.Message}
            case ActionMarkAsAgent:
                taint.IsAgent = true
                if rule.Continue {
                    continue
                }
            case ActionApplyContextPolicy:
                return e.evaluateContextPolicy(context, cmd, args)
            }
        }
    }

    // 5. Default: apply context policy
    return e.evaluateContextPolicy(context, cmd, args)
}

func (e *PolicyEngine) evaluateContextPolicy(ctx *ProcessContext, cmd string, args []string) Decision {
    fullCmd := cmd + " " + strings.Join(args, " ")

    // Check denied commands first
    for _, pattern := range ctx.DeniedCommands {
        if e.matchCommand(pattern, cmd, args) {
            return Decision{Action: Deny, Reason: "command denied by AI sandbox policy"}
        }
    }

    // Check allowed commands
    for _, pattern := range ctx.AllowedCommands {
        if e.matchCommand(pattern, cmd, args) {
            return Decision{Action: Allow}
        }
    }

    // Check require approval
    for _, pattern := range ctx.RequireApproval {
        if e.matchCommand(pattern, cmd, args) {
            return Decision{
                Action:  Approve,
                Message: fmt.Sprintf("AI agent wants to run: %s", fullCmd),
            }
        }
    }

    // Default decision
    return Decision{Action: ctx.DefaultDecision}
}
```

## Platform Integration

### Linux

Process tracking via existing `internal/process/tree_linux.go`:

- **cgroups** (preferred): Automatic child tracking via `cgroup.procs`
- **Fallback**: `/proc` polling every 100ms

Process info via `/proc`:
- `comm`: `/proc/PID/comm`
- `cmdline`: `/proc/PID/cmdline`
- `exe`: `/proc/PID/exe` (symlink to executable)
- `starttime`: `/proc/PID/stat` field 22

### macOS

Process tracking via existing `internal/process/tree_darwin.go`:

- Polling with `pgrep -P <pid>` for children
- Process info via `ps` commands

Enhanced detection:
- Bundle ID via `lsappinfo info -only bundleid <pid>` or `mdls`
- Code signature via `codesign -dvv`

### Windows

Process tracking via existing `internal/process/tree_windows.go`:

- **Job Objects** (preferred): Automatic child tracking
- **Fallback**: `CreateToolhelp32Snapshot` polling

Process info via Win32 APIs:
- Executable name from `ProcessEntry32.ExeFile`
- Full path via `QueryFullProcessImageName`
- Start time via `GetProcessTimes`

## Race Condition Handling

### The Problem

```
t0: Process A spawns Process B
t1: agentsh intercepts B's exec, starts policy check
t2: Process A exits
t3: agentsh tries to validate A → ENOENT
```

### Solution: Multi-Layer Defense

1. **Capture at spawn time**: Taint info captured when child spawns, not at exec
2. **Snapshot in taint**: `SourceSnapshot` preserves parent info even after exit
3. **Start time validation**: Detect PID reuse via start time comparison
4. **Fail-closed option**: Configurable behavior when validation fails

```yaml
process_contexts:
  - name: ai-tools-sandbox
    race_policy:
      on_missing_parent: deny    # deny, allow, approve
      on_pid_mismatch: deny      # PID reuse detected
      on_validation_error: deny  # Other validation failures
      log_race_conditions: true
```

## Agent Detection

### Detection Signals

| Signal | Method | Confidence |
|--------|--------|------------|
| User declaration | Config file | 100% |
| Self-registration | API call or env var | 100% |
| Known signatures | Env vars, args, process names | 90% |
| Behavioral heuristics | High exec rate, LLM API calls | 60-80% |

### Signature-Based Detection

```yaml
agent_signatures:
  env_markers:
    - "CLAUDE_AGENT=*"
    - "COPILOT_AGENT_MODE=*"
    - "AIDER_*"

  arg_patterns:
    - "--agent-mode"
    - "--autonomous"
    - "run-agent"

  process_patterns:
    - "*claude*agent*"
    - "*copilot*agent*"
    - "aider"
```

### Behavioral Detection (Optional)

```go
type AgentBehaviorDetector struct {
    recentExecs     map[int][]time.Time  // PID → exec timestamps
    networkActivity map[int][]string     // PID → domains contacted
}

func (d *AgentBehaviorDetector) IsLikelyAgent(pid int) (bool, float64) {
    score := 0.0

    // High exec rate (>10/min)
    if d.execRate(pid) > 10 {
        score += 0.3
    }

    // Contacts LLM APIs
    if d.contactsLLMAPI(pid) {
        score += 0.5
    }

    // Spawns multiple shells
    if d.shellSpawnCount(pid) > 3 {
        score += 0.2
    }

    return score > 0.5, score
}
```

## Performance Considerations

### Taint Cache

| Operation | Complexity | Notes |
|-----------|------------|-------|
| IsTainted lookup | O(1) | Hash map |
| OnSpawn propagation | O(via_length) | Copy via chain |
| OnExit cleanup | O(1) | Delete from map |
| Memory per process | ~300 bytes | Taint struct + map overhead |

### Optimization Strategies

1. **Lazy classification**: Only classify via chain when needed for rule evaluation
2. **Pattern compilation**: Compile glob/regex patterns once at config load
3. **Early exit**: Chain rules evaluated in priority order, stop on first match
4. **Batch cleanup**: Process exit cleanup batched every 100ms

### Benchmarks (Target)

| Scenario | Target Latency |
|----------|----------------|
| IsTainted check (cache hit) | <100ns |
| Chain rule evaluation (5 rules) | <1ms |
| Full policy evaluation | <5ms |
| Memory overhead (1000 processes) | <500KB |

## CLI Commands

```bash
# View active taints
agentsh taint list
agentsh taint show <pid>

# Debug chain analysis
agentsh taint trace <pid>    # Show full ancestry and taint propagation

# Test policy
agentsh policy test --parent cursor --command "git push"
agentsh policy test --ancestry "cursor,bash,npm,node" --command "curl example.com"

# Monitor in real-time
agentsh taint watch              # Stream taint events
agentsh taint watch --agent-only # Only show agent-detected processes
```

## Testing Strategy

### Unit Tests

```go
// Taint propagation
func TestTaintCache_Propagation(t *testing.T) {
    cache := NewTaintCache(time.Hour)

    // Simulate: Cursor → bash → git
    cache.OnSpawn(1000, 0, &ProcessInfo{Comm: "Cursor"})   // Taint source
    cache.OnSpawn(1001, 1000, &ProcessInfo{Comm: "bash"})  // Inherits
    cache.OnSpawn(1002, 1001, &ProcessInfo{Comm: "git"})   // Inherits

    taint := cache.IsTainted(1002)
    assert.NotNil(t, taint)
    assert.Equal(t, "Cursor", taint.SourceName)
    assert.Equal(t, []string{"bash", "git"}, taint.Via)
    assert.Equal(t, 2, taint.Depth)
}

// Chain rule evaluation
func TestChainRules_UserTerminal(t *testing.T) {
    // User opened terminal - should allow normal policy
    taint := &ProcessTaint{
        Via: []string{"bash"},
        ViaClasses: []ProcessClass{ClassShell},
    }

    rule := ChainRule{
        Condition: ChainCondition{
            ViaIndex: ptr(0),
            ViaIndexMatches: []string{"@shell"},
        },
        Action: ActionAllowNormalPolicy,
    }

    assert.True(t, evaluateCondition(rule.Condition, taint))
}

// Shell laundering detection
func TestChainRules_ShellLaundering(t *testing.T) {
    taint := &ProcessTaint{
        Via: []string{"bash", "bash", "bash", "curl"},
        ViaClasses: []ProcessClass{ClassShell, ClassShell, ClassShell, ClassUnknown},
    }

    rule := ChainRule{
        Condition: ChainCondition{
            ConsecutiveShells: ptr(3),
        },
        Action: ActionDeny,
    }

    assert.True(t, evaluateCondition(rule.Condition, taint))
}
```

### Integration Tests

```go
func TestFullFlow_AgentBlocked(t *testing.T) {
    // 1. Start agentsh with test policy
    // 2. Spawn "fake-cursor" process
    // 3. From fake-cursor, spawn bash
    // 4. From bash, run "git push"
    // 5. Assert: blocked by policy
}

func TestFullFlow_UserTerminalAllowed(t *testing.T) {
    // 1. Start agentsh with test policy
    // 2. Spawn "fake-cursor" process
    // 3. From fake-cursor, spawn bash (simulating integrated terminal)
    // 4. From bash, run "git push"
    // 5. Assert: allowed (user terminal escape hatch)
}
```

### Manual Test Matrix

| Scenario | Cursor | Claude Desktop | VS Code |
|----------|--------|----------------|---------|
| User types in terminal | Allow | Allow | Allow |
| Agent runs git push | Deny/Approve | Deny/Approve | Deny/Approve |
| LSP server runs | Allow | N/A | Allow |
| npm install (agent) | Allow | Allow | Allow |
| curl (agent) | Approve | Approve | Approve |

## Implementation Phases

### Phase 1: Core Taint Infrastructure

- Create `internal/policy/ancestry/` package
- Implement `ProcessTaint` and `TaintCache`
- Implement taint propagation on spawn
- Integrate with existing process tree tracking
- Unit tests for taint propagation

### Phase 2: Process Identity Matching

- Create `internal/policy/identity/` package
- Implement cross-platform process matching
- Implement glob/regex/class pattern syntax
- Built-in classes (@shell, @editor, @agent, @build)
- Unit tests for all matchers

### Phase 3: Chain Analysis

- Implement via chain classification
- Implement chain condition evaluation
- Implement escape hatch rules (user terminal, editor features)
- Implement shell laundering detection
- Unit tests for chain rules

### Phase 4: Policy Integration

- Add `process_contexts` to policy schema
- Integrate with existing command policy evaluation
- Wire up taint-aware policy decisions
- Add race condition handling
- Integration tests

### Phase 5: Agent Detection

- Implement signature-based detection
- Implement self-registration API
- Implement behavioral detection (optional)
- Configuration for detection thresholds

### Phase 6: CLI & Observability

- Add `agentsh taint` commands
- Add `agentsh policy test` with ancestry simulation
- Event emission for taint/untaint events
- Documentation and examples

## Security Considerations

### Bypass Attempts

| Attack | Mitigation |
|--------|------------|
| Rename process | Match by exe path, not just comm |
| Shell laundering | Detect consecutive shells, depth limits |
| Fork bomb to exhaust cache | TTL-based cleanup, memory limits |
| PID reuse | Start time validation |
| LD_PRELOAD to hide ancestry | Already blocked by env policy |

### Defense in Depth

This feature provides an additional layer on top of:

1. Existing command policies (deny dangerous commands)
2. Existing env policies (block LD_PRELOAD, etc.)
3. Existing file policies (protect sensitive paths)
4. Existing network policies (control egress)

Even if ancestry detection is bypassed, other layers provide protection.

## Future Enhancements

1. **Machine learning agent detection**: Train classifier on exec patterns
2. **Cross-session taint persistence**: Remember agent processes across restarts
3. **Remote attestation**: Verify agent identity via cryptographic signatures
4. **Policy templates**: Pre-built policies for common AI tools
5. **Learning mode**: Generate policies from observed behavior
