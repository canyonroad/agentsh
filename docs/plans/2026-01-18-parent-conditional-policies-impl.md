# Parent-Conditional Process Policies Implementation Plan

**Date:** 2026-01-18
**Design Doc:** [2026-01-18-parent-conditional-policies-design.md](./2026-01-18-parent-conditional-policies-design.md)
**Branch:** `feature/parent-conditional-policies`
**Worktree:** `.worktrees/parent-conditional-policies`

## Overview

This plan implements the parent-conditional process policies feature in 6 phases, each building on the previous. Each phase is independently testable and can be merged incrementally.

---

## Phase 1: Core Taint Infrastructure

**Goal:** Create the foundational taint propagation system.

### 1.1 Create Package Structure

```
internal/policy/ancestry/
├── taint.go           # ProcessTaint struct, TaintCache
├── taint_test.go
├── propagation.go     # Taint propagation logic
├── propagation_test.go
├── snapshot.go        # ProcessSnapshot for race protection
└── snapshot_test.go
```

### 1.2 Implement Core Types (`taint.go`)

```go
// ProcessTaint tracks ancestry from AI tools
type ProcessTaint struct {
    SourcePID       int
    SourceName      string
    ContextName     string
    IsAgent         bool
    Via             []string
    ViaClasses      []ProcessClass
    Depth           int
    InheritedAt     time.Time
    SourceSnapshot  ProcessSnapshot
}

// ProcessClass categorizes processes
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

// TaintCache provides O(1) taint lookup
type TaintCache struct {
    mu     sync.RWMutex
    taints map[int]*ProcessTaint
    ttl    time.Duration
}
```

**Tasks:**
- [ ] Create `internal/policy/ancestry/` directory
- [ ] Implement `ProcessTaint` struct with all fields
- [ ] Implement `ProcessClass` enum with String() method
- [ ] Implement `TaintCache` with thread-safe operations:
  - [ ] `NewTaintCache(ttl time.Duration) *TaintCache`
  - [ ] `IsTainted(pid int) *ProcessTaint` (O(1) lookup)
  - [ ] `OnSpawn(pid, ppid int, info *ProcessInfo)`
  - [ ] `OnExit(pid int)`
  - [ ] `MarkAsAgent(pid int)`
- [ ] Implement background cleanup goroutine for TTL expiration
- [ ] Unit tests for TaintCache operations

### 1.3 Implement Process Snapshot (`snapshot.go`)

```go
// ProcessSnapshot captures process info at creation time
type ProcessSnapshot struct {
    Comm      string
    ExePath   string
    Cmdline   []string
    StartTime uint64
}

// CaptureSnapshot captures current process info (cross-platform)
func CaptureSnapshot(pid int) (*ProcessSnapshot, error)

// ValidateSnapshot checks if PID still refers to same process
func ValidateSnapshot(pid int, snapshot *ProcessSnapshot) bool
```

**Tasks:**
- [ ] Implement `ProcessSnapshot` struct
- [ ] Implement `CaptureSnapshot()` with platform-specific implementations:
  - [ ] Linux: Read from `/proc/PID/stat`, `/proc/PID/comm`, `/proc/PID/exe`
  - [ ] macOS: Use `proc_pidinfo` or `ps`
  - [ ] Windows: Use `GetProcessTimes`, `QueryFullProcessImageName`
- [ ] Implement `ValidateSnapshot()` for PID reuse detection
- [ ] Unit tests with mock process info

### 1.4 Implement Taint Propagation (`propagation.go`)

```go
// PropagationConfig controls taint behavior
type PropagationConfig struct {
    MaxDepth    int           // Max ancestry depth before refusing
    TTL         time.Duration // Taint entry TTL
    RacePolicy  RacePolicy    // What to do on validation failure
}

type RacePolicy struct {
    OnMissingParent   string // "deny", "allow", "approve"
    OnPIDMismatch     string
    OnValidationError string
    LogRaceConditions bool
}
```

**Tasks:**
- [ ] Define `PropagationConfig` struct
- [ ] Implement taint inheritance logic in `OnSpawn()`:
  - [ ] Copy parent taint with updated Via chain
  - [ ] Increment depth counter
  - [ ] Classify new process and append to ViaClasses
- [ ] Implement new taint source detection (for AI tool processes)
- [ ] Unit tests for propagation scenarios:
  - [ ] Linear chain: A → B → C
  - [ ] Branching: A → B, A → C
  - [ ] Depth limit enforcement
  - [ ] Exit cleanup

### 1.5 Integrate with Process Tree

**Tasks:**
- [ ] Add taint hooks to `internal/process/tree.go`:
  - [ ] Call `TaintCache.OnSpawn()` from `ProcessTree.handleSpawn()`
  - [ ] Call `TaintCache.OnExit()` from `ProcessTree.handleExit()`
- [ ] Ensure taint cache is created alongside ProcessTree
- [ ] Integration test: spawn processes, verify taint propagation

**Deliverables:**
- `internal/policy/ancestry/` package with full taint infrastructure
- 90%+ test coverage for taint operations
- Taint propagation working with process tree

---

## Phase 2: Process Identity Matching

**Goal:** Cross-platform process identification with pattern matching.

### 2.1 Create Package Structure

```
internal/policy/identity/
├── matcher.go         # ProcessMatcher interface and implementation
├── matcher_test.go
├── platform_linux.go  # Linux-specific detection
├── platform_darwin.go # macOS-specific detection
├── platform_windows.go
├── builtin.go         # @shell, @editor, etc.
└── builtin_test.go
```

### 2.2 Implement Pattern Matching (`internal/policy/pattern/`)

```go
// Pattern represents a compiled glob, regex, or class pattern
type Pattern struct {
    Raw      string
    IsRegex  bool
    IsClass  bool
    compiled interface{} // *regexp.Regexp or glob.Glob
}

func Compile(s string) (*Pattern, error)
func (p *Pattern) Match(s string) bool
func (p *Pattern) MatchWithTimeout(s string, timeout time.Duration) (bool, error)
```

**Tasks:**
- [ ] Create `internal/policy/pattern/` package
- [ ] Implement pattern compilation:
  - [ ] Glob (default): use `gobwas/glob`
  - [ ] Regex (opt-in with `re:` prefix): use `regexp`
  - [ ] Class (opt-in with `@` prefix): expand from builtins
- [ ] Implement ReDoS detection for regex patterns
- [ ] Implement timeout-protected matching
- [ ] Unit tests for all pattern types

### 2.3 Implement Built-in Classes (`builtin.go`)

```go
var BuiltinClasses = map[string][]string{
    "@shell":           {"bash", "zsh", "fish", "sh", ...},
    "@editor":          {"Cursor", "cursor", "code", "vim", ...},
    "@agent":           {"claude-agent", "aider", ...},
    "@build":           {"npm", "cargo", "go", "make", ...},
    "@language-server": {"*-language-server", "tsserver", "gopls", ...},
}

func ExpandClass(name string) []string
func IsBuiltinClass(name string) bool
```

**Tasks:**
- [ ] Define comprehensive built-in classes
- [ ] Implement class expansion
- [ ] Allow user extension via config
- [ ] Unit tests for class expansion

### 2.4 Implement Process Matcher (`matcher.go`)

```go
// ProcessIdentity defines how to match a process
type ProcessIdentity struct {
    Name        string            // For reference
    Description string
    Linux       PlatformMatch
    Darwin      PlatformMatch
    Windows     PlatformMatch
    AllPlatforms *PlatformMatch   // Applied to all
}

type PlatformMatch struct {
    Comm         []string // Process name patterns
    CommPatterns []string // Glob/regex patterns for comm
    ExePath      []string // Executable path patterns
    BundleID     []string // macOS only
    ExeName      []string // Windows only
}

// ProcessMatcher checks if a process matches an identity
type ProcessMatcher struct {
    identities map[string]*ProcessIdentity
    patterns   map[string][]*Pattern // Compiled patterns
}

func (m *ProcessMatcher) Matches(info *ProcessInfo) []string // Returns matching identity names
func (m *ProcessMatcher) MatchesIdentity(info *ProcessInfo, name string) bool
```

**Tasks:**
- [ ] Implement `ProcessIdentity` struct and config parsing
- [ ] Implement `PlatformMatch` with platform selection at runtime
- [ ] Implement `ProcessMatcher` with pattern compilation cache
- [ ] Platform-specific process info gathering:
  - [ ] Linux: `/proc/PID/comm`, `/proc/PID/exe`, `/proc/PID/cmdline`
  - [ ] macOS: `lsappinfo`, code signature, bundle ID
  - [ ] Windows: toolhelp snapshot, `QueryFullProcessImageName`
- [ ] Unit tests for each platform

### 2.5 Add Config Schema

Add to `internal/policy/model.go`:

```go
type ProcessIdentitiesConfig struct {
    Identities map[string]ProcessIdentity `yaml:"process_identities"`
}
```

**Tasks:**
- [ ] Add `process_identities` to policy model
- [ ] Implement YAML parsing for identity config
- [ ] Validate identity config on load
- [ ] Unit tests for config parsing

**Deliverables:**
- `internal/policy/pattern/` package
- `internal/policy/identity/` package
- Cross-platform process matching working
- Built-in classes defined and expandable

---

## Phase 3: Chain Analysis

**Goal:** Via chain classification and escape hatch detection.

### 3.1 Create Chain Analysis Module

```
internal/policy/ancestry/
├── ... (existing)
├── chain.go           # Chain analysis
├── chain_test.go
├── classifier.go      # Process classification
└── classifier_test.go
```

### 3.2 Implement Process Classifier (`classifier.go`)

```go
// ClassifyProcess determines the ProcessClass for a process name
func ClassifyProcess(comm string) ProcessClass

// ClassifyChain classifies each process in a via chain
func ClassifyChain(via []string) []ProcessClass
```

**Tasks:**
- [ ] Implement `ClassifyProcess()` using built-in classes
- [ ] Allow custom classification rules from config
- [ ] Implement `ClassifyChain()` for via arrays
- [ ] Unit tests for classification

### 3.3 Implement Chain Condition Evaluation (`chain.go`)

```go
// ChainCondition represents conditions for chain_rules
type ChainCondition struct {
    ViaIndex           *int              // Check specific via position
    ViaContains        []string          // Any of these in via
    ViaNotContains     []string          // None of these in via
    ViaMatches         []string          // Pattern match against via
    ConsecutiveMatches *ConsecutiveMatch // Detect shell laundering
    DepthGT            *int              // Depth greater than
    DepthLT            *int              // Depth less than
    IsTainted          *bool             // Is descended from AI tool
    IsAgent            *bool             // Is detected as agent
    EnvContains        []string          // Environment patterns
    ArgsContain        []string          // Argument patterns
    Or                 []ChainCondition  // OR sub-conditions
    And                []ChainCondition  // AND sub-conditions
}

type ConsecutiveMatch struct {
    Identity string // Identity or class name
    CountGTE int    // Count >= this
}

// EvaluateCondition checks if a taint matches a condition
func EvaluateCondition(cond *ChainCondition, taint *ProcessTaint, cmd string, args []string) bool
```

**Tasks:**
- [ ] Implement `ChainCondition` struct with all fields
- [ ] Implement `EvaluateCondition()` with support for:
  - [ ] `via_index_N` - check specific position in via chain
  - [ ] `via_contains` / `via_not_contains` - presence checks
  - [ ] `via_matches` - pattern matching against via entries
  - [ ] `consecutive_matches` - detect patterns like shell laundering
  - [ ] `depth_gt` / `depth_lt` - depth limit checks
  - [ ] `is_tainted` / `is_agent` - flag checks
  - [ ] `env_contains` / `args_contain` - execution context
  - [ ] `or` / `and` - logical composition
- [ ] Implement short-circuit evaluation for performance
- [ ] Unit tests for each condition type
- [ ] Unit tests for compound conditions (or, and)

### 3.4 Implement Chain Rules

```go
type ChainRule struct {
    Name      string
    Priority  int
    Condition ChainCondition
    Action    ChainAction
    Message   string
    Continue  bool // Keep evaluating after this rule
}

type ChainAction string

const (
    ActionAllowNormalPolicy  ChainAction = "allow_normal_policy"
    ActionApplyContextPolicy ChainAction = "apply_context_policy"
    ActionDeny               ChainAction = "deny"
    ActionApprove            ChainAction = "approve"
    ActionMarkAsAgent        ChainAction = "mark_as_agent"
)

// EvaluateChainRules evaluates rules in priority order
func EvaluateChainRules(rules []ChainRule, taint *ProcessTaint, cmd string, args []string) *ChainRule
```

**Tasks:**
- [ ] Implement `ChainRule` struct
- [ ] Implement `ChainAction` enum
- [ ] Implement `EvaluateChainRules()` with priority ordering
- [ ] Handle `continue` flag for mark-and-continue patterns
- [ ] Unit tests for rule evaluation order
- [ ] Unit tests for escape hatch scenarios:
  - [ ] User terminal (shell first child)
  - [ ] Editor features (LSP in chain)
  - [ ] Shell laundering (consecutive shells)
  - [ ] Depth limit exceeded

**Deliverables:**
- Chain condition evaluation fully implemented
- Escape hatch detection working
- Shell laundering detection working
- All chain-related unit tests passing

---

## Phase 4: Policy Integration

**Goal:** Wire taint-aware policies into the command evaluation flow.

### 4.1 Add Process Context to Policy Model

Add to `internal/policy/model.go`:

```go
type ProcessContext struct {
    Name            string           `yaml:"name"`
    Description     string           `yaml:"description"`
    ParentMatch     ParentMatchConfig `yaml:"parent_match"`
    ChainRules      []ChainRule      `yaml:"chain_rules"`
    DefaultDecision string           `yaml:"default_decision"`
    AllowedCommands []string         `yaml:"allowed_commands"`
    DeniedCommands  []string         `yaml:"denied_commands"`
    RequireApproval []string         `yaml:"require_approval"`
    CommandOverrides map[string]CommandOverride `yaml:"command_overrides"`
    RacePolicy      RacePolicy       `yaml:"race_policy"`
}

type ParentMatchConfig struct {
    Identity string   `yaml:"identity"` // Reference to process_identities
    Names    []string `yaml:"names"`    // Inline patterns
}

type CommandOverride struct {
    ArgsAllow []string `yaml:"args_allow"`
    ArgsDeny  []string `yaml:"args_deny"`
    Default   string   `yaml:"default"`
}
```

**Tasks:**
- [ ] Add `ProcessContext` to policy model
- [ ] Add `process_contexts` array to `Policy` struct
- [ ] Implement YAML parsing with validation
- [ ] Implement `CommandOverride` for per-command arg filtering
- [ ] Unit tests for config parsing

### 4.2 Integrate with Policy Engine

Modify `internal/policy/engine.go`:

```go
type Engine struct {
    // ... existing fields
    taintCache      *ancestry.TaintCache
    processContexts []*ProcessContext
    matcher         *identity.ProcessMatcher
}

// EvaluateCommand now checks taint before normal evaluation
func (e *Engine) EvaluateCommand(ctx context.Context, pid int, cmd string, args []string) Decision {
    // 1. Check taint
    taint := e.taintCache.IsTainted(pid)
    if taint == nil {
        return e.evaluateNormalPolicy(cmd, args)
    }

    // 2. Validate taint (race protection)
    if !e.validateTaint(taint) {
        return e.handleRaceCondition(taint, cmd, args)
    }

    // 3. Find and apply process context
    ctx := e.findContext(taint.ContextName)
    return e.evaluateWithContext(ctx, taint, cmd, args)
}
```

**Tasks:**
- [ ] Add `TaintCache` to Engine struct
- [ ] Add taint check to command evaluation entry point
- [ ] Implement `findContext()` to lookup by context name
- [ ] Implement `evaluateWithContext()`:
  - [ ] Evaluate chain rules in priority order
  - [ ] Handle each action type appropriately
  - [ ] Fall through to context-specific policy
- [ ] Implement `evaluateContextPolicy()`:
  - [ ] Check denied commands first
  - [ ] Check allowed commands
  - [ ] Check require_approval
  - [ ] Apply command overrides
  - [ ] Fall back to default decision
- [ ] Wire up taint cache to process tree callbacks

### 4.3 Implement Race Condition Handling

```go
func (e *Engine) validateTaint(taint *ProcessTaint) bool {
    // Check if source process still exists with same start time
    if !ancestry.ValidateSnapshot(taint.SourcePID, &taint.SourceSnapshot) {
        // Source changed or exited - taint data still valid though
        return true // Cached data is sufficient
    }
    return true
}

func (e *Engine) handleRaceCondition(taint *ProcessTaint, cmd string, args []string) Decision {
    ctx := e.findContext(taint.ContextName)
    if ctx == nil {
        return e.evaluateNormalPolicy(cmd, args)
    }

    switch ctx.RacePolicy.OnMissingParent {
    case "deny":
        return Decision{Action: Deny, Reason: "race condition: parent unavailable"}
    case "allow":
        return e.evaluateNormalPolicy(cmd, args)
    case "approve":
        return Decision{Action: Approve, Message: "Parent process unavailable"}
    default:
        return Decision{Action: Deny}
    }
}
```

**Tasks:**
- [ ] Implement `validateTaint()` with snapshot check
- [ ] Implement `handleRaceCondition()` with configurable behavior
- [ ] Add race condition logging
- [ ] Unit tests for race scenarios

### 4.4 Integration Tests

**Tasks:**
- [ ] Create test fixture with mock process tree and taint cache
- [ ] Test: Normal command (not tainted) → normal policy applies
- [ ] Test: Tainted command with allow rule → allowed
- [ ] Test: Tainted command with deny rule → denied
- [ ] Test: Tainted command with approve rule → approval requested
- [ ] Test: User terminal escape hatch → normal policy
- [ ] Test: Shell laundering → denied
- [ ] Test: Depth limit exceeded → denied
- [ ] Test: Race condition with deny policy → denied
- [ ] Test: Command override args_deny → denied

**Deliverables:**
- Full policy integration complete
- Taint-aware command evaluation working
- Race condition handling implemented
- Integration tests passing

---

## Phase 5: Agent Detection

**Goal:** Multi-signal agent detection (signatures, registration, behavior).

### 5.1 Implement Signature-Based Detection

Add to `internal/policy/ancestry/`:

```
├── detector.go        # Agent detection
└── detector_test.go
```

```go
type AgentSignatures struct {
    EnvMarkers      []string `yaml:"env_markers"`
    ArgPatterns     []string `yaml:"arg_patterns"`
    ProcessPatterns []string `yaml:"process_patterns"`
}

type AgentDetector struct {
    signatures *AgentSignatures
    patterns   []*pattern.Pattern
}

func (d *AgentDetector) IsAgent(info *ProcessInfo, env []string) (bool, []string)
```

**Tasks:**
- [ ] Implement `AgentSignatures` config
- [ ] Implement `AgentDetector` with pattern matching:
  - [ ] Check environment variables for markers
  - [ ] Check command arguments for patterns
  - [ ] Check process name for patterns
- [ ] Return detection signals for debugging
- [ ] Unit tests for signature matching

### 5.2 Implement Self-Registration API

```go
// AgentRegistry allows agents to self-identify
type AgentRegistry struct {
    mu         sync.RWMutex
    registered map[int]AgentRegistration
}

type AgentRegistration struct {
    PID          int
    Name         string
    Capabilities []string
    RegisteredAt time.Time
}

func (r *AgentRegistry) Register(pid int, name string, caps []string) error
func (r *AgentRegistry) IsRegistered(pid int) *AgentRegistration
func (r *AgentRegistry) Unregister(pid int)
```

**Tasks:**
- [ ] Implement `AgentRegistry` struct
- [ ] Add registration API endpoint (optional, for advanced use)
- [ ] Support environment variable registration: `AGENTSH_AGENT_ID`
- [ ] Support marker file detection: `.agentsh-agent-mode`
- [ ] Wire registry into agent detection flow
- [ ] Unit tests for registration

### 5.3 Implement Behavioral Detection (Optional)

```go
type BehaviorDetector struct {
    execHistory map[int][]time.Time // PID → exec timestamps
    netHistory  map[int][]string    // PID → domains contacted
}

func (d *BehaviorDetector) RecordExec(pid int)
func (d *BehaviorDetector) RecordNetwork(pid int, domain string)
func (d *BehaviorDetector) IsLikelyAgent(pid int) (bool, float64)
```

**Tasks:**
- [ ] Implement behavioral tracking (optional, behind feature flag)
- [ ] Track exec rate per process
- [ ] Track LLM API connections
- [ ] Calculate agent probability score
- [ ] Unit tests for behavior detection

### 5.4 Combine Detection Signals

```go
type AgentDetectionResult struct {
    IsAgent    bool
    Confidence float64
    Signals    []string
    Source     string // "signature", "registration", "behavior", "declared"
}

func (d *AgentDetector) Detect(pid int, info *ProcessInfo, env []string) AgentDetectionResult
```

**Tasks:**
- [ ] Implement combined detection with confidence scoring
- [ ] Priority order: declared > registered > signature > behavior
- [ ] Configure confidence thresholds in policy
- [ ] Auto-mark taint as agent when detected
- [ ] Unit tests for combined detection

**Deliverables:**
- Multi-signal agent detection working
- Self-registration mechanism available
- Behavioral detection optional and behind flag

---

## Phase 6: CLI & Observability

**Goal:** CLI commands for debugging and monitoring.

### 6.1 Add `agentsh taint` Commands

Add to `internal/cli/`:

```
├── taint_cmd.go
└── taint_cmd_test.go
```

```bash
agentsh taint list              # List all tainted processes
agentsh taint show <pid>        # Show taint details for PID
agentsh taint trace <pid>       # Show full ancestry chain
agentsh taint watch             # Stream taint events
agentsh taint watch --agent-only
```

**Tasks:**
- [ ] Implement `taint list` - table of tainted PIDs with source
- [ ] Implement `taint show <pid>` - detailed taint info
- [ ] Implement `taint trace <pid>` - ancestry chain visualization
- [ ] Implement `taint watch` - stream spawn/exit/agent events
- [ ] Add `--agent-only` filter to watch command
- [ ] Unit tests for CLI parsing

### 6.2 Add `agentsh policy test` with Ancestry

Extend existing policy test command:

```bash
agentsh policy test --parent cursor --command "git push"
agentsh policy test --ancestry "cursor,bash,npm,node" --command "curl example.com"
```

**Tasks:**
- [ ] Add `--parent` flag to simulate taint source
- [ ] Add `--ancestry` flag to simulate full via chain
- [ ] Show which chain rules matched
- [ ] Show final decision and reason
- [ ] Unit tests for policy test scenarios

### 6.3 Event Emission

Add events to `internal/events/`:

```go
type TaintEvent struct {
    Type       string // "taint_created", "taint_propagated", "taint_removed", "agent_detected"
    PID        int
    SourcePID  int
    SourceName string
    Via        []string
    Depth      int
    IsAgent    bool
    Timestamp  time.Time
}
```

**Tasks:**
- [ ] Define `TaintEvent` struct
- [ ] Emit events from TaintCache operations
- [ ] Emit agent detection events
- [ ] Wire to existing event broker
- [ ] Events visible in `agentsh taint watch`

### 6.4 Documentation

**Tasks:**
- [ ] Add configuration examples to README
- [ ] Document all chain_rules conditions
- [ ] Document built-in classes
- [ ] Add troubleshooting guide for false positives
- [ ] Add example policies for Cursor, Claude Desktop, VS Code

**Deliverables:**
- Full CLI support for taint debugging
- Policy test with ancestry simulation
- Events emitted for all taint operations
- Documentation complete

---

## Summary

| Phase | Key Deliverable | Est. Files | Dependencies |
|-------|----------------|------------|--------------|
| 1 | Taint propagation infrastructure | 6 | internal/process |
| 2 | Cross-platform process matching | 8 | Phase 1 |
| 3 | Chain analysis & escape hatches | 4 | Phase 2 |
| 4 | Policy engine integration | 3 | Phase 3 |
| 5 | Agent detection | 4 | Phase 4 |
| 6 | CLI & observability | 4 | Phase 5 |

## Testing Strategy

- **Unit tests:** Each new file has corresponding `_test.go`
- **Integration tests:** End-to-end tests with mock process tree
- **Platform tests:** Run on Linux, macOS, Windows CI runners
- **Manual testing:** Test with real Cursor/Claude Desktop

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Performance regression | Benchmark taint lookup, target <1ms |
| False positives | Thorough escape hatch testing |
| Platform differences | Abstract behind interfaces |

## Follow-up Work

The following items are intentionally deferred for future work:

### Server Integration
- Wire `ContextEngine` and `TaintCache` into the server request path
- Integrate taint tracking with session lifecycle
- Add process monitor hooks for taint cache updates

### Taint API Endpoints
- Implement `/api/v1/taints` server endpoints
- Add SSE streaming endpoint for taint events
- Update CLI commands to work with live server data

### ProcessContext Advanced Fields
- Implement `max_depth` enforcement during taint propagation
- Implement `stop_at` process class to terminate taint chain
- Implement `pass_through` process class for taint continuation without policy application
| Config complexity | Good defaults, examples, validation |
