# Signal Interception Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add signal interception to agentsh, allowing policies to control which signals processes can send to each other.

**Architecture:** Extend the policy engine with `signal_rules`, add seccomp interception for signal syscalls on Linux, and provide audit-only support on macOS/Windows with graceful fallback.

**Tech Stack:** seccomp user-notify (Linux), libseccomp-golang, existing policy engine patterns

---

## Task 1: Signal Types and Groups

**Files:**
- Create: `internal/signal/types.go`
- Test: `internal/signal/types_test.go`

**Step 1: Write the failing test**

```go
// internal/signal/types_test.go
package signal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignalFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{"SIGKILL", 9, false},
		{"SIGTERM", 15, false},
		{"9", 9, false},
		{"15", 15, false},
		{"INVALID", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			sig, err := SignalFromString(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, sig)
			}
		})
	}
}

func TestExpandSignalGroup(t *testing.T) {
	tests := []struct {
		group    string
		expected []int
		wantErr  bool
	}{
		{"@fatal", []int{9, 15, 3, 6}, false},   // SIGKILL, SIGTERM, SIGQUIT, SIGABRT
		{"@job", []int{19, 18, 20, 21, 22}, false}, // SIGSTOP, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU
		{"@invalid", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.group, func(t *testing.T) {
			signals, err := ExpandSignalGroup(tt.group)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.ElementsMatch(t, tt.expected, signals)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -v`
Expected: FAIL with "package internal/signal is not in std"

**Step 3: Write minimal implementation**

```go
// internal/signal/types.go
package signal

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Signal name to number mapping (Unix signals)
var signalNames = map[string]int{
	"SIGHUP":    int(unix.SIGHUP),
	"SIGINT":    int(unix.SIGINT),
	"SIGQUIT":   int(unix.SIGQUIT),
	"SIGILL":    int(unix.SIGILL),
	"SIGTRAP":   int(unix.SIGTRAP),
	"SIGABRT":   int(unix.SIGABRT),
	"SIGBUS":    int(unix.SIGBUS),
	"SIGFPE":    int(unix.SIGFPE),
	"SIGKILL":   int(unix.SIGKILL),
	"SIGUSR1":   int(unix.SIGUSR1),
	"SIGSEGV":   int(unix.SIGSEGV),
	"SIGUSR2":   int(unix.SIGUSR2),
	"SIGPIPE":   int(unix.SIGPIPE),
	"SIGALRM":   int(unix.SIGALRM),
	"SIGTERM":   int(unix.SIGTERM),
	"SIGCHLD":   int(unix.SIGCHLD),
	"SIGCONT":   int(unix.SIGCONT),
	"SIGSTOP":   int(unix.SIGSTOP),
	"SIGTSTP":   int(unix.SIGTSTP),
	"SIGTTIN":   int(unix.SIGTTIN),
	"SIGTTOU":   int(unix.SIGTTOU),
	"SIGURG":    int(unix.SIGURG),
	"SIGXCPU":   int(unix.SIGXCPU),
	"SIGXFSZ":   int(unix.SIGXFSZ),
	"SIGVTALRM": int(unix.SIGVTALRM),
	"SIGPROF":   int(unix.SIGPROF),
	"SIGWINCH":  int(unix.SIGWINCH),
	"SIGIO":     int(unix.SIGIO),
	"SIGSYS":    int(unix.SIGSYS),
}

// Signal groups for policy convenience
var signalGroups = map[string][]int{
	"@fatal":  {int(unix.SIGKILL), int(unix.SIGTERM), int(unix.SIGQUIT), int(unix.SIGABRT)},
	"@job":    {int(unix.SIGSTOP), int(unix.SIGCONT), int(unix.SIGTSTP), int(unix.SIGTTIN), int(unix.SIGTTOU)},
	"@reload": {int(unix.SIGHUP), int(unix.SIGUSR1), int(unix.SIGUSR2)},
	"@ignore": {int(unix.SIGCHLD), int(unix.SIGURG), int(unix.SIGWINCH)},
}

// SignalFromString converts a signal name or number to its numeric value.
func SignalFromString(s string) (int, error) {
	s = strings.TrimSpace(strings.ToUpper(s))

	// Try as number first
	if num, err := strconv.Atoi(s); err == nil {
		if num > 0 && num < 64 {
			return num, nil
		}
		return 0, fmt.Errorf("signal number out of range: %d", num)
	}

	// Try as name
	if sig, ok := signalNames[s]; ok {
		return sig, nil
	}

	// Try with SIG prefix
	if !strings.HasPrefix(s, "SIG") {
		if sig, ok := signalNames["SIG"+s]; ok {
			return sig, nil
		}
	}

	return 0, fmt.Errorf("unknown signal: %s", s)
}

// SignalName returns the name of a signal number.
func SignalName(sig int) string {
	for name, num := range signalNames {
		if num == sig {
			return name
		}
	}
	return fmt.Sprintf("SIG%d", sig)
}

// ExpandSignalGroup expands a signal group (e.g., "@fatal") to its signal numbers.
func ExpandSignalGroup(group string) ([]int, error) {
	group = strings.ToLower(strings.TrimSpace(group))
	if signals, ok := signalGroups[group]; ok {
		return append([]int{}, signals...), nil
	}
	return nil, fmt.Errorf("unknown signal group: %s", group)
}

// IsSignalGroup returns true if the string is a signal group (starts with @).
func IsSignalGroup(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), "@")
}

// AllSignals returns all signal numbers (1-31 for standard signals).
func AllSignals() []int {
	signals := make([]int, 31)
	for i := range signals {
		signals[i] = i + 1
	}
	return signals
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add internal/signal/types.go internal/signal/types_test.go
git commit -m "feat(signal): add signal types and group expansion

- SignalFromString converts name/number to signal
- ExpandSignalGroup expands @fatal, @job, @reload, @ignore
- SignalName returns human-readable name"
```

---

## Task 2: Target Types for Signal Rules

**Files:**
- Create: `internal/signal/target.go`
- Test: `internal/signal/target_test.go`

**Step 1: Write the failing test**

```go
// internal/signal/target_test.go
package signal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTargetType(t *testing.T) {
	assert.Equal(t, "self", string(TargetSelf))
	assert.Equal(t, "children", string(TargetChildren))
	assert.Equal(t, "external", string(TargetExternal))
	assert.Equal(t, "system", string(TargetSystem))
}

func TestParseTargetSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     TargetSpec
		wantType TargetType
		wantErr  bool
	}{
		{"simple type", TargetSpec{Type: "self"}, TargetSelf, false},
		{"children", TargetSpec{Type: "children"}, TargetChildren, false},
		{"invalid", TargetSpec{Type: "invalid"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseTargetSpec(tt.spec)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantType, parsed.Type)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -v`
Expected: FAIL with undefined: TargetSelf

**Step 3: Write minimal implementation**

```go
// internal/signal/target.go
package signal

import (
	"fmt"
	"strings"

	"github.com/gobwas/glob"
)

// TargetType identifies the category of signal target.
type TargetType string

const (
	TargetSelf        TargetType = "self"
	TargetChildren    TargetType = "children"
	TargetDescendants TargetType = "descendants"
	TargetSiblings    TargetType = "siblings"
	TargetSession     TargetType = "session"
	TargetParent      TargetType = "parent"
	TargetExternal    TargetType = "external"
	TargetSystem      TargetType = "system"
	TargetUser        TargetType = "user"
	TargetProcess     TargetType = "process"
	TargetPIDRange    TargetType = "pid_range"
)

// TargetSpec defines the target of a signal rule from policy YAML.
type TargetSpec struct {
	Type    string `yaml:"type"`
	Pattern string `yaml:"pattern,omitempty"`   // For process name matching
	Min     int    `yaml:"min,omitempty"`       // For pid_range
	Max     int    `yaml:"max,omitempty"`       // For pid_range
}

// ParsedTarget is a validated and compiled target specification.
type ParsedTarget struct {
	Type         TargetType
	ProcessGlob  glob.Glob // For process name matching
	PIDMin       int
	PIDMax       int
}

// validTargetTypes lists all valid target type strings.
var validTargetTypes = map[string]TargetType{
	"self":        TargetSelf,
	"children":    TargetChildren,
	"descendants": TargetDescendants,
	"siblings":    TargetSiblings,
	"session":     TargetSession,
	"parent":      TargetParent,
	"external":    TargetExternal,
	"system":      TargetSystem,
	"user":        TargetUser,
	"process":     TargetProcess,
	"pid_range":   TargetPIDRange,
}

// ParseTargetSpec validates and compiles a target specification.
func ParseTargetSpec(spec TargetSpec) (*ParsedTarget, error) {
	typeStr := strings.ToLower(strings.TrimSpace(spec.Type))
	targetType, ok := validTargetTypes[typeStr]
	if !ok {
		return nil, fmt.Errorf("invalid target type: %s", spec.Type)
	}

	parsed := &ParsedTarget{
		Type:   targetType,
		PIDMin: spec.Min,
		PIDMax: spec.Max,
	}

	// Compile process pattern if specified
	if targetType == TargetProcess && spec.Pattern != "" {
		g, err := glob.Compile(spec.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid process pattern %q: %w", spec.Pattern, err)
		}
		parsed.ProcessGlob = g
	}

	// Validate pid_range
	if targetType == TargetPIDRange {
		if spec.Min <= 0 || spec.Max <= 0 {
			return nil, fmt.Errorf("pid_range requires positive min and max")
		}
		if spec.Min > spec.Max {
			return nil, fmt.Errorf("pid_range min (%d) > max (%d)", spec.Min, spec.Max)
		}
	}

	return parsed, nil
}

// Matches checks if a target PID matches this target specification.
// Requires context about the source process and session membership.
func (t *ParsedTarget) Matches(ctx *TargetContext) bool {
	switch t.Type {
	case TargetSelf:
		return ctx.TargetPID == ctx.SourcePID
	case TargetChildren:
		return ctx.IsChild
	case TargetDescendants:
		return ctx.IsDescendant
	case TargetSiblings:
		return ctx.IsSibling
	case TargetSession:
		return ctx.InSession
	case TargetParent:
		return ctx.IsParent
	case TargetExternal:
		return !ctx.InSession
	case TargetSystem:
		return ctx.TargetPID == 1 || ctx.TargetPID < 100
	case TargetUser:
		return ctx.SameUser && !ctx.InSession
	case TargetProcess:
		if t.ProcessGlob == nil {
			return false
		}
		return t.ProcessGlob.Match(ctx.TargetCmd)
	case TargetPIDRange:
		return ctx.TargetPID >= t.PIDMin && ctx.TargetPID <= t.PIDMax
	default:
		return false
	}
}

// TargetContext provides information about the signal source and target.
type TargetContext struct {
	SourcePID    int
	TargetPID    int
	TargetCmd    string
	IsChild      bool
	IsDescendant bool
	IsSibling    bool
	IsParent     bool
	InSession    bool
	SameUser     bool
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add internal/signal/target.go internal/signal/target_test.go
git commit -m "feat(signal): add target type definitions and matching

- TargetType enum for self, children, external, system, etc.
- TargetSpec for YAML parsing
- ParsedTarget with glob compilation
- Matches() for evaluating targets"
```

---

## Task 3: Add SignalRule to Policy Model

**Files:**
- Modify: `internal/policy/model.go`
- Test: `internal/policy/model_test.go` (add test)

**Step 1: Write the failing test**

```go
// Add to internal/policy/model_test.go (or create if doesn't exist)
func TestSignalRuleParsing(t *testing.T) {
	yaml := `
version: 1
name: test
signal_rules:
  - name: block-external-kill
    signals: ["@fatal", "SIGKILL"]
    target:
      type: external
    decision: deny
    fallback: audit
`
	var p Policy
	err := yamlv3.Unmarshal([]byte(yaml), &p)
	require.NoError(t, err)
	require.Len(t, p.SignalRules, 1)
	assert.Equal(t, "block-external-kill", p.SignalRules[0].Name)
	assert.Equal(t, []string{"@fatal", "SIGKILL"}, p.SignalRules[0].Signals)
	assert.Equal(t, "external", p.SignalRules[0].Target.Type)
	assert.Equal(t, "deny", p.SignalRules[0].Decision)
	assert.Equal(t, "audit", p.SignalRules[0].Fallback)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/policy/... -run TestSignalRule -v`
Expected: FAIL with "p.SignalRules undefined"

**Step 3: Write minimal implementation**

Add to `internal/policy/model.go`:

```go
// Add to Policy struct (after RegistryRules):
SignalRules   []SignalRule     `yaml:"signal_rules"`

// Add new type after RegistryRule:

// SignalRule controls signal sending between processes.
type SignalRule struct {
	Name        string           `yaml:"name"`
	Description string           `yaml:"description"`
	Signals     []string         `yaml:"signals"`     // Signal names, numbers, or groups (@fatal, @job)
	Target      SignalTargetSpec `yaml:"target"`      // Who can receive the signal
	Decision    string           `yaml:"decision"`    // allow, deny, audit, approve, redirect, absorb
	Fallback    string           `yaml:"fallback"`    // Fallback decision if platform can't enforce
	RedirectTo  string           `yaml:"redirect_to"` // For redirect: target signal
	Message     string           `yaml:"message"`
	Timeout     duration         `yaml:"timeout"`
}

// SignalTargetSpec defines the target of a signal rule.
type SignalTargetSpec struct {
	Type    string `yaml:"type"`              // self, children, external, system, etc.
	Pattern string `yaml:"pattern,omitempty"` // For process name matching
	Min     int    `yaml:"min,omitempty"`     // For pid_range
	Max     int    `yaml:"max,omitempty"`     // For pid_range
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/policy/... -run TestSignalRule -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add internal/policy/model.go internal/policy/model_test.go
git commit -m "feat(policy): add SignalRule to policy model

- SignalRule with signals, target, decision, fallback
- SignalTargetSpec for target configuration
- Supports signal groups (@fatal), names, and numbers"
```

---

## Task 4: Session PID Registry

**Files:**
- Create: `internal/signal/registry.go`
- Test: `internal/signal/registry_test.go`

**Step 1: Write the failing test**

```go
// internal/signal/registry_test.go
package signal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPIDRegistry(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000) // supervisor PID 1000

	// Register some processes
	r.Register(1001, 1000, "bash")    // child of supervisor
	r.Register(1002, 1001, "python")  // grandchild
	r.Register(1003, 1000, "node")    // another child

	// Test classification
	ctx := r.ClassifyTarget(1001, 1001) // self
	assert.True(t, ctx.SourcePID == ctx.TargetPID)

	ctx = r.ClassifyTarget(1001, 1002) // child
	assert.True(t, ctx.IsChild)

	ctx = r.ClassifyTarget(1001, 1003) // sibling
	assert.True(t, ctx.IsSibling)

	ctx = r.ClassifyTarget(1001, 1000) // parent (supervisor)
	assert.True(t, ctx.IsParent)

	ctx = r.ClassifyTarget(1001, 9999) // external
	assert.False(t, ctx.InSession)
}

func TestPIDRegistryUnregister(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)
	r.Register(1001, 1000, "bash")

	ctx := r.ClassifyTarget(1000, 1001)
	assert.True(t, ctx.InSession)

	r.Unregister(1001)

	ctx = r.ClassifyTarget(1000, 1001)
	assert.False(t, ctx.InSession)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestPIDRegistry -v`
Expected: FAIL with undefined: NewPIDRegistry

**Step 3: Write minimal implementation**

```go
// internal/signal/registry.go
package signal

import (
	"sync"
)

// PIDRegistry tracks process membership in a session.
type PIDRegistry struct {
	mu            sync.RWMutex
	sessionID     string
	supervisorPID int

	// pid -> parent pid
	parents map[int]int
	// pid -> command name
	commands map[int]string
	// pid -> child pids
	children map[int][]int
}

// NewPIDRegistry creates a new registry for a session.
func NewPIDRegistry(sessionID string, supervisorPID int) *PIDRegistry {
	return &PIDRegistry{
		sessionID:     sessionID,
		supervisorPID: supervisorPID,
		parents:       make(map[int]int),
		commands:      make(map[int]string),
		children:      make(map[int][]int),
	}
}

// Register adds a process to the session.
func (r *PIDRegistry) Register(pid, parentPID int, command string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.parents[pid] = parentPID
	r.commands[pid] = command
	r.children[parentPID] = append(r.children[parentPID], pid)
}

// Unregister removes a process from the session.
func (r *PIDRegistry) Unregister(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	parentPID := r.parents[pid]
	delete(r.parents, pid)
	delete(r.commands, pid)

	// Remove from parent's children
	if children, ok := r.children[parentPID]; ok {
		for i, child := range children {
			if child == pid {
				r.children[parentPID] = append(children[:i], children[i+1:]...)
				break
			}
		}
	}
	delete(r.children, pid)
}

// InSession checks if a PID is part of this session.
func (r *PIDRegistry) InSession(pid int) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if pid == r.supervisorPID {
		return true
	}
	_, ok := r.parents[pid]
	return ok
}

// ClassifyTarget determines the relationship between source and target PIDs.
func (r *PIDRegistry) ClassifyTarget(sourcePID, targetPID int) *TargetContext {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ctx := &TargetContext{
		SourcePID: sourcePID,
		TargetPID: targetPID,
		TargetCmd: r.commands[targetPID],
		InSession: r.inSessionLocked(targetPID),
		SameUser:  true, // TODO: check actual user
	}

	// Self
	if sourcePID == targetPID {
		return ctx
	}

	// Parent (supervisor or direct parent)
	if targetPID == r.supervisorPID {
		ctx.IsParent = true
		return ctx
	}
	if r.parents[sourcePID] == targetPID {
		ctx.IsParent = true
		return ctx
	}

	// Direct child
	if r.parents[targetPID] == sourcePID {
		ctx.IsChild = true
		ctx.IsDescendant = true
		return ctx
	}

	// Descendant (grandchild, etc.)
	if r.isDescendantLocked(sourcePID, targetPID) {
		ctx.IsDescendant = true
		return ctx
	}

	// Sibling (same parent)
	if r.parents[sourcePID] == r.parents[targetPID] && r.parents[sourcePID] != 0 {
		ctx.IsSibling = true
		return ctx
	}

	return ctx
}

func (r *PIDRegistry) inSessionLocked(pid int) bool {
	if pid == r.supervisorPID {
		return true
	}
	_, ok := r.parents[pid]
	return ok
}

func (r *PIDRegistry) isDescendantLocked(ancestorPID, pid int) bool {
	current := pid
	for {
		parent, ok := r.parents[current]
		if !ok {
			return false
		}
		if parent == ancestorPID {
			return true
		}
		current = parent
	}
}

// SupervisorPID returns the supervisor PID.
func (r *PIDRegistry) SupervisorPID() int {
	return r.supervisorPID
}

// SessionID returns the session ID.
func (r *PIDRegistry) SessionID() string {
	return r.sessionID
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestPIDRegistry -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add internal/signal/registry.go internal/signal/registry_test.go
git commit -m "feat(signal): add PID registry for session tracking

- Track parent/child relationships
- ClassifyTarget determines relationship type
- Thread-safe with RWMutex"
```

---

## Task 5: Signal Policy Engine

**Files:**
- Create: `internal/signal/engine.go`
- Test: `internal/signal/engine_test.go`

**Step 1: Write the failing test**

```go
// internal/signal/engine_test.go
package signal

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignalEngine(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "deny-external-kill",
			Signals:  []string{"@fatal"},
			Target:   policy.SignalTargetSpec{Type: "external"},
			Decision: "deny",
		},
		{
			Name:     "allow-self",
			Signals:  []string{"@all"},
			Target:   policy.SignalTargetSpec{Type: "self"},
			Decision: "allow",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	// Test deny external
	ctx := registry.ClassifyTarget(1001, 9999)
	dec := engine.Check(9, ctx) // SIGKILL to external
	assert.Equal(t, DecisionDeny, dec.Action)

	// Test allow self
	ctx = registry.ClassifyTarget(1001, 1001)
	dec = engine.Check(15, ctx) // SIGTERM to self
	assert.Equal(t, DecisionAllow, dec.Action)
}

func TestSignalEngineRedirect(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:       "redirect-kill-to-term",
			Signals:    []string{"SIGKILL"},
			Target:     policy.SignalTargetSpec{Type: "children"},
			Decision:   "redirect",
			RedirectTo: "SIGTERM",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	ctx := registry.ClassifyTarget(1000, 1001)
	ctx.IsChild = true

	dec := engine.Check(9, ctx) // SIGKILL to child
	assert.Equal(t, DecisionRedirect, dec.Action)
	assert.Equal(t, 15, dec.RedirectSignal) // SIGTERM
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestSignalEngine -v`
Expected: FAIL with undefined: NewEngine

**Step 3: Write minimal implementation**

```go
// internal/signal/engine.go
package signal

import (
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/policy"
)

// DecisionAction represents the action to take for a signal.
type DecisionAction string

const (
	DecisionAllow    DecisionAction = "allow"
	DecisionDeny     DecisionAction = "deny"
	DecisionAudit    DecisionAction = "audit"
	DecisionApprove  DecisionAction = "approve"
	DecisionRedirect DecisionAction = "redirect"
	DecisionAbsorb   DecisionAction = "absorb"
)

// Decision is the result of evaluating a signal against policy.
type Decision struct {
	Action         DecisionAction
	Rule           string
	Message        string
	RedirectSignal int    // For redirect: the new signal
	Fallback       string // Original fallback for platform limitations
}

// compiledSignalRule is a pre-processed signal rule.
type compiledSignalRule struct {
	rule    policy.SignalRule
	signals map[int]struct{} // Expanded signal numbers
	target  *ParsedTarget
	redirect int // For redirect decision
}

// Engine evaluates signals against policy rules.
type Engine struct {
	rules []compiledSignalRule
}

// NewEngine creates a signal policy engine from rules.
func NewEngine(rules []policy.SignalRule) (*Engine, error) {
	e := &Engine{}

	for _, r := range rules {
		cr := compiledSignalRule{
			rule:    r,
			signals: make(map[int]struct{}),
		}

		// Expand signals
		for _, s := range r.Signals {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}

			if s == "@all" {
				for _, sig := range AllSignals() {
					cr.signals[sig] = struct{}{}
				}
			} else if IsSignalGroup(s) {
				sigs, err := ExpandSignalGroup(s)
				if err != nil {
					return nil, fmt.Errorf("rule %q: %w", r.Name, err)
				}
				for _, sig := range sigs {
					cr.signals[sig] = struct{}{}
				}
			} else {
				sig, err := SignalFromString(s)
				if err != nil {
					return nil, fmt.Errorf("rule %q: %w", r.Name, err)
				}
				cr.signals[sig] = struct{}{}
			}
		}

		// Parse target
		target, err := ParseTargetSpec(TargetSpec{
			Type:    r.Target.Type,
			Pattern: r.Target.Pattern,
			Min:     r.Target.Min,
			Max:     r.Target.Max,
		})
		if err != nil {
			return nil, fmt.Errorf("rule %q target: %w", r.Name, err)
		}
		cr.target = target

		// Parse redirect signal
		if strings.ToLower(r.Decision) == "redirect" && r.RedirectTo != "" {
			sig, err := SignalFromString(r.RedirectTo)
			if err != nil {
				return nil, fmt.Errorf("rule %q redirect_to: %w", r.Name, err)
			}
			cr.redirect = sig
		}

		e.rules = append(e.rules, cr)
	}

	return e, nil
}

// Check evaluates a signal against the policy.
func (e *Engine) Check(signal int, ctx *TargetContext) Decision {
	for _, r := range e.rules {
		// Check if signal matches
		if _, ok := r.signals[signal]; !ok {
			continue
		}

		// Check if target matches
		if !r.target.Matches(ctx) {
			continue
		}

		// Rule matched
		action := DecisionAction(strings.ToLower(r.rule.Decision))
		dec := Decision{
			Action:   action,
			Rule:     r.rule.Name,
			Message:  r.rule.Message,
			Fallback: r.rule.Fallback,
		}

		if action == DecisionRedirect {
			dec.RedirectSignal = r.redirect
		}

		return dec
	}

	// Default deny
	return Decision{
		Action: DecisionDeny,
		Rule:   "default-deny-signals",
	}
}

// CanBlock returns true if the platform can enforce blocking.
func CanBlock() bool {
	// TODO: Detect platform capabilities
	return true
}

// ApplyFallback returns the effective decision based on platform capabilities.
func ApplyFallback(dec Decision, canBlock bool) Decision {
	if !canBlock && (dec.Action == DecisionDeny || dec.Action == DecisionRedirect || dec.Action == DecisionAbsorb) {
		if dec.Fallback != "" {
			dec.Action = DecisionAction(strings.ToLower(dec.Fallback))
		} else {
			dec.Action = DecisionAudit // Default fallback
		}
	}
	return dec
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestSignalEngine -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add internal/signal/engine.go internal/signal/engine_test.go
git commit -m "feat(signal): add signal policy engine

- Compile signal rules with group expansion
- Check() evaluates signal against rules
- Support for redirect, deny, allow, audit, approve, absorb
- ApplyFallback for platform limitations"
```

---

## Task 6: Add Signal Events

**Files:**
- Modify: `internal/events/types.go`

**Step 1: Write the failing test**

```go
// Add to internal/events/types_test.go
func TestSignalEventTypes(t *testing.T) {
	assert.Equal(t, EventType("signal_sent"), EventSignalSent)
	assert.Equal(t, EventType("signal_blocked"), EventSignalBlocked)
	assert.Equal(t, "signal", EventCategory[EventSignalBlocked])
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/events/... -run TestSignalEvent -v`
Expected: FAIL with undefined: EventSignalSent

**Step 3: Write minimal implementation**

Add to `internal/events/types.go`:

```go
// Signal events.
const (
	EventSignalSent       EventType = "signal_sent"
	EventSignalBlocked    EventType = "signal_blocked"
	EventSignalRedirected EventType = "signal_redirected"
	EventSignalAbsorbed   EventType = "signal_absorbed"
	EventSignalApproved   EventType = "signal_approved"
	EventSignalWouldDeny  EventType = "signal_would_deny"
)

// Add to EventCategory map:
// Signal
EventSignalSent:       "signal",
EventSignalBlocked:    "signal",
EventSignalRedirected: "signal",
EventSignalAbsorbed:   "signal",
EventSignalApproved:   "signal",
EventSignalWouldDeny:  "signal",

// Add to AllEventTypes slice:
// Signal
EventSignalSent, EventSignalBlocked, EventSignalRedirected,
EventSignalAbsorbed, EventSignalApproved, EventSignalWouldDeny,
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/events/... -run TestSignalEvent -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add internal/events/types.go internal/events/types_test.go
git commit -m "feat(events): add signal event types

- signal_sent, signal_blocked, signal_redirected
- signal_absorbed, signal_approved, signal_would_deny
- Add to EventCategory and AllEventTypes"
```

---

## Task 7: Linux Seccomp Filter for Signals

**Files:**
- Create: `internal/signal/seccomp_linux.go`
- Create: `internal/signal/seccomp_stub.go` (non-Linux)
- Test: `internal/signal/seccomp_linux_test.go`

**Step 1: Write the failing test**

```go
//go:build linux && cgo

// internal/signal/seccomp_linux_test.go
package signal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestSignalSyscalls(t *testing.T) {
	// Verify we have the right syscall numbers
	assert.Equal(t, 62, unix.SYS_KILL)
	assert.Equal(t, 234, unix.SYS_TGKILL)
}

func TestSignalFilterConfig(t *testing.T) {
	cfg := DefaultSignalFilterConfig()
	assert.True(t, cfg.Enabled)
	assert.Contains(t, cfg.Syscalls, unix.SYS_KILL)
	assert.Contains(t, cfg.Syscalls, unix.SYS_TGKILL)
	assert.Contains(t, cfg.Syscalls, unix.SYS_TKILL)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestSignalFilter -v`
Expected: FAIL with undefined: DefaultSignalFilterConfig

**Step 3: Write minimal implementation**

```go
//go:build linux && cgo

// internal/signal/seccomp_linux.go
package signal

import (
	"fmt"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// SignalFilterConfig configures signal syscall interception.
type SignalFilterConfig struct {
	Enabled  bool
	Syscalls []int
}

// DefaultSignalFilterConfig returns config for all signal syscalls.
func DefaultSignalFilterConfig() SignalFilterConfig {
	return SignalFilterConfig{
		Enabled: true,
		Syscalls: []int{
			unix.SYS_KILL,
			unix.SYS_TGKILL,
			unix.SYS_TKILL,
			unix.SYS_RT_SIGQUEUEINFO,
			unix.SYS_RT_TGSIGQUEUEINFO,
			// pidfd_send_signal is 424 on x86_64
		},
	}
}

// SignalFilter encapsulates a loaded seccomp filter for signal syscalls.
type SignalFilter struct {
	fd seccomp.ScmpFd
}

// InstallSignalFilter installs a user-notify seccomp filter for signal syscalls.
func InstallSignalFilter(cfg SignalFilterConfig) (*SignalFilter, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	// Check API version
	api, err := seccomp.GetAPI()
	if err != nil {
		return nil, fmt.Errorf("get seccomp api: %w", err)
	}
	if api < 6 {
		return nil, fmt.Errorf("seccomp API version %d lacks user notify", api)
	}

	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, err
	}

	trap := seccomp.ActNotify
	for _, nr := range cfg.Syscalls {
		sc := seccomp.ScmpSyscall(nr)
		if err := filt.AddRule(sc, trap); err != nil {
			return nil, fmt.Errorf("add signal rule %v: %w", sc, err)
		}
	}

	if err := filt.Load(); err != nil {
		return nil, err
	}

	fd, err := filt.GetNotifFd()
	if err != nil {
		return nil, err
	}

	return &SignalFilter{fd: fd}, nil
}

// NotifFD returns the notify fd for polling.
func (f *SignalFilter) NotifFD() int {
	if f == nil {
		return -1
	}
	return int(f.fd)
}

// Close closes the filter.
func (f *SignalFilter) Close() error {
	if f == nil || f.fd < 0 {
		return nil
	}
	return unix.Close(int(f.fd))
}

// Receive receives one seccomp notification.
func (f *SignalFilter) Receive() (*seccomp.ScmpNotifReq, error) {
	return seccomp.NotifReceive(f.fd)
}

// Respond replies to a notification.
func (f *SignalFilter) Respond(reqID uint64, allow bool, errno int32) error {
	resp := seccomp.ScmpNotifResp{ID: reqID}
	if allow {
		resp.Error = 0
		resp.Val = 0
		resp.Flags = seccomp.NotifRespFlagContinue
	} else {
		resp.Error = -errno
	}
	return seccomp.NotifRespond(f.fd, &resp)
}

// RespondWithValue replies with a specific return value (for absorb).
func (f *SignalFilter) RespondWithValue(reqID uint64, val int64) error {
	resp := seccomp.ScmpNotifResp{
		ID:    reqID,
		Error: 0,
		Val:   val,
	}
	return seccomp.NotifRespond(f.fd, &resp)
}

// SignalContext holds context for a trapped signal syscall.
type SignalContext struct {
	PID       int
	Syscall   int
	TargetPID int
	Signal    int
}

// ExtractSignalContext extracts signal info from a notify request.
func ExtractSignalContext(req *seccomp.ScmpNotifReq) SignalContext {
	ctx := SignalContext{
		PID:     int(req.Pid),
		Syscall: int(req.Data.Syscall),
	}

	switch int(req.Data.Syscall) {
	case unix.SYS_KILL:
		// kill(pid, sig)
		ctx.TargetPID = int(req.Data.Args[0])
		ctx.Signal = int(req.Data.Args[1])
	case unix.SYS_TGKILL:
		// tgkill(tgid, tid, sig)
		ctx.TargetPID = int(req.Data.Args[0]) // tgid
		ctx.Signal = int(req.Data.Args[2])
	case unix.SYS_TKILL:
		// tkill(tid, sig)
		ctx.TargetPID = int(req.Data.Args[0])
		ctx.Signal = int(req.Data.Args[1])
	case unix.SYS_RT_SIGQUEUEINFO:
		// rt_sigqueueinfo(pid, sig, info)
		ctx.TargetPID = int(req.Data.Args[0])
		ctx.Signal = int(req.Data.Args[1])
	case unix.SYS_RT_TGSIGQUEUEINFO:
		// rt_tgsigqueueinfo(tgid, tid, sig, info)
		ctx.TargetPID = int(req.Data.Args[0])
		ctx.Signal = int(req.Data.Args[2])
	}

	return ctx
}

// ModifySignal modifies the signal argument for redirect.
// Note: This requires SECCOMP_IOCTL_NOTIF_ADDFD which is complex.
// For now, we deny and expect caller to re-send with correct signal.
func (f *SignalFilter) ModifySignal(reqID uint64, newSignal int) error {
	// TODO: Implement actual signal modification using SECCOMP_IOCTL_NOTIF_ADDFD
	// For now, return error to indicate caller should use a different approach
	return fmt.Errorf("signal modification not yet implemented")
}

// IsSignalSupportAvailable checks if signal interception is available.
func IsSignalSupportAvailable() bool {
	api, err := seccomp.GetAPI()
	if err != nil {
		return false
	}
	return api >= 6
}
```

**Step 4: Create stub for non-Linux**

```go
//go:build !linux || !cgo

// internal/signal/seccomp_stub.go
package signal

import "fmt"

// SignalFilterConfig configures signal syscall interception.
type SignalFilterConfig struct {
	Enabled  bool
	Syscalls []int
}

// DefaultSignalFilterConfig returns config (disabled on non-Linux).
func DefaultSignalFilterConfig() SignalFilterConfig {
	return SignalFilterConfig{Enabled: false}
}

// SignalFilter is a stub for non-Linux platforms.
type SignalFilter struct{}

// InstallSignalFilter is a stub that returns nil on non-Linux.
func InstallSignalFilter(cfg SignalFilterConfig) (*SignalFilter, error) {
	return nil, nil
}

func (f *SignalFilter) NotifFD() int              { return -1 }
func (f *SignalFilter) Close() error              { return nil }
func (f *SignalFilter) Receive() (interface{}, error) { return nil, fmt.Errorf("not supported") }
func (f *SignalFilter) Respond(reqID uint64, allow bool, errno int32) error { return nil }
func (f *SignalFilter) RespondWithValue(reqID uint64, val int64) error { return nil }

// SignalContext holds context for a trapped signal syscall.
type SignalContext struct {
	PID       int
	Syscall   int
	TargetPID int
	Signal    int
}

// IsSignalSupportAvailable returns false on non-Linux.
func IsSignalSupportAvailable() bool {
	return false
}
```

**Step 5: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestSignal -v`
Expected: PASS

**Step 6: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add internal/signal/seccomp_linux.go internal/signal/seccomp_stub.go internal/signal/seccomp_linux_test.go
git commit -m "feat(signal): add Linux seccomp filter for signal syscalls

- Intercept kill, tgkill, tkill, rt_sigqueueinfo, rt_tgsigqueueinfo
- ExtractSignalContext parses syscall arguments
- Stub implementation for non-Linux platforms"
```

---

## Task 8: Signal Notify Handler

**Files:**
- Create: `internal/signal/handler.go`
- Test: `internal/signal/handler_test.go`

**Step 1: Write the failing test**

```go
// internal/signal/handler_test.go
package signal

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandlerEvaluate(t *testing.T) {
	rules := []policy.SignalRule{
		{
			Name:     "deny-external",
			Signals:  []string{"SIGKILL"},
			Target:   policy.SignalTargetSpec{Type: "external"},
			Decision: "deny",
		},
	}

	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("sess-1", 1000)
	registry.Register(1001, 1000, "bash")

	handler := NewHandler(engine, registry, nil)

	// Test deny external
	dec := handler.Evaluate(SignalContext{
		PID:       1001,
		TargetPID: 9999,
		Signal:    9,
	})
	assert.Equal(t, DecisionDeny, dec.Action)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestHandler -v`
Expected: FAIL with undefined: NewHandler

**Step 3: Write minimal implementation**

```go
// internal/signal/handler.go
package signal

import (
	"context"
	"log/slog"
	"time"

	"github.com/agentsh/agentsh/internal/events"
)

// EventEmitter is an interface for emitting audit events.
type EventEmitter interface {
	Emit(ctx context.Context, eventType events.EventType, data map[string]interface{})
}

// Handler processes signal syscall notifications.
type Handler struct {
	engine   *Engine
	registry *PIDRegistry
	emitter  EventEmitter
	logger   *slog.Logger
}

// NewHandler creates a new signal handler.
func NewHandler(engine *Engine, registry *PIDRegistry, emitter EventEmitter) *Handler {
	return &Handler{
		engine:   engine,
		registry: registry,
		emitter:  emitter,
		logger:   slog.Default(),
	}
}

// Evaluate checks a signal against policy and returns the decision.
func (h *Handler) Evaluate(ctx SignalContext) Decision {
	targetCtx := h.registry.ClassifyTarget(ctx.PID, ctx.TargetPID)
	return h.engine.Check(ctx.Signal, targetCtx)
}

// Handle processes a signal notification and emits appropriate events.
func (h *Handler) Handle(ctx context.Context, sigCtx SignalContext) Decision {
	dec := h.Evaluate(sigCtx)

	// Apply platform fallback
	dec = ApplyFallback(dec, IsSignalSupportAvailable())

	// Emit event
	h.emitEvent(ctx, sigCtx, dec)

	return dec
}

func (h *Handler) emitEvent(ctx context.Context, sigCtx SignalContext, dec Decision) {
	if h.emitter == nil {
		return
	}

	var eventType events.EventType
	switch dec.Action {
	case DecisionAllow:
		eventType = events.EventSignalSent
	case DecisionDeny:
		eventType = events.EventSignalBlocked
	case DecisionRedirect:
		eventType = events.EventSignalRedirected
	case DecisionAbsorb:
		eventType = events.EventSignalAbsorbed
	case DecisionAudit:
		eventType = events.EventSignalSent
	default:
		eventType = events.EventSignalSent
	}

	// Check if this is a fallback (would_deny)
	if dec.Fallback != "" && (dec.Action == DecisionAudit || dec.Action == DecisionAllow) {
		eventType = events.EventSignalWouldDeny
	}

	data := map[string]interface{}{
		"source_pid":  sigCtx.PID,
		"target_pid":  sigCtx.TargetPID,
		"signal":      sigCtx.Signal,
		"signal_name": SignalName(sigCtx.Signal),
		"syscall":     sigCtx.Syscall,
		"decision":    string(dec.Action),
		"rule":        dec.Rule,
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
	}

	if dec.Message != "" {
		data["message"] = dec.Message
	}
	if dec.RedirectSignal != 0 {
		data["redirect_to"] = dec.RedirectSignal
		data["redirect_to_name"] = SignalName(dec.RedirectSignal)
	}
	if dec.Fallback != "" {
		data["fallback"] = true
		data["original_action"] = dec.Fallback
	}

	h.emitter.Emit(ctx, eventType, data)
}

// SetLogger sets the logger for the handler.
func (h *Handler) SetLogger(logger *slog.Logger) {
	h.logger = logger
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestHandler -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add internal/signal/handler.go internal/signal/handler_test.go
git commit -m "feat(signal): add signal notification handler

- Evaluate() checks signal against policy
- Handle() applies fallback and emits events
- Integrates with EventEmitter for audit logging"
```

---

## Task 9: Integrate Signal Rules into Policy Engine

**Files:**
- Modify: `internal/policy/engine.go`
- Test: Add to existing tests

**Step 1: Write the failing test**

```go
// Add to internal/policy/engine_test.go
func TestEngineCheckSignal(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		SignalRules: []SignalRule{
			{
				Name:     "deny-kill-external",
				Signals:  []string{"SIGKILL"},
				Target:   SignalTargetSpec{Type: "external"},
				Decision: "deny",
			},
		},
	}

	engine, err := NewEngine(p, false)
	require.NoError(t, err)

	// Create signal engine
	sigEngine := engine.SignalEngine()
	require.NotNil(t, sigEngine)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/policy/... -run TestEngineCheckSignal -v`
Expected: FAIL with "engine.SignalEngine undefined"

**Step 3: Write minimal implementation**

Add to `internal/policy/engine.go`:

```go
import (
	"github.com/agentsh/agentsh/internal/signal"
)

// Add to Engine struct:
signalEngine *signal.Engine

// Add to NewEngine after other rule compilation:
// Compile signal rules
if len(p.SignalRules) > 0 {
	sigEngine, err := signal.NewEngine(p.SignalRules)
	if err != nil {
		return nil, fmt.Errorf("compile signal rules: %w", err)
	}
	e.signalEngine = sigEngine
}

// Add method:
// SignalEngine returns the signal policy engine, or nil if no signal rules.
func (e *Engine) SignalEngine() *signal.Engine {
	return e.signalEngine
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/policy/... -run TestEngineCheckSignal -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add internal/policy/engine.go internal/policy/engine_test.go
git commit -m "feat(policy): integrate signal engine into policy engine

- Compile signal rules in NewEngine
- SignalEngine() returns the signal policy engine"
```

---

## Task 10: Add Example Signal Policy

**Files:**
- Modify: `configs/policies/dev-safe.yaml`
- Create: `configs/policies/signal-strict.yaml`

**Step 1: Add signal rules to dev-safe.yaml**

Add to the end of `configs/policies/dev-safe.yaml`:

```yaml
# Signal rules (Linux: enforced, macOS/Windows: audit only)
signal_rules:
  # Allow signals to self
  - name: allow-self
    signals: ["@all"]
    target:
      type: self
    decision: allow

  # Allow signals to children
  - name: allow-children
    signals: ["@all"]
    target:
      type: children
    decision: allow

  # Allow signals within session
  - name: allow-session
    signals: ["SIGTERM", "SIGINT", "SIGHUP", "SIGUSR1", "SIGUSR2"]
    target:
      type: session
    decision: allow

  # Audit signals to parent (supervisor)
  - name: audit-parent
    signals: ["@all"]
    target:
      type: parent
    decision: audit

  # Deny fatal signals to external processes
  - name: deny-external-fatal
    signals: ["@fatal"]
    target:
      type: external
    decision: deny
    fallback: audit
    message: "Blocking signal to process outside session"

  # Deny all signals to system processes
  - name: deny-system
    signals: ["@all"]
    target:
      type: system
    decision: deny
    fallback: audit
    message: "Blocking signal to system process"
```

**Step 2: Create signal-strict.yaml**

```yaml
# Signal Strict Policy
# Maximum signal control - deny most signals, require approval for sensitive operations

version: 1
name: signal-strict
description: Strict signal control policy for high-security environments

signal_rules:
  # Allow signals to self only
  - name: allow-self
    signals: ["@all"]
    target:
      type: self
    decision: allow

  # Allow graceful termination of children
  - name: allow-graceful-children
    signals: ["SIGTERM", "SIGINT"]
    target:
      type: children
    decision: allow

  # Redirect SIGKILL to SIGTERM for children (graceful shutdown)
  - name: redirect-kill-to-term
    signals: ["SIGKILL"]
    target:
      type: children
    decision: redirect
    redirect_to: SIGTERM
    message: "Redirecting SIGKILL to SIGTERM for graceful shutdown"

  # Require approval for job control signals
  - name: approve-job-control
    signals: ["@job"]
    target:
      type: session
    decision: approve
    message: "Job control signal requires approval"

  # Deny all signals to parent
  - name: deny-parent
    signals: ["@all"]
    target:
      type: parent
    decision: deny
    fallback: audit
    message: "Signals to supervisor are blocked"

  # Deny all signals to external
  - name: deny-external
    signals: ["@all"]
    target:
      type: external
    decision: deny
    fallback: audit
    message: "Signals to external processes are blocked"

  # Deny all signals to system
  - name: deny-system
    signals: ["@all"]
    target:
      type: system
    decision: deny
    fallback: audit
    message: "Signals to system processes are blocked"
```

**Step 3: Validate policies parse correctly**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/policy/... -v`
Expected: PASS

**Step 4: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add configs/policies/dev-safe.yaml configs/policies/signal-strict.yaml
git commit -m "feat(policy): add signal rules to policies

- Add signal_rules to dev-safe.yaml
- Create signal-strict.yaml for high-security environments
- Support redirect, deny, allow, audit, approve decisions"
```

---

## Task 11: Update Documentation

**Files:**
- Modify: `docs/operations/policies.md`

**Step 1: Add signal rules documentation**

Add new section to `docs/operations/policies.md`:

```markdown
## Signal Rules

Signal rules control which signals processes can send to each other. This provides protection against:
- Processes killing the agentsh supervisor
- Processes killing sibling processes
- Processes killing external system processes

### Platform Support

| Platform | Blocking | Redirect | Audit |
|----------|----------|----------|-------|
| Linux | Yes (seccomp) | Yes | Yes |
| macOS | No | No | Yes (ES) |
| Windows | Partial | No | Yes (ETW) |

On platforms that don't support blocking, use `fallback: audit` to log violations.

### Signal Specification

Signals can be specified as:
- **Name:** `SIGKILL`, `SIGTERM`, `SIGHUP`, etc.
- **Number:** `9`, `15`, `1`, etc.
- **Group:** `@fatal`, `@job`, `@reload`, `@ignore`, `@all`

**Predefined groups:**

| Group | Signals |
|-------|---------|
| `@fatal` | SIGKILL, SIGTERM, SIGQUIT, SIGABRT |
| `@job` | SIGSTOP, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU |
| `@reload` | SIGHUP, SIGUSR1, SIGUSR2 |
| `@ignore` | SIGCHLD, SIGURG, SIGWINCH |
| `@all` | All signals (1-31) |

### Target Types

| Type | Description |
|------|-------------|
| `self` | Process sending to itself |
| `children` | Direct children of sender |
| `descendants` | All descendants (children, grandchildren, etc.) |
| `siblings` | Other processes with same parent |
| `session` | Any process in the agentsh session |
| `parent` | The agentsh supervisor |
| `external` | Any PID outside the session |
| `system` | PID 1 and kernel threads (PID < 100) |
| `user` | Other processes owned by same user |
| `process` | Match by process name pattern |
| `pid_range` | Match by PID range |

### Decision Types

| Decision | Behavior |
|----------|----------|
| `allow` | Allow signal |
| `deny` | Block signal (EPERM) |
| `audit` | Allow + log |
| `approve` | Require manual approval |
| `redirect` | Change signal (e.g., SIGKILL → SIGTERM) |
| `absorb` | Silently drop (no error to sender) |

### Example

```yaml
signal_rules:
  # Allow signals to self and children
  - name: allow-self-and-children
    signals: ["@all"]
    target:
      type: self
    decision: allow

  # Redirect SIGKILL to SIGTERM for graceful shutdown
  - name: graceful-kill
    signals: ["SIGKILL"]
    target:
      type: children
    decision: redirect
    redirect_to: SIGTERM

  # Block fatal signals to external processes
  - name: deny-external-fatal
    signals: ["@fatal"]
    target:
      type: external
    decision: deny
    fallback: audit  # Audit on platforms that can't block
    message: "Blocking signal to external process"

  # Block signals to specific processes
  - name: protect-database
    signals: ["@fatal"]
    target:
      type: process
      pattern: "postgres*"
    decision: deny
```
```

**Step 2: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add docs/operations/policies.md
git commit -m "docs: add signal rules documentation

- Platform support matrix
- Signal specification (names, numbers, groups)
- Target types explanation
- Decision types and examples"
```

---

## Task 12: Integration Tests

**Files:**
- Create: `internal/signal/integration_test.go`

**Step 1: Write integration test**

```go
//go:build linux && cgo && integration

// internal/signal/integration_test.go
package signal_test

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/signal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignalInterceptionE2E(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for seccomp")
	}

	if !signal.IsSignalSupportAvailable() {
		t.Skip("seccomp user notify not available")
	}

	// Create policy
	rules := []policy.SignalRule{
		{
			Name:     "deny-external",
			Signals:  []string{"SIGKILL", "SIGTERM"},
			Target:   policy.SignalTargetSpec{Type: "external"},
			Decision: "deny",
		},
	}

	engine, err := signal.NewEngine(rules)
	require.NoError(t, err)

	registry := signal.NewPIDRegistry("test-session", os.Getpid())
	handler := signal.NewHandler(engine, registry, nil)

	// Start a child process
	cmd := exec.Command("sleep", "60")
	err = cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	registry.Register(cmd.Process.Pid, os.Getpid(), "sleep")

	// Test: signal to external should be denied
	ctx := handler.Evaluate(signal.SignalContext{
		PID:       cmd.Process.Pid,
		TargetPID: 1, // init - external
		Signal:    int(syscall.SIGTERM),
	})
	assert.Equal(t, signal.DecisionDeny, ctx.Action)

	// Test: signal to child should be allowed (no rule matches)
	ctx = handler.Evaluate(signal.SignalContext{
		PID:       os.Getpid(),
		TargetPID: cmd.Process.Pid,
		Signal:    int(syscall.SIGTERM),
	})
	// Default deny since no allow rule
	assert.Equal(t, signal.DecisionDeny, ctx.Action)
}
```

**Step 2: Run test**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && sudo go test ./internal/signal/... -tags=integration -run TestSignalInterception -v`

**Step 3: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add internal/signal/integration_test.go
git commit -m "test(signal): add integration tests

- E2E test for signal interception
- Requires root and seccomp support"
```

---

## Task 13: Run Full Test Suite

**Step 1: Run all tests**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
go test ./... -v
```

**Step 2: Fix any failures**

Address any test failures before proceeding.

**Step 3: Run linter**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
golangci-lint run ./...
```

**Step 4: Final commit if needed**

```bash
cd /home/eran/work/agentsh/.worktrees/signal-interception
git add -A
git commit -m "fix: address test and lint issues"
```

---

## Summary

This plan implements signal interception with:

1. **Signal types and groups** - Parse signal names, numbers, and groups
2. **Target types** - Classify signal targets (self, children, external, etc.)
3. **Policy model** - Add SignalRule to policy YAML
4. **PID registry** - Track session membership
5. **Signal engine** - Evaluate signals against policy
6. **Event types** - Add signal audit events
7. **Linux seccomp** - Intercept signal syscalls
8. **Handler** - Process notifications and emit events
9. **Policy integration** - Wire signal engine into main engine
10. **Example policies** - Add signal rules to dev-safe, create signal-strict
11. **Documentation** - Explain signal rules
12. **Integration tests** - E2E verification
13. **Full test suite** - Ensure nothing is broken

Total: ~13 tasks, each with TDD approach (test first, implement, commit)
