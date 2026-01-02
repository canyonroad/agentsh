# Windows Registry Monitoring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement full registry monitoring and blocking via the mini filter driver with policy evaluation and approval support.

**Architecture:** Driver intercepts registry operations via `CmRegisterCallbackEx`, sends policy check requests to user-mode, user-mode evaluates policy rules using the same pattern as file/network rules, returns decision with cache TTL.

**Tech Stack:** Go, Windows kernel driver (C), gobwas/glob for pattern matching

---

## Task 1: Add RegistryRule to Policy Model

**Files:**
- Modify: `internal/policy/model.go`

**Step 1: Write the test**

Add to `internal/policy/model_test.go` (create if needed):

```go
func TestPolicy_RegistryRules(t *testing.T) {
	yaml := `
version: 1
name: test-registry
registry_rules:
  - name: block-run-keys
    paths:
      - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    operations:
      - write
      - create
    decision: deny
    priority: 100
    cache_ttl: 30s
`
	var p Policy
	if err := yaml.Unmarshal([]byte(yaml), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.RegistryRules) != 1 {
		t.Fatalf("expected 1 registry rule, got %d", len(p.RegistryRules))
	}
	r := p.RegistryRules[0]
	if r.Name != "block-run-keys" {
		t.Errorf("name = %q, want block-run-keys", r.Name)
	}
	if r.Priority != 100 {
		t.Errorf("priority = %d, want 100", r.Priority)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/policy -run TestPolicy_RegistryRules -v`
Expected: FAIL - RegistryRules field does not exist

**Step 3: Add RegistryRule struct to model.go**

Add after `UnixSocketRule`:

```go
// RegistryRule controls Windows registry access (Windows-only).
type RegistryRule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Paths       []string `yaml:"paths"`       // e.g., "HKLM\\SOFTWARE\\..."
	Operations  []string `yaml:"operations"`  // query, set, delete, create, rename
	Decision    string   `yaml:"decision"`    // allow, deny, approve
	Message     string   `yaml:"message"`
	Timeout     duration `yaml:"timeout"`
	Priority    int      `yaml:"priority"`    // Higher = evaluated first
	CacheTTL    duration `yaml:"cache_ttl"`   // Per-rule cache TTL override
	Notify      bool     `yaml:"notify"`      // Always notify on this rule
}
```

Add to `Policy` struct:

```go
	RegistryRules []RegistryRule `yaml:"registry_rules"`
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/policy -run TestPolicy_RegistryRules -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry
git add internal/policy/model.go internal/policy/model_test.go
git commit -m "feat(policy): add RegistryRule to policy model"
```

---

## Task 2: Add CheckRegistry to Policy Engine

**Files:**
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/engine_test.go`

**Step 1: Write the test**

Add to `internal/policy/engine_test.go`:

```go
func TestEngine_CheckRegistry(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		RegistryRules: []RegistryRule{
			{
				Name:       "block-run-keys",
				Paths:      []string{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*`},
				Operations: []string{"set", "create", "delete"},
				Decision:   "deny",
				Priority:   100,
			},
			{
				Name:       "allow-app-settings",
				Paths:      []string{`HKCU\SOFTWARE\MyApp\*`},
				Operations: []string{"*"},
				Decision:   "allow",
				Priority:   50,
			},
		},
	}

	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		op       string
		wantDec  types.Decision
		wantRule string
	}{
		{
			name:     "block run key write",
			path:     `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware`,
			op:       "set",
			wantDec:  types.DecisionDeny,
			wantRule: "block-run-keys",
		},
		{
			name:     "allow app settings",
			path:     `HKCU\SOFTWARE\MyApp\Config`,
			op:       "set",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-app-settings",
		},
		{
			name:     "default deny unmatched",
			path:     `HKLM\SOFTWARE\RandomPath`,
			op:       "set",
			wantDec:  types.DecisionDeny,
			wantRule: "default-deny-registry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.CheckRegistry(tt.path, tt.op)
			if dec.EffectiveDecision != tt.wantDec {
				t.Errorf("decision = %v, want %v", dec.EffectiveDecision, tt.wantDec)
			}
			if dec.Rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", dec.Rule, tt.wantRule)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/policy -run TestEngine_CheckRegistry -v`
Expected: FAIL - CheckRegistry method does not exist

**Step 3: Add compiledRegistryRule and CheckRegistry to engine.go**

Add struct after `compiledUnixRule`:

```go
type compiledRegistryRule struct {
	rule     RegistryRule
	globs    []glob.Glob
	ops      map[string]struct{}
	priority int
}
```

Add field to `Engine`:

```go
	compiledRegistryRules []compiledRegistryRule
```

Add compilation in `NewEngine` after unix rules:

```go
	// Compile registry rules
	for _, r := range p.RegistryRules {
		cr := compiledRegistryRule{
			rule:     r,
			ops:      map[string]struct{}{},
			priority: r.Priority,
		}
		for _, op := range r.Operations {
			cr.ops[strings.ToLower(op)] = struct{}{}
		}
		for _, pat := range r.Paths {
			// Use backslash as separator for Windows registry paths
			g, err := glob.Compile(pat, '\\')
			if err != nil {
				return nil, fmt.Errorf("compile registry rule %q glob %q: %w", r.Name, pat, err)
			}
			cr.globs = append(cr.globs, g)
		}
		e.compiledRegistryRules = append(e.compiledRegistryRules, cr)
	}
	// Sort by priority (higher first)
	sort.Slice(e.compiledRegistryRules, func(i, j int) bool {
		return e.compiledRegistryRules[i].priority > e.compiledRegistryRules[j].priority
	})
```

Add `CheckRegistry` method:

```go
// CheckRegistry evaluates registry_rules against a path and operation.
func (e *Engine) CheckRegistry(path string, operation string) Decision {
	if e.policy == nil {
		return Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	operation = strings.ToLower(operation)
	pathUpper := strings.ToUpper(path)

	for _, r := range e.compiledRegistryRules {
		if !matchOp(r.ops, operation) {
			continue
		}
		for _, g := range r.globs {
			if g.Match(path) || g.Match(pathUpper) {
				return e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)
			}
		}
	}
	return e.wrapDecision(string(types.DecisionDeny), "default-deny-registry", "", nil)
}
```

Add `import "sort"` at top.

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/policy -run TestEngine_CheckRegistry -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry
git add internal/policy/engine.go internal/policy/engine_test.go
git commit -m "feat(policy): add CheckRegistry to policy engine"
```

---

## Task 3: Add CheckRegistry to PolicyAdapter

**Files:**
- Modify: `internal/platform/policy_adapter.go`
- Create: `internal/platform/policy_adapter_test.go`

**Step 1: Write the test**

Create `internal/platform/policy_adapter_test.go`:

```go
package platform

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestPolicyAdapter_CheckRegistry(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		RegistryRules: []policy.RegistryRule{
			{
				Name:       "allow-app",
				Paths:      []string{`HKCU\SOFTWARE\TestApp\*`},
				Operations: []string{"*"},
				Decision:   "allow",
			},
		},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	adapter := NewPolicyAdapter(engine)

	tests := []struct {
		path string
		op   string
		want Decision
	}{
		{`HKCU\SOFTWARE\TestApp\Config`, "set", DecisionAllow},
		{`HKLM\SOFTWARE\Other`, "set", DecisionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := adapter.CheckRegistry(tt.path, tt.op)
			if got != tt.want {
				t.Errorf("CheckRegistry(%q, %q) = %v, want %v", tt.path, tt.op, got, tt.want)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/platform -run TestPolicyAdapter_CheckRegistry -v`
Expected: FAIL - CheckRegistry method does not exist

**Step 3: Add CheckRegistry to policy_adapter.go**

Add method after `CheckCommand`:

```go
// CheckRegistry evaluates registry access policy.
func (a *PolicyAdapter) CheckRegistry(path string, op string) Decision {
	if a == nil || a.engine == nil {
		return DecisionAllow
	}
	decision := a.engine.CheckRegistry(path, op)
	return decision.EffectiveDecision
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/platform -run TestPolicyAdapter_CheckRegistry -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry
git add internal/platform/policy_adapter.go internal/platform/policy_adapter_test.go
git commit -m "feat(platform): add CheckRegistry to PolicyAdapter"
```

---

## Task 4: Add RegistryOperation Type to Platform Types

**Files:**
- Modify: `internal/platform/types.go`

**Step 1: Add RegistryOperation type**

Add after `EnvOperation` constants:

```go
// RegistryOperation identifies registry operation types (Windows-only).
type RegistryOperation string

const (
	RegOpQuery  RegistryOperation = "query"
	RegOpSet    RegistryOperation = "set"
	RegOpDelete RegistryOperation = "delete"
	RegOpCreate RegistryOperation = "create"
	RegOpRename RegistryOperation = "rename"
	RegOpEnum   RegistryOperation = "enum"
)
```

**Step 2: Run tests to verify no regression**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/platform/... -v`
Expected: PASS

**Step 3: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry
git add internal/platform/types.go
git commit -m "feat(platform): add RegistryOperation type"
```

---

## Task 5: Create Registry Policy Evaluator

**Files:**
- Create: `internal/platform/windows/registry_policy.go`
- Create: `internal/platform/windows/registry_policy_test.go`

**Step 1: Write the test**

Create `internal/platform/windows/registry_policy_test.go`:

```go
//go:build windows

package windows

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestRegistryPolicyEvaluator_Evaluate(t *testing.T) {
	cfg := &config.RegistryPolicyConfig{
		DefaultAction:   "deny",
		LogAll:          true,
		DefaultCacheTTL: 30,
		Rules: []config.RegistryPolicyRule{
			{
				Name:       "allow-app",
				Paths:      []string{`HKCU\SOFTWARE\TestApp\*`},
				Operations: []string{"read", "write"},
				Action:     "allow",
				CacheTTL:   60,
			},
			{
				Name:       "block-run-keys",
				Paths:      []string{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*`},
				Operations: []string{"write", "create", "delete"},
				Action:     "deny",
				Priority:   100,
				Notify:     true,
			},
		},
	}

	eval, err := NewRegistryPolicyEvaluator(cfg)
	if err != nil {
		t.Fatalf("NewRegistryPolicyEvaluator: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		op          DriverRegistryOp
		wantDec     PolicyDecision
		wantCacheTTL uint32
	}{
		{
			name:        "allow app read",
			path:        `HKCU\SOFTWARE\TestApp\Config`,
			op:          DriverRegOpQueryValue,
			wantDec:     DecisionAllow,
			wantCacheTTL: 60000, // 60s in ms
		},
		{
			name:        "block run key write",
			path:        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware`,
			op:          DriverRegOpSetValue,
			wantDec:     DecisionDeny,
			wantCacheTTL: 30000, // default
		},
		{
			name:        "default deny",
			path:        `HKLM\SOFTWARE\RandomPath`,
			op:          DriverRegOpSetValue,
			wantDec:     DecisionDeny,
			wantCacheTTL: 30000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RegistryRequest{
				KeyPath:   tt.path,
				Operation: tt.op,
			}
			resp := eval.Evaluate(req)
			if resp.Decision != tt.wantDec {
				t.Errorf("decision = %v, want %v", resp.Decision, tt.wantDec)
			}
			if resp.CacheTTL != tt.wantCacheTTL {
				t.Errorf("cacheTTL = %d, want %d", resp.CacheTTL, tt.wantCacheTTL)
			}
		})
	}
}

func TestRegistryPolicyEvaluator_HighRiskPaths(t *testing.T) {
	cfg := &config.RegistryPolicyConfig{
		DefaultAction: "allow",
	}

	eval, err := NewRegistryPolicyEvaluator(cfg)
	if err != nil {
		t.Fatalf("NewRegistryPolicyEvaluator: %v", err)
	}

	// High-risk paths should be blocked even with default allow
	req := &RegistryRequest{
		KeyPath:   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\TestApp`,
		Operation: DriverRegOpSetValue,
	}
	resp := eval.Evaluate(req)

	// Should be blocked due to built-in high-risk protection
	if resp.Decision != DecisionDeny {
		t.Errorf("high-risk path decision = %v, want deny", resp.Decision)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/platform/windows -run TestRegistryPolicyEvaluator -v`
Expected: FAIL - NewRegistryPolicyEvaluator does not exist

**Step 3: Create registry_policy.go**

Create `internal/platform/windows/registry_policy.go`:

```go
//go:build windows

package windows

import (
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/gobwas/glob"
)

// RegistryPolicyResponse contains the policy decision for a registry operation.
type RegistryPolicyResponse struct {
	Decision PolicyDecision
	CacheTTL uint32 // milliseconds
	Notify   bool
	LogEvent bool
	RuleName string
	RiskInfo *RegistryPathPolicy // non-nil if high-risk path
}

// compiledRegRule holds a pre-compiled registry policy rule.
type compiledRegRule struct {
	name     string
	globs    []glob.Glob
	ops      map[string]struct{}
	action   PolicyDecision
	priority int
	cacheTTL uint32
	notify   bool
}

// RegistryPolicyEvaluator evaluates registry policy rules.
type RegistryPolicyEvaluator struct {
	mu              sync.RWMutex
	rules           []compiledRegRule
	defaultAction   PolicyDecision
	defaultCacheTTL uint32
	logAll          bool
}

// NewRegistryPolicyEvaluator creates a new evaluator from config.
func NewRegistryPolicyEvaluator(cfg *config.RegistryPolicyConfig) (*RegistryPolicyEvaluator, error) {
	e := &RegistryPolicyEvaluator{
		defaultAction:   DecisionDeny,
		defaultCacheTTL: 30000, // 30s default
		logAll:          cfg != nil && cfg.LogAll,
	}

	if cfg == nil {
		return e, nil
	}

	// Parse default action
	switch strings.ToLower(cfg.DefaultAction) {
	case "allow":
		e.defaultAction = DecisionAllow
	case "deny", "":
		e.defaultAction = DecisionDeny
	}

	if cfg.DefaultCacheTTL > 0 {
		e.defaultCacheTTL = uint32(cfg.DefaultCacheTTL) * 1000 // convert to ms
	}

	// Compile rules
	for _, r := range cfg.Rules {
		cr := compiledRegRule{
			name:     r.Name,
			ops:      make(map[string]struct{}),
			priority: r.Priority,
			notify:   r.Notify,
		}

		// Parse action
		switch strings.ToLower(r.Action) {
		case "allow":
			cr.action = DecisionAllow
		case "deny":
			cr.action = DecisionDeny
		case "approve":
			cr.action = DecisionPending
		default:
			cr.action = DecisionDeny
		}

		// Parse operations
		for _, op := range r.Operations {
			cr.ops[strings.ToLower(op)] = struct{}{}
		}

		// Cache TTL
		if r.CacheTTL > 0 {
			cr.cacheTTL = uint32(r.CacheTTL) * 1000
		} else {
			cr.cacheTTL = e.defaultCacheTTL
		}

		// Compile path globs
		for _, pat := range r.Paths {
			g, err := glob.Compile(pat, '\\')
			if err != nil {
				// Try without separator
				g, err = glob.Compile(pat)
				if err != nil {
					continue // Skip invalid pattern
				}
			}
			cr.globs = append(cr.globs, g)
		}

		e.rules = append(e.rules, cr)
	}

	// Sort by priority (higher first)
	for i := 0; i < len(e.rules)-1; i++ {
		for j := i + 1; j < len(e.rules); j++ {
			if e.rules[j].priority > e.rules[i].priority {
				e.rules[i], e.rules[j] = e.rules[j], e.rules[i]
			}
		}
	}

	return e, nil
}

// Evaluate evaluates a registry request against policy rules.
func (e *RegistryPolicyEvaluator) Evaluate(req *RegistryRequest) *RegistryPolicyResponse {
	e.mu.RLock()
	defer e.mu.RUnlock()

	resp := &RegistryPolicyResponse{
		Decision: e.defaultAction,
		CacheTTL: e.defaultCacheTTL,
		LogEvent: e.logAll,
	}

	// Check if this is a high-risk path
	isHighRisk, riskPolicy := IsHighRiskPath(req.KeyPath)
	if isHighRisk {
		resp.RiskInfo = riskPolicy
		// For high-risk paths, default to deny for write operations
		if isWriteOp(req.Operation) {
			resp.Decision = DecisionDeny
			resp.Notify = true
			resp.LogEvent = true
		}
	}

	// Convert driver operation to policy operation string
	opStr := driverOpToString(req.Operation)

	// Check user-defined rules (higher priority can override high-risk defaults)
	for _, r := range e.rules {
		if !matchRegOp(r.ops, opStr) {
			continue
		}
		for _, g := range r.globs {
			if g.Match(req.KeyPath) || g.Match(strings.ToUpper(req.KeyPath)) {
				resp.Decision = r.action
				resp.CacheTTL = r.cacheTTL
				resp.Notify = r.notify
				resp.RuleName = r.name
				resp.LogEvent = e.logAll || r.notify
				return resp
			}
		}
	}

	return resp
}

// isWriteOp returns true if the operation modifies the registry.
func isWriteOp(op DriverRegistryOp) bool {
	switch op {
	case DriverRegOpSetValue, DriverRegOpDeleteKey, DriverRegOpDeleteValue, DriverRegOpCreateKey, DriverRegOpRenameKey:
		return true
	default:
		return false
	}
}

// driverOpToString converts driver operation to policy string.
func driverOpToString(op DriverRegistryOp) string {
	switch op {
	case DriverRegOpQueryValue:
		return "read"
	case DriverRegOpSetValue:
		return "write"
	case DriverRegOpDeleteKey, DriverRegOpDeleteValue:
		return "delete"
	case DriverRegOpCreateKey:
		return "create"
	case DriverRegOpRenameKey:
		return "rename"
	default:
		return "unknown"
	}
}

// matchRegOp checks if operation matches the rule's operations.
func matchRegOp(ops map[string]struct{}, op string) bool {
	if len(ops) == 0 {
		return true
	}
	if _, ok := ops["*"]; ok {
		return true
	}
	_, ok := ops[op]
	return ok
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/platform/windows -run TestRegistryPolicyEvaluator -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry
git add internal/platform/windows/registry_policy.go internal/platform/windows/registry_policy_test.go
git commit -m "feat(windows): add RegistryPolicyEvaluator"
```

---

## Task 6: Update config.RegistryPolicyConfig

**Files:**
- Modify: `internal/config/policy_loader.go`

**Step 1: Add missing fields to RegistryPolicyConfig**

Update `RegistryPolicyConfig`:

```go
// RegistryPolicyConfig configures Windows registry access policy.
type RegistryPolicyConfig struct {
	DefaultAction   string               `yaml:"default_action"`
	LogAll          bool                 `yaml:"log_all"`
	DefaultCacheTTL int                  `yaml:"default_cache_ttl"` // seconds
	NotifyOnDeny    bool                 `yaml:"notify_on_deny"`
	Rules           []RegistryPolicyRule `yaml:"rules"`
}

// RegistryPolicyRule defines a Windows registry access rule.
type RegistryPolicyRule struct {
	Name           string                  `yaml:"name"`
	Paths          []string                `yaml:"paths"`
	Operations     []string                `yaml:"operations"`
	Action         string                  `yaml:"action"`
	Priority       int                     `yaml:"priority"`
	CacheTTL       int                     `yaml:"cache_ttl"` // seconds, 0 = use default
	TimeoutSeconds int                     `yaml:"timeout_seconds,omitempty"`
	Notify         bool                    `yaml:"notify"`
	Redirect       *RegistryRedirectConfig `yaml:"redirect,omitempty"`
}
```

**Step 2: Run tests to verify no regression**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/config/... -v`
Expected: PASS

**Step 3: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry
git add internal/config/policy_loader.go
git commit -m "feat(config): add priority and cache_ttl to RegistryPolicyRule"
```

---

## Task 7: Wire Up Registry Policy Handler in Driver Client

**Files:**
- Modify: `internal/platform/windows/driver_client.go`

**Step 1: Write integration test**

Add to `internal/platform/windows/driver_client_test.go`:

```go
//go:build windows

func TestDriverClient_RegistryPolicyHandler(t *testing.T) {
	// Test that registry policy handler is called correctly
	handlerCalled := false
	var capturedReq *RegistryRequest

	handler := func(req *RegistryRequest) (PolicyDecision, uint32) {
		handlerCalled = true
		capturedReq = req
		return DecisionDeny, 5000
	}

	client := NewDriverClient()
	client.SetRegistryPolicyHandler(handler)

	// Simulate a registry policy check message
	// Header(16) + token(8) + pid(4) + tid(4) + op(4) + valueType(4) + dataSize(4) + keyPath(520*2) + valueName(256*2)
	msg := make([]byte, 16+8+4+4+4+4+4+520*2+256*2)
	binary.LittleEndian.PutUint32(msg[0:4], MsgPolicyCheckRegistry)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(len(msg)))
	binary.LittleEndian.PutUint64(msg[8:16], 123) // request ID
	binary.LittleEndian.PutUint64(msg[16:24], 456) // session token
	binary.LittleEndian.PutUint32(msg[24:28], 1234) // pid
	binary.LittleEndian.PutUint32(msg[28:32], 5678) // tid
	binary.LittleEndian.PutUint32(msg[32:36], uint32(DriverRegOpSetValue))

	// Encode key path as UTF-16LE
	keyPath := `HKLM\SOFTWARE\Test`
	pathBytes := utf16Encode(keyPath)
	copy(msg[44:], pathBytes)

	reply := make([]byte, 512)
	replyLen := client.handleRegistryPolicyCheck(msg, reply)

	if !handlerCalled {
		t.Error("handler was not called")
	}
	if capturedReq == nil {
		t.Fatal("captured request is nil")
	}
	if capturedReq.ProcessId != 1234 {
		t.Errorf("ProcessId = %d, want 1234", capturedReq.ProcessId)
	}
	if capturedReq.Operation != DriverRegOpSetValue {
		t.Errorf("Operation = %v, want DriverRegOpSetValue", capturedReq.Operation)
	}
	if !strings.HasPrefix(capturedReq.KeyPath, "HKLM") {
		t.Errorf("KeyPath = %q, want prefix HKLM", capturedReq.KeyPath)
	}
	if replyLen != 24 {
		t.Errorf("replyLen = %d, want 24", replyLen)
	}

	// Check reply contains deny decision
	decision := binary.LittleEndian.Uint32(reply[16:20])
	if PolicyDecision(decision) != DecisionDeny {
		t.Errorf("reply decision = %d, want DecisionDeny", decision)
	}
}
```

**Step 2: Run test**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/platform/windows -run TestDriverClient_RegistryPolicyHandler -v`
Expected: Should pass (handler already exists, this validates it works correctly)

**Step 3: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry
git add internal/platform/windows/driver_client_test.go
git commit -m "test(windows): add registry policy handler test"
```

---

## Task 8: Create Registry Event Emitter

**Files:**
- Modify: `internal/platform/windows/registry.go`

**Step 1: Add event emission functions**

Add to `registry.go`:

```go
// RegistryEventEmitter emits registry events to the event channel.
type RegistryEventEmitter struct {
	eventChan chan<- types.Event
	sessionID string
}

// NewRegistryEventEmitter creates a new event emitter.
func NewRegistryEventEmitter(eventChan chan<- types.Event, sessionID string) *RegistryEventEmitter {
	return &RegistryEventEmitter{
		eventChan: eventChan,
		sessionID: sessionID,
	}
}

// EmitRegistryEvent emits a registry operation event.
func (e *RegistryEventEmitter) EmitRegistryEvent(
	req *RegistryRequest,
	resp *RegistryPolicyResponse,
	processName string,
) {
	if e.eventChan == nil {
		return
	}

	eventType := "registry_write"
	switch req.Operation {
	case DriverRegOpQueryValue:
		eventType = "registry_read"
	case DriverRegOpCreateKey:
		eventType = "registry_create"
	case DriverRegOpDeleteKey, DriverRegOpDeleteValue:
		eventType = "registry_delete"
	case DriverRegOpRenameKey:
		eventType = "registry_rename"
	}

	if resp.Decision == DecisionDeny {
		eventType = "registry_blocked"
	}

	decision := types.DecisionAllow
	if resp.Decision == DecisionDeny {
		decision = types.DecisionDeny
	} else if resp.Decision == DecisionPending {
		decision = types.DecisionApprove
	}

	ev := types.Event{
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		SessionID: e.sessionID,
		Path:      req.KeyPath,
		Operation: driverOpToString(req.Operation),
		PID:       int(req.ProcessId),
		Policy: &types.PolicyInfo{
			Decision:          decision,
			EffectiveDecision: decision,
			Rule:              resp.RuleName,
		},
		Fields: map[string]any{
			"source":       "registry_policy",
			"platform":     "windows",
			"hive":         parseHive(req.KeyPath),
			"value_name":   req.ValueName,
			"process_name": processName,
		},
	}

	// Add risk info if present
	if resp.RiskInfo != nil {
		ev.Fields["risk_level"] = resp.RiskInfo.Risk.String()
		ev.Fields["description"] = resp.RiskInfo.Description
		ev.Fields["mitre_technique"] = resp.RiskInfo.Technique
	}

	e.eventChan <- ev
}
```

**Step 2: Run tests**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/platform/windows -v`
Expected: PASS

**Step 3: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry
git add internal/platform/windows/registry.go
git commit -m "feat(windows): add RegistryEventEmitter"
```

---

## Task 9: Integration - Connect All Components

**Files:**
- Create: `internal/platform/windows/registry_interceptor.go`
- Create: `internal/platform/windows/registry_interceptor_test.go`

**Step 1: Write integration test**

Create `internal/platform/windows/registry_interceptor_test.go`:

```go
//go:build windows

package windows

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestRegistryInterceptor_HandleRequest(t *testing.T) {
	eventChan := make(chan types.Event, 10)

	cfg := &config.RegistryPolicyConfig{
		DefaultAction:   "deny",
		DefaultCacheTTL: 30,
		Rules: []config.RegistryPolicyRule{
			{
				Name:       "allow-test-app",
				Paths:      []string{`HKCU\SOFTWARE\TestApp\*`},
				Operations: []string{"*"},
				Action:     "allow",
			},
		},
	}

	interceptor, err := NewRegistryInterceptor(cfg, eventChan, "test-session")
	if err != nil {
		t.Fatalf("NewRegistryInterceptor: %v", err)
	}

	tests := []struct {
		name    string
		req     *RegistryRequest
		wantDec PolicyDecision
	}{
		{
			name: "allow configured path",
			req: &RegistryRequest{
				KeyPath:   `HKCU\SOFTWARE\TestApp\Config`,
				Operation: DriverRegOpSetValue,
				ProcessId: 1234,
			},
			wantDec: DecisionAllow,
		},
		{
			name: "deny unconfigured path",
			req: &RegistryRequest{
				KeyPath:   `HKLM\SOFTWARE\Other`,
				Operation: DriverRegOpSetValue,
				ProcessId: 1234,
			},
			wantDec: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, cacheTTL := interceptor.HandleRequest(tt.req)
			if decision != tt.wantDec {
				t.Errorf("decision = %v, want %v", decision, tt.wantDec)
			}
			if cacheTTL == 0 {
				t.Error("cacheTTL should not be 0")
			}
		})
	}
}
```

**Step 2: Create registry_interceptor.go**

```go
//go:build windows

package windows

import (
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

// RegistryInterceptor handles registry policy enforcement.
type RegistryInterceptor struct {
	evaluator *RegistryPolicyEvaluator
	emitter   *RegistryEventEmitter
}

// NewRegistryInterceptor creates a new registry interceptor.
func NewRegistryInterceptor(
	cfg *config.RegistryPolicyConfig,
	eventChan chan<- types.Event,
	sessionID string,
) (*RegistryInterceptor, error) {
	eval, err := NewRegistryPolicyEvaluator(cfg)
	if err != nil {
		return nil, err
	}

	return &RegistryInterceptor{
		evaluator: eval,
		emitter:   NewRegistryEventEmitter(eventChan, sessionID),
	}, nil
}

// HandleRequest evaluates a registry request and returns the decision.
// This method is designed to be used as the RegistryPolicyHandler callback.
func (i *RegistryInterceptor) HandleRequest(req *RegistryRequest) (PolicyDecision, uint32) {
	resp := i.evaluator.Evaluate(req)

	// Emit event if logging is enabled
	if resp.LogEvent || resp.Notify || resp.Decision == DecisionDeny {
		i.emitter.EmitRegistryEvent(req, resp, "")
	}

	return resp.Decision, resp.CacheTTL
}

// PolicyHandler returns a handler function suitable for DriverClient.
func (i *RegistryInterceptor) PolicyHandler() RegistryPolicyHandler {
	return i.HandleRequest
}
```

**Step 3: Run test**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./internal/platform/windows -run TestRegistryInterceptor -v`
Expected: PASS

**Step 4: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry
git add internal/platform/windows/registry_interceptor.go internal/platform/windows/registry_interceptor_test.go
git commit -m "feat(windows): add RegistryInterceptor"
```

---

## Task 10: Run Full Test Suite

**Step 1: Run all tests**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry && go test ./... -short
```
Expected: All tests PASS

**Step 2: Run linter**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry && golangci-lint run ./...
```
Expected: No errors

**Step 3: Final commit if needed**

```bash
cd /home/eran/work/agentsh/.worktrees/windows-registry
git status
# If any uncommitted changes, commit them
```

---

## Summary

After completing all tasks, the implementation includes:

1. **Policy Model** - `RegistryRule` added to `policy.Policy`
2. **Policy Engine** - `CheckRegistry()` method with glob matching
3. **Policy Adapter** - `CheckRegistry()` bridging platform to policy
4. **Platform Types** - `RegistryOperation` type
5. **Registry Policy Evaluator** - Standalone evaluator with high-risk path protection
6. **Config** - Extended `RegistryPolicyConfig` with priority/cache fields
7. **Driver Client** - Handler integration tested
8. **Event Emitter** - Registry events with MITRE mappings
9. **Registry Interceptor** - Ties evaluator and emitter together

The driver client's existing `handleRegistryPolicyCheck` now has a full policy evaluation pipeline ready to be connected.
