# Policy Generate Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `agentsh policy generate <session-id>` command that generates restrictive policies from session activity.

**Architecture:** New `internal/policygen` package with generator, grouping heuristics, and risky command detection. CLI command in `internal/cli/policy_cmd.go` follows existing `report` command pattern. Outputs YAML policy with provenance comments.

**Tech Stack:** Go 1.21+, YAML v3, existing event store, policy model, cobra CLI.

---

### Task 1: Create policygen package structure with types

**Files:**
- Create: `internal/policygen/types.go`
- Create: `internal/policygen/types_test.go`

**Step 1: Write the test for basic types**

```go
// internal/policygen/types_test.go
package policygen

import (
	"testing"
	"time"
)

func TestProvenance_String(t *testing.T) {
	p := Provenance{
		EventCount: 47,
		FirstSeen:  time.Date(2025, 1, 15, 14, 20, 0, 0, time.UTC),
		LastSeen:   time.Date(2025, 1, 15, 14, 31, 45, 0, time.UTC),
		SamplePaths: []string{"/workspace/src/index.ts", "/workspace/src/utils.ts"},
	}
	s := p.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
	if !contains(s, "47 events") {
		t.Errorf("expected '47 events' in %q", s)
	}
}

func TestOptions_Defaults(t *testing.T) {
	opts := DefaultOptions()
	if opts.Threshold != 5 {
		t.Errorf("expected threshold 5, got %d", opts.Threshold)
	}
	if !opts.IncludeBlocked {
		t.Error("expected IncludeBlocked true")
	}
	if !opts.ArgPatterns {
		t.Error("expected ArgPatterns true")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -v`
Expected: FAIL - package does not exist

**Step 3: Write minimal implementation**

```go
// internal/policygen/types.go
package policygen

import (
	"fmt"
	"time"
)

// Options controls policy generation behavior.
type Options struct {
	Name           string // Policy name (default: generated-<session-id>)
	Threshold      int    // Files in same dir before collapsing to glob
	IncludeBlocked bool   // Include blocked ops as comments
	ArgPatterns    bool   // Generate arg patterns for risky commands
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Threshold:      5,
		IncludeBlocked: true,
		ArgPatterns:    true,
	}
}

// Provenance tracks the source events for a generated rule.
type Provenance struct {
	EventCount  int
	FirstSeen   time.Time
	LastSeen    time.Time
	SamplePaths []string // Up to 3 example paths/domains/commands
	Blocked     bool     // True if this was a blocked operation
	BlockReason string   // Reason if blocked
}

// String returns a human-readable provenance comment.
func (p Provenance) String() string {
	timeRange := ""
	if !p.FirstSeen.IsZero() && !p.LastSeen.IsZero() {
		timeRange = fmt.Sprintf(" (%s - %s)",
			p.FirstSeen.Format("15:04:05"),
			p.LastSeen.Format("15:04:05"))
	}
	return fmt.Sprintf("%d events%s", p.EventCount, timeRange)
}

// GeneratedRule represents a rule with its provenance.
type GeneratedRule struct {
	Name        string
	Description string
	Provenance  Provenance
}

// FileRuleGen extends GeneratedRule for file rules.
type FileRuleGen struct {
	GeneratedRule
	Paths      []string
	Operations []string
	Decision   string
}

// NetworkRuleGen extends GeneratedRule for network rules.
type NetworkRuleGen struct {
	GeneratedRule
	Domains []string
	Ports   []int
	CIDRs   []string
	Decision string
}

// CommandRuleGen extends GeneratedRule for command rules.
type CommandRuleGen struct {
	GeneratedRule
	Commands    []string
	ArgsPattern string // Regex pattern for risky commands
	Decision    string
	Risky       bool   // If true, this is a risky command
	RiskyReason string // Why it's risky (builtin, network, destructive)
}

// UnixRuleGen extends GeneratedRule for unix socket rules.
type UnixRuleGen struct {
	GeneratedRule
	Paths      []string
	Operations []string
	Decision   string
}

// GeneratedPolicy holds all generated rules.
type GeneratedPolicy struct {
	SessionID   string
	GeneratedAt time.Time
	Duration    time.Duration
	EventCount  int

	FileRules    []FileRuleGen
	NetworkRules []NetworkRuleGen
	CommandRules []CommandRuleGen
	UnixRules    []UnixRuleGen

	// Blocked operations (for comments)
	BlockedFiles    []FileRuleGen
	BlockedNetwork  []NetworkRuleGen
	BlockedCommands []CommandRuleGen
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-policy-generate
git add internal/policygen/
git commit -m "feat(policygen): add types for policy generation"
```

---

### Task 2: Implement risky command detection

**Files:**
- Create: `internal/policygen/risky.go`
- Create: `internal/policygen/risky_test.go`

**Step 1: Write the test**

```go
// internal/policygen/risky_test.go
package policygen

import "testing"

func TestIsBuiltinRisky(t *testing.T) {
	tests := []struct {
		cmd      string
		expected bool
		reason   string
	}{
		{"curl", true, "network"},
		{"wget", true, "network"},
		{"ssh", true, "network"},
		{"rm", true, "destructive"},
		{"sudo", true, "privileged"},
		{"docker", true, "container"},
		{"npm", false, ""},
		{"node", false, ""},
		{"git", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			risky, reason := IsBuiltinRisky(tt.cmd)
			if risky != tt.expected {
				t.Errorf("IsBuiltinRisky(%q) = %v, want %v", tt.cmd, risky, tt.expected)
			}
			if tt.expected && reason != tt.reason {
				t.Errorf("IsBuiltinRisky(%q) reason = %q, want %q", tt.cmd, reason, tt.reason)
			}
		})
	}
}

func TestRiskyDetector_MarkNetworkCapable(t *testing.T) {
	d := NewRiskyDetector()
	d.MarkNetworkCapable("my-custom-tool")

	if !d.IsRisky("my-custom-tool") {
		t.Error("expected my-custom-tool to be risky after marking")
	}
	reason := d.Reason("my-custom-tool")
	if reason != "network-observed" {
		t.Errorf("expected reason 'network-observed', got %q", reason)
	}
}

func TestRiskyDetector_MarkDestructive(t *testing.T) {
	d := NewRiskyDetector()
	d.MarkDestructive("cleanup-script")

	if !d.IsRisky("cleanup-script") {
		t.Error("expected cleanup-script to be risky after marking")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -v`
Expected: FAIL - undefined functions

**Step 3: Write minimal implementation**

```go
// internal/policygen/risky.go
package policygen

import (
	"path/filepath"
	"strings"
)

// builtinRisky maps command names to their risk category.
var builtinRisky = map[string]string{
	// Network-capable
	"curl":    "network",
	"wget":    "network",
	"ssh":     "network",
	"scp":     "network",
	"rsync":   "network",
	"nc":      "network",
	"netcat":  "network",
	"telnet":  "network",
	"ftp":     "network",
	"sftp":    "network",

	// Destructive/privileged
	"rm":    "destructive",
	"chmod": "destructive",
	"chown": "destructive",
	"sudo":  "privileged",
	"su":    "privileged",
	"doas":  "privileged",

	// Container/orchestration
	"docker":  "container",
	"podman":  "container",
	"kubectl": "orchestration",
	"helm":    "orchestration",

	// Package managers (can run arbitrary code)
	"pip":   "package",
	"pip3":  "package",
	"gem":   "package",
	"cargo": "package",
}

// IsBuiltinRisky checks if a command is in the built-in risky list.
func IsBuiltinRisky(cmd string) (bool, string) {
	// Normalize: take base name, remove extension
	base := filepath.Base(cmd)
	base = strings.TrimSuffix(base, filepath.Ext(base))

	if reason, ok := builtinRisky[base]; ok {
		return true, reason
	}
	return false, ""
}

// RiskyDetector tracks which commands are risky based on behavior.
type RiskyDetector struct {
	observed map[string]string // command -> reason
}

// NewRiskyDetector creates a new detector.
func NewRiskyDetector() *RiskyDetector {
	return &RiskyDetector{
		observed: make(map[string]string),
	}
}

// MarkNetworkCapable marks a command as risky because it made network calls.
func (d *RiskyDetector) MarkNetworkCapable(cmd string) {
	base := filepath.Base(cmd)
	if _, exists := d.observed[base]; !exists {
		d.observed[base] = "network-observed"
	}
}

// MarkDestructive marks a command as risky because it deleted files.
func (d *RiskyDetector) MarkDestructive(cmd string) {
	base := filepath.Base(cmd)
	if _, exists := d.observed[base]; !exists {
		d.observed[base] = "destructive-observed"
	}
}

// MarkPrivileged marks a command as risky because it changed UID.
func (d *RiskyDetector) MarkPrivileged(cmd string) {
	base := filepath.Base(cmd)
	if _, exists := d.observed[base]; !exists {
		d.observed[base] = "privilege-observed"
	}
}

// IsRisky checks if a command is risky (builtin or observed).
func (d *RiskyDetector) IsRisky(cmd string) bool {
	base := filepath.Base(cmd)
	if _, ok := builtinRisky[base]; ok {
		return true
	}
	_, ok := d.observed[base]
	return ok
}

// Reason returns why a command is risky.
func (d *RiskyDetector) Reason(cmd string) string {
	base := filepath.Base(cmd)
	if reason, ok := builtinRisky[base]; ok {
		return reason
	}
	if reason, ok := d.observed[base]; ok {
		return reason
	}
	return ""
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-policy-generate
git add internal/policygen/risky.go internal/policygen/risky_test.go
git commit -m "feat(policygen): add risky command detection"
```

---

### Task 3: Implement path grouping heuristics

**Files:**
- Create: `internal/policygen/grouping.go`
- Create: `internal/policygen/grouping_test.go`

**Step 1: Write the test**

```go
// internal/policygen/grouping_test.go
package policygen

import "testing"

func TestGroupPaths_ThresholdCollapse(t *testing.T) {
	paths := []string{
		"/workspace/src/a.ts",
		"/workspace/src/b.ts",
		"/workspace/src/c.ts",
		"/workspace/src/d.ts",
		"/workspace/src/e.ts",
		"/workspace/src/f.ts",
	}

	groups := GroupPaths(paths, 5)

	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Pattern != "/workspace/src/**" {
		t.Errorf("expected pattern '/workspace/src/**', got %q", groups[0].Pattern)
	}
}

func TestGroupPaths_BelowThreshold(t *testing.T) {
	paths := []string{
		"/workspace/src/a.ts",
		"/workspace/src/b.ts",
	}

	groups := GroupPaths(paths, 5)

	// Below threshold, keep individual paths
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}

func TestGroupPaths_CommonPrefix(t *testing.T) {
	paths := []string{
		"/workspace/node_modules/lodash/index.js",
		"/workspace/node_modules/lodash/fp.js",
		"/workspace/node_modules/express/index.js",
		"/workspace/node_modules/express/router.js",
		"/workspace/node_modules/axios/index.js",
		"/workspace/node_modules/axios/lib/core.js",
	}

	groups := GroupPaths(paths, 3)

	// Should collapse to /workspace/node_modules/**
	if len(groups) != 1 {
		t.Fatalf("expected 1 group after prefix collapse, got %d: %+v", len(groups), groups)
	}
	if groups[0].Pattern != "/workspace/node_modules/**" {
		t.Errorf("expected '/workspace/node_modules/**', got %q", groups[0].Pattern)
	}
}

func TestGroupDomains_WildcardCollapse(t *testing.T) {
	domains := []string{
		"api.github.com",
		"raw.github.com",
		"gist.github.com",
	}

	groups := GroupDomains(domains)

	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Pattern != "*.github.com" {
		t.Errorf("expected '*.github.com', got %q", groups[0].Pattern)
	}
}

func TestGroupDomains_NoCollapse(t *testing.T) {
	domains := []string{
		"api.github.com",
		"registry.npmjs.org",
	}

	groups := GroupDomains(domains)

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -v`
Expected: FAIL - undefined functions

**Step 3: Write minimal implementation**

```go
// internal/policygen/grouping.go
package policygen

import (
	"path/filepath"
	"sort"
	"strings"
)

// PathGroup represents a group of paths collapsed into a pattern.
type PathGroup struct {
	Pattern    string
	Paths      []string
	Operations []string
	Count      int
}

// DomainGroup represents a group of domains collapsed into a pattern.
type DomainGroup struct {
	Pattern string
	Domains []string
	Ports   []int
	Count   int
}

// GroupPaths groups paths by directory and collapses to globs if above threshold.
func GroupPaths(paths []string, threshold int) []PathGroup {
	if len(paths) == 0 {
		return nil
	}

	// Group by directory
	byDir := make(map[string][]string)
	for _, p := range paths {
		dir := filepath.Dir(p)
		byDir[dir] = append(byDir[dir], p)
	}

	var groups []PathGroup

	// Check if we should collapse parent directories
	// Group directories by their parent
	byParent := make(map[string][]string)
	for dir := range byDir {
		parent := filepath.Dir(dir)
		byParent[parent] = append(byParent[parent], dir)
	}

	// If multiple subdirs under same parent exceed threshold, collapse to parent/**
	collapsedParents := make(map[string]bool)
	for parent, dirs := range byParent {
		if len(dirs) >= threshold {
			collapsedParents[parent] = true
			// Count all paths under this parent
			count := 0
			var allPaths []string
			for _, dir := range dirs {
				count += len(byDir[dir])
				allPaths = append(allPaths, byDir[dir]...)
			}
			groups = append(groups, PathGroup{
				Pattern: parent + "/**",
				Paths:   allPaths,
				Count:   count,
			})
		}
	}

	// Process remaining directories not collapsed
	for dir, dirPaths := range byDir {
		// Skip if parent was collapsed
		parent := filepath.Dir(dir)
		if collapsedParents[parent] {
			continue
		}

		if len(dirPaths) >= threshold {
			groups = append(groups, PathGroup{
				Pattern: dir + "/**",
				Paths:   dirPaths,
				Count:   len(dirPaths),
			})
		} else {
			// Keep individual paths
			for _, p := range dirPaths {
				groups = append(groups, PathGroup{
					Pattern: p,
					Paths:   []string{p},
					Count:   1,
				})
			}
		}
	}

	// Sort by pattern for deterministic output
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Pattern < groups[j].Pattern
	})

	return groups
}

// GroupDomains groups domains by base domain and collapses subdomains.
func GroupDomains(domains []string) []DomainGroup {
	if len(domains) == 0 {
		return nil
	}

	// Group by base domain (last two parts)
	byBase := make(map[string][]string)
	for _, d := range domains {
		base := getBaseDomain(d)
		byBase[base] = append(byBase[base], d)
	}

	var groups []DomainGroup

	for base, subdomains := range byBase {
		if len(subdomains) > 1 {
			// Multiple subdomains - collapse to wildcard
			groups = append(groups, DomainGroup{
				Pattern: "*." + base,
				Domains: subdomains,
				Count:   len(subdomains),
			})
		} else {
			// Single domain - keep as-is
			groups = append(groups, DomainGroup{
				Pattern: subdomains[0],
				Domains: subdomains,
				Count:   1,
			})
		}
	}

	// Sort for deterministic output
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Pattern < groups[j].Pattern
	})

	return groups
}

// getBaseDomain extracts the base domain (e.g., "github.com" from "api.github.com").
func getBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// GroupCIDR groups IPs into CIDRs if they cluster in the same /24.
func GroupCIDR(ips []string) []string {
	if len(ips) == 0 {
		return nil
	}

	// Group by /24 prefix
	byPrefix := make(map[string][]string)
	for _, ip := range ips {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			continue // Skip non-IPv4
		}
		prefix := strings.Join(parts[:3], ".")
		byPrefix[prefix] = append(byPrefix[prefix], ip)
	}

	var cidrs []string
	for prefix, prefixIPs := range byPrefix {
		if len(prefixIPs) >= 3 {
			// Collapse to CIDR
			cidrs = append(cidrs, prefix+".0/24")
		} else {
			// Keep individual IPs
			cidrs = append(cidrs, prefixIPs...)
		}
	}

	sort.Strings(cidrs)
	return cidrs
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-policy-generate
git add internal/policygen/grouping.go internal/policygen/grouping_test.go
git commit -m "feat(policygen): add path and domain grouping heuristics"
```

---

### Task 4: Implement core generator

**Files:**
- Create: `internal/policygen/generator.go`
- Create: `internal/policygen/generator_test.go`

**Step 1: Write the test**

```go
// internal/policygen/generator_test.go
package policygen

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

type mockEventStore struct {
	events []types.Event
}

func (m *mockEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return m.events, nil
}
func (m *mockEventStore) AppendEvent(ctx context.Context, ev types.Event) error { return nil }
func (m *mockEventStore) Close() error                                          { return nil }

func TestGenerator_EmptySession(t *testing.T) {
	store := &mockEventStore{events: nil}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	_, err := gen.Generate(context.Background(), sess, DefaultOptions())

	if err == nil {
		t.Error("expected error for empty session")
	}
}

func TestGenerator_FileEvents(t *testing.T) {
	now := time.Now()
	events := []types.Event{
		{Type: "file_write", Path: "/workspace/src/a.ts", Timestamp: now, Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		{Type: "file_write", Path: "/workspace/src/b.ts", Timestamp: now.Add(time.Second), Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		{Type: "file_read", Path: "/workspace/src/c.ts", Timestamp: now.Add(2 * time.Second), Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	opts := DefaultOptions()
	opts.Threshold = 2 // Low threshold for test

	policy, err := gen.Generate(context.Background(), sess, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policy.FileRules) == 0 {
		t.Error("expected file rules to be generated")
	}
}

func TestGenerator_BlockedEvents(t *testing.T) {
	now := time.Now()
	events := []types.Event{
		{Type: "file_write", Path: "/workspace/src/a.ts", Timestamp: now, Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		{Type: "file_write", Path: "/etc/hosts", Timestamp: now.Add(time.Second), Policy: &types.PolicyInfo{Decision: types.DecisionDeny, Message: "system file"}},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	opts := DefaultOptions()
	opts.IncludeBlocked = true

	policy, err := gen.Generate(context.Background(), sess, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policy.BlockedFiles) == 0 {
		t.Error("expected blocked file rules")
	}
}

func TestGenerator_NetworkEvents(t *testing.T) {
	now := time.Now()
	events := []types.Event{
		{Type: "net_connect", Domain: "api.github.com", Timestamp: now, Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		{Type: "net_connect", Domain: "raw.github.com", Timestamp: now.Add(time.Second), Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "test-session"}
	policy, err := gen.Generate(context.Background(), sess, DefaultOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policy.NetworkRules) == 0 {
		t.Error("expected network rules")
	}
	// Should collapse to *.github.com
	if policy.NetworkRules[0].Domains[0] != "*.github.com" {
		t.Errorf("expected '*.github.com', got %q", policy.NetworkRules[0].Domains[0])
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -v`
Expected: FAIL - undefined functions

**Step 3: Write minimal implementation**

```go
// internal/policygen/generator.go
package policygen

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/pkg/types"
)

// Generator creates policies from session events.
type Generator struct {
	store store.EventStore
}

// NewGenerator creates a new policy generator.
func NewGenerator(s store.EventStore) *Generator {
	return &Generator{store: s}
}

// Generate creates a policy from session events.
func (g *Generator) Generate(ctx context.Context, sess types.Session, opts Options) (*GeneratedPolicy, error) {
	events, err := g.store.QueryEvents(ctx, types.EventQuery{
		SessionID: sess.ID,
		Asc:       true,
	})
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("session %s has no event data; run with audit logging enabled", sess.ID)
	}

	policy := &GeneratedPolicy{
		SessionID:   sess.ID,
		GeneratedAt: time.Now().UTC(),
		EventCount:  len(events),
	}

	if len(events) > 0 {
		policy.Duration = events[len(events)-1].Timestamp.Sub(events[0].Timestamp)
	}

	// Separate events by category and decision
	var (
		allowedFiles    []fileEvent
		blockedFiles    []fileEvent
		allowedNetwork  []networkEvent
		blockedNetwork  []networkEvent
		allowedCommands []commandEvent
		blockedCommands []commandEvent
		allowedUnix     []unixEvent
	)

	risky := NewRiskyDetector()

	for _, ev := range events {
		decision := getDecision(ev)

		switch {
		case isFileEvent(ev.Type):
			fe := fileEvent{
				path:      ev.Path,
				operation: getFileOp(ev.Type),
				timestamp: ev.Timestamp,
			}
			if decision == types.DecisionDeny {
				fe.blockReason = getBlockReason(ev)
				blockedFiles = append(blockedFiles, fe)
			} else if decision == types.DecisionAllow || decision == types.DecisionAudit {
				allowedFiles = append(allowedFiles, fe)
			}

			// Track destructive commands
			if ev.Type == "file_delete" {
				if cmd := getCommandFromEvent(ev); cmd != "" {
					risky.MarkDestructive(cmd)
				}
			}

		case isNetworkEvent(ev.Type):
			ne := networkEvent{
				domain:    ev.Domain,
				port:      getPort(ev),
				timestamp: ev.Timestamp,
			}
			if decision == types.DecisionDeny {
				ne.blockReason = getBlockReason(ev)
				blockedNetwork = append(blockedNetwork, ne)
			} else if decision == types.DecisionAllow || decision == types.DecisionAudit {
				allowedNetwork = append(allowedNetwork, ne)
			}

			// Track network-capable commands
			if cmd := getCommandFromEvent(ev); cmd != "" {
				risky.MarkNetworkCapable(cmd)
			}

		case isCommandEvent(ev.Type):
			ce := commandEvent{
				command:   getCommandName(ev),
				args:      getCommandArgs(ev),
				timestamp: ev.Timestamp,
			}
			if decision == types.DecisionDeny {
				ce.blockReason = getBlockReason(ev)
				blockedCommands = append(blockedCommands, ce)
			} else if decision == types.DecisionAllow || decision == types.DecisionAudit {
				allowedCommands = append(allowedCommands, ce)
			}

		case isUnixSocketEvent(ev.Type):
			ue := unixEvent{
				path:      ev.Path,
				operation: ev.Operation,
				timestamp: ev.Timestamp,
			}
			if decision == types.DecisionAllow || decision == types.DecisionAudit {
				allowedUnix = append(allowedUnix, ue)
			}
		}
	}

	// Generate file rules
	policy.FileRules = g.generateFileRules(allowedFiles, opts)
	if opts.IncludeBlocked {
		policy.BlockedFiles = g.generateFileRules(blockedFiles, opts)
		for i := range policy.BlockedFiles {
			policy.BlockedFiles[i].Provenance.Blocked = true
		}
	}

	// Generate network rules
	policy.NetworkRules = g.generateNetworkRules(allowedNetwork)
	if opts.IncludeBlocked {
		policy.BlockedNetwork = g.generateNetworkRules(blockedNetwork)
		for i := range policy.BlockedNetwork {
			policy.BlockedNetwork[i].Provenance.Blocked = true
		}
	}

	// Generate command rules
	policy.CommandRules = g.generateCommandRules(allowedCommands, risky, opts)
	if opts.IncludeBlocked {
		policy.BlockedCommands = g.generateCommandRules(blockedCommands, risky, opts)
		for i := range policy.BlockedCommands {
			policy.BlockedCommands[i].Provenance.Blocked = true
		}
	}

	// Generate unix socket rules
	policy.UnixRules = g.generateUnixRules(allowedUnix)

	return policy, nil
}

// Internal event types for processing
type fileEvent struct {
	path        string
	operation   string
	timestamp   time.Time
	blockReason string
}

type networkEvent struct {
	domain      string
	port        int
	timestamp   time.Time
	blockReason string
}

type commandEvent struct {
	command     string
	args        []string
	timestamp   time.Time
	blockReason string
}

type unixEvent struct {
	path      string
	operation string
	timestamp time.Time
}

func (g *Generator) generateFileRules(events []fileEvent, opts Options) []FileRuleGen {
	if len(events) == 0 {
		return nil
	}

	// Group by path
	pathOps := make(map[string]map[string]bool)
	pathTimes := make(map[string][]time.Time)
	for _, ev := range events {
		if _, ok := pathOps[ev.path]; !ok {
			pathOps[ev.path] = make(map[string]bool)
		}
		pathOps[ev.path][ev.operation] = true
		pathTimes[ev.path] = append(pathTimes[ev.path], ev.timestamp)
	}

	// Get unique paths
	var paths []string
	for p := range pathOps {
		paths = append(paths, p)
	}

	// Group paths
	groups := GroupPaths(paths, opts.Threshold)

	var rules []FileRuleGen
	for _, group := range groups {
		// Collect all operations for this group
		ops := make(map[string]bool)
		var allTimes []time.Time
		for _, p := range group.Paths {
			for op := range pathOps[p] {
				ops[op] = true
			}
			allTimes = append(allTimes, pathTimes[p]...)
		}

		var opList []string
		for op := range ops {
			opList = append(opList, op)
		}

		// Build provenance
		var first, last time.Time
		if len(allTimes) > 0 {
			first, last = allTimes[0], allTimes[0]
			for _, t := range allTimes {
				if t.Before(first) {
					first = t
				}
				if t.After(last) {
					last = t
				}
			}
		}

		samples := group.Paths
		if len(samples) > 3 {
			samples = samples[:3]
		}

		rules = append(rules, FileRuleGen{
			GeneratedRule: GeneratedRule{
				Name:        sanitizeName(group.Pattern),
				Description: fmt.Sprintf("File access: %s", group.Pattern),
				Provenance: Provenance{
					EventCount:  group.Count,
					FirstSeen:   first,
					LastSeen:    last,
					SamplePaths: samples,
				},
			},
			Paths:      []string{group.Pattern},
			Operations: opList,
			Decision:   "allow",
		})
	}

	return rules
}

func (g *Generator) generateNetworkRules(events []networkEvent) []NetworkRuleGen {
	if len(events) == 0 {
		return nil
	}

	// Collect domains and ports
	domainPorts := make(map[string]map[int]bool)
	domainTimes := make(map[string][]time.Time)
	for _, ev := range events {
		if ev.domain == "" {
			continue
		}
		if _, ok := domainPorts[ev.domain]; !ok {
			domainPorts[ev.domain] = make(map[int]bool)
		}
		if ev.port > 0 {
			domainPorts[ev.domain][ev.port] = true
		}
		domainTimes[ev.domain] = append(domainTimes[ev.domain], ev.timestamp)
	}

	var domains []string
	for d := range domainPorts {
		domains = append(domains, d)
	}

	groups := GroupDomains(domains)

	var rules []NetworkRuleGen
	for _, group := range groups {
		// Collect ports for all domains in group
		ports := make(map[int]bool)
		var allTimes []time.Time
		for _, d := range group.Domains {
			for p := range domainPorts[d] {
				ports[p] = true
			}
			allTimes = append(allTimes, domainTimes[d]...)
		}

		var portList []int
		for p := range ports {
			portList = append(portList, p)
		}

		var first, last time.Time
		if len(allTimes) > 0 {
			first, last = allTimes[0], allTimes[0]
			for _, t := range allTimes {
				if t.Before(first) {
					first = t
				}
				if t.After(last) {
					last = t
				}
			}
		}

		rules = append(rules, NetworkRuleGen{
			GeneratedRule: GeneratedRule{
				Name:        sanitizeName(group.Pattern),
				Description: fmt.Sprintf("Network access: %s", group.Pattern),
				Provenance: Provenance{
					EventCount:  group.Count,
					FirstSeen:   first,
					LastSeen:    last,
					SamplePaths: group.Domains,
				},
			},
			Domains:  []string{group.Pattern},
			Ports:    portList,
			Decision: "allow",
		})
	}

	return rules
}

func (g *Generator) generateCommandRules(events []commandEvent, risky *RiskyDetector, opts Options) []CommandRuleGen {
	if len(events) == 0 {
		return nil
	}

	// Group by command base name
	cmdArgs := make(map[string][][]string)
	cmdTimes := make(map[string][]time.Time)
	for _, ev := range events {
		if ev.command == "" {
			continue
		}
		base := filepath.Base(ev.command)
		cmdArgs[base] = append(cmdArgs[base], ev.args)
		cmdTimes[base] = append(cmdTimes[base], ev.timestamp)
	}

	var rules []CommandRuleGen
	for cmd, argsLists := range cmdArgs {
		times := cmdTimes[cmd]
		var first, last time.Time
		if len(times) > 0 {
			first, last = times[0], times[0]
			for _, t := range times {
				if t.Before(first) {
					first = t
				}
				if t.After(last) {
					last = t
				}
			}
		}

		rule := CommandRuleGen{
			GeneratedRule: GeneratedRule{
				Name:        sanitizeName(cmd),
				Description: fmt.Sprintf("Command: %s", cmd),
				Provenance: Provenance{
					EventCount: len(argsLists),
					FirstSeen:  first,
					LastSeen:   last,
				},
			},
			Commands: []string{cmd},
			Decision: "allow",
		}

		// Check if risky
		if risky.IsRisky(cmd) {
			rule.Risky = true
			rule.RiskyReason = risky.Reason(cmd)

			// Generate arg pattern if enabled
			if opts.ArgPatterns && len(argsLists) > 0 {
				rule.ArgsPattern = generateArgPattern(argsLists)
			}
		}

		rules = append(rules, rule)
	}

	return rules
}

func (g *Generator) generateUnixRules(events []unixEvent) []UnixRuleGen {
	if len(events) == 0 {
		return nil
	}

	// Group by path
	pathOps := make(map[string]map[string]bool)
	pathTimes := make(map[string][]time.Time)
	for _, ev := range events {
		if ev.path == "" {
			continue
		}
		if _, ok := pathOps[ev.path]; !ok {
			pathOps[ev.path] = make(map[string]bool)
		}
		pathOps[ev.path][ev.operation] = true
		pathTimes[ev.path] = append(pathTimes[ev.path], ev.timestamp)
	}

	var rules []UnixRuleGen
	for path, ops := range pathOps {
		times := pathTimes[path]
		var first, last time.Time
		if len(times) > 0 {
			first, last = times[0], times[0]
			for _, t := range times {
				if t.Before(first) {
					first = t
				}
				if t.After(last) {
					last = t
				}
			}
		}

		var opList []string
		for op := range ops {
			opList = append(opList, op)
		}

		rule := UnixRuleGen{
			GeneratedRule: GeneratedRule{
				Name:        sanitizeName(path),
				Description: fmt.Sprintf("Unix socket: %s", path),
				Provenance: Provenance{
					EventCount: len(times),
					FirstSeen:  first,
					LastSeen:   last,
				},
			},
			Paths:      []string{path},
			Operations: opList,
			Decision:   "allow",
		}

		// Add warning for docker socket
		if strings.Contains(path, "docker.sock") {
			rule.Description = "Unix socket: Docker (WARNING: grants significant privileges)"
		}

		rules = append(rules, rule)
	}

	return rules
}

// Helper functions

func getDecision(ev types.Event) types.Decision {
	if ev.Policy == nil {
		return ""
	}
	if ev.Policy.EffectiveDecision != "" {
		return ev.Policy.EffectiveDecision
	}
	return ev.Policy.Decision
}

func getBlockReason(ev types.Event) string {
	if ev.Policy != nil && ev.Policy.Message != "" {
		return ev.Policy.Message
	}
	return "blocked by policy"
}

func isFileEvent(t string) bool {
	return strings.HasPrefix(t, "file_") || strings.HasPrefix(t, "dir_")
}

func isNetworkEvent(t string) bool {
	return t == "net_connect" || t == "dns_query"
}

func isCommandEvent(t string) bool {
	return t == "command_intercept" || t == "command_policy" ||
		t == "command_started" || t == "process_start"
}

func isUnixSocketEvent(t string) bool {
	return strings.HasPrefix(t, "unix_socket_")
}

func getFileOp(t string) string {
	switch t {
	case "file_read":
		return "read"
	case "file_write":
		return "write"
	case "file_create":
		return "create"
	case "file_delete":
		return "delete"
	case "file_stat":
		return "stat"
	case "dir_read", "dir_list":
		return "read"
	case "dir_create":
		return "create"
	case "dir_delete":
		return "delete"
	default:
		return "read"
	}
}

func getPort(ev types.Event) int {
	if p, ok := ev.Fields["port"].(float64); ok {
		return int(p)
	}
	if p, ok := ev.Fields["port"].(int); ok {
		return p
	}
	return 443 // Default to HTTPS
}

func getCommandFromEvent(ev types.Event) string {
	if cmd, ok := ev.Fields["command"].(string); ok {
		parts := strings.Fields(cmd)
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return ""
}

func getCommandName(ev types.Event) string {
	if cmd, ok := ev.Fields["command"].(string); ok {
		parts := strings.Fields(cmd)
		if len(parts) > 0 {
			return parts[0]
		}
	}
	if cmd, ok := ev.Fields["cmd"].(string); ok {
		parts := strings.Fields(cmd)
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return ""
}

func getCommandArgs(ev types.Event) []string {
	if cmd, ok := ev.Fields["command"].(string); ok {
		parts := strings.Fields(cmd)
		if len(parts) > 1 {
			return parts[1:]
		}
	}
	if args, ok := ev.Fields["args"].([]interface{}); ok {
		var result []string
		for _, a := range args {
			if s, ok := a.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func sanitizeName(s string) string {
	// Convert path/domain to a valid rule name
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, "*", "star")
	s = strings.ReplaceAll(s, "**", "glob")
	s = strings.TrimPrefix(s, "-")
	s = strings.TrimSuffix(s, "-")
	if s == "" {
		s = "unnamed"
	}
	return s
}

func generateArgPattern(argsLists [][]string) string {
	// Extract URLs or paths from args and create a pattern
	var urls []string
	for _, args := range argsLists {
		for _, arg := range args {
			if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
				urls = append(urls, arg)
			}
		}
	}

	if len(urls) == 0 {
		return ""
	}

	// Extract domains from URLs and create pattern
	domains := make(map[string]bool)
	for _, u := range urls {
		// Simple domain extraction
		u = strings.TrimPrefix(u, "https://")
		u = strings.TrimPrefix(u, "http://")
		parts := strings.Split(u, "/")
		if len(parts) > 0 {
			domains[parts[0]] = true
		}
	}

	if len(domains) == 1 {
		for d := range domains {
			return fmt.Sprintf("^https?://%s/", escapeRegex(d))
		}
	}

	// Multiple domains - create alternation
	var domainList []string
	for d := range domains {
		domainList = append(domainList, escapeRegex(d))
	}
	return fmt.Sprintf("^https?://(%s)/", strings.Join(domainList, "|"))
}

func escapeRegex(s string) string {
	// Escape regex special chars
	replacer := strings.NewReplacer(
		".", "\\.",
		"-", "\\-",
	)
	return replacer.Replace(s)
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-policy-generate
git add internal/policygen/generator.go internal/policygen/generator_test.go
git commit -m "feat(policygen): add core policy generator"
```

---

### Task 5: Implement YAML output formatter

**Files:**
- Create: `internal/policygen/output.go`
- Create: `internal/policygen/output_test.go`

**Step 1: Write the test**

```go
// internal/policygen/output_test.go
package policygen

import (
	"strings"
	"testing"
	"time"
)

func TestFormatYAML_Header(t *testing.T) {
	policy := &GeneratedPolicy{
		SessionID:   "abc123",
		GeneratedAt: time.Date(2025, 1, 15, 14, 32, 0, 0, time.UTC),
		Duration:    12*time.Minute + 34*time.Second,
		EventCount:  1847,
	}

	yaml := FormatYAML(policy, "test-policy")

	if !strings.Contains(yaml, "# Generated by: agentsh policy generate abc123") {
		t.Error("missing generated-by header")
	}
	if !strings.Contains(yaml, "# Source session: abc123") {
		t.Error("missing source session")
	}
	if !strings.Contains(yaml, "version: 1") {
		t.Error("missing version")
	}
	if !strings.Contains(yaml, "name: test-policy") {
		t.Error("missing policy name")
	}
}

func TestFormatYAML_FileRules(t *testing.T) {
	policy := &GeneratedPolicy{
		SessionID:   "abc123",
		GeneratedAt: time.Now(),
		FileRules: []FileRuleGen{
			{
				GeneratedRule: GeneratedRule{
					Name:        "workspace-src",
					Description: "Source files",
					Provenance:  Provenance{EventCount: 47},
				},
				Paths:      []string{"/workspace/src/**"},
				Operations: []string{"read", "write"},
				Decision:   "allow",
			},
		},
	}

	yaml := FormatYAML(policy, "test")

	if !strings.Contains(yaml, "file_rules:") {
		t.Error("missing file_rules section")
	}
	if !strings.Contains(yaml, "# Provenance: 47 events") {
		t.Error("missing provenance comment")
	}
	if !strings.Contains(yaml, `paths: ["/workspace/src/**"]`) {
		t.Error("missing paths")
	}
}

func TestFormatYAML_BlockedComments(t *testing.T) {
	policy := &GeneratedPolicy{
		SessionID:   "abc123",
		GeneratedAt: time.Now(),
		BlockedFiles: []FileRuleGen{
			{
				GeneratedRule: GeneratedRule{
					Name: "etc-hosts",
					Provenance: Provenance{
						Blocked:     true,
						BlockReason: "system file denied",
					},
				},
				Paths:    []string{"/etc/hosts"},
				Decision: "allow",
			},
		},
	}

	yaml := FormatYAML(policy, "test")

	if !strings.Contains(yaml, "# --- Blocked operations") {
		t.Error("missing blocked section header")
	}
	if !strings.Contains(yaml, "# BLOCKED:") {
		t.Error("missing BLOCKED marker")
	}
	// Blocked rules should be commented out
	if !strings.Contains(yaml, "#   - name:") {
		t.Error("blocked rules should be commented")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -v`
Expected: FAIL - undefined FormatYAML

**Step 3: Write minimal implementation**

```go
// internal/policygen/output.go
package policygen

import (
	"fmt"
	"sort"
	"strings"
)

// FormatYAML formats a generated policy as YAML with provenance comments.
func FormatYAML(policy *GeneratedPolicy, name string) string {
	var b strings.Builder

	// Header comments
	b.WriteString(fmt.Sprintf("# Generated by: agentsh policy generate %s\n", policy.SessionID))
	b.WriteString(fmt.Sprintf("# Source session: %s\n", policy.SessionID))
	b.WriteString(fmt.Sprintf("# Generated at: %s\n", policy.GeneratedAt.Format("2006-01-02T15:04:05Z")))
	b.WriteString(fmt.Sprintf("# Session duration: %s\n", formatDuration(policy.Duration)))
	b.WriteString(fmt.Sprintf("# Total events analyzed: %d\n", policy.EventCount))
	b.WriteString("\n")

	// Policy metadata
	b.WriteString("version: 1\n")
	if name != "" {
		b.WriteString(fmt.Sprintf("name: %s\n", name))
	} else {
		b.WriteString(fmt.Sprintf("name: generated-%s\n", truncateID(policy.SessionID)))
	}
	b.WriteString(fmt.Sprintf("description: Auto-generated from session %s\n", policy.SessionID))
	b.WriteString("\n")

	// File rules
	if len(policy.FileRules) > 0 || len(policy.BlockedFiles) > 0 {
		b.WriteString("file_rules:\n")

		if len(policy.FileRules) > 0 {
			uniquePaths := countUniquePaths(policy.FileRules)
			b.WriteString(fmt.Sprintf("  # --- Allowed file operations (%d unique paths → %d rules) ---\n\n",
				uniquePaths, len(policy.FileRules)))

			for _, rule := range policy.FileRules {
				writeFileRule(&b, rule, false)
			}
		}

		if len(policy.BlockedFiles) > 0 {
			b.WriteString("  # --- Blocked operations (commented for review) ---\n")
			for _, rule := range policy.BlockedFiles {
				writeFileRule(&b, rule, true)
			}
		}
		b.WriteString("\n")
	}

	// Network rules
	if len(policy.NetworkRules) > 0 || len(policy.BlockedNetwork) > 0 {
		b.WriteString("network_rules:\n")

		for _, rule := range policy.NetworkRules {
			writeNetworkRule(&b, rule, false)
		}

		if len(policy.BlockedNetwork) > 0 {
			b.WriteString("  # --- Blocked network (commented for review) ---\n")
			for _, rule := range policy.BlockedNetwork {
				writeNetworkRule(&b, rule, true)
			}
		}
		b.WriteString("\n")
	}

	// Command rules
	if len(policy.CommandRules) > 0 || len(policy.BlockedCommands) > 0 {
		b.WriteString("command_rules:\n")

		for _, rule := range policy.CommandRules {
			writeCommandRule(&b, rule, false)
		}

		if len(policy.BlockedCommands) > 0 {
			b.WriteString("  # --- Blocked commands (commented for review) ---\n")
			for _, rule := range policy.BlockedCommands {
				writeCommandRule(&b, rule, true)
			}
		}
		b.WriteString("\n")
	}

	// Unix socket rules
	if len(policy.UnixRules) > 0 {
		b.WriteString("unix_socket_rules:\n")
		for _, rule := range policy.UnixRules {
			writeUnixRule(&b, rule)
		}
	}

	return b.String()
}

func writeFileRule(b *strings.Builder, rule FileRuleGen, commented bool) {
	prefix := "  "
	if commented {
		prefix = "  # "
		b.WriteString(fmt.Sprintf("  # BLOCKED: %s\n", rule.Provenance.BlockReason))
	}

	b.WriteString(fmt.Sprintf("%s- name: %s\n", prefix, rule.Name))
	if rule.Description != "" {
		b.WriteString(fmt.Sprintf("%s  description: %q\n", prefix, rule.Description))
	}
	b.WriteString(fmt.Sprintf("%s  # Provenance: %s\n", prefix, rule.Provenance.String()))
	if len(rule.Provenance.SamplePaths) > 0 {
		b.WriteString(fmt.Sprintf("%s  # Sample paths: %s\n", prefix, strings.Join(rule.Provenance.SamplePaths, ", ")))
	}
	b.WriteString(fmt.Sprintf("%s  paths: %s\n", prefix, formatStringList(rule.Paths)))
	b.WriteString(fmt.Sprintf("%s  operations: %s\n", prefix, formatStringList(rule.Operations)))
	b.WriteString(fmt.Sprintf("%s  decision: %s\n", prefix, rule.Decision))
	b.WriteString("\n")
}

func writeNetworkRule(b *strings.Builder, rule NetworkRuleGen, commented bool) {
	prefix := "  "
	if commented {
		prefix = "  # "
		b.WriteString(fmt.Sprintf("  # BLOCKED: %s\n", rule.Provenance.BlockReason))
	}

	b.WriteString(fmt.Sprintf("%s- name: %s\n", prefix, rule.Name))
	b.WriteString(fmt.Sprintf("%s  # Provenance: %s\n", prefix, rule.Provenance.String()))
	b.WriteString(fmt.Sprintf("%s  domains: %s\n", prefix, formatStringList(rule.Domains)))
	if len(rule.Ports) > 0 {
		b.WriteString(fmt.Sprintf("%s  ports: %s\n", prefix, formatIntList(rule.Ports)))
	}
	b.WriteString(fmt.Sprintf("%s  decision: %s\n", prefix, rule.Decision))
	b.WriteString("\n")
}

func writeCommandRule(b *strings.Builder, rule CommandRuleGen, commented bool) {
	prefix := "  "
	if commented {
		prefix = "  # "
		b.WriteString(fmt.Sprintf("  # BLOCKED: %s\n", rule.Provenance.BlockReason))
	}

	b.WriteString(fmt.Sprintf("%s- name: %s\n", prefix, rule.Name))
	b.WriteString(fmt.Sprintf("%s  # Provenance: %d invocations", prefix, rule.Provenance.EventCount))
	if rule.Risky {
		b.WriteString(fmt.Sprintf(" (risky: %s)", rule.RiskyReason))
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%s  commands: %s\n", prefix, formatStringList(rule.Commands)))
	if rule.ArgsPattern != "" {
		b.WriteString(fmt.Sprintf("%s  args_patterns: [%q]\n", prefix, rule.ArgsPattern))
	}
	b.WriteString(fmt.Sprintf("%s  decision: %s\n", prefix, rule.Decision))
	b.WriteString("\n")
}

func writeUnixRule(b *strings.Builder, rule UnixRuleGen) {
	b.WriteString(fmt.Sprintf("  - name: %s\n", rule.Name))
	b.WriteString(fmt.Sprintf("    # Provenance: %s\n", rule.Provenance.String()))
	if strings.Contains(rule.Description, "WARNING") {
		b.WriteString(fmt.Sprintf("    # %s\n", rule.Description))
	}
	b.WriteString(fmt.Sprintf("    paths: %s\n", formatStringList(rule.Paths)))
	if len(rule.Operations) > 0 {
		b.WriteString(fmt.Sprintf("    operations: %s\n", formatStringList(rule.Operations)))
	}
	b.WriteString(fmt.Sprintf("    decision: %s\n", rule.Decision))
	b.WriteString("\n")
}

func formatStringList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = fmt.Sprintf("%q", item)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func formatIntList(items []int) string {
	if len(items) == 0 {
		return "[]"
	}
	sort.Ints(items)
	strs := make([]string, len(items))
	for i, item := range items {
		strs[i] = fmt.Sprintf("%d", item)
	}
	return "[" + strings.Join(strs, ", ") + "]"
}

func formatDuration(d time.Duration) string {
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm %ds", minutes, seconds)
}

func truncateID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func countUniquePaths(rules []FileRuleGen) int {
	paths := make(map[string]bool)
	for _, r := range rules {
		for _, p := range r.Provenance.SamplePaths {
			paths[p] = true
		}
	}
	return len(paths)
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-policy-generate
git add internal/policygen/output.go internal/policygen/output_test.go
git commit -m "feat(policygen): add YAML output formatter with provenance"
```

---

### Task 6: Add CLI command

**Files:**
- Modify: `internal/cli/policy_cmd.go`
- Create: `internal/cli/policy_generate_test.go`

**Step 1: Write the test**

```go
// internal/cli/policy_generate_test.go
package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestPolicyGenerateCmd_RequiresSessionArg(t *testing.T) {
	cmd := newPolicyCmd()
	cmd.SetArgs([]string{"generate"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for missing session arg")
	}
}

func TestPolicyGenerateCmd_OutputsYAML(t *testing.T) {
	// This test requires a mock or integration setup
	// For now, just verify the command structure
	cmd := newPolicyCmd()

	// Find generate subcommand
	var generateCmd *cobra.Command
	for _, c := range cmd.Commands() {
		if c.Name() == "generate" {
			generateCmd = c
			break
		}
	}

	if generateCmd == nil {
		t.Fatal("generate subcommand not found")
	}

	// Check flags exist
	if generateCmd.Flag("output") == nil {
		t.Error("missing --output flag")
	}
	if generateCmd.Flag("name") == nil {
		t.Error("missing --name flag")
	}
	if generateCmd.Flag("threshold") == nil {
		t.Error("missing --threshold flag")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/cli/... -run TestPolicyGenerate -v`
Expected: FAIL - generate subcommand not found

**Step 3: Add generate subcommand to policy_cmd.go**

Add this to `internal/cli/policy_cmd.go` inside the `newPolicyCmd()` function, after the existing subcommands:

```go
// Add to internal/cli/policy_cmd.go - inside newPolicyCmd() before "return cmd"

	// Generate subcommand
	var (
		genOutput       string
		genName         string
		genThreshold    int
		genIncludeBlock bool
		genArgPatterns  bool
		genDirectDB     bool
		genDBPath       string
	)

	generateCmd := &cobra.Command{
		Use:   "generate <session-id|latest>",
		Short: "Generate a policy from session activity",
		Long: `Generate a restrictive policy based on observed session behavior.

This command analyzes events from a session and creates a policy that
would allow only the operations that were performed during that session.

Examples:
  # Generate policy from latest session
  agentsh policy generate latest --output=ci-policy.yaml

  # Generate with custom name and threshold
  agentsh policy generate abc123 --name=production-build --threshold=10

  # Quick preview to stdout
  agentsh policy generate latest`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionArg := args[0]
			ctx := cmd.Context()

			var sess types.Session
			var events []types.Event
			var err error

			if genDirectDB {
				if genDBPath == "" {
					genDBPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
				}
				sess, events, err = loadReportFromDB(ctx, genDBPath, sessionArg)
			} else {
				cfg := getClientConfig(cmd)
				sess, events, err = loadReportFromAPI(ctx, cfg, sessionArg)
			}

			if err != nil {
				return err
			}

			// Create generator with mock store
			store := &memoryEventStore{events: events}
			gen := policygen.NewGenerator(store)

			opts := policygen.Options{
				Name:           genName,
				Threshold:      genThreshold,
				IncludeBlocked: genIncludeBlock,
				ArgPatterns:    genArgPatterns,
			}

			if opts.Name == "" {
				opts.Name = fmt.Sprintf("generated-%s", truncateSessionID(sess.ID))
			}

			policy, err := gen.Generate(ctx, sess, opts)
			if err != nil {
				return fmt.Errorf("generate policy: %w", err)
			}

			yaml := policygen.FormatYAML(policy, opts.Name)

			if genOutput != "" {
				if err := os.WriteFile(genOutput, []byte(yaml), 0644); err != nil {
					return fmt.Errorf("write output file: %w", err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Policy written to %s\n", genOutput)
			} else {
				fmt.Fprint(cmd.OutOrStdout(), yaml)
			}

			return nil
		},
	}

	generateCmd.Flags().StringVar(&genOutput, "output", "", "Output file path (default: stdout)")
	generateCmd.Flags().StringVar(&genName, "name", "", "Policy name (default: generated-<session-id>)")
	generateCmd.Flags().IntVar(&genThreshold, "threshold", 5, "Files in same dir before collapsing to glob")
	generateCmd.Flags().BoolVar(&genIncludeBlock, "include-blocked", true, "Include blocked ops as comments")
	generateCmd.Flags().BoolVar(&genArgPatterns, "arg-patterns", true, "Generate arg patterns for risky commands")
	generateCmd.Flags().BoolVar(&genDirectDB, "direct-db", false, "Query local database directly (offline mode)")
	generateCmd.Flags().StringVar(&genDBPath, "db-path", "", "Path to events database")

	cmd.AddCommand(generateCmd)
```

Also add the import and helper function:

```go
// Add to imports at top of policy_cmd.go
import (
	// ... existing imports ...
	"github.com/agentsh/agentsh/internal/policygen"
)

// Add helper function
func truncateSessionID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/cli/... -run TestPolicyGenerate -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-policy-generate
git add internal/cli/policy_cmd.go internal/cli/policy_generate_test.go
git commit -m "feat(cli): add 'policy generate' command"
```

---

### Task 7: Integration test

**Files:**
- Create: `internal/policygen/integration_test.go`

**Step 1: Write integration test**

```go
// internal/policygen/integration_test.go
package policygen

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestIntegration_FullPolicyGeneration(t *testing.T) {
	// Simulate a realistic CI/CD session
	now := time.Now()
	events := []types.Event{
		// npm install - file reads
		{Type: "file_read", Path: "/workspace/package.json", Timestamp: now, Policy: allow()},
		{Type: "file_read", Path: "/workspace/package-lock.json", Timestamp: now.Add(time.Second), Policy: allow()},

		// npm install - network
		{Type: "net_connect", Domain: "registry.npmjs.org", Timestamp: now.Add(2 * time.Second), Policy: allow(), Fields: map[string]any{"port": 443}},

		// npm install - node_modules writes (many files)
		{Type: "file_write", Path: "/workspace/node_modules/lodash/index.js", Timestamp: now.Add(3 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/node_modules/lodash/fp.js", Timestamp: now.Add(3 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/node_modules/express/index.js", Timestamp: now.Add(4 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/node_modules/express/router.js", Timestamp: now.Add(4 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/node_modules/axios/index.js", Timestamp: now.Add(5 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/node_modules/axios/core.js", Timestamp: now.Add(5 * time.Second), Policy: allow()},

		// Build - source files
		{Type: "file_read", Path: "/workspace/src/index.ts", Timestamp: now.Add(10 * time.Second), Policy: allow()},
		{Type: "file_read", Path: "/workspace/src/utils.ts", Timestamp: now.Add(10 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/dist/index.js", Timestamp: now.Add(11 * time.Second), Policy: allow()},

		// Commands
		{Type: "command_intercept", Timestamp: now.Add(time.Second), Policy: allow(), Fields: map[string]any{"command": "npm install"}},
		{Type: "command_intercept", Timestamp: now.Add(10 * time.Second), Policy: allow(), Fields: map[string]any{"command": "npm run build"}},

		// Risky command with URL
		{Type: "command_intercept", Timestamp: now.Add(15 * time.Second), Policy: allow(), Fields: map[string]any{"command": "curl https://api.github.com/repos/test"}},
		{Type: "net_connect", Domain: "api.github.com", Timestamp: now.Add(15 * time.Second), Policy: allow(), Fields: map[string]any{"port": 443, "command": "curl"}},

		// Blocked operation
		{Type: "file_write", Path: "/etc/hosts", Timestamp: now.Add(20 * time.Second), Policy: deny("system file")},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "integration-test-session"}
	opts := DefaultOptions()
	opts.Threshold = 3 // Low for testing

	policy, err := gen.Generate(context.Background(), sess, opts)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	// Verify structure
	if policy.SessionID != "integration-test-session" {
		t.Errorf("wrong session ID: %s", policy.SessionID)
	}

	// Should have file rules
	if len(policy.FileRules) == 0 {
		t.Error("expected file rules")
	}

	// Should collapse node_modules
	hasNodeModulesGlob := false
	for _, r := range policy.FileRules {
		if strings.Contains(r.Paths[0], "node_modules/**") {
			hasNodeModulesGlob = true
			break
		}
	}
	if !hasNodeModulesGlob {
		t.Error("expected node_modules to be collapsed to glob")
	}

	// Should have network rules
	if len(policy.NetworkRules) == 0 {
		t.Error("expected network rules")
	}

	// Should have command rules
	if len(policy.CommandRules) == 0 {
		t.Error("expected command rules")
	}

	// curl should be marked as risky with arg pattern
	var curlRule *CommandRuleGen
	for i := range policy.CommandRules {
		if policy.CommandRules[i].Commands[0] == "curl" {
			curlRule = &policy.CommandRules[i]
			break
		}
	}
	if curlRule == nil {
		t.Error("expected curl command rule")
	} else {
		if !curlRule.Risky {
			t.Error("curl should be marked risky")
		}
		if curlRule.ArgsPattern == "" {
			t.Error("curl should have arg pattern")
		}
	}

	// Should have blocked files
	if len(policy.BlockedFiles) == 0 {
		t.Error("expected blocked file rules")
	}

	// Format as YAML and verify
	yaml := FormatYAML(policy, "ci-build")

	if !strings.Contains(yaml, "version: 1") {
		t.Error("missing version in YAML")
	}
	if !strings.Contains(yaml, "name: ci-build") {
		t.Error("missing name in YAML")
	}
	if !strings.Contains(yaml, "# BLOCKED:") {
		t.Error("missing blocked section in YAML")
	}
	if !strings.Contains(yaml, "risky:") {
		t.Error("missing risky indicator in YAML")
	}
}

func allow() *types.PolicyInfo {
	return &types.PolicyInfo{Decision: types.DecisionAllow}
}

func deny(msg string) *types.PolicyInfo {
	return &types.PolicyInfo{Decision: types.DecisionDeny, Message: msg}
}
```

**Step 2: Run test**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./internal/policygen/... -run TestIntegration -v`
Expected: PASS

**Step 3: Commit**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-policy-generate
git add internal/policygen/integration_test.go
git commit -m "test(policygen): add integration test for full policy generation"
```

---

### Task 8: Run full test suite and verify

**Files:** none

**Step 1: Run all tests**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go test ./... -v 2>&1 | tail -50`
Expected: All tests pass

**Step 2: Build to verify compilation**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go build ./...`
Expected: Success

**Step 3: Verify CLI help**

Run: `cd /home/eran/work/agentsh/.worktrees/feature-policy-generate && go run ./cmd/agentsh policy generate --help`
Expected: Shows help with flags

---

### Task 9: Final cleanup and documentation

**Files:**
- Modify: `docs/plans/2025-12-30-policy-generate-design.md` (update status)

**Step 1: Update design doc status**

Change `Status: Approved` to `Status: Implemented`

**Step 2: Final commit**

```bash
cd /home/eran/work/agentsh/.worktrees/feature-policy-generate
git add docs/plans/2025-12-30-policy-generate-design.md
git commit -m "docs: mark policy generate design as implemented"
```

---

## Execution Checklist

- [ ] Task 1: Types package
- [ ] Task 2: Risky command detection
- [ ] Task 3: Path/domain grouping
- [ ] Task 4: Core generator
- [ ] Task 5: YAML output formatter
- [ ] Task 6: CLI command
- [ ] Task 7: Integration test
- [ ] Task 8: Full test suite
- [ ] Task 9: Documentation update
