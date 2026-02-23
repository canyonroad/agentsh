package mcpinspect

import (
	"fmt"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

// CrossServerDecision is the output of SessionAnalyzer.Check.
// It describes which rule fired, the severity, and the related tool calls
// that contributed to the detection.
type CrossServerDecision struct {
	Blocked  bool
	Rule     string // "read_then_send", "burst", "cross_server_flow", "shadow_tool"
	Reason   string
	Severity string // "critical", "high", "medium"
	Related  []ToolCallRecord
}

// shadowInfo tracks a tool that was overwritten by a different server.
type shadowInfo struct {
	OriginalServerID string
	NewServerID      string
}

// SessionAnalyzer detects cross-server attack patterns by analysing
// sequences of MCP tool calls within a session. It implements four
// detection rules: shadow tool, burst, read-then-send, and cross-server flow.
//
// The analyzer starts in an inactive state. Call Activate() to allocate the
// sliding window and burst tracking state. Shadow tool tracking (via
// NotifyOverwrite) is always active regardless of activation state.
type SessionAnalyzer struct {
	mu        sync.Mutex
	active    bool   // flipped by Activate()
	sessionID string
	cfg       config.CrossServerConfig
	classifier *ToolClassifier

	// Sliding window -- only allocated on Activate()
	window    []ToolCallRecord
	maxWindow time.Duration // max age of records to keep

	// Shadow tracking -- populated by NotifyOverwrite(), always active
	shadows map[string]shadowInfo // toolName -> overwrite info

	// Burst tracking -- per-server call timestamps
	bursts map[string][]time.Time // serverID -> recent timestamps
}

// NewSessionAnalyzer creates an inactive analyzer. The shadows map is
// initialized immediately (always active). The window and bursts fields
// remain nil until Activate() is called.
func NewSessionAnalyzer(sessionID string, cfg config.CrossServerConfig) *SessionAnalyzer {
	return &SessionAnalyzer{
		sessionID:  sessionID,
		cfg:        cfg,
		classifier: NewToolClassifier(),
		shadows:    make(map[string]shadowInfo),
	}
}

// Activate allocates the sliding window and burst map. Sets active=true.
// This method is idempotent.
func (a *SessionAnalyzer) Activate() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.active {
		return
	}

	a.active = true
	a.window = make([]ToolCallRecord, 0, 64)
	a.bursts = make(map[string][]time.Time)
	a.maxWindow = computeMaxWindow(a.cfg)
}

// computeMaxWindow returns the maximum of all configured windows so the
// sliding window retains enough history for every rule.
func computeMaxWindow(cfg config.CrossServerConfig) time.Duration {
	max := cfg.ReadThenSend.Window
	if cfg.Burst.Window > max {
		max = cfg.Burst.Window
	}
	if cfg.CrossServerFlow.Window > max {
		max = cfg.CrossServerFlow.Window
	}
	if max == 0 {
		// Safety default so we never have a zero-length window.
		max = 30 * time.Second
	}
	return max
}

// NotifyOverwrite records a tool name collision. This always works even
// before activation. Thread-safe.
func (a *SessionAnalyzer) NotifyOverwrite(toolName, oldServerID, newServerID string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.shadows[toolName] = shadowInfo{
		OriginalServerID: oldServerID,
		NewServerID:      newServerID,
	}
}

// Check evaluates all enabled rules against the current state.
// Returns nil if no rule triggers.
//
// When inactive and no shadows exist, returns nil immediately.
// When inactive but shadows exist, only checks the shadow rule.
// When active, checks all enabled rules in order:
//  1. Shadow tool (always, if enabled)
//  2. Burst (if enabled)
//  3. Read-then-send (if enabled, only when category is "send")
//  4. Cross-server flow (if enabled, only when category is "write" or "send")
func (a *SessionAnalyzer) Check(serverID, toolName, requestID string) *CrossServerDecision {
	a.mu.Lock()
	defer a.mu.Unlock()

	hasShadows := len(a.shadows) > 0

	// Fast path: nothing to check.
	if !a.active && !hasShadows {
		return nil
	}

	now := time.Now()

	// 1. Shadow tool detection (always checked if enabled).
	if a.cfg.ShadowTool.Enabled {
		if dec := a.checkShadow(toolName); dec != nil {
			return dec
		}
	}

	// Remaining rules require activation.
	if !a.active {
		return nil
	}

	// 2. Burst detection.
	if a.cfg.Burst.Enabled {
		if dec := a.checkBurst(serverID, now); dec != nil {
			return dec
		}
	}

	// Classify the tool for category-aware rules.
	category := a.classifier.Classify(toolName)

	// 3. Read-then-send (only when category is "send").
	if a.cfg.ReadThenSend.Enabled && category == CategorySend {
		if dec := a.checkReadThenSend(serverID, now); dec != nil {
			return dec
		}
	}

	// 4. Cross-server flow (only when category is "write" or "send").
	if a.cfg.CrossServerFlow.Enabled && (category == CategoryWrite || category == CategorySend) {
		if dec := a.checkCrossServerFlow(serverID, requestID, now); dec != nil {
			return dec
		}
	}

	return nil
}

// Record appends a tool call record to the sliding window and prunes entries
// older than maxWindow. No-op when inactive.
func (a *SessionAnalyzer) Record(rec ToolCallRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.active {
		return
	}

	a.window = append(a.window, rec)
	a.pruneWindow(rec.Timestamp)
}

// --- internal detection helpers (must be called with mu held) ---

func (a *SessionAnalyzer) checkShadow(toolName string) *CrossServerDecision {
	info, ok := a.shadows[toolName]
	if !ok {
		return nil
	}
	return &CrossServerDecision{
		Blocked:  true,
		Rule:     "shadow_tool",
		Severity: "critical",
		Reason: fmt.Sprintf(
			"Tool %q was shadowed: originally from %q, now served by %q",
			toolName, info.OriginalServerID, info.NewServerID,
		),
	}
}

func (a *SessionAnalyzer) checkBurst(serverID string, now time.Time) *CrossServerDecision {
	window := a.cfg.Burst.Window
	maxCalls := a.cfg.Burst.MaxCalls

	// Prune old timestamps for this server.
	cutoff := now.Add(-window)
	ts := a.bursts[serverID]
	pruned := ts[:0]
	for _, t := range ts {
		if !t.Before(cutoff) {
			pruned = append(pruned, t)
		}
	}

	// Add the current call.
	pruned = append(pruned, now)
	a.bursts[serverID] = pruned

	if len(pruned) >= maxCalls {
		return &CrossServerDecision{
			Blocked:  true,
			Rule:     "burst",
			Severity: "high",
			Reason: fmt.Sprintf(
				"Server %q exceeded burst limit: %d calls in %s",
				serverID, len(pruned), window,
			),
		}
	}
	return nil
}

func (a *SessionAnalyzer) checkReadThenSend(serverID string, now time.Time) *CrossServerDecision {
	window := a.cfg.ReadThenSend.Window
	cutoff := now.Add(-window)

	for i := len(a.window) - 1; i >= 0; i-- {
		rec := a.window[i]
		if rec.Timestamp.Before(cutoff) {
			break // window is sorted by time; older entries are before
		}
		if rec.Category == CategoryRead && rec.Action == "allow" && rec.ServerID != serverID {
			elapsed := now.Sub(rec.Timestamp)
			return &CrossServerDecision{
				Blocked:  true,
				Rule:     "read_then_send",
				Severity: "critical",
				Reason: fmt.Sprintf(
					"Server %q attempted send after %q read data %s ago",
					serverID, rec.ServerID, elapsed.Round(time.Millisecond),
				),
				Related: []ToolCallRecord{rec},
			}
		}
	}
	return nil
}

func (a *SessionAnalyzer) checkCrossServerFlow(serverID, requestID string, now time.Time) *CrossServerDecision {
	window := a.cfg.CrossServerFlow.Window
	sameTurnOnly := a.cfg.CrossServerFlow.SameTurnOnly
	cutoff := now.Add(-window)

	for i := len(a.window) - 1; i >= 0; i-- {
		rec := a.window[i]
		if rec.Timestamp.Before(cutoff) {
			break
		}
		if rec.Category == CategoryRead && rec.Action == "allow" && rec.ServerID != serverID {
			if sameTurnOnly && rec.RequestID != requestID {
				continue
			}
			return &CrossServerDecision{
				Blocked:  true,
				Rule:     "cross_server_flow",
				Severity: "high",
				Reason: fmt.Sprintf(
					"Cross-server data flow: %q read -> %q write/send in same turn",
					rec.ServerID, serverID,
				),
				Related: []ToolCallRecord{rec},
			}
		}
	}
	return nil
}

// pruneWindow removes entries older than maxWindow from the sliding window.
func (a *SessionAnalyzer) pruneWindow(now time.Time) {
	cutoff := now.Add(-a.maxWindow)
	idx := 0
	for idx < len(a.window) && a.window[idx].Timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		n := copy(a.window, a.window[idx:])
		// Zero out stale references to allow GC.
		for i := n; i < len(a.window); i++ {
			a.window[i] = ToolCallRecord{}
		}
		a.window = a.window[:n]
	}
}
