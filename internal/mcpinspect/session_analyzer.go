package mcpinspect

import (
	"fmt"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

// maxWindowEntries is the hard cap on the sliding window size. This bounds
// both memory and CPU (linear scan) under adversarial conditions.
const maxWindowEntries = 1000

// CrossServerDecision is the output of SessionAnalyzer.CheckAndRecord.
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

// ClearShadow removes a shadow entry for a tool. Called when a server
// legitimately re-registers a tool (e.g., after restart) and the shadow
// is no longer valid. Thread-safe.
func (a *SessionAnalyzer) ClearShadow(toolName string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.shadows, toolName)
}

// CheckAndRecord atomically evaluates all enabled cross-server rules and
// records the tool call in the sliding window. This single-lock operation
// eliminates the TOCTOU race between evaluating rules and recording.
//
// The call is recorded with action="allow" initially. If the caller's
// PolicyEvaluator subsequently blocks the call, call MarkBlocked() to
// update the record (prevents a blocked read from triggering
// read-then-send for subsequent calls).
//
// Returns the cross-server decision (nil if no rule triggers) and the
// tool's classified category.
//
// When the feature is disabled, returns (nil, category) immediately.
// When inactive and no shadows exist, returns (nil, category) immediately.
// When inactive but shadows exist, only checks the shadow rule.
// When active, checks all enabled rules in order:
//  1. Shadow tool (always, if enabled)
//  2. Burst (if enabled)
//  3. Read-then-send (if enabled, only when category is "send")
//  4. Cross-server flow (if enabled, when category is write/send/compute/unknown from different server)
func (a *SessionAnalyzer) CheckAndRecord(serverID, toolName, requestID string) (*CrossServerDecision, string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	category := a.classifier.Classify(toolName)

	// Global kill switch: when cross-server detection is disabled, skip all rules.
	if !a.cfg.Enabled {
		return nil, category
	}

	hasShadows := len(a.shadows) > 0

	// Fast path: nothing to check.
	if !a.active && !hasShadows {
		return nil, category
	}

	now := time.Now()

	// 1. Shadow tool detection (always checked if enabled).
	if a.cfg.ShadowTool.Enabled {
		if dec := a.checkShadow(toolName); dec != nil {
			a.recordLocked(serverID, toolName, requestID, "block", category, now)
			return dec, category
		}
	}

	// Remaining rules require activation.
	if !a.active {
		return nil, category
	}

	// 2. Burst detection.
	if a.cfg.Burst.Enabled {
		if dec := a.checkBurst(serverID, now); dec != nil {
			a.recordLocked(serverID, toolName, requestID, "block", category, now)
			return dec, category
		}
	}

	// 3. Read-then-send (only when category is "send").
	if a.cfg.ReadThenSend.Enabled && category == CategorySend {
		if dec := a.checkReadThenSend(serverID, now); dec != nil {
			a.recordLocked(serverID, toolName, requestID, "block", category, now)
			return dec, category
		}
	}

	// 4. Cross-server flow: triggers on write, send, compute, or unknown
	// from a different server when a prior cross-server read exists.
	// Unknown-category tools are included because an attacker can choose
	// tool names to avoid classification (e.g., "transmit_data").
	if a.cfg.CrossServerFlow.Enabled && isSuspiciousCategory(category) {
		if dec := a.checkCrossServerFlow(serverID, requestID, now); dec != nil {
			a.recordLocked(serverID, toolName, requestID, "block", category, now)
			return dec, category
		}
	}

	// No rule triggered — record as "allow" atomically so the entry is
	// immediately visible to concurrent CheckAndRecord calls.
	a.recordLocked(serverID, toolName, requestID, "allow", category, now)
	return nil, category
}

// MarkBlocked updates the most recent "allow" window entry for the given
// tool call to action="block". Called when the PolicyEvaluator blocks a
// call that the cross-server analyzer initially allowed. This prevents a
// blocked read from triggering read-then-send for subsequent calls.
// Thread-safe.
func (a *SessionAnalyzer) MarkBlocked(serverID, toolName, requestID string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Walk backward to find the most recent matching "allow" entry.
	for i := len(a.window) - 1; i >= 0; i-- {
		rec := &a.window[i]
		if rec.ServerID == serverID && rec.ToolName == toolName &&
			rec.RequestID == requestID && rec.Action == "allow" {
			rec.Action = "block"
			return
		}
	}
}

// Record adds a tool call to the sliding window. This is used for test setup
// to inject records with specific timestamps and categories. Production code
// should use CheckAndRecord() which records atomically with rule evaluation.
func (a *SessionAnalyzer) Record(rec ToolCallRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.active {
		return
	}
	a.window = append(a.window, rec)
	a.pruneWindow(rec.Timestamp)
}

// isSuspiciousCategory returns true for categories that could be used for
// data exfiltration or modification in cross-server patterns. Includes
// "unknown" because an attacker can name tools to avoid classification.
func isSuspiciousCategory(category string) bool {
	switch category {
	case CategoryWrite, CategorySend, CategoryCompute, CategoryUnknown:
		return true
	default:
		return false
	}
}

// recordLocked appends a tool call to the sliding window and prunes.
// Must be called with mu held.
func (a *SessionAnalyzer) recordLocked(serverID, toolName, requestID, action, category string, now time.Time) {
	if !a.active {
		return
	}
	a.window = append(a.window, ToolCallRecord{
		Timestamp: now,
		ServerID:  serverID,
		ToolName:  toolName,
		RequestID: requestID,
		Action:    action,
		Category:  category,
	})
	a.pruneWindow(now)
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

// Classify returns the category for a tool name by delegating to the internal
// classifier. The classifier is immutable after construction, so this method
// is safe for concurrent use without locking.
func (a *SessionAnalyzer) Classify(toolName string) string {
	return a.classifier.Classify(toolName)
}

// pruneWindow removes entries older than maxWindow from the sliding window
// and enforces the hard cap on window size.
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

	// Hard cap: if the window exceeds maxWindowEntries, drop the oldest.
	if len(a.window) > maxWindowEntries {
		excess := len(a.window) - maxWindowEntries
		n := copy(a.window, a.window[excess:])
		for i := n; i < len(a.window); i++ {
			a.window[i] = ToolCallRecord{}
		}
		a.window = a.window[:n]
	}
}
