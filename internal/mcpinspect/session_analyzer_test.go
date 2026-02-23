package mcpinspect

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

// allEnabledConfig returns a CrossServerConfig with all rules enabled and
// reasonable windows for testing.
func allEnabledConfig() config.CrossServerConfig {
	return config.CrossServerConfig{
		Enabled: true,
		ReadThenSend: config.ReadThenSendConfig{
			Enabled: true,
			Window:  30 * time.Second,
		},
		Burst: config.BurstConfig{
			Enabled:  true,
			MaxCalls: 10,
			Window:   5 * time.Second,
		},
		CrossServerFlow: config.CrossServerFlowConfig{
			Enabled:      true,
			SameTurnOnly: true,
			Window:       30 * time.Second,
		},
		ShadowTool: config.ShadowToolConfig{
			Enabled: true,
		},
	}
}

// 1. Inactive returns nil
func TestSessionAnalyzer_InactiveReturnsNil(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())

	dec, _ := a.CheckAndRecord("server-a", "send_email", "req-1")
	if dec != nil {
		t.Fatalf("expected nil decision from inactive analyzer, got %+v", dec)
	}
}

// 2. Activation allocates state
func TestSessionAnalyzer_ActivationAllocatesState(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())

	// Before activation.
	if a.active {
		t.Fatal("expected active to be false before Activate()")
	}
	if a.window != nil {
		t.Fatal("expected window to be nil before Activate()")
	}
	if a.bursts != nil {
		t.Fatal("expected bursts to be nil before Activate()")
	}

	a.Activate()

	if !a.active {
		t.Fatal("expected active to be true after Activate()")
	}
	if a.window == nil {
		t.Fatal("expected window to be non-nil after Activate()")
	}
	if a.bursts == nil {
		t.Fatal("expected bursts to be non-nil after Activate()")
	}

	// Idempotent: calling again should not panic or reset.
	a.Activate()
	if !a.active {
		t.Fatal("expected active to remain true after second Activate()")
	}
}

// 3. Read-then-send detection
func TestSessionAnalyzer_ReadThenSendDetection(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())
	a.Activate()

	now := time.Now()

	// Record a read from server-a.
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_secrets",
		RequestID: "req-1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// Check a send from server-b.
	dec, _ := a.CheckAndRecord("server-b", "send_email", "req-1")
	if dec == nil {
		t.Fatal("expected a decision, got nil")
	}
	if dec.Rule != "read_then_send" {
		t.Errorf("expected rule read_then_send, got %q", dec.Rule)
	}
	if dec.Severity != "critical" {
		t.Errorf("expected severity critical, got %q", dec.Severity)
	}
	if !dec.Blocked {
		t.Error("expected Blocked to be true")
	}
	if len(dec.Related) != 1 {
		t.Errorf("expected 1 related record, got %d", len(dec.Related))
	}
}

// 4. Read-then-send same server (no detection)
func TestSessionAnalyzer_ReadThenSendSameServer(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())
	a.Activate()

	now := time.Now()

	// Record a read from server-a.
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "req-1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// Check a send from the SAME server (server-a).
	dec, _ := a.CheckAndRecord("server-a", "send_email", "req-1")
	if dec != nil {
		t.Fatalf("expected nil for same-server send, got %+v", dec)
	}
}

// 5. Read-then-send expired
func TestSessionAnalyzer_ReadThenSendExpired(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())
	a.Activate()

	now := time.Now()

	// Record a read from 60 seconds ago (window is 30s).
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-60 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "req-1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// Check a send from server-b now.
	dec, _ := a.CheckAndRecord("server-b", "send_email", "req-2")
	if dec != nil {
		t.Fatalf("expected nil for expired read, got %+v", dec)
	}
}

// 6. Burst detection
func TestSessionAnalyzer_BurstDetection(t *testing.T) {
	cfg := allEnabledConfig()
	// Disable read-then-send and cross-server flow to isolate burst test.
	cfg.ReadThenSend.Enabled = false
	cfg.CrossServerFlow.Enabled = false

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	// Make 9 calls (under threshold) then the 10th should trigger.
	for i := 0; i < 9; i++ {
		dec, _ := a.CheckAndRecord("server-a", "get_data", "req-1")
		if dec != nil {
			t.Fatalf("call %d: expected nil, got %+v", i+1, dec)
		}
	}

	// 10th call should trigger burst.
	dec, _ := a.CheckAndRecord("server-a", "get_data", "req-1")
	if dec == nil {
		t.Fatal("expected burst detection on 10th call, got nil")
	}
	if dec.Rule != "burst" {
		t.Errorf("expected rule burst, got %q", dec.Rule)
	}
	if dec.Severity != "high" {
		t.Errorf("expected severity high, got %q", dec.Severity)
	}
	if !dec.Blocked {
		t.Error("expected Blocked to be true")
	}
}

// 7. Burst under threshold
func TestSessionAnalyzer_BurstUnderThreshold(t *testing.T) {
	cfg := allEnabledConfig()
	cfg.ReadThenSend.Enabled = false
	cfg.CrossServerFlow.Enabled = false

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	// Make 9 calls (maxCalls is 10).
	for i := 0; i < 9; i++ {
		dec, _ := a.CheckAndRecord("server-a", "get_data", "req-1")
		if dec != nil {
			t.Fatalf("call %d: expected nil, got %+v", i+1, dec)
		}
	}
	// No 10th call -- should remain nil.
}

// 8. Cross-server flow same turn
func TestSessionAnalyzer_CrossServerFlowSameTurn(t *testing.T) {
	cfg := allEnabledConfig()
	cfg.ReadThenSend.Enabled = false
	cfg.Burst.Enabled = false

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	now := time.Now()

	// Record read from server-a with request R1.
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "R1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// Check write from server-b with same request R1.
	dec, _ := a.CheckAndRecord("server-b", "write_file", "R1")
	if dec == nil {
		t.Fatal("expected cross_server_flow detection, got nil")
	}
	if dec.Rule != "cross_server_flow" {
		t.Errorf("expected rule cross_server_flow, got %q", dec.Rule)
	}
	if dec.Severity != "high" {
		t.Errorf("expected severity high, got %q", dec.Severity)
	}
	if !dec.Blocked {
		t.Error("expected Blocked to be true")
	}
}

// 9. Cross-server flow different turn (same_turn_only=true)
func TestSessionAnalyzer_CrossServerFlowDifferentTurn(t *testing.T) {
	cfg := allEnabledConfig()
	cfg.ReadThenSend.Enabled = false
	cfg.Burst.Enabled = false
	cfg.CrossServerFlow.SameTurnOnly = true

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	now := time.Now()

	// Record read from server-a with request R1.
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "R1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// Check write from server-b with DIFFERENT request R2.
	dec, _ := a.CheckAndRecord("server-b", "write_file", "R2")
	if dec != nil {
		t.Fatalf("expected nil for different turn, got %+v", dec)
	}
}

// 10. Shadow tool detection
func TestSessionAnalyzer_ShadowToolDetection(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())
	a.Activate()

	a.NotifyOverwrite("my_tool", "server-a", "server-b")

	dec, _ := a.CheckAndRecord("server-b", "my_tool", "req-1")
	if dec == nil {
		t.Fatal("expected shadow_tool detection, got nil")
	}
	if dec.Rule != "shadow_tool" {
		t.Errorf("expected rule shadow_tool, got %q", dec.Rule)
	}
	if dec.Severity != "critical" {
		t.Errorf("expected severity critical, got %q", dec.Severity)
	}
	if !dec.Blocked {
		t.Error("expected Blocked to be true")
	}
}

// 11. Shadow tool before activation
func TestSessionAnalyzer_ShadowToolBeforeActivation(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())

	// Do NOT call Activate().
	a.NotifyOverwrite("my_tool", "server-a", "server-b")

	dec, _ := a.CheckAndRecord("server-b", "my_tool", "req-1")
	if dec == nil {
		t.Fatal("expected shadow_tool detection before activation, got nil")
	}
	if dec.Rule != "shadow_tool" {
		t.Errorf("expected rule shadow_tool, got %q", dec.Rule)
	}
	if dec.Severity != "critical" {
		t.Errorf("expected severity critical, got %q", dec.Severity)
	}
}

// 12. Window pruning
func TestSessionAnalyzer_WindowPruning(t *testing.T) {
	cfg := allEnabledConfig()
	// All windows are 30s, so maxWindow will be 30s.
	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	now := time.Now()

	// Add an old record (60s ago, beyond maxWindow of 30s).
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-60 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "req-old",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// Add a recent record.
	a.Record(ToolCallRecord{
		Timestamp: now,
		ServerID:  "server-b",
		ToolName:  "get_data",
		RequestID: "req-new",
		Action:    "allow",
		Category:  CategoryRead,
	})

	a.mu.Lock()
	windowLen := len(a.window)
	a.mu.Unlock()

	if windowLen != 1 {
		t.Errorf("expected window to have 1 entry after pruning, got %d", windowLen)
	}
}

// 13. Classifier integration
func TestSessionAnalyzer_ClassifierIntegration(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())
	a.Activate()

	now := time.Now()

	// Record a read from server-a using a "get_" prefixed tool.
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "req-1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// "send_email" should be classified as "send" by the classifier,
	// triggering read_then_send since server-a just did a read.
	dec, _ := a.CheckAndRecord("server-b", "send_email", "req-1")
	if dec == nil {
		t.Fatal("expected detection, got nil")
	}
	if dec.Rule != "read_then_send" {
		t.Errorf("expected rule read_then_send, got %q", dec.Rule)
	}

	// "write_file" from server-b with matching requestID should trigger
	// cross_server_flow. Reset the analyzer to avoid burst interference.
	a2 := NewSessionAnalyzer("sess-2", allEnabledConfig())
	a2.Activate()

	a2.Record(ToolCallRecord{
		Timestamp: now.Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "req-1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// "write_file" is classified as "write" -> should trigger cross_server_flow
	// (not read_then_send, since that only fires for "send" category).
	dec2, _ := a2.CheckAndRecord("server-b", "write_file", "req-1")
	if dec2 == nil {
		t.Fatal("expected detection for write, got nil")
	}
	if dec2.Rule != "cross_server_flow" {
		t.Errorf("expected rule cross_server_flow, got %q", dec2.Rule)
	}
}

// 14. Config disabled (all sub-rules disabled)
func TestSessionAnalyzer_ConfigDisabled(t *testing.T) {
	cfg := config.CrossServerConfig{
		Enabled: false,
		ReadThenSend: config.ReadThenSendConfig{
			Enabled: false,
			Window:  30 * time.Second,
		},
		Burst: config.BurstConfig{
			Enabled:  false,
			MaxCalls: 10,
			Window:   5 * time.Second,
		},
		CrossServerFlow: config.CrossServerFlowConfig{
			Enabled:      false,
			SameTurnOnly: true,
			Window:       30 * time.Second,
		},
		ShadowTool: config.ShadowToolConfig{
			Enabled: false,
		},
	}

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	// Set up shadow overwrite (would normally trigger).
	a.NotifyOverwrite("my_tool", "server-a", "server-b")

	// Record read from server-a.
	a.Record(ToolCallRecord{
		Timestamp: time.Now().Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "req-1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// Check shadowed tool: should not trigger since all disabled.
	dec, _ := a.CheckAndRecord("server-b", "my_tool", "req-1")
	if dec != nil {
		t.Fatalf("expected nil with all rules disabled (shadow tool check), got %+v", dec)
	}

	// Check send from different server.
	dec, _ = a.CheckAndRecord("server-b", "send_email", "req-1")
	if dec != nil {
		t.Fatalf("expected nil with all rules disabled (read_then_send check), got %+v", dec)
	}

	// Check write from different server.
	dec, _ = a.CheckAndRecord("server-b", "write_file", "req-1")
	if dec != nil {
		t.Fatalf("expected nil with all rules disabled (cross_server_flow check), got %+v", dec)
	}

	// Burst: make 15 rapid calls.
	for i := 0; i < 15; i++ {
		dec, _ = a.CheckAndRecord("server-a", "get_data", "req-1")
		if dec != nil {
			t.Fatalf("call %d: expected nil with all rules disabled (burst check), got %+v", i+1, dec)
		}
	}
}

// 15. Top-level Enabled=false disables all rules even when sub-rules are enabled.
func TestSessionAnalyzer_TopLevelDisabledOverridesSubRules(t *testing.T) {
	cfg := config.CrossServerConfig{
		Enabled: false, // top-level kill switch
		ReadThenSend: config.ReadThenSendConfig{
			Enabled: true,
			Window:  30 * time.Second,
		},
		Burst: config.BurstConfig{
			Enabled:  true,
			MaxCalls: 10,
			Window:   5 * time.Second,
		},
		CrossServerFlow: config.CrossServerFlowConfig{
			Enabled:      true,
			SameTurnOnly: true,
			Window:       30 * time.Second,
		},
		ShadowTool: config.ShadowToolConfig{
			Enabled: true,
		},
	}

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	// Shadow tool should not trigger.
	a.NotifyOverwrite("my_tool", "server-a", "server-b")
	dec, _ := a.CheckAndRecord("server-b", "my_tool", "req-1")
	if dec != nil {
		t.Fatalf("expected nil with top-level disabled (shadow), got %+v", dec)
	}

	// Read-then-send should not trigger.
	a.Record(ToolCallRecord{
		Timestamp: time.Now().Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "req-1",
		Action:    "allow",
		Category:  CategoryRead,
	})
	dec, _ = a.CheckAndRecord("server-b", "send_email", "req-1")
	if dec != nil {
		t.Fatalf("expected nil with top-level disabled (read_then_send), got %+v", dec)
	}
}

// 16. Unknown-category tools from different server trigger cross_server_flow.
func TestSessionAnalyzer_UnknownCategoryTriggersCrossServerFlow(t *testing.T) {
	cfg := allEnabledConfig()
	cfg.ReadThenSend.Enabled = false
	cfg.Burst.Enabled = false

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	now := time.Now()

	// Record a read from server-a.
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "req-1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// "transmit_data" is unknown-category; should trigger cross_server_flow.
	dec, cat := a.CheckAndRecord("server-b", "transmit_data", "req-1")
	if cat != CategoryUnknown {
		t.Errorf("expected category unknown, got %q", cat)
	}
	if dec == nil {
		t.Fatal("expected cross_server_flow detection for unknown-category tool, got nil")
	}
	if dec.Rule != "cross_server_flow" {
		t.Errorf("expected rule cross_server_flow, got %q", dec.Rule)
	}
}

// 17. Compute-category tools trigger cross_server_flow.
func TestSessionAnalyzer_ComputeCategoryTriggersCrossServerFlow(t *testing.T) {
	cfg := allEnabledConfig()
	cfg.ReadThenSend.Enabled = false
	cfg.Burst.Enabled = false

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	now := time.Now()

	// Record a read from server-a.
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_secrets",
		RequestID: "req-1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// "exec_shell" is compute-category; should trigger cross_server_flow.
	dec, cat := a.CheckAndRecord("server-b", "exec_shell", "req-1")
	if cat != CategoryCompute {
		t.Errorf("expected category compute, got %q", cat)
	}
	if dec == nil {
		t.Fatal("expected cross_server_flow detection for compute-category tool, got nil")
	}
	if dec.Rule != "cross_server_flow" {
		t.Errorf("expected rule cross_server_flow, got %q", dec.Rule)
	}
}

// 18. Cross-server flow with SameTurnOnly=false triggers on different turns.
func TestSessionAnalyzer_CrossServerFlowSameTurnOnlyFalse(t *testing.T) {
	cfg := allEnabledConfig()
	cfg.ReadThenSend.Enabled = false
	cfg.Burst.Enabled = false
	cfg.CrossServerFlow.SameTurnOnly = false

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	now := time.Now()

	// Record read from server-a with request R1.
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "R1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// Check write from server-b with DIFFERENT request R2.
	// With SameTurnOnly=false, this should still trigger.
	dec, _ := a.CheckAndRecord("server-b", "write_file", "R2")
	if dec == nil {
		t.Fatal("expected cross_server_flow detection with SameTurnOnly=false, got nil")
	}
	if dec.Rule != "cross_server_flow" {
		t.Errorf("expected rule cross_server_flow, got %q", dec.Rule)
	}
}

// 19. Burst window expiry — burst resets after window expires.
func TestSessionAnalyzer_BurstWindowExpiry(t *testing.T) {
	cfg := allEnabledConfig()
	cfg.ReadThenSend.Enabled = false
	cfg.CrossServerFlow.Enabled = false
	cfg.Burst.MaxCalls = 3
	cfg.Burst.Window = 2 * time.Second

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	now := time.Now()

	// Manually add 2 burst timestamps that are old (3s ago).
	a.mu.Lock()
	a.bursts["server-a"] = []time.Time{
		now.Add(-3 * time.Second),
		now.Add(-3 * time.Second),
	}
	a.mu.Unlock()

	// Next call should prune the old timestamps and only count this one.
	dec, _ := a.CheckAndRecord("server-a", "get_data", "req-1")
	if dec != nil {
		t.Fatalf("expected nil after burst window expired, got %+v", dec)
	}

	// Verify only 1 timestamp remains.
	a.mu.Lock()
	count := len(a.bursts["server-a"])
	a.mu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 burst timestamp after expiry, got %d", count)
	}
}

// 20. ClearShadow removes a shadow entry.
func TestSessionAnalyzer_ClearShadow(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())
	a.Activate()

	a.NotifyOverwrite("my_tool", "server-a", "server-b")

	// Should trigger before clearing.
	dec, _ := a.CheckAndRecord("server-b", "my_tool", "req-1")
	if dec == nil {
		t.Fatal("expected shadow_tool detection, got nil")
	}

	// Clear the shadow.
	a.ClearShadow("my_tool")

	// Should no longer trigger.
	dec, _ = a.CheckAndRecord("server-b", "my_tool", "req-2")
	if dec != nil {
		t.Fatalf("expected nil after ClearShadow, got %+v", dec)
	}
}

// 21. MarkBlocked updates window record.
func TestSessionAnalyzer_MarkBlocked(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())
	a.Activate()

	// CheckAndRecord a read from server-a (will be recorded as "allow").
	dec, _ := a.CheckAndRecord("server-a", "get_data", "req-1")
	if dec != nil {
		t.Fatalf("expected nil, got %+v", dec)
	}

	// The window should have the "allow" record.
	a.mu.Lock()
	if len(a.window) != 1 || a.window[0].Action != "allow" {
		t.Fatalf("expected 1 allow record, got %v", a.window)
	}
	a.mu.Unlock()

	// Mark it as blocked (simulating PolicyEvaluator blocking it).
	a.MarkBlocked("server-a", "get_data", "req-1")

	// The window record should now be "block".
	a.mu.Lock()
	if a.window[0].Action != "block" {
		t.Errorf("expected action block after MarkBlocked, got %q", a.window[0].Action)
	}
	a.mu.Unlock()

	// A subsequent send from server-b should NOT trigger read_then_send
	// because the read was marked as blocked.
	dec, _ = a.CheckAndRecord("server-b", "send_email", "req-2")
	if dec != nil && dec.Rule == "read_then_send" {
		t.Fatalf("expected no read_then_send after MarkBlocked, got %+v", dec)
	}
}

// 22. Window size cap prevents unbounded growth.
func TestSessionAnalyzer_WindowSizeCap(t *testing.T) {
	cfg := allEnabledConfig()
	cfg.Burst.Enabled = false
	cfg.ReadThenSend.Enabled = false
	cfg.CrossServerFlow.Enabled = false

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	now := time.Now()

	// Fill beyond the cap by injecting records directly.
	a.mu.Lock()
	for i := 0; i < maxWindowEntries+100; i++ {
		a.window = append(a.window, ToolCallRecord{
			Timestamp: now.Add(-1 * time.Second), // recent, so not pruned by time
			ServerID:  "server-a",
			ToolName:  "get_data",
			RequestID: "req-1",
			Action:    "allow",
			Category:  CategoryRead,
		})
	}
	a.mu.Unlock()

	// Next CheckAndRecord triggers pruning via recordLocked.
	a.CheckAndRecord("server-a", "get_data", "req-2")

	a.mu.Lock()
	windowLen := len(a.window)
	a.mu.Unlock()

	if windowLen > maxWindowEntries {
		t.Errorf("expected window size <= %d, got %d", maxWindowEntries, windowLen)
	}
}

// 23. CheckAndRecord returns correct category.
func TestSessionAnalyzer_CheckAndRecordReturnsCategory(t *testing.T) {
	a := NewSessionAnalyzer("sess-1", allEnabledConfig())
	a.Activate()

	tests := []struct {
		toolName string
		wantCat  string
	}{
		{"get_data", CategoryRead},
		{"send_email", CategorySend},
		{"write_file", CategoryWrite},
		{"exec_shell", CategoryCompute},
		{"my_custom_tool", CategoryUnknown},
	}
	for _, tt := range tests {
		_, cat := a.CheckAndRecord("server-a", tt.toolName, "req-1")
		if cat != tt.wantCat {
			t.Errorf("CheckAndRecord(%q) category = %q, want %q", tt.toolName, cat, tt.wantCat)
		}
	}
}

// 24. Unknown-category from same server does NOT trigger (no cross-server).
func TestSessionAnalyzer_UnknownCategorySameServerNoTrigger(t *testing.T) {
	cfg := allEnabledConfig()
	cfg.ReadThenSend.Enabled = false
	cfg.Burst.Enabled = false

	a := NewSessionAnalyzer("sess-1", cfg)
	a.Activate()

	now := time.Now()

	// Record a read from server-a.
	a.Record(ToolCallRecord{
		Timestamp: now.Add(-2 * time.Second),
		ServerID:  "server-a",
		ToolName:  "get_data",
		RequestID: "req-1",
		Action:    "allow",
		Category:  CategoryRead,
	})

	// Unknown-category tool from the SAME server should not trigger.
	dec, _ := a.CheckAndRecord("server-a", "transmit_data", "req-1")
	if dec != nil {
		t.Fatalf("expected nil for unknown-category tool from same server, got %+v", dec)
	}
}
