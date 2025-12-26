package simulation

import (
	"testing"
)

func TestDefaultModeConfig(t *testing.T) {
	cfg := DefaultModeConfig()

	if cfg.DryRun.Enabled {
		t.Error("DryRun should be disabled by default")
	}
	if !cfg.DryRun.LogDecisions {
		t.Error("DryRun.LogDecisions should be true by default")
	}
	if !cfg.Strict.Enabled {
		t.Error("Strict should be enabled by default")
	}
}

type mockLogger struct {
	calls []struct {
		op          *Operation
		decision    Decision
		wouldEnforce bool
	}
}

func (m *mockLogger) LogDecision(op *Operation, decision Decision, wouldEnforce bool) {
	m.calls = append(m.calls, struct {
		op           *Operation
		decision     Decision
		wouldEnforce bool
	}{op, decision, wouldEnforce})
}

func TestNewModeManager(t *testing.T) {
	cfg := DefaultModeConfig()
	logger := &mockLogger{}
	mm := NewModeManager(cfg, logger)

	if mm == nil {
		t.Fatal("NewModeManager returned nil")
	}

	// Should be strict by default
	if mm.CurrentMode() != ModeStrict {
		t.Errorf("CurrentMode() = %v, want strict", mm.CurrentMode())
	}
}

func TestModeManager_DryRunMode(t *testing.T) {
	cfg := DefaultModeConfig()
	cfg.DryRun.Enabled = true
	cfg.Strict.Enabled = false
	logger := &mockLogger{}
	mm := NewModeManager(cfg, logger)

	if mm.CurrentMode() != ModeDryRun {
		t.Errorf("CurrentMode() = %v, want dry_run", mm.CurrentMode())
	}

	if mm.ShouldEnforce() {
		t.Error("ShouldEnforce() should return false in dry-run mode")
	}

	if !mm.IsDryRun() {
		t.Error("IsDryRun() should return true")
	}
}

func TestModeManager_PermissiveMode(t *testing.T) {
	cfg := DefaultModeConfig()
	cfg.Permissive.Enabled = true
	cfg.Strict.Enabled = false
	logger := &mockLogger{}
	mm := NewModeManager(cfg, logger)

	if mm.CurrentMode() != ModePermissive {
		t.Errorf("CurrentMode() = %v, want permissive", mm.CurrentMode())
	}

	if mm.ShouldEnforce() {
		t.Error("ShouldEnforce() should return false in permissive mode")
	}

	if mm.DefaultDecision() != DecisionAllow {
		t.Errorf("DefaultDecision() = %v, want allow", mm.DefaultDecision())
	}
}

func TestModeManager_StrictMode(t *testing.T) {
	cfg := DefaultModeConfig()
	mm := NewModeManager(cfg, nil)

	if mm.CurrentMode() != ModeStrict {
		t.Errorf("CurrentMode() = %v, want strict", mm.CurrentMode())
	}

	if !mm.ShouldEnforce() {
		t.Error("ShouldEnforce() should return true in strict mode")
	}

	if mm.DefaultDecision() != DecisionDeny {
		t.Errorf("DefaultDecision() = %v, want deny", mm.DefaultDecision())
	}
}

func TestModeManager_ProcessDecision_DryRun(t *testing.T) {
	cfg := DefaultModeConfig()
	cfg.DryRun.Enabled = true
	cfg.DryRun.LogDecisions = true
	cfg.Strict.Enabled = false
	logger := &mockLogger{}
	mm := NewModeManager(cfg, logger)

	op := &Operation{Type: "file_read", Path: "/etc/passwd"}

	// In dry-run, deny should become allow
	result := mm.ProcessDecision(op, DecisionDeny)
	if result != DecisionAllow {
		t.Errorf("ProcessDecision() = %v, want allow (dry-run converts deny)", result)
	}

	// Should have logged
	if len(logger.calls) != 1 {
		t.Errorf("Expected 1 log call, got %d", len(logger.calls))
	}
	if logger.calls[0].wouldEnforce {
		t.Error("wouldEnforce should be false in dry-run")
	}
}

func TestModeManager_ProcessDecision_Strict(t *testing.T) {
	cfg := DefaultModeConfig()
	logger := &mockLogger{}
	mm := NewModeManager(cfg, logger)

	op := &Operation{Type: "file_read", Path: "/etc/passwd"}

	// In strict mode, deny stays deny
	result := mm.ProcessDecision(op, DecisionDeny)
	if result != DecisionDeny {
		t.Errorf("ProcessDecision() = %v, want deny", result)
	}

	// Should have logged
	if len(logger.calls) != 1 {
		t.Errorf("Expected 1 log call, got %d", len(logger.calls))
	}
	if !logger.calls[0].wouldEnforce {
		t.Error("wouldEnforce should be true in strict mode")
	}
}

func TestModeManager_SetMode(t *testing.T) {
	cfg := DefaultModeConfig()
	mm := NewModeManager(cfg, nil)

	mm.SetMode(ModePermissive)
	if mm.CurrentMode() != ModePermissive {
		t.Errorf("CurrentMode() = %v, want permissive", mm.CurrentMode())
	}
}

func TestMode_Constants(t *testing.T) {
	modes := []Mode{ModeNormal, ModeDryRun, ModeSimulation, ModePermissive, ModeStrict}
	for _, m := range modes {
		if string(m) == "" {
			t.Error("Mode constant is empty")
		}
	}
}

func TestDecision_Constants(t *testing.T) {
	decisions := []Decision{DecisionAllow, DecisionDeny, DecisionApprove, DecisionRedirect, DecisionAudit}
	for _, d := range decisions {
		if string(d) == "" {
			t.Error("Decision constant is empty")
		}
	}
}

func TestModeManager_Config(t *testing.T) {
	cfg := DefaultModeConfig()
	mm := NewModeManager(cfg, nil)

	got := mm.Config()
	if got.Strict.Enabled != cfg.Strict.Enabled {
		t.Error("Config() should return the configuration")
	}
}
