//go:build windows

package windows

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestRiskLevel_String(t *testing.T) {
	tests := []struct {
		level RiskLevel
		want  string
	}{
		{RiskLow, "low"},
		{RiskMedium, "medium"},
		{RiskHigh, "high"},
		{RiskCritical, "critical"},
		{RiskLevel(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.level.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHighRiskRegistryPaths(t *testing.T) {
	paths := GetHighRiskPaths()

	if len(paths) == 0 {
		t.Error("HighRiskRegistryPaths is empty")
	}

	// Check for known critical paths
	foundRun := false
	foundDefender := false
	for _, p := range paths {
		if strings.Contains(p.Path, "CurrentVersion\\Run") {
			foundRun = true
			if p.Risk != RiskCritical {
				t.Errorf("Run key should be RiskCritical, got %v", p.Risk)
			}
		}
		if strings.Contains(p.Path, "Windows Defender") {
			foundDefender = true
			if p.Risk != RiskCritical {
				t.Errorf("Windows Defender path should be RiskCritical, got %v", p.Risk)
			}
		}
	}

	if !foundRun {
		t.Error("Missing Run key in high-risk paths")
	}
	if !foundDefender {
		t.Error("Missing Windows Defender path in high-risk paths")
	}
}

func TestIsHighRiskPath(t *testing.T) {
	tests := []struct {
		path     string
		wantRisk bool
	}{
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, true},
		{`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyApp`, true},
		{`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`, true},
		{`HKCU\SOFTWARE\MyCompany\MyApp`, false},
		{`HKLM\SOFTWARE\SomeRandomPath`, false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			isRisk, policy := IsHighRiskPath(tt.path)
			if isRisk != tt.wantRisk {
				t.Errorf("IsHighRiskPath(%q) = %v, want %v", tt.path, isRisk, tt.wantRisk)
			}
			if tt.wantRisk && policy == nil {
				t.Error("Expected policy to be non-nil for high-risk path")
			}
		})
	}
}

func TestParseHive(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{`HKLM\SOFTWARE\Test`, string(HiveLocalMachine)},
		{`HKEY_LOCAL_MACHINE\SOFTWARE\Test`, string(HiveLocalMachine)},
		{`HKCU\SOFTWARE\Test`, string(HiveCurrentUser)},
		{`HKEY_CURRENT_USER\SOFTWARE\Test`, string(HiveCurrentUser)},
		{`HKCR\CLSID\Test`, string(HiveClassesRoot)},
		{`HKU\.DEFAULT`, string(HiveUsers)},
		{`HKCC\System`, string(HiveCurrentConfig)},
		{`UNKNOWN\Path`, "UNKNOWN"},
		{``, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := parseHive(tt.path); got != tt.want {
				t.Errorf("parseHive(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestNewRegistryMonitor(t *testing.T) {
	eventChan := make(chan types.Event, 10)
	m := NewRegistryMonitor(eventChan)

	if m == nil {
		t.Fatal("NewRegistryMonitor() returned nil")
	}

	if m.eventChan != eventChan {
		t.Error("eventChan not set correctly")
	}

	if m.watches == nil {
		t.Error("watches map is nil")
	}

	if m.stopChan == nil {
		t.Error("stopChan is nil")
	}
}

func TestRegistryMonitor_StartStop(t *testing.T) {
	eventChan := make(chan types.Event, 100)
	m := NewRegistryMonitor(eventChan)

	ctx := context.Background()

	// Start
	if err := m.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	if !m.running {
		t.Error("running should be true after Start()")
	}

	// Start again should error
	if err := m.Start(ctx); err == nil {
		t.Error("Start() should error when already running")
	}

	// Wait a bit for watches to be added
	time.Sleep(50 * time.Millisecond)

	// Should have some watched paths
	paths := m.WatchedPaths()
	if len(paths) == 0 {
		t.Log("No paths being watched (may be expected if registry access fails)")
	}

	// Stop
	if err := m.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	if m.running {
		t.Error("running should be false after Stop()")
	}

	// Stop again should not error
	if err := m.Stop(); err != nil {
		t.Errorf("Stop() second time error = %v", err)
	}
}

func TestRegistryMonitor_WatchedPaths(t *testing.T) {
	eventChan := make(chan types.Event, 10)
	m := NewRegistryMonitor(eventChan)

	// Initially empty
	paths := m.WatchedPaths()
	if len(paths) != 0 {
		t.Errorf("WatchedPaths() initially = %d, want 0", len(paths))
	}

	// Add a watch
	policy := &RegistryPathPolicy{
		Path:        `HKLM\SOFTWARE\Test`,
		Risk:        RiskLow,
		Description: "Test path",
	}
	m.addWatch(policy)

	paths = m.WatchedPaths()
	if len(paths) != 1 {
		t.Errorf("WatchedPaths() after addWatch = %d, want 1", len(paths))
	}
}

func TestRegistryMonitor_HandleRegistryChange(t *testing.T) {
	eventChan := make(chan types.Event, 10)
	m := NewRegistryMonitor(eventChan)

	watch := &registryWatch{
		path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		policy: &RegistryPathPolicy{
			Path:        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			Risk:        RiskCritical,
			Description: "Startup programs",
			Technique:   "T1547.001",
		},
	}

	m.handleRegistryChange(watch, RegOpSetValue, "TestApp")

	select {
	case ev := <-eventChan:
		if ev.Type != "registry_write" {
			t.Errorf("Type = %q, want registry_write", ev.Type)
		}
		if ev.Path != watch.path {
			t.Errorf("Path = %q, want %q", ev.Path, watch.path)
		}
		if ev.Fields["risk_level"] != "critical" {
			t.Errorf("Fields[risk_level] = %v, want critical", ev.Fields["risk_level"])
		}
		if ev.Fields["technique"] != "T1547.001" {
			t.Errorf("Fields[technique] = %v, want T1547.001", ev.Fields["technique"])
		}
	case <-time.After(time.Second):
		t.Error("Timeout waiting for event")
	}
}

func TestRegistryMonitor_HandleRegistryChange_NilChannel(t *testing.T) {
	m := &RegistryMonitor{
		eventChan: nil,
	}

	watch := &registryWatch{
		path:   `HKLM\SOFTWARE\Test`,
		policy: &RegistryPathPolicy{Path: `HKLM\SOFTWARE\Test`},
	}

	// Should not panic
	m.handleRegistryChange(watch, RegOpSetValue, "Test")
}

func TestRegistryMonitor_SendErrorEvent(t *testing.T) {
	eventChan := make(chan types.Event, 10)
	m := NewRegistryMonitor(eventChan)

	testErr := context.DeadlineExceeded
	m.sendErrorEvent(testErr)

	select {
	case ev := <-eventChan:
		if ev.Type != "registry_error" {
			t.Errorf("Type = %q, want registry_error", ev.Type)
		}
		if ev.Fields["error"] != testErr.Error() {
			t.Errorf("Fields[error] = %v, want %v", ev.Fields["error"], testErr.Error())
		}
	case <-time.After(time.Second):
		t.Error("Timeout waiting for error event")
	}
}

func TestRegistryMonitor_SendErrorEvent_NilChannel(t *testing.T) {
	m := &RegistryMonitor{
		eventChan: nil,
	}

	// Should not panic
	m.sendErrorEvent(context.DeadlineExceeded)
}

func TestRegistryOperation_Constants(t *testing.T) {
	// Verify operation constants are defined
	ops := []RegistryOperation{
		RegOpQueryValue,
		RegOpSetValue,
		RegOpDeleteValue,
		RegOpCreateKey,
		RegOpDeleteKey,
		RegOpRenameKey,
		RegOpEnumKeys,
		RegOpEnumValues,
		RegOpOpenKey,
		RegOpCloseKey,
	}

	for _, op := range ops {
		if op == "" {
			t.Errorf("Registry operation constant is empty")
		}
	}
}

func TestRegistryHive_Constants(t *testing.T) {
	// Verify hive constants are defined
	hives := []RegistryHive{
		HiveClassesRoot,
		HiveCurrentUser,
		HiveLocalMachine,
		HiveUsers,
		HiveCurrentConfig,
	}

	for _, hive := range hives {
		if hive == "" {
			t.Errorf("Registry hive constant is empty")
		}
	}
}
