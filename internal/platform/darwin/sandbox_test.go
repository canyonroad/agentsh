//go:build darwin

package darwin

import (
	"context"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewSandboxManager(t *testing.T) {
	m := NewSandboxManager()
	if m == nil {
		t.Fatal("NewSandboxManager() returned nil")
	}

	if m.sandboxes == nil {
		t.Error("sandboxes map should be initialized")
	}
}

func TestSandboxManager_Available(t *testing.T) {
	m := &SandboxManager{
		available: true,
		sandboxes: make(map[string]*Sandbox),
	}

	if !m.Available() {
		t.Error("Available() should return true when available is true")
	}

	m.available = false
	if m.Available() {
		t.Error("Available() should return false when available is false")
	}
}

func TestSandboxManager_IsolationLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    platform.IsolationLevel
		expected platform.IsolationLevel
	}{
		{"none", platform.IsolationNone, platform.IsolationNone},
		{"minimal", platform.IsolationMinimal, platform.IsolationMinimal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &SandboxManager{
				available:      true,
				isolationLevel: tt.level,
				sandboxes:      make(map[string]*Sandbox),
			}

			if got := m.IsolationLevel(); got != tt.expected {
				t.Errorf("IsolationLevel() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSandboxManager_Create_NotAvailable(t *testing.T) {
	m := &SandboxManager{
		available: false,
		sandboxes: make(map[string]*Sandbox),
	}

	_, err := m.Create(platform.SandboxConfig{Name: "test"})
	if err == nil {
		t.Error("Create() should error when not available")
	}
}

func TestSandboxManager_Create_Success(t *testing.T) {
	m := &SandboxManager{
		available:      true,
		isolationLevel: platform.IsolationMinimal,
		sandboxes:      make(map[string]*Sandbox),
	}

	cfg := platform.SandboxConfig{
		Name:          "test-sandbox",
		WorkspacePath: "/tmp/test-workspace",
	}

	sandbox, err := m.Create(cfg)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if sandbox == nil {
		t.Fatal("Create() returned nil sandbox")
	}

	if sandbox.ID() != "test-sandbox" {
		t.Errorf("ID() = %q, want test-sandbox", sandbox.ID())
	}

	// Check internal state
	s := sandbox.(*Sandbox)
	if s.profile == "" {
		t.Error("profile should not be empty")
	}
}

func TestSandboxManager_Create_DefaultName(t *testing.T) {
	m := &SandboxManager{
		available: true,
		sandboxes: make(map[string]*Sandbox),
	}

	sandbox, err := m.Create(platform.SandboxConfig{})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if sandbox.ID() != "sandbox-darwin" {
		t.Errorf("ID() = %q, want sandbox-darwin", sandbox.ID())
	}
}

func TestSandbox_ID(t *testing.T) {
	s := &Sandbox{id: "test-id"}
	if got := s.ID(); got != "test-id" {
		t.Errorf("ID() = %q, want test-id", got)
	}
}

func TestSandbox_Execute_Closed(t *testing.T) {
	s := &Sandbox{
		id:     "test",
		closed: true,
	}

	_, err := s.Execute(context.Background(), "echo", "hello")
	if err == nil {
		t.Error("Execute() should error when sandbox is closed")
	}
}

func TestSandbox_Close(t *testing.T) {
	s := &Sandbox{id: "test"}

	if err := s.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if !s.closed {
		t.Error("closed should be true after Close()")
	}

	// Closing again should not error
	if err := s.Close(); err != nil {
		t.Errorf("Close() second call error = %v", err)
	}
}

func TestGenerateSandboxProfile_Basic(t *testing.T) {
	config := platform.SandboxConfig{
		WorkspacePath: "/Users/test/workspace",
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile() error = %v", err)
	}

	// Check profile contains essential parts
	if !strings.Contains(profile, "(version 1)") {
		t.Error("profile should contain version")
	}
	if !strings.Contains(profile, "(deny default)") {
		t.Error("profile should contain deny default")
	}
	if !strings.Contains(profile, "/Users/test/workspace") {
		t.Error("profile should contain workspace path")
	}
}

func TestGenerateSandboxProfile_WithAllowedPaths(t *testing.T) {
	config := platform.SandboxConfig{
		WorkspacePath: "/Users/test/workspace",
		AllowedPaths:  []string{"/Users/test/data", "/Users/test/config"},
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile() error = %v", err)
	}

	if !strings.Contains(profile, "/Users/test/data") {
		t.Error("profile should contain first allowed path")
	}
	if !strings.Contains(profile, "/Users/test/config") {
		t.Error("profile should contain second allowed path")
	}
}

func TestGenerateSandboxProfile_WithNetwork(t *testing.T) {
	config := platform.SandboxConfig{
		WorkspacePath: "/Users/test/workspace",
		Capabilities:  []string{"network"},
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile() error = %v", err)
	}

	if !strings.Contains(profile, "(allow network*)") {
		t.Error("profile should allow network when capability is specified")
	}
}

func TestGenerateSandboxProfile_NoNetwork(t *testing.T) {
	config := platform.SandboxConfig{
		WorkspacePath: "/Users/test/workspace",
	}

	profile, err := generateSandboxProfile(config)
	if err != nil {
		t.Fatalf("generateSandboxProfile() error = %v", err)
	}

	if strings.Contains(profile, "(allow network*)") {
		t.Error("profile should not allow network by default")
	}
}

func TestEscapeSBPLPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/simple/path", "/simple/path"},
		{"/path with spaces", "/path with spaces"},
		{`/path\with\backslashes`, `/path\\with\\backslashes`},
		{`/path"with"quotes`, `/path\"with\"quotes`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := escapeSBPLPath(tt.input)
			if result != tt.expected {
				t.Errorf("escapeSBPLPath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSandbox_InterfaceCompliance(t *testing.T) {
	var _ platform.SandboxManager = (*SandboxManager)(nil)
	var _ platform.Sandbox = (*Sandbox)(nil)
}
