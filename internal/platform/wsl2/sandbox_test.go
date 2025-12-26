//go:build windows

package wsl2

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewSandboxManager(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	m := NewSandboxManager(p)

	if m == nil {
		t.Fatal("NewSandboxManager() returned nil")
	}

	if m.platform != p {
		t.Error("platform not set correctly")
	}

	if m.sandboxes == nil {
		t.Error("sandboxes map is nil")
	}
}

func TestSandboxManager_Available(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	m := &SandboxManager{
		platform:  p,
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
	p := &Platform{distro: "Ubuntu"}
	m := &SandboxManager{
		platform:       p,
		available:      true,
		isolationLevel: platform.IsolationFull,
		sandboxes:      make(map[string]*Sandbox),
	}

	if got := m.IsolationLevel(); got != platform.IsolationFull {
		t.Errorf("IsolationLevel() = %v, want IsolationFull", got)
	}
}

func TestSandboxManager_Create(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	m := &SandboxManager{
		platform:       p,
		available:      true,
		isolationLevel: platform.IsolationFull,
		sandboxes:      make(map[string]*Sandbox),
	}

	cfg := platform.SandboxConfig{
		Name:          "test-sandbox",
		WorkspacePath: `C:\Users\test\workspace`,
	}

	sb, err := m.Create(cfg)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if sb == nil {
		t.Fatal("Create() returned nil sandbox")
	}

	s, ok := sb.(*Sandbox)
	if !ok {
		t.Fatal("Create() did not return *Sandbox")
	}

	if s.id != cfg.Name {
		t.Errorf("id = %q, want %q", s.id, cfg.Name)
	}

	if s.wslWorkspace != "/mnt/c/Users/test/workspace" {
		t.Errorf("wslWorkspace = %q, want /mnt/c/Users/test/workspace", s.wslWorkspace)
	}
}

func TestSandboxManager_Create_NotAvailable(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	m := &SandboxManager{
		platform:  p,
		available: false,
		sandboxes: make(map[string]*Sandbox),
	}

	cfg := platform.SandboxConfig{
		Name: "test-sandbox",
	}

	_, err := m.Create(cfg)
	if err == nil {
		t.Error("Create() should error when not available")
	}
}

func TestSandboxManager_Create_DefaultName(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	m := &SandboxManager{
		platform:  p,
		available: true,
		sandboxes: make(map[string]*Sandbox),
	}

	cfg := platform.SandboxConfig{
		Name: "", // Empty name
	}

	sb, err := m.Create(cfg)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	s := sb.(*Sandbox)
	if s.id != "sandbox-wsl2" {
		t.Errorf("id = %q, want sandbox-wsl2", s.id)
	}
}

func TestSandbox_ID(t *testing.T) {
	s := &Sandbox{
		id: "test-sandbox",
	}

	if got := s.ID(); got != "test-sandbox" {
		t.Errorf("ID() = %q, want test-sandbox", got)
	}
}

func TestSandbox_Close(t *testing.T) {
	s := &Sandbox{
		id: "test-sandbox",
	}

	err := s.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if !s.closed {
		t.Error("closed should be true after Close()")
	}

	// Close again should not error
	err = s.Close()
	if err != nil {
		t.Errorf("Close() second time error = %v", err)
	}
}

func TestDetectIsolationLevel(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}

	// Test with unavailable sandboxing
	m := &SandboxManager{
		platform:  p,
		available: false,
	}

	level := m.detectIsolationLevel()
	if level != platform.IsolationNone {
		t.Errorf("detectIsolationLevel() with unavailable = %v, want IsolationNone", level)
	}
}

func TestSandboxManager_InterfaceCompliance(t *testing.T) {
	var _ platform.SandboxManager = (*SandboxManager)(nil)
	var _ platform.Sandbox = (*Sandbox)(nil)
}
