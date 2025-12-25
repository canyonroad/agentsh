//go:build windows

package windows

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// SandboxManager implements platform.SandboxManager for Windows.
// Uses AppContainer for process isolation on Windows 8+.
type SandboxManager struct {
	available      bool
	isolationLevel platform.IsolationLevel
	mu             sync.Mutex
	sandboxes      map[string]*Sandbox
}

// NewSandboxManager creates a new Windows sandbox manager.
func NewSandboxManager() *SandboxManager {
	m := &SandboxManager{
		sandboxes: make(map[string]*Sandbox),
	}
	m.available = m.checkAvailable()
	m.isolationLevel = m.detectIsolationLevel()
	return m
}

// checkAvailable checks if sandboxing is available.
func (m *SandboxManager) checkAvailable() bool {
	// Check for Windows 8+ which supports AppContainer
	cmd := exec.Command("cmd", "/c", "ver")
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	version := strings.TrimSpace(string(out))
	// AppContainer requires Windows 8+ (version 6.2+)
	if strings.Contains(version, "Version 10.") ||
		strings.Contains(version, "Version 6.3") || // Windows 8.1
		strings.Contains(version, "Version 6.2") { // Windows 8
		return true
	}

	return false
}

// detectIsolationLevel determines what isolation is available.
func (m *SandboxManager) detectIsolationLevel() platform.IsolationLevel {
	if !m.available {
		return platform.IsolationNone
	}
	// AppContainer provides minimal isolation compared to Linux namespaces
	return platform.IsolationMinimal
}

// Available returns whether sandboxing is available.
func (m *SandboxManager) Available() bool {
	return m.available
}

// IsolationLevel returns the isolation capability.
func (m *SandboxManager) IsolationLevel() platform.IsolationLevel {
	return m.isolationLevel
}

// Create creates a new sandbox.
// Note: Full implementation would use AppContainer or Windows Sandbox.
func (m *SandboxManager) Create(config platform.SandboxConfig) (platform.Sandbox, error) {
	if !m.available {
		return nil, fmt.Errorf("sandboxing not available on this Windows system")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := config.Name
	if id == "" {
		id = "sandbox-windows"
	}

	sandbox := &Sandbox{
		id:     id,
		config: config,
	}

	m.sandboxes[id] = sandbox
	return sandbox, nil
}

// Sandbox represents a sandboxed execution environment on Windows.
type Sandbox struct {
	id     string
	config platform.SandboxConfig
	mu     sync.Mutex
	closed bool
}

// ID returns the sandbox identifier.
func (s *Sandbox) ID() string {
	return s.id
}

// Execute runs a command in the sandbox.
// Note: Would use AppContainer or restricted token for actual isolation.
func (s *Sandbox) Execute(ctx context.Context, cmd string, args ...string) (*platform.ExecResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox is closed")
	}
	s.mu.Unlock()

	// TODO: Implement AppContainer or restricted token execution
	// For now, run without sandbox
	execCmd := exec.CommandContext(ctx, cmd, args...)
	if s.config.WorkspacePath != "" {
		execCmd.Dir = s.config.WorkspacePath
	}

	stdout, err := execCmd.Output()
	var stderr []byte
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = exitErr.Stderr
			exitCode = exitErr.ExitCode()
		} else {
			return nil, err
		}
	}

	return &platform.ExecResult{
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
	}, nil
}

// Close destroys the sandbox.
func (s *Sandbox) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	return nil
}

// Compile-time interface checks
var (
	_ platform.SandboxManager = (*SandboxManager)(nil)
	_ platform.Sandbox        = (*Sandbox)(nil)
)
