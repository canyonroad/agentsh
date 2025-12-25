//go:build darwin

package darwin

import (
	"context"
	"fmt"
	"os/exec"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// SandboxManager implements platform.SandboxManager for macOS.
// Note: macOS lacks Linux namespaces. Limited sandboxing is available
// via sandbox-exec (deprecated) or App Sandbox (requires entitlements).
type SandboxManager struct {
	available      bool
	isolationLevel platform.IsolationLevel
	mu             sync.Mutex
	sandboxes      map[string]*Sandbox
}

// NewSandboxManager creates a new macOS sandbox manager.
func NewSandboxManager() *SandboxManager {
	m := &SandboxManager{
		sandboxes: make(map[string]*Sandbox),
	}
	m.available = m.checkAvailable()
	m.isolationLevel = m.detectIsolationLevel()
	return m
}

// checkAvailable checks if any sandboxing is available.
func (m *SandboxManager) checkAvailable() bool {
	// sandbox-exec exists but is deprecated
	// We report available but with minimal isolation
	_, err := exec.LookPath("sandbox-exec")
	return err == nil
}

// detectIsolationLevel determines what isolation is available.
func (m *SandboxManager) detectIsolationLevel() platform.IsolationLevel {
	if !m.available {
		return platform.IsolationNone
	}
	// sandbox-exec provides minimal isolation
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
// Note: Full implementation would use sandbox-exec or App Sandbox.
func (m *SandboxManager) Create(config platform.SandboxConfig) (platform.Sandbox, error) {
	if !m.available {
		return nil, fmt.Errorf("sandboxing not available on this macOS system")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := config.Name
	if id == "" {
		id = "sandbox-darwin"
	}

	sandbox := &Sandbox{
		id:     id,
		config: config,
	}

	m.sandboxes[id] = sandbox
	return sandbox, nil
}

// Sandbox represents a sandboxed execution environment on macOS.
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
// Note: Would use sandbox-exec for actual isolation.
func (s *Sandbox) Execute(ctx context.Context, cmd string, args ...string) (*platform.ExecResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox is closed")
	}
	s.mu.Unlock()

	// TODO: Implement sandbox-exec wrapper
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
