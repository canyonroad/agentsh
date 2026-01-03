//go:build windows

package wsl2

import (
	"context"
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// SandboxManager implements platform.SandboxManager for WSL2.
// It delegates to the Linux namespace-based sandbox running inside WSL2.
type SandboxManager struct {
	platform       *Platform
	available      bool
	isolationLevel platform.IsolationLevel
	mu             sync.Mutex
	sandboxes      map[string]*Sandbox
}

// NewSandboxManager creates a new WSL2 sandbox manager.
func NewSandboxManager(p *Platform) *SandboxManager {
	m := &SandboxManager{
		platform:  p,
		sandboxes: make(map[string]*Sandbox),
	}
	m.available = m.checkAvailable()
	m.isolationLevel = m.detectIsolationLevel()
	return m
}

// checkAvailable checks if namespace-based sandboxing is available in WSL2.
func (m *SandboxManager) checkAvailable() bool {
	// Check if unshare is available
	_, err := m.platform.RunInWSL("which", "unshare")
	return err == nil
}

// detectIsolationLevel determines what isolation is available in WSL2.
func (m *SandboxManager) detectIsolationLevel() platform.IsolationLevel {
	if !m.available {
		return platform.IsolationNone
	}

	// Check for user namespace support
	_, err := m.platform.RunInWSL("unshare", "--user", "true")
	if err == nil {
		return platform.IsolationFull
	}

	// At minimum we have mount/pid namespaces
	return platform.IsolationPartial
}

// Available returns whether sandboxing is available.
func (m *SandboxManager) Available() bool {
	return m.available
}

// IsolationLevel returns the isolation capability.
func (m *SandboxManager) IsolationLevel() platform.IsolationLevel {
	return m.isolationLevel
}

// Create creates a new sandbox inside WSL2.
func (m *SandboxManager) Create(config platform.SandboxConfig) (platform.Sandbox, error) {
	if !m.available {
		return nil, fmt.Errorf("sandboxing not available in WSL2")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := config.Name
	if id == "" {
		id = "sandbox-wsl2"
	}

	// Translate Windows workspace path to WSL path
	wslWorkspace := ""
	if config.WorkspacePath != "" {
		wslWorkspace = WindowsToWSLPath(config.WorkspacePath)
	}

	sandbox := &Sandbox{
		id:            id,
		config:        config,
		wslWorkspace:  wslWorkspace,
		platform:      m.platform,
		isolationLevel: m.isolationLevel,
	}

	m.sandboxes[id] = sandbox
	return sandbox, nil
}

// Sandbox represents a sandboxed execution environment in WSL2.
type Sandbox struct {
	id             string
	config         platform.SandboxConfig
	wslWorkspace   string
	platform       *Platform
	isolationLevel platform.IsolationLevel
	mu             sync.Mutex
	closed         bool
}

// ID returns the sandbox identifier.
func (s *Sandbox) ID() string {
	return s.id
}

// Execute runs a command in the sandbox inside WSL2.
func (s *Sandbox) Execute(ctx context.Context, cmd string, args ...string) (*platform.ExecResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox is closed")
	}
	s.mu.Unlock()

	// Build the command to run inside WSL2 with namespace isolation
	var wslArgs []string

	switch s.isolationLevel {
	case platform.IsolationFull:
		// Full isolation: all namespaces including user namespace
		// --fork: fork before executing command (required for PID namespace)
		// --map-root-user: map current user to root in user namespace
		// --mount-proc: mount new /proc for the new PID namespace
		wslArgs = []string{
			"unshare",
			"--user",
			"--map-root-user",
			"--mount",
			"--uts",
			"--ipc",
			"--net",
			"--pid",
			"--fork",
			"--mount-proc",
		}
		// Add working directory if specified
		if s.wslWorkspace != "" {
			wslArgs = append(wslArgs, "--wd="+s.wslWorkspace)
		}
		wslArgs = append(wslArgs, "--", cmd)
		wslArgs = append(wslArgs, args...)

	case platform.IsolationPartial:
		// Partial isolation: mount, UTS, IPC, PID namespaces (no user namespace)
		// Requires root/sudo for some operations
		wslArgs = []string{
			"unshare",
			"--mount",
			"--uts",
			"--ipc",
			"--pid",
			"--fork",
			"--mount-proc",
		}
		// Add working directory if specified
		if s.wslWorkspace != "" {
			wslArgs = append(wslArgs, "--wd="+s.wslWorkspace)
		}
		wslArgs = append(wslArgs, "--", cmd)
		wslArgs = append(wslArgs, args...)

	default:
		// No isolation or minimal - run command directly
		if s.wslWorkspace != "" {
			// Use sh -c to handle cd and command
			shellCmd := fmt.Sprintf("cd %s && %s", s.wslWorkspace, cmd)
			for _, arg := range args {
				shellCmd += " " + arg
			}
			wslArgs = []string{"sh", "-c", shellCmd}
		} else {
			wslArgs = []string{cmd}
			wslArgs = append(wslArgs, args...)
		}
	}

	out, err := s.platform.RunInWSL(wslArgs...)
	if err != nil {
		return &platform.ExecResult{
			ExitCode: 1,
			Stderr:   []byte(err.Error()),
		}, nil
	}

	return &platform.ExecResult{
		ExitCode: 0,
		Stdout:   []byte(out),
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
