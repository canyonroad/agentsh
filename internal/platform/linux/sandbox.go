//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/google/uuid"
)

// SandboxManager implements platform.SandboxManager for Linux.
// It uses namespaces for process isolation.
type SandboxManager struct {
	available      bool
	isolationLevel platform.IsolationLevel
	mu             sync.Mutex
	sandboxes      map[string]*Sandbox
}

// NewSandboxManager creates a new Linux sandbox manager.
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
	// Check for mount namespace support
	if _, err := os.Stat("/proc/self/ns/mnt"); err != nil {
		return false
	}
	// Check for pid namespace support
	if _, err := os.Stat("/proc/self/ns/pid"); err != nil {
		return false
	}
	return true
}

// detectIsolationLevel determines what level of isolation is available.
func (m *SandboxManager) detectIsolationLevel() platform.IsolationLevel {
	if !m.available {
		return platform.IsolationNone
	}

	// Check for user namespace support (enables unprivileged isolation)
	hasUserNS := false
	if data, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		if len(data) > 0 && data[0] != '0' {
			hasUserNS = true
		}
	}

	// Check for seccomp support
	hasSeccomp := false
	if _, err := os.Stat("/proc/sys/kernel/seccomp"); err == nil {
		hasSeccomp = true
	} else if data, err := os.ReadFile("/proc/self/status"); err == nil {
		if contains(string(data), "Seccomp:") {
			hasSeccomp = true
		}
	}

	// Full isolation requires user namespaces and seccomp
	if hasUserNS && hasSeccomp {
		return platform.IsolationFull
	}

	// Partial isolation with just namespaces
	if hasUserNS {
		return platform.IsolationPartial
	}

	// Minimal isolation (root-only namespaces)
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
func (m *SandboxManager) Create(config platform.SandboxConfig) (platform.Sandbox, error) {
	if !m.available {
		return nil, fmt.Errorf("sandboxing not available")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := "sandbox-" + uuid.NewString()[:8]
	if config.Name != "" {
		id = config.Name
	}

	sandbox := &Sandbox{
		id:            id,
		config:        config,
		isolationLevel: m.isolationLevel,
	}

	m.sandboxes[id] = sandbox
	return sandbox, nil
}

// Sandbox implements platform.Sandbox for Linux.
type Sandbox struct {
	id             string
	config         platform.SandboxConfig
	isolationLevel platform.IsolationLevel
	mu             sync.Mutex
	closed         bool
}

// ID returns the sandbox identifier.
func (s *Sandbox) ID() string {
	return s.id
}

// Execute runs a command in the sandbox with namespace isolation.
func (s *Sandbox) Execute(ctx context.Context, cmd string, args ...string) (*platform.ExecResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox is closed")
	}
	s.mu.Unlock()

	execCmd := exec.CommandContext(ctx, cmd, args...)

	// Set working directory
	if s.config.WorkspacePath != "" {
		execCmd.Dir = s.config.WorkspacePath
	}

	// Set environment
	if len(s.config.Environment) > 0 {
		env := os.Environ()
		for k, v := range s.config.Environment {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		execCmd.Env = env
	}

	// Configure namespace isolation
	execCmd.SysProcAttr = s.buildSysProcAttr()

	// Capture output
	stdout, err := execCmd.Output()
	var stderr []byte
	if exitErr, ok := err.(*exec.ExitError); ok {
		stderr = exitErr.Stderr
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("failed to execute command: %w", err)
		}
	}

	return &platform.ExecResult{
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
	}, nil
}

// buildSysProcAttr creates SysProcAttr for namespace isolation.
func (s *Sandbox) buildSysProcAttr() *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Add namespace flags based on isolation level
	switch s.isolationLevel {
	case platform.IsolationFull:
		// Full isolation with user namespace (allows unprivileged)
		attr.Cloneflags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC
		attr.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		}
		attr.GidMappings = []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		}
	case platform.IsolationPartial:
		// Partial isolation (may require root)
		attr.Cloneflags = syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC
	case platform.IsolationMinimal:
		// Minimal: just process group isolation
		// No additional cloneflags
	}

	return attr
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
