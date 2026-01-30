//go:build windows

package windows

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	// AppContainer provides partial isolation (capability-based, not namespace-based)
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

// Create creates a new sandbox.
// Uses AppContainer for process isolation on Windows 8+.
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
		id:      id,
		config:  config,
		manager: m,
	}

	// Get options with defaults
	opts := config.WindowsOptions
	if opts == nil {
		opts = platform.DefaultWindowsSandboxOptions()
	}

	// Setup AppContainer if enabled
	if opts.UseAppContainer {
		container := newAppContainer(id)
		if err := container.create(); err != nil {
			if opts.FailOnAppContainerError {
				return nil, fmt.Errorf("AppContainer setup failed: %w", err)
			}
			// AppContainer setup failed, continuing without container isolation
			// TODO: Add structured logging when logger is available
		} else {
			sandbox.container = container

			// Configure network
			if err := container.setNetworkCapabilities(opts.NetworkAccess); err != nil {
				container.cleanup()
				return nil, fmt.Errorf("network capability setup failed: %w", err)
			}

			// Grant access to workspace
			if config.WorkspacePath != "" {
				if err := container.grantPathAccess(config.WorkspacePath, AccessReadWrite); err != nil {
					container.cleanup()
					return nil, fmt.Errorf("grant workspace access failed: %w", err)
				}
			}

			// Grant access to allowed paths
			for _, path := range config.AllowedPaths {
				if err := container.grantPathAccess(path, AccessRead); err != nil {
					container.cleanup()
					return nil, fmt.Errorf("grant allowed path %s failed: %w", path, err)
				}
			}

			// Grant access to system directories for basic operation
			systemRoot := os.Getenv("SystemRoot")
			if systemRoot == "" {
				systemRoot = "C:\\Windows"
			}
			systemPaths := []string{
				filepath.Join(systemRoot, "System32"),
				filepath.Join(systemRoot, "SysWOW64"),
			}
			for _, path := range systemPaths {
				_ = container.grantPathAccess(path, AccessReadExecute) // Best effort
			}
		}
	}

	// Setup minifilter if enabled
	if opts.UseMinifilter {
		client := NewDriverClient()
		if err := client.Connect(); err == nil {
			sandbox.driverClient = client
		}
		// Minifilter connection failed, continuing without policy enforcement
		// TODO: Add structured logging when logger is available
	}

	m.sandboxes[id] = sandbox
	return sandbox, nil
}

// Sandbox represents a sandboxed execution environment on Windows.
type Sandbox struct {
	id           string
	config       platform.SandboxConfig
	mu           sync.Mutex
	closed       bool
	container    *appContainer  // nil if UseAppContainer=false
	driverClient *DriverClient  // For minifilter integration
	manager      *SandboxManager // Reference to parent manager for cleanup
}

// ID returns the sandbox identifier.
func (s *Sandbox) ID() string {
	return s.id
}

// Execute runs a command in the sandbox.
// Uses AppContainer if configured, otherwise falls back to unsandboxed execution.
func (s *Sandbox) Execute(ctx context.Context, cmd string, args ...string) (*platform.ExecResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox is closed")
	}
	s.mu.Unlock()

	opts := s.config.WindowsOptions
	if opts == nil {
		opts = platform.DefaultWindowsSandboxOptions()
	}

	// Try AppContainer execution if enabled and container is available
	if opts.UseAppContainer && s.container != nil {
		return s.executeInAppContainer(ctx, cmd, args)
	}

	// Fallback to unsandboxed execution
	return s.executeUnsandboxed(ctx, cmd, args)
}

func (s *Sandbox) executeInAppContainer(ctx context.Context, cmd string, args []string) (*platform.ExecResult, error) {
	proc, err := s.container.createProcessWithCapture(ctx, cmd, args, s.config.Environment, s.config.WorkspacePath, true)
	if err != nil {
		return nil, err
	}
	defer proc.Close()

	// Read stdout and stderr concurrently
	var stdout, stderr []byte
	var stdoutErr, stderrErr error
	var wg sync.WaitGroup

	if proc.Stdout != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stdout, stdoutErr = io.ReadAll(proc.Stdout)
		}()
	}

	if proc.Stderr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stderr, stderrErr = io.ReadAll(proc.Stderr)
		}()
	}

	// Wait for process to complete
	state, err := proc.Wait()

	// Wait for I/O to complete
	wg.Wait()

	if err != nil {
		return nil, err
	}

	// Check for I/O errors (non-fatal, just log)
	if stdoutErr != nil && stdoutErr != io.EOF {
		// Could log this error if we had a logger
		_ = stdoutErr
	}
	if stderrErr != nil && stderrErr != io.EOF {
		_ = stderrErr
	}

	return &platform.ExecResult{
		ExitCode: state.ExitCode(),
		Stdout:   stdout,
		Stderr:   stderr,
	}, nil
}

func (s *Sandbox) executeUnsandboxed(ctx context.Context, cmd string, args []string) (*platform.ExecResult, error) {
	execCmd := exec.CommandContext(ctx, cmd, args...)
	if s.config.WorkspacePath != "" {
		execCmd.Dir = s.config.WorkspacePath
	}

	// Set environment if configured
	if len(s.config.Environment) > 0 {
		env := os.Environ()
		for k, v := range s.config.Environment {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		execCmd.Env = env
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

// Close destroys the sandbox and releases all resources.
func (s *Sandbox) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	var errs []error

	// Cleanup AppContainer
	if s.container != nil {
		if err := s.container.cleanup(); err != nil {
			errs = append(errs, err)
		}
		s.container = nil
	}

	// Disconnect minifilter
	if s.driverClient != nil {
		s.driverClient.Disconnect()
		s.driverClient = nil
	}

	// Remove from manager's map
	if s.manager != nil {
		s.manager.mu.Lock()
		delete(s.manager.sandboxes, s.id)
		s.manager.mu.Unlock()
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

// Compile-time interface checks
var (
	_ platform.SandboxManager = (*SandboxManager)(nil)
	_ platform.Sandbox        = (*Sandbox)(nil)
)
