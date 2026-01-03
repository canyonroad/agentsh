//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"

	"github.com/agentsh/agentsh/internal/platform"
)

// SandboxManager implements platform.SandboxManager for macOS.
// Uses sandbox-exec with SBPL (Sandbox Profile Language) profiles.
// Note: sandbox-exec is deprecated but still functional on macOS.
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

// checkAvailable checks if sandbox-exec is available.
func (m *SandboxManager) checkAvailable() bool {
	_, err := exec.LookPath("sandbox-exec")
	return err == nil
}

// detectIsolationLevel determines what isolation is available.
func (m *SandboxManager) detectIsolationLevel() platform.IsolationLevel {
	if !m.available {
		return platform.IsolationNone
	}
	// sandbox-exec provides minimal isolation (file/network restrictions)
	// but no process namespace isolation like Linux
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
		return nil, fmt.Errorf("sandbox-exec not available on this macOS system")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := config.Name
	if id == "" {
		id = "sandbox-darwin"
	}

	// Generate the sandbox profile
	profile, err := generateSandboxProfile(config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sandbox profile: %w", err)
	}

	sandbox := &Sandbox{
		id:      id,
		config:  config,
		profile: profile,
	}

	m.sandboxes[id] = sandbox
	return sandbox, nil
}

// Sandbox represents a sandboxed execution environment on macOS.
type Sandbox struct {
	id      string
	config  platform.SandboxConfig
	profile string
	mu      sync.Mutex
	closed  bool
}

// ID returns the sandbox identifier.
func (s *Sandbox) ID() string {
	return s.id
}

// Execute runs a command in the sandbox using sandbox-exec.
func (s *Sandbox) Execute(ctx context.Context, cmd string, args ...string) (*platform.ExecResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox is closed")
	}
	s.mu.Unlock()

	// Build sandbox-exec command with inline profile
	// sandbox-exec -p 'profile' command args...
	sandboxArgs := []string{"-p", s.profile, cmd}
	sandboxArgs = append(sandboxArgs, args...)

	execCmd := exec.CommandContext(ctx, "sandbox-exec", sandboxArgs...)
	if s.config.WorkspacePath != "" {
		execCmd.Dir = s.config.WorkspacePath
	}

	// Set environment variables if specified
	if len(s.config.Environment) > 0 {
		execCmd.Env = make([]string, 0, len(s.config.Environment))
		for k, v := range s.config.Environment {
			execCmd.Env = append(execCmd.Env, k+"="+v)
		}
	}

	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	err := execCmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, err
		}
	}

	return &platform.ExecResult{
		ExitCode: exitCode,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
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

// sandboxProfileTemplate is the SBPL (Sandbox Profile Language) template.
// This provides a restrictive default that allows only specified paths.
const sandboxProfileTemplate = `(version 1)

;; Start with deny-all policy
(deny default)

;; Allow basic process operations
(allow process-fork)
(allow process-exec)
(allow signal (target self))

;; Allow sysctl reads for basic system info
(allow sysctl-read)

;; Allow reading system libraries and frameworks
(allow file-read*
    (subpath "/usr/lib")
    (subpath "/usr/share")
    (subpath "/System/Library")
    (subpath "/Library/Frameworks")
    (subpath "/private/var/db/dyld")
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/dev/zero"))

;; Allow reading common tool locations
(allow file-read*
    (subpath "/usr/bin")
    (subpath "/usr/sbin")
    (subpath "/bin")
    (subpath "/sbin")
    (subpath "/usr/local/bin")
    (subpath "/opt/homebrew/bin")
    (subpath "/opt/homebrew/Cellar"))

;; Allow TTY access for interactive commands
(allow file-read* file-write*
    (regex #"^/dev/ttys[0-9]+$")
    (regex #"^/dev/pty[pqrs][0-9a-f]$")
    (literal "/dev/tty"))

;; Allow temporary file operations
(allow file-read* file-write*
    (subpath "/private/tmp")
    (subpath "/tmp")
    (subpath "/var/folders"))

{{if .WorkspacePath}}
;; Allow full access to workspace
(allow file-read* file-write* file-ioctl
    (subpath "{{.WorkspacePath}}"))
{{end}}

{{range .AllowedPaths}}
;; Allow access to additional path
(allow file-read* file-write*
    (subpath "{{.}}"))
{{end}}

{{if .AllowNetwork}}
;; Allow network access
(allow network*)
{{else}}
;; Network access denied by default
{{end}}

;; Allow mach messaging for IPC (required for many operations)
(allow mach-lookup)
(allow mach-register)

;; Allow ipc-posix operations
(allow ipc-posix*)
`

// profileData holds data for the sandbox profile template.
type profileData struct {
	WorkspacePath string
	AllowedPaths  []string
	AllowNetwork  bool
}

// generateSandboxProfile creates an SBPL profile from the config.
func generateSandboxProfile(config platform.SandboxConfig) (string, error) {
	tmpl, err := template.New("sandbox").Parse(sandboxProfileTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse profile template: %w", err)
	}

	// Clean and resolve paths
	workspacePath := ""
	if config.WorkspacePath != "" {
		workspacePath, err = filepath.Abs(config.WorkspacePath)
		if err != nil {
			return "", fmt.Errorf("failed to resolve workspace path: %w", err)
		}
	}

	allowedPaths := make([]string, 0, len(config.AllowedPaths))
	for _, p := range config.AllowedPaths {
		absPath, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		// Escape any special characters for SBPL
		allowedPaths = append(allowedPaths, escapeSBPLPath(absPath))
	}

	// Check if network capability is requested
	allowNetwork := false
	for _, cap := range config.Capabilities {
		if strings.ToLower(cap) == "network" || strings.ToLower(cap) == "net" {
			allowNetwork = true
			break
		}
	}

	data := profileData{
		WorkspacePath: escapeSBPLPath(workspacePath),
		AllowedPaths:  allowedPaths,
		AllowNetwork:  allowNetwork,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute profile template: %w", err)
	}

	return buf.String(), nil
}

// escapeSBPLPath escapes special characters in paths for SBPL.
func escapeSBPLPath(path string) string {
	// SBPL uses Scheme-like syntax, backslashes and quotes need escaping
	path = strings.ReplaceAll(path, "\\", "\\\\")
	path = strings.ReplaceAll(path, "\"", "\\\"")
	return path
}

// Compile-time interface checks
var (
	_ platform.SandboxManager = (*SandboxManager)(nil)
	_ platform.Sandbox        = (*Sandbox)(nil)
)
