//go:build darwin && cgo

package darwin

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/agentsh/agentsh/internal/platform"
)

// SetResourceHandle associates a resource handle with this sandbox.
func (s *Sandbox) SetResourceHandle(h *ResourceHandle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Note: resourceHandle field is not stored on Sandbox struct
	// as it would require different struct definitions for cgo/nocgo.
	// Instead, pass the handle directly to ExecuteWithResources.
}

// ExecuteWithResources runs a command with resource limiting.
func (s *Sandbox) ExecuteWithResources(ctx context.Context, rh *ResourceHandle, cmd string, args ...string) (*platform.ExecResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox is closed")
	}
	s.mu.Unlock()

	// Build sandbox-exec command with inline profile
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

	// Start the process (non-blocking)
	if err := execCmd.Start(); err != nil {
		return nil, err
	}

	// Register with resource handle for CPU monitoring
	if rh != nil {
		rh.AssignProcess(execCmd.Process.Pid)
	}

	// Wait for completion
	err := execCmd.Wait()
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
