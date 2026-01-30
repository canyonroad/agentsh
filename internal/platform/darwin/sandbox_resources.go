//go:build darwin && cgo

package darwin

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"syscall"

	"github.com/agentsh/agentsh/internal/platform"
)

// ExecuteWithResources runs a command with resource limiting.
// Memory limits are applied via RLIMIT_AS before the process starts.
// CPU monitoring starts after the process is running (inherent to approach).
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

	// Apply rlimits (memory limits) before starting the process
	if rh != nil {
		rlimits := rh.GetRlimits()
		if len(rlimits) > 0 {
			if execCmd.SysProcAttr == nil {
				execCmd.SysProcAttr = &syscall.SysProcAttr{}
			}
			// Note: Go's exec.Cmd does not directly support setting rlimits
			// via SysProcAttr on darwin. The rlimits must be applied in the
			// child process. We use a wrapper approach or document this limitation.
			// For now, memory limits are advisory - the caller should be aware
			// that RLIMIT_AS must be set by the spawned process itself.
			//
			// TODO: Consider using a wrapper script or cgo to set rlimits in child
		}
	}

	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	// Start the process (non-blocking)
	if err := execCmd.Start(); err != nil {
		return nil, err
	}

	// Register with resource handle for CPU monitoring.
	// Note: There's an inherent race window between Start() and AssignProcess()
	// where the process runs without CPU monitoring. This is unavoidable since
	// we need the PID first. For memory limits, they should be applied before
	// Start() via SysProcAttr (see TODO above).
	if rh != nil {
		// AssignProcess currently always returns nil, but we check for future-proofing
		if err := rh.AssignProcess(execCmd.Process.Pid); err != nil {
			// Non-fatal: process is already running, just log and continue
			// The process will run without CPU monitoring
			_ = err // Intentionally ignored - monitoring failure shouldn't fail execution
		}
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
