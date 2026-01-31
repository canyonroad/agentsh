//go:build darwin && cgo

package darwin

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/agentsh/agentsh/internal/platform"
)

// rlimitExecWrapper is the name of the wrapper binary for applying rlimits.
const rlimitExecWrapper = "agentsh-rlimit-exec"

// ExecuteWithResources runs a command with resource limiting.
// Memory limits are applied via RLIMIT_AS using the agentsh-rlimit-exec wrapper.
// CPU monitoring starts after the process is running.
func (s *Sandbox) ExecuteWithResources(ctx context.Context, rh *ResourceHandle, cmd string, args ...string) (*platform.ExecResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox is closed")
	}
	s.mu.Unlock()

	// Determine if we need to wrap the command for rlimit enforcement
	actualCmd := cmd
	actualArgs := args
	var rlimitEnv string

	if rh != nil {
		rlimits := rh.GetRlimits()
		for _, rl := range rlimits {
			if rl.Resource == RlimitAS && rl.Cur > 0 {
				// Wrap with agentsh-rlimit-exec
				actualCmd = rlimitExecWrapper
				actualArgs = append([]string{cmd}, args...)
				rlimitEnv = fmt.Sprintf("AGENTSH_RLIMIT_AS=%d", rl.Cur)
				break
			}
		}
	}

	// Build sandbox-exec command with inline profile
	sandboxArgs := []string{"-p", s.profile, actualCmd}
	sandboxArgs = append(sandboxArgs, actualArgs...)

	execCmd := exec.CommandContext(ctx, "sandbox-exec", sandboxArgs...)
	if s.config.WorkspacePath != "" {
		execCmd.Dir = s.config.WorkspacePath
	}

	// Set environment variables
	// Start with current environment so wrapper can find commands in PATH
	execCmd.Env = os.Environ()
	for k, v := range s.config.Environment {
		execCmd.Env = append(execCmd.Env, k+"="+v)
	}
	if rlimitEnv != "" {
		execCmd.Env = append(execCmd.Env, rlimitEnv)
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
	// we need the PID first.
	if rh != nil {
		if err := rh.AssignProcess(execCmd.Process.Pid); err != nil {
			// Non-fatal: process is already running, just continue
			_ = err
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
