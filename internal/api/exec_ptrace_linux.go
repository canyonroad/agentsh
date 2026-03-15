//go:build linux

package api

import (
	"fmt"
	"log/slog"

	"github.com/agentsh/agentsh/internal/ptrace"
	"github.com/agentsh/agentsh/pkg/types"
)

// ptraceExecResult holds the result of waiting for a traced process to exit.
type ptraceExecResult struct {
	exitCode  int
	resources types.ExecResources
	err       error // non-nil for ExitTracerDown
}

// ptraceExecAttach attaches the ptrace tracer to a running process, waits for
// the attachment to complete, and optionally keeps the process stopped (for
// cgroup hook). Returns a waitExit function that blocks until the process exits
// (replacing cmd.Wait()) and a resume function for keepStopped mode.
//
// Registration ordering: RegisterExitNotify is called BEFORE AttachPID to
// guarantee the channel exists before the tracer can dispatch exit events.
func ptraceExecAttach(tracer any, pid int, sessionID, commandID string, keepStopped bool) (waitExit func() ptraceExecResult, resume func() error, err error) {
	tr, ok := tracer.(*ptrace.Tracer)
	if !ok || tr == nil {
		return nil, nil, fmt.Errorf("ptraceExecAttach: invalid tracer type %T", tracer)
	}

	// Register exit notify BEFORE attach — process can't exit via tracer
	// until it's attached, so this is race-free.
	exitCh, regErr := tr.RegisterExitNotify(pid)
	if regErr != nil {
		return nil, nil, fmt.Errorf("register exit notify pid %d: %w", pid, regErr)
	}

	opts := []ptrace.AttachOption{
		ptrace.WithSessionID(sessionID),
		ptrace.WithCommandID(commandID),
	}
	if keepStopped {
		opts = append(opts, ptrace.WithKeepStopped())
	}

	if err := tr.AttachPID(pid, opts...); err != nil {
		tr.UnregisterExitNotify(pid, exitCh)
		return nil, nil, fmt.Errorf("attach pid %d: %w", pid, err)
	}
	if err := tr.WaitAttached(pid); err != nil {
		tr.UnregisterExitNotify(pid, exitCh)
		return nil, nil, fmt.Errorf("wait attached pid %d: %w", pid, err)
	}

	waitFn := func() ptraceExecResult {
		status := <-exitCh
		var code int
		switch status.Reason {
		case ptrace.ExitNormal:
			if status.Signal != 0 {
				code = -1 // matches ee.ExitCode() for signaled processes
			} else {
				code = status.Code
			}
		case ptrace.ExitVanished:
			code = -1 // process disappeared, treat like signaled
			slog.Warn("traced process vanished (ESRCH)", "pid", pid)
		case ptrace.ExitTracerDown:
			code = 127 // infrastructure failure
			slog.Error("tracer shut down while process was running", "pid", pid)
		}
		return ptraceExecResult{
			exitCode:  code,
			resources: resourcesFromRusage(status.Rusage),
			err:       func() error { if status.Reason == ptrace.ExitTracerDown { return fmt.Errorf("tracer shut down") }; return nil }(),
		}
	}

	if keepStopped {
		return waitFn, func() error {
			return tr.ResumePID(pid)
		}, nil
	}
	return waitFn, func() error { return nil }, nil
}
