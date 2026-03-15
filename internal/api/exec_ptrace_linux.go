//go:build linux

package api

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/ptrace"
)

// ptraceExecAttach attaches the ptrace tracer to a running process, waits for
// the attachment to complete, and optionally keeps the process stopped (for
// cgroup hook). Returns a resume function that must be called after the hook.
func ptraceExecAttach(tracer any, pid int, sessionID, commandID string, keepStopped bool) (resume func() error, err error) {
	tr, ok := tracer.(*ptrace.Tracer)
	if !ok || tr == nil {
		return nil, fmt.Errorf("ptraceExecAttach: invalid tracer type %T", tracer)
	}

	opts := []ptrace.AttachOption{
		ptrace.WithSessionID(sessionID),
		ptrace.WithCommandID(commandID),
	}
	if keepStopped {
		opts = append(opts, ptrace.WithKeepStopped())
	}

	if err := tr.AttachPID(pid, opts...); err != nil {
		return nil, fmt.Errorf("attach pid %d: %w", pid, err)
	}
	if err := tr.WaitAttached(pid); err != nil {
		return nil, fmt.Errorf("wait attached pid %d: %w", pid, err)
	}

	if keepStopped {
		return func() error {
			return tr.ResumePID(pid)
		}, nil
	}
	return func() error { return nil }, nil
}
