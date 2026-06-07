package api

import (
	"bufio"
	"log/slog"
	"os"
)

// closeWrapperLogPipe releases both wrapper-log pipe ends on exec paths
// that fail before startWrapperHandlers runs (pre-start cancel,
// cmd.Start() failure). Safe to call multiple times and on configs
// without a log pipe. The pre-existing notify/signal socketpairs are
// deliberately left to their finalizers on these paths (see
// buildWrapperSetup); the pipe is closed here because it is new on
// this branch and cheap to handle (issue #415).
func (e *extraProcConfig) closeWrapperLogPipe() {
	if e == nil {
		return
	}
	if e.wrapperLogChild != nil {
		_ = e.wrapperLogChild.Close()
		e.wrapperLogChild = nil
	}
	if e.wrapperLogParent != nil {
		_ = e.wrapperLogParent.Close()
		e.wrapperLogParent = nil
	}
}

// startWrapperLogDrain forwards agentsh-unixwrap diagnostic lines from
// the wrapper log pipe into the server log (issue #415). The wrapper
// sets FD_CLOEXEC on its end, so EOF arrives when it execs the real
// command (or exits) — the goroutine is short-lived by construction.
// Lines are forwarded verbatim as an attr; no re-parsing or re-leveling,
// so "wait_killable=..." stays greppable at the default level.
//
// The returned channel closes when the drain finishes (test hook).
func startWrapperLogDrain(r *os.File, logger *slog.Logger, sessionID, command string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer r.Close()
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			logger.Info("unixwrap", "session_id", sessionID, "command", command, "line", sc.Text())
		}
		// Normal exit is EOF (wrapper exec'd or died). Anything else —
		// e.g. bufio.ErrTooLong past the 64KiB token cap — silently
		// stops draining, so leave a trace for operators.
		if err := sc.Err(); err != nil {
			logger.Debug("unixwrap log drain stopped early", "session_id", sessionID, "error", err)
		}
	}()
	return done
}
