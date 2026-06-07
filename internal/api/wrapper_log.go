package api

import (
	"bufio"
	"log/slog"
	"os"
)

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
	}()
	return done
}
