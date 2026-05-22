//go:build linux && cgo
// +build linux,cgo

package unix

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// IterationResult classifies one probe iteration's outcome. Issue #369:
// the kernel bug manifests as the child being killed by signal during
// its post-execve syscall storm, or as a notify-recv that never returns
// (which the parent times out).
type IterationResult int

const (
	// IterPass: child exec'd /bin/true and exited cleanly. The kernel
	// did not exhibit the bug for this iteration.
	IterPass IterationResult = iota
	// IterKilled: child terminated by signal (WIFSIGNALED) instead of
	// exiting normally. Strong signal of the issue #369 kernel bug.
	IterKilled
	// IterTimeout: child still alive after the per-iteration deadline.
	// Treated as a failure mode equivalent to IterKilled — a wedged
	// notify handshake is just as broken as an outright kill.
	IterTimeout
)

// runProbeIteration runs a single probe iteration. The real fork/exec
// implementation lands in a follow-up task; this placeholder lets the
// decision logic be tested in isolation. Exposed as a package var so
// tests can inject a mocked runner.
var runProbeIteration = func(ctx context.Context) (IterationResult, error) {
	return 0, errors.New("runProbeIteration not implemented yet")
}

// iterationName maps an IterationResult to a stable log-friendly string
// for the per-iteration log lines emitted by ProbeWaitKillableBehavior.
// Unknown values yield "unknown_N" so a future enum addition without a
// corresponding case update is still grep-able.
func iterationName(r IterationResult) string {
	switch r {
	case IterPass:
		return "pass"
	case IterKilled:
		return "killed"
	case IterTimeout:
		return "timeout"
	default:
		return fmt.Sprintf("unknown_%d", int(r))
	}
}

// ProbeWaitKillableBehavior runs `iterations` real probes of the
// production filter composition under WAIT_KILLABLE_RECV. Returns true
// only when every iteration's child exits cleanly (exit_status=0).
// Short-circuits on the first iteration that fails.
//
// Errors from runProbeIteration (fork/socketpair/filter-install failures)
// cause this function to return the error so callers can apply
// fail-safe semantics. Iteration outcomes IterKilled and IterTimeout
// both indicate the kernel bug from issue #369 and cause (false, nil).
func ProbeWaitKillableBehavior(ctx context.Context, iterations int) (bool, error) {
	if iterations <= 0 {
		return false, fmt.Errorf("ProbeWaitKillableBehavior: iterations must be >0, got %d", iterations)
	}
	// timeout_per_iter_ms matches the 1s deadline the production runner
	// applies in runProbeIteration. Hardcoded here to keep the log line
	// self-contained — a slight drift from a future runner change is
	// acceptable; the log is operator triage, not telemetry.
	slog.Info("seccomp: wait_killable behavioral probe starting",
		"iterations", iterations,
		"timeout_per_iter_ms", 1000)
	probeStart := time.Now()
	for i := 1; i <= iterations; i++ {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		iterStart := time.Now()
		res, err := runProbeIteration(ctx)
		iterDur := time.Since(iterStart)
		if err != nil {
			slog.Info("seccomp: wait_killable iteration error",
				"iteration", i,
				"duration_ms", iterDur.Milliseconds(),
				"error", err.Error())
			// Emit a final "probe complete" line on the error path too,
			// so the probe-complete log is symmetric with the killed and
			// timeout paths. Lets operators grep one line for the final
			// decision regardless of which terminal branch fired.
			slog.Info("seccomp: wait_killable probe complete",
				"decision", false,
				"reason", fmt.Sprintf("iteration %d error: %v", i, err),
				"total_duration_ms", time.Since(probeStart).Milliseconds())
			return false, err
		}
		slog.Info("seccomp: wait_killable iteration",
			"iteration", i,
			"result", iterationName(res),
			"duration_ms", iterDur.Milliseconds())
		switch res {
		case IterPass:
			continue
		case IterKilled, IterTimeout:
			slog.Info("seccomp: wait_killable probe complete",
				"decision", false,
				"reason", fmt.Sprintf("iteration %d %s", i, iterationName(res)),
				"total_duration_ms", time.Since(probeStart).Milliseconds())
			return false, nil
		default:
			return false, fmt.Errorf("ProbeWaitKillableBehavior: unknown IterationResult %d", res)
		}
	}
	slog.Info("seccomp: wait_killable probe complete",
		"decision", true,
		"reason", "all iterations passed",
		"total_duration_ms", time.Since(probeStart).Milliseconds())
	return true, nil
}
