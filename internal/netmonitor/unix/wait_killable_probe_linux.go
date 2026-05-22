//go:build linux && cgo
// +build linux,cgo

package unix

import (
	"context"
	"errors"
	"fmt"
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
	for i := 1; i <= iterations; i++ {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		res, err := runProbeIteration(ctx)
		if err != nil {
			return false, err
		}
		switch res {
		case IterPass:
			continue
		case IterKilled, IterTimeout:
			return false, nil
		default:
			return false, fmt.Errorf("ProbeWaitKillableBehavior: unknown IterationResult %d", res)
		}
	}
	return true, nil
}
