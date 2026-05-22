//go:build linux && cgo
// +build linux,cgo

package unix

import (
	"context"
	"errors"
	"fmt"
)

// IterationResult classifies one probe iteration.
type IterationResult int

const (
	IterPass IterationResult = iota
	IterKilled
	IterTimeout
)

// runProbeIteration runs a single probe iteration. Production
// implementation lands in wait_killable_probe_runner_linux.go (Task 7).
// Exposed as a package var so the decision-logic test can inject a
// mocked runner.
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
