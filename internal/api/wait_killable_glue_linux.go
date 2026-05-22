//go:build linux && cgo
// +build linux,cgo

package api

import (
	"context"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
)

// waitKillableProbeIterations is the spec-recommended iteration count for
// the behavioral probe (issue #369). Five iterations balance signal
// strength against the ~100-700ms wall-clock cost on a healthy kernel.
const waitKillableProbeIterations = 5

// waitKillableKernelSupports reports whether the running kernel exposes
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV. Wraps the cgo-bound probe.
func waitKillableKernelSupports() bool { return unixmon.ProbeWaitKillable() }

// waitKillableProbe runs the behavioral probe to detect the kernel bug
// described in issue #369. Returns (true, nil) when the flag is safe to
// set, (false, nil) when the bug reproduces, and (false, err) on probe
// setup failure (callers treat errors as fail-safe = false).
func waitKillableProbe(ctx context.Context) (bool, error) {
	return unixmon.ProbeWaitKillableBehavior(ctx, waitKillableProbeIterations)
}
