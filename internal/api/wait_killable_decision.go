package api

import (
	"context"

	"github.com/agentsh/agentsh/internal/config"
)

// waitKillableDeps wraps the inputs to decideWaitKillable so tests can
// inject the kernel-version probe and the behavioral probe without
// crossing platform build tags.
type waitKillableDeps struct {
	cfg            config.SandboxSeccompConfig
	kernelSupports func() bool
	probe          func(context.Context) (bool, error)
}

// decideWaitKillable applies the four-branch decision from issue #369
// and returns (decision, source). Source is a stable string suitable for
// inclusion in log lines so operators can grep one line to triage.
//
// Branches, in priority order:
//
//  1. Operator override (cfg.WaitKillable non-nil) → use as-is.
//  2. Kernel <6 → false (the flag doesn't exist).
//  3. Filter composition cannot trigger the bug → true (probe unneeded).
//  4. Behavioral probe → its result. Probe errors are fail-safe (false).
func decideWaitKillable(ctx context.Context, deps waitKillableDeps) (bool, string) {
	if v := deps.cfg.WaitKillable; v != nil {
		return *v, "config"
	}
	if !deps.kernelSupports() {
		return false, "kernel_unsupported"
	}
	if !config.WaitKillableFilterCompositionTriggersBug(deps.cfg) {
		return true, "filter_composition_safe"
	}
	ok, err := deps.probe(ctx)
	if err != nil {
		return false, "behavioral_probe_error"
	}
	return ok, "behavioral_probe"
}
