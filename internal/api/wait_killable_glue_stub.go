//go:build !linux || !cgo
// +build !linux !cgo

package api

import "context"

// Non-Linux (or linux-without-cgo): WAIT_KILLABLE_RECV doesn't exist on
// these platforms, so the decision is always false regardless of config.
// The decideWaitKillable switch handles this via the kernel_unsupported
// branch (kernelSupports returns false, so the cfg override is the only
// way to coerce true — which would be a config error on these targets,
// but is intentionally honored as an explicit operator choice).
func waitKillableKernelSupports() bool { return false }

func waitKillableProbe(_ context.Context) (bool, error) { return false, nil }
