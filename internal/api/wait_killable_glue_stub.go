//go:build !linux || !cgo
// +build !linux !cgo

package api

import "context"

// Non-Linux (or linux-without-cgo): the kernel feature WAIT_KILLABLE_RECV
// is unavailable on these platforms by default, so kernelSupports
// reports false and the decision lands on the kernel_unsupported branch
// in decideWaitKillable. An explicit operator override via cfg still
// wins per the switch's priority order — honored as an intentional
// operator choice even though the underlying kernel constant is absent.
func waitKillableKernelSupports() bool { return false }

func waitKillableProbe(_ context.Context) (bool, error) { return false, nil }
