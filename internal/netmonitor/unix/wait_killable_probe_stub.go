//go:build !linux || !cgo
// +build !linux !cgo

package unix

import "context"

// ProbeWaitKillableBehavior is a stub for non-Linux and linux-without-cgo
// builds. Returns (false, nil) so callers behave as if WAIT_KILLABLE_RECV
// is not safe — which is also true: the real probe requires cgo, and the
// flag itself is Linux-only.
//
// The build-tag pair (`!linux || !cgo` here vs. `linux && cgo` in
// wait_killable_probe_linux.go) ensures `ProbeWaitKillableBehavior` is
// always exported from package unix, so glue code compiled under
// `linux && !cgo` still links.
func ProbeWaitKillableBehavior(_ context.Context, _ int) (bool, error) {
	return false, nil
}
