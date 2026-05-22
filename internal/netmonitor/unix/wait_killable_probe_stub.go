//go:build !linux
// +build !linux

package unix

import "context"

// ProbeWaitKillableBehavior is a non-Linux stub. Returns (false, nil) so
// non-Linux callers behave as if WAIT_KILLABLE_RECV is not safe, which
// is also true: the flag is Linux-only.
func ProbeWaitKillableBehavior(_ context.Context, _ int) (bool, error) {
	return false, nil
}
