//go:build !linux

package decisionctx

import "context"

const defaultTailscaleSocket = ""

// defaultTailscaleStatus is a stub on non-Linux platforms: the local-API
// socket transport is Linux-only for v1, so Tailscale identity is reported
// as unavailable and the OS user is used.
func defaultTailscaleStatus(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil
}
