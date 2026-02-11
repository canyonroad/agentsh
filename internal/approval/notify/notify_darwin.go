//go:build darwin

package notify

import (
	"context"
)

// hasNotifyBackend returns false — macOS notification backend not yet implemented.
func hasNotifyBackend() bool {
	return false
}

// showNative is a stub on macOS.
func showNative(_ context.Context, _ Request) (Response, error) {
	return Response{}, ErrNoBackend
}
