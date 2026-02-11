//go:build windows

package notify

import (
	"context"
)

// hasNotifyBackend returns false — Windows notification backend not yet implemented.
func hasNotifyBackend() bool {
	return false
}

// showNative is a stub on Windows.
func showNative(_ context.Context, _ Request) (Response, error) {
	return Response{}, ErrNoBackend
}
