//go:build !linux || !cgo

package api

import (
	"context"
	"os"

	"github.com/agentsh/agentsh/internal/policy"
)

// startNotifyHandler is a no-op on non-Linux platforms or without CGO.
// Unix socket enforcement via seccomp user-notify is Linux-only.
func startNotifyHandler(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker) {
	// Unix socket enforcement not available on this platform
	if parentSock != nil {
		_ = parentSock.Close()
	}
}
