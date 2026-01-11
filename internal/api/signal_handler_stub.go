//go:build !linux || !cgo

package api

import (
	"context"
	"os"

	"github.com/agentsh/agentsh/internal/signal"
)

// startSignalHandler is a no-op on non-Linux platforms.
func startSignalHandler(ctx context.Context, parentSock *os.File, sessID string, supervisorPID int,
	engine *signal.Engine, registry *signal.PIDRegistry,
	store eventStore, broker eventBroker, commandIDFunc func() string) {
	// Signal interception not supported on this platform
	if parentSock != nil {
		_ = parentSock.Close()
	}
}
