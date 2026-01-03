//go:build linux && cgo

package api

import (
	"context"
	"log/slog"
	"os"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// notifyEmitterAdapter adapts the API's event store/broker to the unix handler's Emitter interface.
type notifyEmitterAdapter struct {
	store  eventStore
	broker eventBroker
}

func (a *notifyEmitterAdapter) AppendEvent(ctx context.Context, ev types.Event) error {
	return a.store.AppendEvent(ctx, ev)
}

func (a *notifyEmitterAdapter) Publish(ev types.Event) {
	a.broker.Publish(ev)
}

// startNotifyHandler receives the seccomp notify fd from the parent socket and
// starts the ServeNotify handler in a goroutine. It returns immediately.
// The handler runs until ctx is cancelled or the fd is closed.
func startNotifyHandler(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker) {
	if parentSock == nil || pol == nil {
		return
	}

	// Receive the notify fd from the wrapper process
	notifyFD, err := unixmon.RecvFD(parentSock)
	if err != nil {
		slog.Debug("failed to receive notify fd", "error", err)
		_ = parentSock.Close()
		return
	}
	_ = parentSock.Close()

	if notifyFD == nil {
		return
	}

	emitter := &notifyEmitterAdapter{store: store, broker: broker}

	// Start the notify handler in a goroutine
	go func() {
		defer notifyFD.Close()
		unixmon.ServeNotify(ctx, notifyFD, sessID, pol, emitter)
	}()
}
