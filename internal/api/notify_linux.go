//go:build linux && cgo

package api

import (
	"context"
	"log/slog"
	"os"
	"time"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// recvFDTimeout is the timeout for receiving the notify fd from the wrapper.
// This prevents blocking forever if the wrapper fails to set up seccomp.
const recvFDTimeout = 10 * time.Second

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

	// Run the entire receive and serve logic in a goroutine to return immediately
	go func() {
		defer parentSock.Close()

		// Set a read deadline to prevent blocking forever if wrapper fails
		if err := parentSock.SetReadDeadline(time.Now().Add(recvFDTimeout)); err != nil {
			slog.Debug("failed to set read deadline on notify socket", "error", err)
			return
		}

		// Receive the notify fd from the wrapper process
		notifyFD, err := unixmon.RecvFD(parentSock)
		if err != nil {
			slog.Debug("failed to receive notify fd", "error", err)
			return
		}

		if notifyFD == nil {
			return
		}
		defer notifyFD.Close()

		emitter := &notifyEmitterAdapter{store: store, broker: broker}
		unixmon.ServeNotify(ctx, notifyFD, sessID, pol, emitter)
	}()
}
