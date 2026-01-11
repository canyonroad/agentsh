//go:build linux && cgo

package api

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/signal"
	"github.com/agentsh/agentsh/pkg/types"
)

// signalEmitterAdapter adapts the API's event store/broker to the signal handler's EventEmitter interface.
type signalEmitterAdapter struct {
	store     eventStore
	broker    eventBroker
	sessionID string
	commandID func() string
}

func (a *signalEmitterAdapter) Emit(ctx context.Context, eventType events.EventType, data map[string]interface{}) {
	ev := types.Event{
		ID:        fmt.Sprintf("sig-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      string(eventType),
		SessionID: a.sessionID,
		CommandID: a.commandID(),
		Fields:    data,
	}
	if a.store != nil {
		_ = a.store.AppendEvent(ctx, ev)
	}
	if a.broker != nil {
		a.broker.Publish(ev)
	}
}

// startSignalHandler receives the signal filter notify fd from the parent socket and
// starts the signal handler loop in a goroutine. It returns immediately.
// The handler runs until ctx is cancelled or the fd is closed.
func startSignalHandler(ctx context.Context, parentSock *os.File, sessID string, supervisorPID int,
	engine *signal.Engine, registry *signal.PIDRegistry,
	store eventStore, broker eventBroker, commandIDFunc func() string) {

	if parentSock == nil || engine == nil {
		return
	}

	// Receive the signal filter fd from the wrapper process
	signalFD, err := unixmon.RecvFD(parentSock)
	if err != nil {
		slog.Debug("failed to receive signal fd", "error", err)
		_ = parentSock.Close()
		return
	}
	_ = parentSock.Close()

	if signalFD == nil {
		return
	}

	emitter := &signalEmitterAdapter{
		store:     store,
		broker:    broker,
		sessionID: sessID,
		commandID: commandIDFunc,
	}
	handler := signal.NewHandler(engine, registry, emitter)

	// Start the signal handler loop in a goroutine
	go func() {
		defer signalFD.Close()
		serveSignalNotify(ctx, signalFD, handler)
	}()
}

// serveSignalNotify runs the signal notification loop.
func serveSignalNotify(ctx context.Context, fd *os.File, handler *signal.Handler) {
	// Create a SignalFilter from the fd
	filter := signal.NewSignalFilterFromFD(int(fd.Fd()))
	if filter == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := filter.Receive()
		if err != nil {
			// Check for context cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}
			// Transient error - continue
			slog.Debug("signal filter receive", "error", err)
			continue
		}

		sigCtx := signal.ExtractSignalContext(req)
		dec := handler.Handle(ctx, sigCtx)

		// Respond based on decision
		allow := dec.Action == signal.DecisionAllow ||
			dec.Action == signal.DecisionAudit ||
			dec.Action == signal.DecisionAbsorb // Absorb allows but doesn't deliver

		var errno int32 = 0
		if !allow {
			errno = 1 // EPERM
		}

		if err := filter.Respond(req.ID, allow, errno); err != nil {
			slog.Debug("signal filter respond", "error", err)
		}
	}
}
