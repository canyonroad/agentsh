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
	"golang.org/x/sys/unix"
)

// Note on libseccomp-golang error semantics:
// notifReceive internally retries EINTR, so any non-nil error from
// filter.Receive() indicates either ENOENT (filter destroyed because the
// tracee exited) or a permanent failure. In both cases, the goroutine must
// exit to release the fd and avoid a hot loop; the next exec installs a
// fresh filter and handler.

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

	// Run the entire receive and serve logic in a goroutine to return immediately
	go func() {
		defer parentSock.Close()

		// Set SO_RCVTIMEO directly on the socket. unixmon.RecvFD calls recvmsg
		// on the raw fd, bypassing Go's netpoll — so SetReadDeadline wouldn't
		// apply. SO_RCVTIMEO is a kernel-level timeout that works with raw
		// blocking recvmsg.
		tv := unix.NsecToTimeval(recvFDTimeout.Nanoseconds())
		if err := unix.SetsockoptTimeval(int(parentSock.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			slog.Debug("failed to set SO_RCVTIMEO on signal socket", "error", err)
			// Don't return - RecvFD will still work, just without a timeout
		}

		// Receive the signal filter fd from the wrapper process
		signalFD, err := unixmon.RecvFD(parentSock)
		if err != nil {
			slog.Debug("failed to receive signal fd", "error", err)
			return
		}

		if signalFD == nil {
			return
		}
		defer signalFD.Close()

		// Close the signal FD when context is cancelled to unblock any stuck
		// NotifReceive ioctl. The done channel ensures this watchdog goroutine
		// exits if serveSignalNotify returns early (error/setup failure) while
		// context is still active. Mirrors the pattern used in notify_linux.go.
		handlerDone := make(chan struct{})
		defer close(handlerDone)
		go func() {
			select {
			case <-ctx.Done():
				signalFD.Close()
			case <-handlerDone:
			}
		}()

		emitter := &signalEmitterAdapter{
			store:     store,
			broker:    broker,
			sessionID: sessID,
			commandID: commandIDFunc,
		}
		handler := signal.NewHandler(engine, registry, emitter)
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
			// libseccomp auto-retries EINTR internally, so any error here is
			// permanent: ENOENT (filter destroyed because the tracee exited),
			// EBADF (watchdog closed the fd on ctx cancellation), or a real
			// failure. Exit to release the fd — the next exec will install a
			// fresh filter. Looping here would hot-spin on ENOENT until ctx
			// eventually cancels, burning CPU and potentially interfering
			// with cleanup of the next exec's setup.
			slog.Debug("signal filter exiting on error", "error", err)
			return
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
