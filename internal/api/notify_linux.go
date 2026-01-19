//go:build linux && cgo

package api

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/agentsh/agentsh/internal/config"
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

// createExecveHandler creates an ExecveHandler from the configuration.
// Returns nil if the config is not valid or policy is nil.
func createExecveHandler(cfg config.ExecveConfig, pol *policy.Engine) any {
	if !cfg.Enabled {
		return nil
	}

	// Create depth tracker for process ancestry tracking
	dt := unixmon.NewDepthTracker()

	handlerCfg := unixmon.ExecveHandlerConfig{
		MaxArgc:               cfg.MaxArgc,
		MaxArgvBytes:          cfg.MaxArgvBytes,
		OnTruncated:           cfg.OnTruncated,
		ApprovalTimeout:       cfg.ApprovalTimeout,
		ApprovalTimeoutAction: cfg.ApprovalTimeoutAction,
		InternalBypass:        cfg.InternalBypass,
	}

	// Create policy checker wrapper if policy engine exists
	var policyChecker unixmon.PolicyChecker
	if pol != nil {
		policyChecker = &policyEngineWrapper{engine: pol}
	}

	return unixmon.NewExecveHandler(handlerCfg, policyChecker, dt, nil)
}

// policyEngineWrapper adapts policy.Engine to unixmon.PolicyChecker.
type policyEngineWrapper struct {
	engine *policy.Engine
}

func (w *policyEngineWrapper) CheckExecve(filename string, argv []string, depth int) unixmon.PolicyDecision {
	dec := w.engine.CheckExecve(filename, argv, depth)
	return unixmon.PolicyDecision{
		Decision: string(dec.EffectiveDecision),
		Rule:     dec.Rule,
		Message:  dec.Message,
	}
}

// startNotifyHandler receives the seccomp notify fd from the parent socket and
// starts the ServeNotify handler in a goroutine. It returns immediately.
// The handler runs until ctx is cancelled or the fd is closed.
// If execveHandler is non-nil, uses ServeNotifyWithExecve for execve interception.
func startNotifyHandler(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker, execveHandler any) {
	if parentSock == nil {
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

		// Type-assert and set emitter on execve handler if configured
		var h *unixmon.ExecveHandler
		if execveHandler != nil {
			h, _ = execveHandler.(*unixmon.ExecveHandler)
			if h != nil {
				h.SetEmitter(emitter)
			}
		}
		unixmon.ServeNotifyWithExecve(ctx, notifyFD, sessID, pol, emitter, h)
	}()
}
