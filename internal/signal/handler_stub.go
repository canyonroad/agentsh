//go:build windows

package signal

import (
	"context"
	"log/slog"
)

// EventEmitter is the interface for emitting signal events.
type EventEmitter interface {
	Emit(ctx context.Context, eventType string, data map[string]interface{})
}

// Handler handles signal interception decisions.
type Handler struct{}

// NewHandler creates a new signal handler.
func NewHandler(engine *Engine, registry *PIDRegistry, emitter EventEmitter) *Handler {
	return nil
}

// SetLogger sets the logger for the handler.
func (h *Handler) SetLogger(logger *slog.Logger) {}

// Evaluate evaluates a signal context and returns a decision.
func (h *Handler) Evaluate(sigCtx SignalContext) Decision {
	return Decision{Action: DecisionDeny}
}

// Handle handles a signal context with event emission.
func (h *Handler) Handle(ctx context.Context, sigCtx SignalContext) Decision {
	return Decision{Action: DecisionDeny}
}
