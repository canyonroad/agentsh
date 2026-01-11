//go:build !windows

// internal/signal/handler.go
package signal

import (
	"context"
	"log/slog"
	"time"

	"github.com/agentsh/agentsh/internal/events"
)

// EventEmitter is an interface for emitting audit events.
type EventEmitter interface {
	Emit(ctx context.Context, eventType events.EventType, data map[string]interface{})
}

// Handler processes signal syscall notifications.
type Handler struct {
	engine   *Engine
	registry *PIDRegistry
	emitter  EventEmitter
	logger   *slog.Logger
}

// NewHandler creates a new signal handler.
func NewHandler(engine *Engine, registry *PIDRegistry, emitter EventEmitter) *Handler {
	return &Handler{
		engine:   engine,
		registry: registry,
		emitter:  emitter,
		logger:   slog.Default(),
	}
}

// SetLogger sets the logger for the handler.
func (h *Handler) SetLogger(logger *slog.Logger) {
	if logger != nil {
		h.logger = logger
	}
}

// Evaluate checks a signal against policy and returns the decision.
// This does not emit events or apply fallback - use Handle for that.
func (h *Handler) Evaluate(sigCtx SignalContext) Decision {
	// Build target context from registry
	targetCtx := h.registry.ClassifyTarget(sigCtx.PID, sigCtx.TargetPID)

	// Check against policy
	return h.engine.Check(sigCtx.Signal, targetCtx)
}

// Handle processes a signal notification and emits appropriate events.
// It evaluates the signal, applies platform fallback if needed, emits
// an audit event, and returns the decision.
func (h *Handler) Handle(ctx context.Context, sigCtx SignalContext) Decision {
	// Evaluate against policy
	dec := h.Evaluate(sigCtx)

	// For now, assume we can block (seccomp user-notify supports it)
	// In a real implementation, this would be determined by platform detection
	canBlock := true
	finalDec := ApplyFallback(dec, canBlock)

	// Emit appropriate event
	h.emitEvent(ctx, sigCtx, dec, finalDec)

	return finalDec
}

// emitEvent emits the appropriate audit event based on the decision.
func (h *Handler) emitEvent(ctx context.Context, sigCtx SignalContext, originalDec, finalDec Decision) {
	if h.emitter == nil {
		return
	}

	// Build base event data
	data := map[string]interface{}{
		"source_pid":  sigCtx.PID,
		"target_pid":  sigCtx.TargetPID,
		"signal":      sigCtx.Signal,
		"signal_name": SignalName(sigCtx.Signal),
		"syscall":     sigCtx.Syscall,
		"decision":    string(finalDec.Action),
		"rule":        finalDec.Rule,
		"timestamp":   time.Now(),
	}

	// Add message if present
	if finalDec.Message != "" {
		data["message"] = finalDec.Message
	}

	// Add redirect info if applicable
	if finalDec.Action == DecisionRedirect {
		data["redirect_to"] = finalDec.RedirectSignal
		data["redirect_to_name"] = SignalName(finalDec.RedirectSignal)
	}

	// Add fallback info if fallback was applied
	if originalDec.Action != finalDec.Action {
		data["fallback"] = string(finalDec.Action)
		data["original_action"] = string(originalDec.Action)
	}

	// Determine event type based on decision
	var eventType events.EventType
	switch finalDec.Action {
	case DecisionAllow, DecisionAudit:
		eventType = events.EventSignalSent
	case DecisionDeny:
		eventType = events.EventSignalBlocked
	case DecisionRedirect:
		eventType = events.EventSignalRedirected
	case DecisionAbsorb:
		eventType = events.EventSignalAbsorbed
	case DecisionApprove:
		eventType = events.EventSignalApproved
	default:
		// For unknown decisions, log as blocked for safety
		eventType = events.EventSignalBlocked
	}

	h.emitter.Emit(ctx, eventType, data)
}
