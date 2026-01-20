//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

// ExecveHandlerConfig configures the execve handler.
type ExecveHandlerConfig struct {
	MaxArgc               int
	MaxArgvBytes          int
	OnTruncated           string // deny | allow | approval
	ApprovalTimeout       time.Duration
	ApprovalTimeoutAction string // deny | allow
	InternalBypass        []string
}

// ExecveContext holds context for an execve notification.
type ExecveContext struct {
	PID       int
	ParentPID int
	Filename  string
	Argv      []string
	Truncated bool
	SessionID string
	Depth     int
}

// ExecveResult holds the result of handling an execve.
type ExecveResult struct {
	Allow    bool
	Rule     string
	Reason   string
	Errno    int32
	Decision string // The actual policy decision (allow, deny, audit, redirect, approve)
}

// PolicyChecker interface for policy evaluation
type PolicyChecker interface {
	CheckExecve(filename string, argv []string, depth int) PolicyDecision
}

// PolicyDecision represents a policy check result
type PolicyDecision struct {
	Decision          string // The policy decision (allow, deny, approve, audit, redirect)
	EffectiveDecision string // What actually happens (allow or deny, respects enforcement mode)
	Rule              string
	Message           string
}

// ExecveEmitter interface for emitting execve events.
type ExecveEmitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

// ExecveHandler handles execve/execveat notifications.
type ExecveHandler struct {
	cfg          ExecveHandlerConfig
	policy       PolicyChecker
	depthTracker *DepthTracker
	emitter      ExecveEmitter
}

// NewExecveHandler creates a new execve handler.
func NewExecveHandler(cfg ExecveHandlerConfig, policy PolicyChecker, dt *DepthTracker, emitter ExecveEmitter) *ExecveHandler {
	return &ExecveHandler{
		cfg:          cfg,
		policy:       policy,
		depthTracker: dt,
		emitter:      emitter,
	}
}

// SetEmitter sets the event emitter for the handler.
// This allows setting the emitter after creation when it's not available at construction time.
func (h *ExecveHandler) SetEmitter(emitter ExecveEmitter) {
	h.emitter = emitter
}

// RegisterSession registers the session root PID for depth tracking.
// The root is registered at depth -1 so first command (direct) is at depth 0.
func (h *ExecveHandler) RegisterSession(pid int, sessionID string) {
	if h.depthTracker != nil {
		h.depthTracker.RegisterSession(pid, sessionID)
	}
}

// Handle processes an execve notification and returns the decision.
func (h *ExecveHandler) Handle(ctx ExecveContext) ExecveResult {
	// Get depth from tracker first - needed even for internal bypass
	// so that children of bypassed binaries inherit correct depth
	if h.depthTracker != nil {
		// First try to find parent's state
		state, ok := h.depthTracker.Get(ctx.ParentPID)
		if ok {
			ctx.Depth = state.Depth + 1
			ctx.SessionID = state.SessionID
		} else {
			// Parent not tracked - check if current PID has state
			// This handles two cases:
			// 1. First execve from wrapper: wrapper registered at depth -1, increment to 0
			// 2. Re-exec in same PID: use existing depth (don't increment)
			selfState, selfOk := h.depthTracker.Get(ctx.PID)
			if selfOk {
				if selfState.Depth == -1 {
					// Session root transitioning to first command
					ctx.Depth = 0
				} else {
					// Re-exec in same PID - preserve depth
					ctx.Depth = selfState.Depth
				}
				ctx.SessionID = selfState.SessionID
			}
		}
	}

	// Check internal bypass (fast path, but still track depth)
	if h.isInternalBypass(ctx.Filename) {
		// Record for depth tracking so children inherit correct depth
		if h.depthTracker != nil {
			h.depthTracker.RecordExecve(ctx.PID, ctx.ParentPID)
		}
		result := ExecveResult{Allow: true, Rule: "internal_bypass", Decision: "allow"}
		// Log every execve per design doc, including internal bypass
		h.emitEvent(ctx, result, "internal_bypass")
		return result
	}

	// Check truncation policy
	if ctx.Truncated {
		switch h.cfg.OnTruncated {
		case "deny":
			result := ExecveResult{
				Allow:    false,
				Reason:   "truncated",
				Errno:    int32(unix.EACCES),
				Decision: "deny",
			}
			h.emitEvent(ctx, result, "truncated")
			return result
		case "approval":
			// TODO: implement approval flow
			result := ExecveResult{
				Allow:    false,
				Reason:   "truncated_needs_approval",
				Errno:    int32(unix.EACCES),
				Decision: "approve",
			}
			h.emitEvent(ctx, result, "truncated_approval")
			return result
		// "allow" falls through to policy check
		}
	}

	// Skip policy check if no policy configured
	if h.policy == nil {
		result := ExecveResult{Allow: true, Rule: "no_policy", Decision: "allow"}
		// Record for depth tracking even without policy
		if h.depthTracker != nil {
			h.depthTracker.RecordExecve(ctx.PID, ctx.ParentPID)
		}
		// Log every execve per design doc, including when no policy
		h.emitEvent(ctx, result, "no_policy")
		return result
	}

	// Check policy
	decision := h.policy.CheckExecve(ctx.Filename, ctx.Argv, ctx.Depth)

	// Use EffectiveDecision for actual enforcement (respects shadow mode)
	// Use Decision for logging to preserve full policy semantics
	effectiveDecision := decision.EffectiveDecision
	if effectiveDecision == "" {
		// Fallback if EffectiveDecision not set (e.g., old policy wrapper)
		effectiveDecision = decision.Decision
	}

	switch effectiveDecision {
	case "allow":
		// Allowed by effective decision (includes shadow approve/audit/redirect)
		// Record this PID for depth tracking
		if h.depthTracker != nil {
			h.depthTracker.RecordExecve(ctx.PID, ctx.ParentPID)
		}
		result := ExecveResult{Allow: true, Rule: decision.Rule, Decision: decision.Decision}
		h.emitEvent(ctx, result, decision.Rule)
		return result

	case "deny":
		result := ExecveResult{
			Allow:    false,
			Rule:     decision.Rule,
			Reason:   decision.Message,
			Errno:    int32(unix.EACCES),
			Decision: decision.Decision,
		}
		h.emitEvent(ctx, result, decision.Rule)
		return result

	default:
		// Unknown effective decision - deny (fail-secure)
		result := ExecveResult{
			Allow:    false,
			Reason:   "unknown_decision",
			Errno:    int32(unix.EACCES),
			Decision: decision.Decision,
		}
		h.emitEvent(ctx, result, "unknown")
		return result
	}
}

// emitEvent emits an execve event to the emitter if configured.
func (h *ExecveHandler) emitEvent(ctx ExecveContext, result ExecveResult, rule string) {
	if h.emitter == nil {
		return
	}

	action := "allowed"
	if !result.Allow {
		action = "blocked"
	}

	// Use the actual policy decision, defaulting to allow/deny based on Allow flag
	decision := types.Decision(result.Decision)
	if decision == "" {
		if result.Allow {
			decision = types.DecisionAllow
		} else {
			decision = types.DecisionDeny
		}
	}

	// Effective decision reflects what actually happened
	effectiveDecision := types.DecisionAllow
	if !result.Allow {
		effectiveDecision = types.DecisionDeny
	}

	ev := types.Event{
		ID:        fmt.Sprintf("execve-%d-%d", ctx.PID, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "execve",
		SessionID: ctx.SessionID,
		PID:       ctx.PID,
		ParentPID: ctx.ParentPID,
		Depth:     ctx.Depth,
		Filename:  ctx.Filename,
		Argv:      ctx.Argv,
		Truncated: ctx.Truncated,
		Policy: &types.PolicyInfo{
			Decision:          decision,
			EffectiveDecision: effectiveDecision,
			Rule:              rule,
			Message:           result.Reason,
		},
		EffectiveAction: action,
	}

	_ = h.emitter.AppendEvent(context.Background(), ev)
	h.emitter.Publish(ev)
}

// isInternalBypass checks if filename matches internal bypass patterns.
func (h *ExecveHandler) isInternalBypass(filename string) bool {
	base := filepath.Base(filename)

	for _, pattern := range h.cfg.InternalBypass {
		// Try full path match
		if matched, _ := filepath.Match(pattern, filename); matched {
			return true
		}
		// Try basename match
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}
	return false
}
