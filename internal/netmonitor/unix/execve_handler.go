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

// Action constants for pipeline routing decisions.
const (
	ActionContinue = "continue" // Allow execve in-place (zero overhead)
	ActionRedirect = "redirect" // Redirect execve to agentsh-stub
	ActionDeny     = "deny"     // Fail execve with errno
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
	Action   string // ActionContinue | ActionRedirect | ActionDeny
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

// ApprovalRequester requests approval for exec operations.
type ApprovalRequester interface {
	RequestExecApproval(ctx context.Context, req ApprovalRequest) (bool, error)
}

// ApprovalRequest contains information for an exec approval request.
type ApprovalRequest struct {
	SessionID string
	Command   string
	Args      []string
	Reason    string
	Rule      string
}

// ExecveEmitter interface for emitting execve events.
type ExecveEmitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

// ExecveHandler handles execve/execveat notifications.
type ExecveHandler struct {
	cfg             ExecveHandlerConfig
	policy          PolicyChecker
	depthTracker    *DepthTracker
	emitter         ExecveEmitter
	approver        ApprovalRequester
	stubSymlinkPath string // Short symlink path pointing to agentsh-stub
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

// SetApprover sets the approval requester for the handler.
func (h *ExecveHandler) SetApprover(approver ApprovalRequester) {
	h.approver = approver
}

// SetStubSymlinkPath sets the path to the short symlink used for execve redirect.
func (h *ExecveHandler) SetStubSymlinkPath(path string) {
	h.stubSymlinkPath = path
}

// RegisterSession registers the session root PID for depth tracking.
// The root is registered at depth -1 so first command (direct) is at depth 0.
func (h *ExecveHandler) RegisterSession(pid int, sessionID string) {
	if h.depthTracker != nil {
		h.depthTracker.RegisterSession(pid, sessionID)
	}
}

// Handle processes an execve notification and returns the decision.
func (h *ExecveHandler) Handle(goCtx context.Context, ctx ExecveContext) ExecveResult {
	if goCtx == nil {
		goCtx = context.Background()
	}
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
		result := ExecveResult{Allow: true, Action: ActionContinue, Rule: "internal_bypass", Decision: "allow"}
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
				Action:   ActionDeny,
				Reason:   "truncated",
				Errno:    int32(unix.EACCES),
				Decision: "deny",
			}
			h.emitEvent(ctx, result, "truncated")
			return result
		case "approval":
			if h.approver == nil {
				result := ExecveResult{
					Allow:    false,
					Action:   ActionDeny,
					Reason:   "truncated_no_approver",
					Errno:    int32(unix.EACCES),
					Decision: "deny",
				}
				h.emitEvent(ctx, result, "truncated_no_approver")
				return result
			}
			timeout := h.cfg.ApprovalTimeout
			if timeout <= 0 {
				timeout = 5 * time.Minute
			}
			approvalCtx, cancel := context.WithTimeout(goCtx, timeout)
			approved, err := h.approver.RequestExecApproval(approvalCtx, ApprovalRequest{
				SessionID: ctx.SessionID,
				Command:   ctx.Filename,
				Args:      ctx.Argv,
				Reason:    "truncated args require approval",
				Rule:      "truncated",
			})
			cancel()
			if err != nil {
				// Only treat context deadline/cancellation as timeout;
				// other errors (transport, auth) always fail-secure.
				isTimeout := err == context.DeadlineExceeded || err == context.Canceled
				if isTimeout && h.cfg.ApprovalTimeoutAction == "allow" {
					break // fall through to policy check
				}
				reason := "truncated_approval_error"
				if isTimeout {
					reason = "truncated_approval_timeout"
				}
				result := ExecveResult{
					Allow:    false,
					Action:   ActionDeny,
					Reason:   reason,
					Errno:    int32(unix.EACCES),
					Decision: "deny",
				}
				h.emitEvent(ctx, result, reason)
				return result
			}
			if !approved {
				result := ExecveResult{
					Allow:    false,
					Action:   ActionDeny,
					Reason:   "truncated_approval_denied",
					Errno:    int32(unix.EACCES),
					Decision: "deny",
				}
				h.emitEvent(ctx, result, "truncated_approval_denied")
				return result
			}
			// Approved — fall through to policy check
		// "allow" falls through to policy check
		}
	}

	// Skip policy check if no policy configured
	if h.policy == nil {
		result := ExecveResult{Allow: true, Action: ActionContinue, Rule: "no_policy", Decision: "allow"}
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
		result := ExecveResult{Allow: true, Action: ActionContinue, Rule: decision.Rule, Decision: decision.Decision}
		h.emitEvent(ctx, result, decision.Rule)
		return result

	case "deny":
		result := ExecveResult{
			Allow:    false,
			Action:   ActionDeny,
			Rule:     decision.Rule,
			Reason:   decision.Message,
			Errno:    int32(unix.EACCES),
			Decision: decision.Decision,
		}
		h.emitEvent(ctx, result, decision.Rule)
		return result

	case "approve":
		// Redirect to agentsh-stub for approval workflow
		result := ExecveResult{
			Allow:    false,
			Action:   ActionRedirect,
			Rule:     decision.Rule,
			Reason:   decision.Message,
			Decision: decision.Decision,
		}
		h.emitEvent(ctx, result, decision.Rule)
		return result

	case "redirect":
		// Redirect execve to agentsh-stub
		result := ExecveResult{
			Allow:    false,
			Action:   ActionRedirect,
			Rule:     decision.Rule,
			Reason:   decision.Message,
			Decision: decision.Decision,
		}
		h.emitEvent(ctx, result, decision.Rule)
		return result

	default:
		// Unknown effective decision - deny (fail-secure)
		result := ExecveResult{
			Allow:    false,
			Action:   ActionDeny,
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
