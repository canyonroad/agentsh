//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/agentsh/agentsh/internal/netmonitor"
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
	PID         int
	ParentPID   int
	Filename    string
	RawFilename string // Original filename before canonicalization
	Argv        []string
	Truncated      bool
	SessionID      string
	Depth          int
	UnwrappedFrom  string   // If unwrapped: the transparent wrapper command
	PayloadCommand string   // If unwrapped: the real command being evaluated
}

// ExecveResult holds the result of handling an execve.
type ExecveResult struct {
	Allow    bool
	Action   string // ActionContinue | ActionRedirect | ActionDeny
	Rule     string
	Reason   string
	Errno    int32
	Decision string // The actual policy decision (allow, deny, audit, redirect, approve)
	Redirect *types.RedirectInfo
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
	Redirect          *types.RedirectInfo
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
	stubSymlinkPath      string // Short symlink path pointing to agentsh-stub
	transparentOverrides *netmonitor.TransparentOverrides
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

// SetTransparentOverrides sets the transparent command overrides for unwrapping.
func (h *ExecveHandler) SetTransparentOverrides(overrides *netmonitor.TransparentOverrides) {
	h.transparentOverrides = overrides
}

// RegisterSession registers the session root PID for depth tracking.
// The root is registered at depth -1 so first command (direct) is at depth 0.
func (h *ExecveHandler) RegisterSession(pid int, sessionID string) {
	if h.depthTracker != nil {
		h.depthTracker.RegisterSession(pid, sessionID)
	}
}

// Handle processes an execve notification and returns the decision plus an
// optional audit event. The caller is responsible for emitting the event.
func (h *ExecveHandler) Handle(goCtx context.Context, ctx ExecveContext) (ExecveResult, *types.Event) {
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
		return result, h.buildEvent(ctx, result, "internal_bypass")
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
			return result, h.buildEvent(ctx, result, "truncated")
		case "approval":
			if h.approver == nil {
				result := ExecveResult{
					Allow:    false,
					Action:   ActionDeny,
					Reason:   "truncated_no_approver",
					Errno:    int32(unix.EACCES),
					Decision: "deny",
				}
				return result, h.buildEvent(ctx, result, "truncated_no_approver")
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
				return result, h.buildEvent(ctx, result, reason)
			}
			if !approved {
				result := ExecveResult{
					Allow:    false,
					Action:   ActionDeny,
					Reason:   "truncated_approval_denied",
					Errno:    int32(unix.EACCES),
					Decision: "deny",
				}
				return result, h.buildEvent(ctx, result, "truncated_approval_denied")
			}
			// Approved — fall through to policy check
		// "allow" falls through to policy check
		}
	}

	// Transparent command unwrapping: detect wrappers and evaluate payload
	payloadCmd, payloadArgs, unwrapDepth := netmonitor.UnwrapTransparentCommand(
		ctx.Filename, ctx.Argv, h.transparentOverrides,
	)

	if unwrapDepth > 0 && h.policy != nil {
		ctx.UnwrappedFrom = ctx.Filename
		ctx.PayloadCommand = payloadCmd

		// Evaluate the payload command against policy
		payloadDecision := h.policy.CheckExecve(payloadCmd, payloadArgs, ctx.Depth)
		payloadEffective := payloadDecision.EffectiveDecision
		if payloadEffective == "" {
			payloadEffective = payloadDecision.Decision
		}

		// Evaluate the wrapper command against policy
		wrapperDecision := h.policy.CheckExecve(ctx.Filename, ctx.Argv, ctx.Depth)
		wrapperEffective := wrapperDecision.EffectiveDecision
		if wrapperEffective == "" {
			wrapperEffective = wrapperDecision.Decision
		}

		// Most restrictive wins: if either denies, deny
		if payloadEffective == "deny" {
			result := ExecveResult{
				Allow:    false,
				Action:   ActionDeny,
				Rule:     payloadDecision.Rule,
				Reason:   fmt.Sprintf("denied: %s (unwrapped from: %s)", payloadCmd, filepath.Base(ctx.Filename)),
				Errno:    int32(unix.EACCES),
				Decision: payloadDecision.Decision,
			}
			return result, h.buildEvent(ctx, result, payloadDecision.Rule)
		}
		if wrapperEffective == "deny" {
			result := ExecveResult{
				Allow:    false,
				Action:   ActionDeny,
				Rule:     wrapperDecision.Rule,
				Reason:   wrapperDecision.Message,
				Errno:    int32(unix.EACCES),
				Decision: wrapperDecision.Decision,
			}
			return result, h.buildEvent(ctx, result, wrapperDecision.Rule)
		}

		// Both allowed — use the more restrictive decision
		chosenDecision := wrapperDecision
		if isMoreRestrictive(payloadEffective, wrapperEffective) {
			chosenDecision = payloadDecision
		}

		if h.depthTracker != nil {
			h.depthTracker.RecordExecve(ctx.PID, ctx.ParentPID)
		}

		effectiveDecision := chosenDecision.EffectiveDecision
		if effectiveDecision == "" {
			effectiveDecision = chosenDecision.Decision
		}

		switch effectiveDecision {
		case "allow":
			result := ExecveResult{Allow: true, Action: ActionContinue, Rule: chosenDecision.Rule, Decision: chosenDecision.Decision}
			return result, h.buildEvent(ctx, result, chosenDecision.Rule)
		case "approve", "redirect":
			result := ExecveResult{
				Allow:    false,
				Action:   ActionRedirect,
				Rule:     chosenDecision.Rule,
				Reason:   chosenDecision.Message,
				Decision: chosenDecision.Decision,
				Redirect: chosenDecision.Redirect,
			}
			return result, h.buildEvent(ctx, result, chosenDecision.Rule)
		default:
			// Unknown — fall through to normal evaluation
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
		return result, h.buildEvent(ctx, result, "no_policy")
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
		return result, h.buildEvent(ctx, result, decision.Rule)

	case "deny":
		result := ExecveResult{
			Allow:    false,
			Action:   ActionDeny,
			Rule:     decision.Rule,
			Reason:   decision.Message,
			Errno:    int32(unix.EACCES),
			Decision: decision.Decision,
		}
		return result, h.buildEvent(ctx, result, decision.Rule)

	case "approve":
		// Redirect to agentsh-stub for approval workflow
		result := ExecveResult{
			Allow:    false,
			Action:   ActionRedirect,
			Rule:     decision.Rule,
			Reason:   decision.Message,
			Decision: decision.Decision,
			Redirect: decision.Redirect,
		}
		return result, h.buildEvent(ctx, result, decision.Rule)

	case "redirect":
		// Redirect execve to agentsh-stub
		result := ExecveResult{
			Allow:    false,
			Action:   ActionRedirect,
			Rule:     decision.Rule,
			Reason:   decision.Message,
			Decision: decision.Decision,
			Redirect: decision.Redirect,
		}
		return result, h.buildEvent(ctx, result, decision.Rule)

	default:
		// Unknown effective decision - deny (fail-secure)
		result := ExecveResult{
			Allow:    false,
			Action:   ActionDeny,
			Reason:   "unknown_decision",
			Errno:    int32(unix.EACCES),
			Decision: decision.Decision,
		}
		return result, h.buildEvent(ctx, result, "unknown")
	}
}

// buildEvent builds an execve audit event without emitting it.
func (h *ExecveHandler) buildEvent(ctx ExecveContext, result ExecveResult, rule string) *types.Event {
	if h.emitter == nil {
		return nil
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

	return &types.Event{
		ID:        fmt.Sprintf("execve-%d-%d", ctx.PID, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "execve",
		SessionID: ctx.SessionID,
		PID:       ctx.PID,
		ParentPID: ctx.ParentPID,
		Depth:     ctx.Depth,
		Filename:    ctx.Filename,
		RawFilename: ctx.RawFilename,
		Argv:        ctx.Argv,
		Truncated:      ctx.Truncated,
		UnwrappedFrom:  ctx.UnwrappedFrom,
		PayloadCommand: ctx.PayloadCommand,
		Policy: &types.PolicyInfo{
			Decision:          decision,
			EffectiveDecision: effectiveDecision,
			Rule:              rule,
			Message:           result.Reason,
		},
		EffectiveAction: action,
	}
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

// isMoreRestrictive returns true if decision a is more restrictive than decision b.
func isMoreRestrictive(a, b string) bool {
	order := map[string]int{"deny": 5, "approve": 4, "redirect": 3, "audit": 2, "allow": 1}
	return order[a] > order[b]
}
