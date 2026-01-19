//go:build linux && cgo

package unix

import (
	"path/filepath"
	"time"

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
	Allow  bool
	Rule   string
	Reason string
	Errno  int32
}

// PolicyChecker interface for policy evaluation
type PolicyChecker interface {
	CheckExecve(filename string, argv []string, depth int) PolicyDecision
}

// PolicyDecision represents a policy check result
type PolicyDecision struct {
	Decision string
	Rule     string
	Message  string
}

// ExecveHandler handles execve/execveat notifications.
type ExecveHandler struct {
	cfg          ExecveHandlerConfig
	policy       PolicyChecker
	depthTracker *DepthTracker
}

// NewExecveHandler creates a new execve handler.
func NewExecveHandler(cfg ExecveHandlerConfig, policy PolicyChecker, dt *DepthTracker, emitter interface{}) *ExecveHandler {
	return &ExecveHandler{
		cfg:          cfg,
		policy:       policy,
		depthTracker: dt,
	}
}

// Handle processes an execve notification and returns the decision.
func (h *ExecveHandler) Handle(ctx ExecveContext) ExecveResult {
	// Check internal bypass first (fast path)
	if h.isInternalBypass(ctx.Filename) {
		return ExecveResult{Allow: true, Rule: "internal_bypass"}
	}

	// Get depth from tracker
	if h.depthTracker != nil {
		state, ok := h.depthTracker.Get(ctx.ParentPID)
		if ok {
			ctx.Depth = state.Depth + 1
			ctx.SessionID = state.SessionID
		}
	}

	// Check truncation policy
	if ctx.Truncated {
		switch h.cfg.OnTruncated {
		case "deny":
			return ExecveResult{
				Allow:  false,
				Reason: "truncated",
				Errno:  int32(unix.EACCES),
			}
		case "approval":
			// TODO: implement approval flow
			return ExecveResult{
				Allow:  false,
				Reason: "truncated_needs_approval",
				Errno:  int32(unix.EACCES),
			}
		// "allow" falls through to policy check
		}
	}

	// Skip policy check if no policy configured
	if h.policy == nil {
		return ExecveResult{Allow: true, Rule: "no_policy"}
	}

	// Check policy
	decision := h.policy.CheckExecve(ctx.Filename, ctx.Argv, ctx.Depth)

	switch decision.Decision {
	case "allow":
		// Record this PID for depth tracking
		if h.depthTracker != nil {
			h.depthTracker.RecordExecve(ctx.PID, ctx.ParentPID)
		}
		return ExecveResult{Allow: true, Rule: decision.Rule}

	case "deny":
		return ExecveResult{
			Allow:  false,
			Rule:   decision.Rule,
			Reason: decision.Message,
			Errno:  int32(unix.EACCES),
		}

	case "approval":
		// TODO: implement approval flow with timeout
		return ExecveResult{
			Allow:  false,
			Rule:   decision.Rule,
			Reason: "approval_required",
			Errno:  int32(unix.EACCES),
		}

	default:
		return ExecveResult{
			Allow:  false,
			Reason: "unknown_decision",
			Errno:  int32(unix.EACCES),
		}
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
