package windows

// WinExecPolicyChecker evaluates exec policy for a command.
type WinExecPolicyChecker interface {
	CheckCommand(cmd, cmdLine string) WinExecPolicyResult
}

// WinExecPolicyResult holds the result of a policy check.
type WinExecPolicyResult struct {
	Decision          string // Raw decision: "allow", "deny", "approve", "audit"
	EffectiveDecision string // Effective decision after overrides
	Rule              string // Matching rule name
	Message           string // Human-readable message
}

// WinExecHandler maps policy decisions to driver-level ExecDecision actions.
type WinExecHandler struct {
	policyChecker WinExecPolicyChecker
	stubBinary    string
}

// NewWinExecHandler creates a new exec handler.
func NewWinExecHandler(checker WinExecPolicyChecker, stubBinary string) *WinExecHandler {
	return &WinExecHandler{
		policyChecker: checker,
		stubBinary:    stubBinary,
	}
}

// HandleSuspended evaluates the policy for a suspended process and returns
// the appropriate ExecDecision.
func (h *WinExecHandler) HandleSuspended(req *SuspendedProcessRequest) ExecDecision {
	if h.policyChecker == nil {
		// Fail-open: resume if no policy checker
		return ExecDecisionResume
	}

	result := h.policyChecker.CheckCommand(req.ImagePath, req.CommandLine)

	// Use effective decision if available, fall back to raw decision
	decision := result.EffectiveDecision
	if decision == "" {
		decision = result.Decision
	}

	switch decision {
	case "allow", "audit":
		return ExecDecisionResume
	case "deny":
		return ExecDecisionTerminate
	case "approve":
		if h.stubBinary != "" {
			return ExecDecisionRedirect
		}
		// No stub binary available, fall back to terminate
		return ExecDecisionTerminate
	default:
		// Unknown decision: fail-secure
		return ExecDecisionTerminate
	}
}
