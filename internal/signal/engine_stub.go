//go:build windows

package signal

// Decision action constants
const (
	DecisionAllow   DecisionAction = "allow"
	DecisionDeny    DecisionAction = "deny"
	DecisionAudit   DecisionAction = "audit"
	DecisionAbsorb  DecisionAction = "absorb"
	DecisionDefault DecisionAction = "default"
)

// DecisionAction represents the action to take for a signal.
type DecisionAction string

// Decision represents the result of evaluating a signal against policy.
type Decision struct {
	Action         DecisionAction
	Rule           string
	Message        string
	RedirectSignal int
}

// SignalRule defines a policy rule for signal handling.
type SignalRule struct {
	Name           string
	Signals        []string
	Target         TargetSpec
	Decision       string
	RedirectSignal string
}

// Engine is the signal policy engine.
type Engine struct{}

// NewEngine creates a new signal policy engine.
func NewEngine(rules []SignalRule) (*Engine, error) {
	return nil, ErrSignalUnsupported
}

// Check evaluates a signal against the policy rules.
func (e *Engine) Check(signal int, ctx *TargetContext) Decision {
	return Decision{Action: DecisionDeny}
}

// ApplyFallback applies fallback logic to a decision.
func ApplyFallback(dec Decision, canBlock bool) Decision {
	return dec
}
