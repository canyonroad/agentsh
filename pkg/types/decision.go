package types

type Decision string

const (
	DecisionAllow    Decision = "allow"
	DecisionDeny     Decision = "deny"
	DecisionApprove  Decision = "approve"
	DecisionRedirect Decision = "redirect"
)

type ApprovalMode string

const (
	ApprovalModeShadow   ApprovalMode = "shadow"
	ApprovalModeEnforced ApprovalMode = "enforced"
)

type RedirectInfo struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}
