package types

type Decision string

const (
	DecisionAllow   Decision = "allow"
	DecisionDeny    Decision = "deny"
	DecisionApprove Decision = "approve"
)

type ApprovalMode string

const (
	ApprovalModeShadow   ApprovalMode = "shadow"
	ApprovalModeEnforced ApprovalMode = "enforced"
)

