package types

type Decision string

const (
	DecisionAllow      Decision = "allow"
	DecisionDeny       Decision = "deny"
	DecisionApprove    Decision = "approve"
	DecisionRedirect   Decision = "redirect"
	DecisionAudit      Decision = "audit"       // Allow + enhanced logging
	DecisionSoftDelete Decision = "soft_delete" // Redirect destructive ops to trash
)

type ApprovalMode string

const (
	ApprovalModeShadow   ApprovalMode = "shadow"
	ApprovalModeEnforced ApprovalMode = "enforced"
)

type RedirectInfo struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args,omitempty"`        // Prepended args
	ArgsAppend  []string          `json:"args_append,omitempty"` // Appended args
	Environment map[string]string `json:"environment,omitempty"` // Environment overrides
	Reason      string            `json:"reason,omitempty"`
}

// FileRedirectInfo describes a file path redirect.
type FileRedirectInfo struct {
	OriginalPath string `json:"original_path"`
	RedirectPath string `json:"redirect_path"`
	Operation    string `json:"operation"`
	Reason       string `json:"reason,omitempty"`
}
