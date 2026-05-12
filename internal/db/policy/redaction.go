package policy

// RedactionTier is the statement-text redaction tier per §10.3. It is locally
// defined (not imported from internal/db/events) so that internal/db/events
// can later import this package without a cycle.
type RedactionTier uint8

const (
	RedactNone RedactionTier = iota
	RedactParametersRedacted
	RedactFull
)

var redactionTierNames = [...]string{
	RedactNone:               "none",
	RedactParametersRedacted: "parameters_redacted",
	RedactFull:               "full",
}

func (r RedactionTier) String() string {
	if int(r) >= len(redactionTierNames) {
		return ""
	}
	return redactionTierNames[r]
}

// ParseRedactionTier parses the canonical lowercase tier name. Empty input
// returns ok=false (callers may want to apply a default at a higher level).
func ParseRedactionTier(s string) (RedactionTier, bool) {
	for i, n := range redactionTierNames {
		if n == s {
			return RedactionTier(i), true
		}
	}
	return 0, false
}

// RedactionConfig is the policies.db block. See §10.3.
//
// Defaults applied by Decode when a field is missing:
//
//	LogStatements:            RedactParametersRedacted
//	ApprovalStatementPreview: RedactParametersRedacted (named "redacted" in YAML)
//	ApprovalStatementChars:   200
type RedactionConfig struct {
	LogStatements            RedactionTier
	ApprovalStatementPreview RedactionTier
	ApprovalStatementChars   int

	// EscalateUnknownFunctions reflects policies.db.escalate_unknown_functions.
	// When true, classifier reclassifies SELECT calling a function NOT in
	// SafeFunctionAllowlist as procedural rather than read.
	EscalateUnknownFunctions bool

	// SafeFunctionAllowlist is the lowercase canonical function names that
	// stay classified as `read` when EscalateUnknownFunctions is on. When
	// the config omits the key but escalate is on, Decode populates this
	// with classify/postgres.DefaultSafeFunctionAllowlist() keys.
	SafeFunctionAllowlist []string
}
