// internal/db/events/redaction.go
package events

// Redaction is the statement-text redaction tier per §10.3 (R4: enum form).
// Default for new events is RedactionParametersRedacted.
type Redaction uint8

const (
	RedactionNone Redaction = iota
	RedactionParametersRedacted
	RedactionFull
)

var redactionNames = [...]string{
	RedactionNone:               "none",
	RedactionParametersRedacted: "parameters_redacted",
	RedactionFull:               "full",
}

func (r Redaction) String() string {
	if int(r) >= len(redactionNames) {
		return ""
	}
	return redactionNames[r]
}

// MarshalJSON / UnmarshalJSON: emit/parse the canonical lowercase string form.
func (r Redaction) MarshalJSON() ([]byte, error) {
	return []byte(`"` + r.String() + `"`), nil
}

func (r *Redaction) UnmarshalJSON(b []byte) error {
	if len(b) < 2 {
		return nil
	}
	parsed, ok := ParseRedaction(string(b[1 : len(b)-1]))
	if !ok {
		return errInvalidRedaction
	}
	*r = parsed
	return nil
}

func ParseRedaction(s string) (Redaction, bool) {
	for i, name := range redactionNames {
		if name == s {
			return Redaction(i), true
		}
	}
	return 0, false
}

var errInvalidRedaction = &redactionError{}

type redactionError struct{}

func (e *redactionError) Error() string { return "invalid redaction value" }
