package service

// Unavoidability is the policies.db.unavoidability flag per
// docs/agentsh-db-access-spec.md §11.1. Operators select one of three modes:
//
//	off     (default): proxy is inert; no listeners are bound.
//	observe: listeners bind; declared services are intercepted; events emit.
//	enforce: same as observe in Plan 04a (and through Plan 04c). Plan 07
//	         generates the unavoidability bundle (egress denial, SessionID-
//	         keyed proxy identity) and makes enforce the high-assurance default.
//
// The zero value is UnavoidabilityOff, which is the safe default for any
// caller holding a not-yet-decoded RuleSet.
type Unavoidability uint8

const (
	UnavoidabilityOff Unavoidability = iota
	UnavoidabilityObserve
	UnavoidabilityEnforce
)

func (u Unavoidability) String() string {
	switch u {
	case UnavoidabilityOff:
		return "off"
	case UnavoidabilityObserve:
		return "observe"
	case UnavoidabilityEnforce:
		return "enforce"
	default:
		return ""
	}
}

// ParseUnavoidability accepts the canonical lowercase mode names. Empty input
// returns ok=false (callers may want to apply a default at a higher level).
func ParseUnavoidability(s string) (Unavoidability, bool) {
	switch s {
	case "off":
		return UnavoidabilityOff, true
	case "observe":
		return UnavoidabilityObserve, true
	case "enforce":
		return UnavoidabilityEnforce, true
	default:
		return UnavoidabilityOff, false
	}
}
