// internal/db/effects/statement.go
package effects

// ParserBackend identifies which parser produced a classification, per §7.8.
type ParserBackend uint8

const (
	ParserBackendUnknown ParserBackend = iota
	ParserBackendLibPgQuery
	ParserBackendPureGo
)

func (b ParserBackend) String() string {
	switch b {
	case ParserBackendLibPgQuery:
		return "libpg_query"
	case ParserBackendPureGo:
		return "pure_go"
	default:
		return ""
	}
}

// ClassifiedStatement is the output of the Postgres classifier (Plan 03) and
// the input to the policy evaluator (Plan 02). Effects must be in canonical
// order per Order(); the first entry is the primary effect.
type ClassifiedStatement struct {
	Effects       []Effect
	RawVerb       string        // hint, e.g. "CREATE_SUBSCRIPTION" — informational only
	ParserBackend ParserBackend // which parser produced this
}

// Primary returns the first (canonical) effect. ok=false on empty effects list.
func (s ClassifiedStatement) Primary() (Effect, bool) {
	if len(s.Effects) == 0 {
		return Effect{}, false
	}
	return s.Effects[0], true
}

// FoldResolution returns the worst (least-confident) Resolution across all
// effects, per §6.2. Returns ResolutionQualified if Effects is empty.
func (s ClassifiedStatement) FoldResolution() Resolution {
	rs := make([]Resolution, len(s.Effects))
	for i, e := range s.Effects {
		rs[i] = e.Resolution
	}
	return Fold(rs)
}
