// internal/db/effects/statement.go
package effects

import "fmt"

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

// BulkOpKind classifies whether a statement initiates a wire-protocol COPY
// stream the proxy must follow. COPY to/from server paths or PROGRAM forms do
// not set this because no client-side CopyData stream follows the Q frame.
type BulkOpKind uint8

const (
	BulkOpNone BulkOpKind = iota
	BulkOpIn
	BulkOpOut
)

func (b BulkOpKind) String() string {
	switch b {
	case BulkOpIn:
		return "copy_in"
	case BulkOpOut:
		return "copy_out"
	default:
		return ""
	}
}

func (b BulkOpKind) MarshalJSON() ([]byte, error) {
	return []byte(`"` + b.String() + `"`), nil
}

func (b *BulkOpKind) UnmarshalJSON(bs []byte) error {
	switch string(bs) {
	case `""`, `null`:
		*b = BulkOpNone
	case `"copy_in"`:
		*b = BulkOpIn
	case `"copy_out"`:
		*b = BulkOpOut
	default:
		return fmt.Errorf("unknown bulk_op %s", bs)
	}
	return nil
}

// ClassifiedStatement is the output of the Postgres classifier (Plan 03) and
// the input to the policy evaluator (Plan 02). Effects must be in canonical
// order per Order(); the first entry is the primary effect.
type ClassifiedStatement struct {
	Effects       []Effect      `json:"effects"`
	RawVerb       string        `json:"raw_verb,omitempty"`
	ParserBackend ParserBackend `json:"parser_backend,omitempty"`
	Error         string        `json:"error,omitempty"`

	// SourceStart / SourceEnd are byte offsets into the original SQL input
	// (Plan 04c needs these to slice per-stmt text under RedactionFull). Both
	// zero when the parser cannot supply them (e.g. unknown-statement path).
	SourceStart int32 `json:"source_start,omitempty"`
	SourceEnd   int32 `json:"source_end,omitempty"`

	// PreparedName is populated for PREPARE / EXECUTE / DEALLOCATE classifications.
	// Empty for any other verb. For DEALLOCATE ALL, PreparedName is "" (the
	// proxy's sqlprepared.Intercept distinguishes by RawVerb).
	PreparedName string `json:"prepared_name,omitempty"`

	// BulkOp is non-None for COPY statements that open a CopyData stream the
	// proxy must follow.
	BulkOp BulkOpKind `json:"bulk_op,omitempty"`
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
