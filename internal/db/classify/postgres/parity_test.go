package postgres

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/db/classify/postgres/corpus"
)

// TestBackendDeterministic runs the corpus twice under the active backend and
// asserts byte-identical JSON output. Catches accidental nondeterminism in the
// classifier (map iteration order, slice mutation, internal cache state, etc.).
//
// Cross-backend parity (CGO libpg_query vs WASM libpg_query byte-equality, per
// design §10) is a CI-level concern that requires running two separately
// compiled test binaries (CGO_ENABLED=1 vs CGO_ENABLED=0) and diffing their
// outputs. That orchestration is left to a Make target / CI pipeline; this
// in-process smoke covers the determinism property of whichever backend is
// active for the running binary.
func TestBackendDeterministic(t *testing.T) {
	rows, err := corpus.LoadAll("corpus")
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(rows) < 50 {
		t.Skipf("need >=50 corpus rows for parity smoke; have %d", len(rows))
	}

	snap1 := snapshotCorpus(t, rows)
	snap2 := snapshotCorpus(t, rows)
	if snap1 != snap2 {
		t.Fatalf("non-deterministic classification across two runs of the same corpus:\n--- run1 ---\n%s\n--- run2 ---\n%s", snap1, snap2)
	}
}

// snapshotCorpus classifies every row and returns a stable JSON encoding of
// the result shape that matters for cross-backend parity: per-statement
// RawVerb, ordered Effects (group/subtype/resolution/objects), and Error.
// ParserBackend is excluded — it intentionally differs between CGO and WASM.
func snapshotCorpus(t *testing.T, rows []corpus.Row) string {
	t.Helper()

	type objSnap struct {
		Kind   string `json:"kind"`
		Schema string `json:"schema,omitempty"`
		Name   string `json:"name,omitempty"`
		Host   string `json:"host,omitempty"`
		Port   int    `json:"port,omitempty"`
		Path   string `json:"path,omitempty"`
		Argv0  string `json:"argv0,omitempty"`
	}
	type effSnap struct {
		Group      string    `json:"group"`
		Subtype    string    `json:"subtype,omitempty"`
		Resolution string    `json:"resolution"`
		Objects    []objSnap `json:"objects,omitempty"`
	}
	type stmtSnap struct {
		Fixture string    `json:"fixture"`
		Index   int       `json:"index"`
		RawVerb string    `json:"raw_verb,omitempty"`
		Effects []effSnap `json:"effects"`
		Error   string    `json:"error,omitempty"`
	}

	out := make([]stmtSnap, 0, len(rows))
	for _, row := range rows {
		d := DialectPostgres
		if row.Dialect != "" {
			if pd, ok := ParseDialect(row.Dialect); ok {
				d = pd
			}
		}
		sess := SessionState{
			SearchPath:        row.Session.SearchPath,
			DefaultSearchPath: row.Session.DefaultSearchPath,
			Role:              row.Session.Role,
			InTransaction:     row.Session.InTransaction,
		}
		if len(row.Session.TempTables) > 0 {
			sess.TempTables = make(map[string]struct{}, len(row.Session.TempTables))
			for _, n := range row.Session.TempTables {
				sess.TempTables[n] = struct{}{}
			}
		}
		opts := Options{EscalateUnknownFunctions: row.Options.EscalateUnknownFunctions}
		if len(row.Options.SafeFunctionAllowlist) > 0 {
			opts.SafeFunctionAllowlist = make(map[string]struct{}, len(row.Options.SafeFunctionAllowlist))
			for _, n := range row.Options.SafeFunctionAllowlist {
				opts.SafeFunctionAllowlist[strings.ToLower(n)] = struct{}{}
			}
		}

		stmts, err := New(d).Classify(row.SQL, sess, opts)
		if err != nil {
			t.Fatalf("Classify(%s): %v", row.Name, err)
		}
		for i, s := range stmts {
			snap := stmtSnap{
				Fixture: row.Name,
				Index:   i,
				RawVerb: s.RawVerb,
				Error:   s.Error,
				Effects: make([]effSnap, 0, len(s.Effects)),
			}
			for _, e := range s.Effects {
				es := effSnap{
					Group:      e.Group.String(),
					Subtype:    e.Subtype.String(),
					Resolution: e.Resolution.String(),
				}
				if len(e.Objects) > 0 {
					es.Objects = make([]objSnap, 0, len(e.Objects))
					for _, o := range e.Objects {
						es.Objects = append(es.Objects, objSnap{
							Kind:   o.Kind.String(),
							Schema: o.Schema,
							Name:   o.Name,
							Host:   o.Host,
							Port:   o.Port,
							Path:   o.Path,
							Argv0:  o.Argv0,
						})
					}
				}
				snap.Effects = append(snap.Effects, es)
			}
			out = append(out, snap)
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(b)
}
