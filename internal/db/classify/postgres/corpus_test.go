package postgres

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/db/classify/postgres/corpus"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

func TestCorpus(t *testing.T) {
	t.Skip("re-enabled in Task 5 once ast_walk lands")

	rows, err := corpus.LoadAll("corpus")
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no corpus rows loaded — corpus/*.yaml missing?")
	}

	rs := policy.MustLoadSample()

	for _, row := range rows {
		row := row
		t.Run(row.Name, func(t *testing.T) {
			d := DialectPostgres
			if row.Dialect != "" {
				if got, ok := ParseDialect(row.Dialect); ok {
					d = got
				} else {
					t.Fatalf("unknown dialect: %q", row.Dialect)
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

			got, err := New(d).Classify(row.SQL, sess, opts)
			if err != nil {
				t.Fatalf("Classify: %v", err)
			}
			if len(got) != len(row.ExpectedClassification) {
				t.Fatalf("statement count: got %d want %d", len(got), len(row.ExpectedClassification))
			}
			for i, exp := range row.ExpectedClassification {
				assertStatement(t, i, got[i], exp)
			}

			if row.ExpectedDecision != nil {
				if len(got) != 1 {
					t.Fatalf("expected_decision requires single-statement fixture; got %d statements", len(got))
				}
				dec := policy.Evaluate(got[0], rs, "appdb")
				if dec.Verb.String() != row.ExpectedDecision.Verb {
					t.Fatalf("decision verb: got %q want %q", dec.Verb.String(), row.ExpectedDecision.Verb)
				}
				if row.ExpectedDecision.RuleName != "" && dec.RuleName != row.ExpectedDecision.RuleName {
					t.Fatalf("decision rule: got %q want %q", dec.RuleName, row.ExpectedDecision.RuleName)
				}
				if c := row.ExpectedDecision.Reason; c != "" && !strings.Contains(dec.Reason, c) {
					t.Fatalf("decision reason: got %q want substring %q", dec.Reason, c)
				}
			}
		})
	}
}

func assertStatement(t *testing.T, idx int, got effects.ClassifiedStatement, exp corpus.ExpectedStatement) {
	t.Helper()
	if exp.ErrorPrefix != "" {
		if !strings.HasPrefix(got.Error, exp.ErrorPrefix) {
			t.Fatalf("stmt[%d] error: got %q want prefix %q", idx, got.Error, exp.ErrorPrefix)
		}
	}
	if exp.RawVerb != "" && got.RawVerb != exp.RawVerb {
		t.Fatalf("stmt[%d] raw_verb: got %q want %q", idx, got.RawVerb, exp.RawVerb)
	}
	prim, primaryOk := got.Primary()
	if primaryOk {
		if exp.PrimaryGroup != "" && prim.Group.String() != exp.PrimaryGroup {
			t.Fatalf("stmt[%d] primary group: got %q want %q", idx, prim.Group.String(), exp.PrimaryGroup)
		}
		if exp.PrimarySubtype != "" && prim.Subtype.String() != exp.PrimarySubtype {
			t.Fatalf("stmt[%d] primary subtype: got %q want %q", idx, prim.Subtype.String(), exp.PrimarySubtype)
		}
	} else if exp.PrimaryGroup != "" {
		t.Fatalf("stmt[%d] no primary effect; expected %q", idx, exp.PrimaryGroup)
	}
	if exp.TopResolution != "" && got.FoldResolution().String() != exp.TopResolution {
		t.Fatalf("stmt[%d] fold resolution: got %q want %q", idx, got.FoldResolution().String(), exp.TopResolution)
	}
	if len(exp.Effects) != 0 {
		if len(got.Effects) != len(exp.Effects) {
			t.Fatalf("stmt[%d] effect count: got %d want %d", idx, len(got.Effects), len(exp.Effects))
		}
		for i, ee := range exp.Effects {
			ge := got.Effects[i]
			if ee.Group != "" && ge.Group.String() != ee.Group {
				t.Fatalf("stmt[%d].effect[%d] group: got %q want %q", idx, i, ge.Group.String(), ee.Group)
			}
			if ee.Subtype != "" && ge.Subtype.String() != ee.Subtype {
				t.Fatalf("stmt[%d].effect[%d] subtype: got %q want %q", idx, i, ge.Subtype.String(), ee.Subtype)
			}
			if ee.Resolution != "" && ge.Resolution.String() != ee.Resolution {
				t.Fatalf("stmt[%d].effect[%d] resolution: got %q want %q", idx, i, ge.Resolution.String(), ee.Resolution)
			}
			if len(ee.Objects) != 0 {
				assertObjects(t, idx, i, ge.Objects, ee.Objects)
			}
		}
	}
}

func assertObjects(t *testing.T, sIdx, eIdx int, got []effects.ObjectRef, exp []corpus.ExpectedObject) {
	t.Helper()
	if len(got) != len(exp) {
		t.Fatalf("stmt[%d].effect[%d] object count: got %d want %d", sIdx, eIdx, len(got), len(exp))
	}
	for i, e := range exp {
		g := got[i]
		if e.Kind != "" && g.Kind.String() != e.Kind {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] kind: got %q want %q", sIdx, eIdx, i, g.Kind.String(), e.Kind)
		}
		if e.Schema != "" && g.Schema != e.Schema {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] schema: got %q want %q", sIdx, eIdx, i, g.Schema, e.Schema)
		}
		if e.Name != "" && g.Name != e.Name {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] name: got %q want %q", sIdx, eIdx, i, g.Name, e.Name)
		}
		if e.Host != "" && g.Host != e.Host {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] host: got %q want %q", sIdx, eIdx, i, g.Host, e.Host)
		}
		if e.Port != 0 && g.Port != e.Port {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] port: got %d want %d", sIdx, eIdx, i, g.Port, e.Port)
		}
		if e.Path != "" && g.Path != e.Path {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] path: got %q want %q", sIdx, eIdx, i, g.Path, e.Path)
		}
		if e.Argv0 != "" && g.Argv0 != e.Argv0 {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] argv0: got %q want %q", sIdx, eIdx, i, g.Argv0, e.Argv0)
		}
	}
}
