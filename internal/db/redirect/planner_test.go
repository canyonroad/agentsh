package redirect

import (
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

func TestPlannerRejectsMissingTarget(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users",
		Statement: readStatement("public", "users"),
		Action: Action{
			RuleName:       "redirect-users",
			SourceRelation: "public.users",
		},
	})

	assertRejection(t, err, ReasonMissingRedirectTarget)
}

func TestPlannerRejectsWhitespaceOnlyTarget(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users",
		Statement: readStatement("public", "users"),
		Action: Action{
			RuleName:       "redirect-users",
			SourceRelation: "public.users",
			TargetRelation: " \t\n ",
		},
	})

	assertRejection(t, err, ReasonMissingRedirectTarget)
}

func TestPlannerRejectsWhitespaceOnlySource(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users",
		Statement: readStatement("public", "users"),
		Action: Action{
			RuleName:       "redirect-users",
			SourceRelation: " \t\n ",
			TargetRelation: "archive.users",
		},
	})

	assertRejection(t, err, ReasonSourceNotFound)
}

func TestPlannerRejectsUnresolvedObject(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL: "SELECT * FROM users",
		Statement: effects.ClassifiedStatement{Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionUnresolved,
			Objects: []effects.ObjectRef{{
				Kind: effects.ObjectTable,
				Name: "users",
			}},
		}}},
		Action: testAction(),
	})

	assertRejection(t, err, ReasonUnresolvedObject)
}

func TestPlannerRejectsWriteStatement(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL: "INSERT INTO public.users (id) VALUES (1)",
		Statement: effects.ClassifiedStatement{Effects: []effects.Effect{{
			Group: effects.GroupWrite,
			ResolvedObjects: []effects.ResolvedObjectRef{{
				Kind:   effects.ResolvedObjectRelation,
				Schema: "public",
				Name:   "users",
			}},
			Resolution: effects.ResolutionCatalogResolved,
		}}},
		Action: testAction(),
	})

	assertRejection(t, err, ReasonWriteStatement)
}

func TestPlannerRejectsMissingSourceRelationBeforeParsing(t *testing.T) {
	backend := &fakeBackend{t: t}
	_, err := Planner{Backend: backend}.Plan(Input{
		SQL:       "SELECT * FROM public.users",
		Statement: readStatement("public", "orders"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonSourceNotFound)
	if backend.parseCalled {
		t.Fatal("Parse called before source relation validation")
	}
}

func TestPlannerRejectsSourceRelationWithoutCatalogMetadataBeforeParsing(t *testing.T) {
	tests := []struct {
		name     string
		resolved effects.ResolvedObjectRef
	}{
		{
			name: "empty source",
			resolved: effects.ResolvedObjectRef{
				Kind:   effects.ResolvedObjectRelation,
				Schema: "public",
				Name:   "users",
			},
		},
		{
			name: "unresolved reason",
			resolved: effects.ResolvedObjectRef{
				Source:           effects.ResolvedObjectSourceCatalog,
				Kind:             effects.ResolvedObjectRelation,
				Schema:           "public",
				Name:             "users",
				UnresolvedReason: "not visible",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &fakeBackend{t: t}
			_, err := Planner{Backend: backend}.Plan(Input{
				SQL:       "SELECT * FROM public.users",
				Statement: readStatementWithResolved(tt.resolved),
				Action:    testAction(),
			})

			assertRejection(t, err, ReasonSourceNotFound)
			if backend.parseCalled {
				t.Fatal("Parse called before catalog source relation validation")
			}
		})
	}
}

func TestPlannerRejectsMultiStatement(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users; SELECT * FROM public.users",
		Statement: readStatement("public", "users"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonMultiStatement)
}

func TestPlannerRejectsNonSelectStatement(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "BEGIN",
		Statement: readStatement("public", "users"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonNonSelectStatement)
}

func TestPlannerRejectsNilParseResultAsMultiStatement(t *testing.T) {
	_, err := Planner{Backend: &fakeBackend{parseResult: nil}}.Plan(Input{
		SQL:       "SELECT * FROM public.users",
		Statement: readStatement("public", "users"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonMultiStatement)
}

func TestRejectionValueImplementsError(t *testing.T) {
	err := error(Rejection{Reason: ReasonUnsupportedStatement})

	var rej Rejection
	if !errors.As(err, &rej) {
		t.Fatalf("errors.As() = false, want true for Rejection value")
	}
	if rej.Reason != ReasonUnsupportedStatement {
		t.Fatalf("rejection reason = %q, want %q", rej.Reason, ReasonUnsupportedStatement)
	}
}

func testPlanner() Planner {
	return Planner{Backend: postgres.NewRewriteBackend(postgres.DialectPostgres)}
}

func testAction() Action {
	return Action{
		RuleName:       "redirect-users",
		SourceRelation: "public.users",
		TargetRelation: "archive.users",
	}
}

func readStatement(schema, name string) effects.ClassifiedStatement {
	return readStatementWithResolved(effects.ResolvedObjectRef{
		Source: effects.ResolvedObjectSourceCatalog,
		Kind:   effects.ResolvedObjectRelation,
		Schema: schema,
		Name:   name,
	})
}

func readStatementWithResolved(resolved effects.ResolvedObjectRef) effects.ClassifiedStatement {
	return effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:           effects.GroupRead,
		Resolution:      effects.ResolutionCatalogResolved,
		ResolvedObjects: []effects.ResolvedObjectRef{resolved},
	}}}
}

func assertRejection(t *testing.T, err error, reason Reason) {
	t.Helper()
	var rej Rejection
	if !errors.As(err, &rej) {
		t.Fatalf("Plan() error = %T %v, want Rejection", err, err)
	}
	if rej.Reason != reason {
		t.Fatalf("rejection reason = %q, want %q", rej.Reason, reason)
	}
}

type fakeBackend struct {
	t           *testing.T
	parseCalled bool
	parseResult *pg_query.ParseResult
}

func (f *fakeBackend) Parse(string) (*pg_query.ParseResult, error) {
	if f.t != nil {
		f.t.Helper()
	}
	f.parseCalled = true
	return f.parseResult, nil
}

func (f *fakeBackend) Deparse(*pg_query.ParseResult) (string, error) {
	return "", nil
}

func (f *fakeBackend) Backend() effects.ParserBackend {
	return effects.ParserBackendPureGo
}
