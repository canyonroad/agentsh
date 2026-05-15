package redirect

import (
	"errors"
	"strings"
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

func TestPlannerRewritesQualifiedRelation(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users",
		Statement: readStatement("public", "users"),
		Action: Action{
			RuleName:       "redirect-users",
			SourceRelation: "public.users",
			TargetRelation: "public.safe_users",
		},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	assertPlanMetadata(t, plan, "redirect-users", "public.users", "public.safe_users")
	assertSQLContains(t, plan.RewrittenSQL, "public.safe_users")
	assertSQLNotContains(t, plan.RewrittenSQL, "public.users")
}

func TestPlannerRewritesUnqualifiedResolvedRelation(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM users",
		Statement: readStatement("public", "users"),
		Action: Action{
			RuleName:       "redirect-users",
			SourceRelation: "public.users",
			TargetRelation: "public.safe_users",
		},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	assertPlanMetadata(t, plan, "redirect-users", "public.users", "public.safe_users")
	assertSQLContains(t, plan.RewrittenSQL, "public.safe_users")
	assertSQLNotContains(t, plan.RewrittenSQL, " FROM users")
}

func TestPlannerPreservesAlias(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT u.id FROM public.users AS u",
		Statement: readStatement("public", "users"),
		Action: Action{
			RuleName:       "redirect-users",
			SourceRelation: "public.users",
			TargetRelation: "public.safe_users",
		},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	rewritten := strings.ToLower(plan.RewrittenSQL)
	if !strings.Contains(rewritten, "public.safe_users as u") &&
		!strings.Contains(rewritten, "public.safe_users u") {
		t.Fatalf("rewritten SQL = %q, want rewritten FROM relation to keep alias u", plan.RewrittenSQL)
	}
}

func TestPlannerRewritesOneRelationInJoin(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users JOIN public.orders ON users.id = orders.user_id",
		Statement: readStatement("public", "users"),
		Action: Action{
			RuleName:       "redirect-users",
			SourceRelation: "public.users",
			TargetRelation: "public.safe_users",
		},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	assertSQLContains(t, plan.RewrittenSQL, "public.safe_users")
	assertSQLContains(t, plan.RewrittenSQL, "public.orders")
	assertSQLNotContains(t, plan.RewrittenSQL, "public.users")
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

func assertPlanMetadata(t *testing.T, plan Plan, ruleName, source, target string) {
	t.Helper()
	if plan.RuleName != ruleName {
		t.Fatalf("RuleName = %q, want %q", plan.RuleName, ruleName)
	}
	if plan.SourceRelation != source {
		t.Fatalf("SourceRelation = %q, want %q", plan.SourceRelation, source)
	}
	if plan.TargetRelation != target {
		t.Fatalf("TargetRelation = %q, want %q", plan.TargetRelation, target)
	}
}

func assertSQLContains(t *testing.T, sql, want string) {
	t.Helper()
	if !strings.Contains(sql, want) {
		t.Fatalf("rewritten SQL = %q, want to contain %q", sql, want)
	}
}

func assertSQLNotContains(t *testing.T, sql, unwanted string) {
	t.Helper()
	if strings.Contains(sql, unwanted) {
		t.Fatalf("rewritten SQL = %q, want not to contain %q", sql, unwanted)
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
