package redirect

import (
	"errors"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

func TestReasonAmbiguousSourceAlias(t *testing.T) {
	if ReasonAmbiguousSource != ReasonAmbiguousRedirectSource {
		t.Fatalf("ReasonAmbiguousSource = %q, want %q", ReasonAmbiguousSource, ReasonAmbiguousRedirectSource)
	}
}

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

func TestPlannerRewritesTableQualifiedColumnReferenceWithImplicitAlias(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT users.id FROM public.users",
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

	assertRewrittenRelationAlias(t, plan.RewrittenSQL, "public.safe_users", "users")
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

	assertRewrittenRelationAlias(t, plan.RewrittenSQL, "public.safe_users", "u")
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

func TestPlannerRewritesJoinTableQualifiedReferenceWithImplicitAlias(t *testing.T) {
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

	assertRewrittenRelationAlias(t, plan.RewrittenSQL, "public.safe_users", "users")
	assertSQLContains(t, plan.RewrittenSQL, "public.orders")
}

func TestPlannerRewritesNestedSubselect(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM (SELECT id FROM public.users) s",
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
	assertSQLNotContains(t, plan.RewrittenSQL, "public.users")
}

func TestPlannerRewritesReadOnlyCTE(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "WITH u AS (SELECT id FROM public.users) SELECT * FROM u",
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
	assertSQLNotContains(t, plan.RewrittenSQL, "public.users")
}

func TestPlannerRewritesCTEShadowingSourceName(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "WITH users AS (SELECT id FROM users) SELECT * FROM users",
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
	assertSQLContains(t, plan.RewrittenSQL, "FROM users")
	assertSQLNotContains(t, plan.RewrittenSQL, "public.users")
}

func TestPlannerRewritesCTESiblingReferenceNotSource(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "WITH users AS (SELECT id FROM public.users), x AS (SELECT * FROM users) SELECT * FROM x",
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
	assertSQLContains(t, plan.RewrittenSQL, "FROM users")
	assertSQLContains(t, plan.RewrittenSQL, "FROM x")
	assertSQLNotContains(t, plan.RewrittenSQL, "public.users")
}

func TestPlannerRewritesSetOperation(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL: "SELECT id FROM public.users UNION ALL SELECT id FROM public.archive_users",
		Statement: readStatementWithResolved(
			resolvedRelation("public", "users"),
			resolvedRelation("public", "archive_users"),
		),
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
	assertSQLContains(t, plan.RewrittenSQL, "public.archive_users")
	assertSQLNotContains(t, plan.RewrittenSQL, "public.users")
}

func TestPlannerRewritesWhereExistsSubquery(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL: "SELECT * FROM public.orders WHERE EXISTS (SELECT 1 FROM public.users WHERE users.id = orders.user_id)",
		Statement: readStatementWithResolved(
			resolvedRelation("public", "orders"),
			resolvedRelation("public", "users"),
		),
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

func TestPlannerRejectsWhereExistsMultipleSourceOccurrences(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users WHERE EXISTS (SELECT 1 FROM public.users u2 WHERE u2.id = users.id)",
		Statement: readStatement("public", "users"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonAmbiguousRedirectSource)
}

func TestPlannerRewritesScalarTargetListSubquery(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT (SELECT id FROM public.users LIMIT 1) AS user_id",
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
	assertSQLNotContains(t, plan.RewrittenSQL, "public.users")
}

func TestPlannerRewritesInSubquery(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL: "SELECT * FROM public.orders WHERE user_id IN (SELECT id FROM public.users)",
		Statement: readStatementWithResolved(
			resolvedRelation("public", "orders"),
			resolvedRelation("public", "users"),
		),
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

func TestPlannerRejectsSchemaQualifiedSourceColumnReference(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT public.users.id FROM public.users",
		Statement: readStatement("public", "users"),
		Action: Action{
			RuleName:       "redirect-users",
			SourceRelation: "public.users",
			TargetRelation: "public.safe_users",
		},
	})

	assertRejection(t, err, ReasonUnsupportedStatement)
}

func TestPlannerRejectsSelectInto(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * INTO temp_user_ids FROM public.users",
		Statement: readStatement("public", "users"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonDDLStatement)
}

func TestPlannerRejectsDataModifyingCTE(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "WITH moved AS (DELETE FROM public.users RETURNING id) SELECT * FROM moved",
		Statement: readStatement("public", "users"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonWriteStatement)
}

func TestPlannerRejectsLockingClause(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users FOR UPDATE",
		Statement: readStatement("public", "users"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonUnsupportedStatement)
}

func TestPlannerRejectsRangeFunction(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users, generate_series(1, 3)",
		Statement: readStatement("public", "users"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonProceduralStatement)
}

func TestPlannerRejectsSampledSourceWithExpressionSubquery(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users TABLESAMPLE SYSTEM (1) WHERE EXISTS (SELECT 1 FROM public.users)",
		Statement: readStatement("public", "users"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonUnsupportedStatement)
}

func TestPlannerRejectsMultipleSourceOccurrences(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users u1 JOIN public.users u2 ON u1.id = u2.id",
		Statement: readStatement("public", "users"),
		Action:    testAction(),
	})

	assertRejection(t, err, ReasonAmbiguousRedirectSource)
}

func TestRewriteRangeNodeRejectsMalformedRangeSubselect(t *testing.T) {
	tests := []struct {
		name string
		node *pg_query.Node
	}{
		{
			name: "missing subquery",
			node: &pg_query.Node{Node: &pg_query.Node_RangeSubselect{
				RangeSubselect: &pg_query.RangeSubselect{},
			}},
		},
		{
			name: "non-select subquery",
			node: &pg_query.Node{Node: &pg_query.Node_RangeSubselect{
				RangeSubselect: &pg_query.RangeSubselect{Subquery: &pg_query.Node{
					Node: &pg_query.Node_InsertStmt{InsertStmt: &pg_query.InsertStmt{}},
				}},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rewriteRangeNode(tt.node, testRewrite())
			assertRejection(t, err, ReasonUnsupportedStatement)
		})
	}
}

func TestRewriteRangeNodeRejectsUnsupportedRangeTableFunc(t *testing.T) {
	_, err := rewriteRangeNode(&pg_query.Node{Node: &pg_query.Node_RangeTableFunc{
		RangeTableFunc: &pg_query.RangeTableFunc{},
	}}, testRewrite())

	assertRejection(t, err, ReasonUnsupportedStatement)
}

func TestRewriteRangeNodeRejectsUnknownRangeVariant(t *testing.T) {
	_, err := rewriteRangeNode(&pg_query.Node{Node: &pg_query.Node_RangeTblRef{
		RangeTblRef: &pg_query.RangeTblRef{},
	}}, testRewrite())

	assertRejection(t, err, ReasonUnsupportedStatement)
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

func testRewrite() relationRewrite {
	return relationRewrite{
		sourceSchema: "public",
		sourceName:   "users",
		targetSchema: "public",
		targetName:   "safe_users",
	}
}

func readStatement(schema, name string) effects.ClassifiedStatement {
	return readStatementWithResolved(resolvedRelation(schema, name))
}

func readStatementWithResolved(resolved ...effects.ResolvedObjectRef) effects.ClassifiedStatement {
	return effects.ClassifiedStatement{Effects: []effects.Effect{readEffect(resolved...)}}
}

func readEffect(resolved ...effects.ResolvedObjectRef) effects.Effect {
	return effects.Effect{
		Group:           effects.GroupRead,
		Resolution:      effects.ResolutionCatalogResolved,
		ResolvedObjects: resolved,
	}
}

func resolvedRelation(schema, name string) effects.ResolvedObjectRef {
	return effects.ResolvedObjectRef{
		Source: effects.ResolvedObjectSourceCatalog,
		Kind:   effects.ResolvedObjectRelation,
		Schema: schema,
		Name:   name,
	}
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

func assertRewrittenRelationAlias(t *testing.T, sql, relation, alias string) {
	t.Helper()
	rewritten := strings.ToLower(sql)
	relation = strings.ToLower(relation)
	alias = strings.ToLower(alias)
	if !strings.Contains(rewritten, relation+" as "+alias) &&
		!strings.Contains(rewritten, relation+" "+alias) {
		t.Fatalf("rewritten SQL = %q, want rewritten FROM relation to keep alias %s", sql, alias)
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
