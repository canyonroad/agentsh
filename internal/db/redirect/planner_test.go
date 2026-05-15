package redirect

import (
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
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
		SQL: "BEGIN",
		Statement: effects.ClassifiedStatement{Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionCatalogResolved,
		}}},
		Action: testAction(),
	})

	assertRejection(t, err, ReasonNonSelectStatement)
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
	return effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			Schema: schema,
			Name:   name,
		}},
	}}}
}

func assertRejection(t *testing.T, err error, reason Reason) {
	t.Helper()
	var rej *Rejection
	if !errors.As(err, &rej) {
		t.Fatalf("Plan() error = %T %v, want *Rejection", err, err)
	}
	if rej.Reason != reason {
		t.Fatalf("rejection reason = %q, want %q", rej.Reason, reason)
	}
}
