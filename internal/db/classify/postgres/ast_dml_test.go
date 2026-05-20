package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// classifyOne is a thin test helper that runs the classifier and asserts a
// single statement comes back, returning it.
func classifyOne(t *testing.T, sql string, sess SessionState) effects.ClassifiedStatement {
	t.Helper()
	got, err := New(DialectPostgres).Classify(sql, sess, Options{})
	if err != nil {
		t.Fatalf("Classify(%q): %v", sql, err)
	}
	if len(got) != 1 {
		t.Fatalf("Classify(%q): got %d stmts; want 1", sql, len(got))
	}
	return got[0]
}

func TestClassifySelect_Smoke(t *testing.T) {
	cs := classifyOne(t, "SELECT * FROM users", SessionState{})
	if cs.RawVerb != "SELECT" {
		t.Fatalf("RawVerb: got %q want SELECT", cs.RawVerb)
	}
	prim, ok := cs.Primary()
	if !ok {
		t.Fatalf("no primary effect")
	}
	if prim.Group != effects.GroupRead {
		t.Fatalf("primary group: got %v want read", prim.Group)
	}
	if len(prim.Objects) != 1 || prim.Objects[0].Name != "users" {
		t.Fatalf("objects: got %+v want [{users}]", prim.Objects)
	}
}

func TestClassifySelect_IntoClauseProducesSchemaCreate(t *testing.T) {
	cs := classifyOne(t, "SELECT * INTO new_customers FROM customers", SessionState{})
	if cs.RawVerb != "SELECT_INTO" {
		t.Fatalf("RawVerb: got %q want SELECT_INTO", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaCreate {
		t.Fatalf("primary group: got %v want schema_create", prim.Group)
	}
	if prim.Subtype != effects.SubtypeCreateTable {
		t.Fatalf("primary subtype: got %v want create_table", prim.Subtype)
	}
	// Should also have a read effect for the source table.
	hasRead := false
	for _, e := range cs.Effects {
		if e.Group == effects.GroupRead {
			hasRead = true
			if len(e.Objects) != 1 || e.Objects[0].Name != "customers" {
				t.Fatalf("read objects: got %+v want [{customers}]", e.Objects)
			}
		}
	}
	if !hasRead {
		t.Fatalf("expected secondary read effect; got %+v", cs.Effects)
	}
}

func TestClassifyInsert_Smoke(t *testing.T) {
	cs := classifyOne(t, "INSERT INTO audit_log VALUES (1, 'note')", SessionState{})
	if cs.RawVerb != "INSERT" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupWrite {
		t.Fatalf("primary group: got %v want write", prim.Group)
	}
	if len(prim.Objects) != 1 || prim.Objects[0].Name != "audit_log" {
		t.Fatalf("objects: got %+v", prim.Objects)
	}
}

func TestClassifyInsertSelect_AddsReadEffect(t *testing.T) {
	cs := classifyOne(t, "INSERT INTO audit_log SELECT * FROM users", SessionState{})
	if len(cs.Effects) != 2 {
		t.Fatalf("effects count: got %d want 2: %+v", len(cs.Effects), cs.Effects)
	}
	if cs.Effects[0].Group != effects.GroupWrite {
		t.Fatalf("primary should be write, got %v", cs.Effects[0].Group)
	}
	if cs.Effects[1].Group != effects.GroupRead {
		t.Fatalf("secondary should be read, got %v", cs.Effects[1].Group)
	}
	if len(cs.Effects[1].Objects) != 1 || cs.Effects[1].Objects[0].Name != "users" {
		t.Fatalf("read objects: got %+v", cs.Effects[1].Objects)
	}
}

func TestClassifyUpdate_Smoke(t *testing.T) {
	cs := classifyOne(t, "UPDATE users SET active = false WHERE id = 1", SessionState{})
	if cs.RawVerb != "UPDATE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupModify {
		t.Fatalf("primary group: got %v want modify", prim.Group)
	}
}

func TestClassifyUpdate_HasWhere(t *testing.T) {
	cs := classifyOne(t, "UPDATE users SET active = false WHERE id = 1", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupModify {
		t.Fatalf("primary group: got %v want modify", prim.Group)
	}
	if !prim.HasWhere {
		t.Fatalf("UPDATE with WHERE should set HasWhere on primary effect: %+v", prim)
	}
}

func TestClassifyUpdate_NoWhere(t *testing.T) {
	cs := classifyOne(t, "UPDATE users SET active = false", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupModify {
		t.Fatalf("primary group: got %v want modify", prim.Group)
	}
	if prim.HasWhere {
		t.Fatalf("UPDATE without WHERE should not set HasWhere: %+v", prim)
	}
}

func TestClassifyUpdate_HasWhereOnlyOnModifyEffect(t *testing.T) {
	cs := classifyOne(t, "UPDATE users SET active = false FROM logins WHERE users.id = logins.user_id", SessionState{})
	if len(cs.Effects) != 2 {
		t.Fatalf("effects count: got %d want 2: %+v", len(cs.Effects), cs.Effects)
	}
	if !cs.Effects[0].HasWhere {
		t.Fatalf("primary modify effect should have HasWhere: %+v", cs.Effects[0])
	}
	if cs.Effects[1].Group != effects.GroupRead {
		t.Fatalf("secondary effect group = %v want read", cs.Effects[1].Group)
	}
	if cs.Effects[1].HasWhere {
		t.Fatalf("secondary read effect should not inherit HasWhere: %+v", cs.Effects[1])
	}
}

func TestClassifyUpdate_HasWhereWithCTE(t *testing.T) {
	cs := classifyOne(t, "WITH r AS (SELECT id FROM logins) UPDATE users SET active = false WHERE id IN (SELECT id FROM r)", SessionState{})
	e := requireEffectGroup(t, cs, effects.GroupModify)
	if !e.HasWhere {
		t.Fatalf("top-level UPDATE with CTE and WHERE should set HasWhere: %+v", e)
	}
}

func TestClassifyUpdate_FromClauseAddsRead(t *testing.T) {
	cs := classifyOne(t, "UPDATE users SET active = false FROM logins WHERE users.id = logins.user_id", SessionState{})
	if len(cs.Effects) != 2 {
		t.Fatalf("effects count: got %d want 2: %+v", len(cs.Effects), cs.Effects)
	}
	if cs.Effects[0].Group != effects.GroupModify {
		t.Fatalf("primary not modify: %v", cs.Effects[0].Group)
	}
	if cs.Effects[1].Group != effects.GroupRead {
		t.Fatalf("secondary not read: %v", cs.Effects[1].Group)
	}
}

func TestClassifyDelete_Smoke(t *testing.T) {
	cs := classifyOne(t, "DELETE FROM users WHERE id = 1", SessionState{})
	if cs.RawVerb != "DELETE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupDelete {
		t.Fatalf("primary group: got %v want delete", prim.Group)
	}
}

func TestClassifyDelete_HasWhere(t *testing.T) {
	cs := classifyOne(t, "DELETE FROM users WHERE id = 1", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupDelete {
		t.Fatalf("primary group: got %v want delete", prim.Group)
	}
	if !prim.HasWhere {
		t.Fatalf("DELETE with WHERE should set HasWhere on primary effect: %+v", prim)
	}
}

func TestClassifyDelete_NoWhere(t *testing.T) {
	cs := classifyOne(t, "DELETE FROM users", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupDelete {
		t.Fatalf("primary group: got %v want delete", prim.Group)
	}
	if prim.HasWhere {
		t.Fatalf("DELETE without WHERE should not set HasWhere: %+v", prim)
	}
}

func TestClassifyPrepare_UpdateHasWhereNestedOnly(t *testing.T) {
	cs := classifyOne(t, "PREPARE q AS UPDATE users SET active = false WHERE id = 1", SessionState{})
	e := requireEffectGroup(t, cs, effects.GroupModify)
	if e.HasWhere {
		t.Fatalf("nested PREPARE UPDATE should not set HasWhere: %+v", e)
	}
}

func TestClassifyWithUpdateHasWhereNestedOnly(t *testing.T) {
	cs := classifyOne(t, "WITH u AS (UPDATE users SET active = false WHERE id = 1 RETURNING id) SELECT * FROM u", SessionState{})
	e := requireEffectGroup(t, cs, effects.GroupModify)
	if e.HasWhere {
		t.Fatalf("data-modifying CTE UPDATE should not set HasWhere: %+v", e)
	}
}

func TestClassifyCopyQueryDeleteHasWhereNestedOnly(t *testing.T) {
	cs := classifyOne(t, "COPY (DELETE FROM users WHERE id = 1 RETURNING *) TO STDOUT", SessionState{})
	e := requireEffectGroup(t, cs, effects.GroupDelete)
	if e.HasWhere {
		t.Fatalf("COPY query DELETE should not set HasWhere: %+v", e)
	}
}

func TestClassifyDelete_ReturningAddsRead(t *testing.T) {
	cs := classifyOne(t, "DELETE FROM users WHERE id = 1 RETURNING *", SessionState{})
	hasRead := false
	for _, e := range cs.Effects {
		if e.Group == effects.GroupRead {
			hasRead = true
		}
	}
	if !hasRead {
		t.Fatalf("expected read effect for RETURNING; got %+v", cs.Effects)
	}
}

func TestClassifyMerge_Smoke(t *testing.T) {
	sql := "MERGE INTO target USING source ON target.id = source.id " +
		"WHEN MATCHED THEN UPDATE SET v = source.v"
	cs := classifyOne(t, sql, SessionState{})
	if cs.RawVerb != "MERGE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupModify {
		t.Fatalf("primary group: got %v want modify", prim.Group)
	}
	if len(prim.Objects) != 1 || prim.Objects[0].Name != "target" {
		t.Fatalf("primary objects: got %+v want [target]", prim.Objects)
	}
	hasRead := false
	for _, e := range cs.Effects {
		if e.Group == effects.GroupRead {
			hasRead = true
			if len(e.Objects) != 1 || e.Objects[0].Name != "source" {
				t.Fatalf("source objects: got %+v want [source]", e.Objects)
			}
		}
	}
	if !hasRead {
		t.Fatalf("expected read effect on source: %+v", cs.Effects)
	}
}

func TestClassifyExplain_Plain(t *testing.T) {
	cs := classifyOne(t, "EXPLAIN SELECT * FROM customers", SessionState{})
	if cs.RawVerb != "EXPLAIN" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupRead {
		t.Fatalf("primary group: got %v want read", prim.Group)
	}
}

func TestClassifyExplain_AnalyzeRecursesIntoInner(t *testing.T) {
	cs := classifyOne(t, "EXPLAIN ANALYZE DELETE FROM users", SessionState{})
	if cs.RawVerb != "EXPLAIN_ANALYZE" {
		t.Fatalf("RawVerb: got %q want EXPLAIN_ANALYZE", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupDelete {
		t.Fatalf("primary group: got %v want delete (inner)", prim.Group)
	}
}

func TestClassifyPrepare_RecursesIntoInner(t *testing.T) {
	cs := classifyOne(t, "PREPARE q AS SELECT * FROM customers", SessionState{})
	if cs.RawVerb != "PREPARE_SELECT" {
		t.Fatalf("RawVerb: got %q want PREPARE_SELECT", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupRead {
		t.Fatalf("primary group: got %v want read", prim.Group)
	}
}

func TestClassifyExecute_DefersToProxy(t *testing.T) {
	cs := classifyOne(t, "EXECUTE q", SessionState{})
	if cs.RawVerb != "EXECUTE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupUnknown {
		t.Fatalf("primary group: got %v want unknown", prim.Group)
	}
	if cs.Error == "" {
		t.Fatalf("expected non-empty Error")
	}
}

func TestClassifyDeallocate_DiscardPlans(t *testing.T) {
	cs := classifyOne(t, "DEALLOCATE q", SessionState{})
	if cs.RawVerb != "DEALLOCATE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSession {
		t.Fatalf("primary group: got %v want session", prim.Group)
	}
	if prim.Subtype != effects.SubtypeDiscardPlans {
		t.Fatalf("primary subtype: got %v want discard_plans", prim.Subtype)
	}
}

func TestClassifyWithDeleteReturning_PropagatesCTEEffects(t *testing.T) {
	cs := classifyOne(t, "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d", SessionState{})
	// Outer SELECT contributes a read; CTE body contributes delete + read.
	groups := map[effects.Group]int{}
	for _, e := range cs.Effects {
		groups[e.Group]++
	}
	if groups[effects.GroupDelete] == 0 {
		t.Fatalf("expected delete effect from CTE body; got %+v", cs.Effects)
	}
	if groups[effects.GroupRead] == 0 {
		t.Fatalf("expected read effect; got %+v", cs.Effects)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupDelete {
		t.Fatalf("primary group: got %v want delete (highest tier in canonical order)", prim.Group)
	}
}

func TestClassifyQualifiedSelect_Resolution(t *testing.T) {
	cs := classifyOne(t, "SELECT * FROM public.customers", SessionState{})
	prim, _ := cs.Primary()
	if prim.Resolution != effects.ResolutionQualified {
		t.Fatalf("resolution: got %v want qualified", prim.Resolution)
	}
}

func TestClassifySelect_AmbiguousAfterSearchPath(t *testing.T) {
	sess := SessionState{SearchPath: []string{"app", "public"}, DefaultSearchPath: []string{"public"}}
	cs := classifyOne(t, "SELECT * FROM users", sess)
	prim, _ := cs.Primary()
	if prim.Resolution != effects.ResolutionAmbiguousAfterSearchPath {
		t.Fatalf("resolution: got %v want ambiguous_after_search_path", prim.Resolution)
	}
}

func TestClassifySelect_TempShadowed(t *testing.T) {
	sess := SessionState{TempTables: map[string]struct{}{"users": {}}}
	cs := classifyOne(t, "SELECT * FROM users", sess)
	prim, _ := cs.Primary()
	if prim.Resolution != effects.ResolutionMaybeTempShadowed {
		t.Fatalf("resolution: got %v want maybe_temp_shadowed", prim.Resolution)
	}
}

func TestClassifyPrepare_PopulatesPreparedName(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("PREPARE s1 AS SELECT 1", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].PreparedName != "s1" {
		t.Fatalf("PreparedName=%q want s1", got[0].PreparedName)
	}
}

func TestClassifyExecute_PopulatesPreparedName(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("EXECUTE s1(42)", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].PreparedName != "s1" {
		t.Fatalf("PreparedName=%q want s1", got[0].PreparedName)
	}
}

func TestClassifyDeallocate_Named(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("DEALLOCATE s1", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].RawVerb != "DEALLOCATE" {
		t.Fatalf("RawVerb=%q", got[0].RawVerb)
	}
	if got[0].PreparedName != "s1" {
		t.Fatalf("PreparedName=%q want s1", got[0].PreparedName)
	}
}

func TestClassifyDeallocate_All(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("DEALLOCATE ALL", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].PreparedName != "" {
		t.Fatalf("PreparedName=%q want \"\" for DEALLOCATE ALL", got[0].PreparedName)
	}
}

func requireEffectGroup(t *testing.T, cs effects.ClassifiedStatement, group effects.Group) effects.Effect {
	t.Helper()
	for _, e := range cs.Effects {
		if e.Group == group {
			return e
		}
	}
	t.Fatalf("missing effect group %v in %+v", group, cs.Effects)
	return effects.Effect{}
}
