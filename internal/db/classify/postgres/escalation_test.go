package postgres

import (
	"testing"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// extractSelectStmt parses a SQL string and returns the SelectStmt of the
// first RawStmt. Fails the test if the parse doesn't shape to a SELECT.
func extractSelectStmt(t *testing.T, sql string) *pg_query.SelectStmt {
	t.Helper()
	tree, err := parseSQL(sql)
	if err != nil {
		t.Fatalf("parse(%q): %v", sql, err)
	}
	if len(tree.Stmts) == 0 || tree.Stmts[0].Stmt == nil {
		t.Fatalf("parse(%q): empty stmts", sql)
	}
	sel, ok := tree.Stmts[0].Stmt.Node.(*pg_query.Node_SelectStmt)
	if !ok || sel.SelectStmt == nil {
		t.Fatalf("parse(%q): not a SelectStmt; got %T", sql, tree.Stmts[0].Stmt.Node)
	}
	return sel.SelectStmt
}

func TestCollectFuncCallsAny_NoFuncCalls(t *testing.T) {
	s := extractSelectStmt(t, "SELECT * FROM t")
	if collectFuncCallsAny(s, map[string]struct{}{}) {
		t.Fatalf("expected false; SELECT * FROM t has no FuncCall")
	}
}

func TestCollectFuncCallsAny_NilSelectStmt(t *testing.T) {
	if collectFuncCallsAny(nil, map[string]struct{}{}) {
		t.Fatalf("nil SelectStmt should return false")
	}
}

func TestCollectFuncCallsAny_UnknownFuncTrips(t *testing.T) {
	s := extractSelectStmt(t, "SELECT now()")
	if !collectFuncCallsAny(s, map[string]struct{}{}) {
		t.Fatalf("expected true; now() not in empty allowlist")
	}
}

func TestCollectFuncCallsAny_AllowlistedFunc(t *testing.T) {
	s := extractSelectStmt(t, "SELECT now()")
	allow := map[string]struct{}{"now": {}}
	if collectFuncCallsAny(s, allow) {
		t.Fatalf("expected false; now() is allowlisted")
	}
}

func TestCollectFuncCallsAny_SchemaQualified(t *testing.T) {
	s := extractSelectStmt(t, "SELECT public.now()")
	allow := map[string]struct{}{"public.now": {}}
	if collectFuncCallsAny(s, allow) {
		t.Fatalf("expected false; public.now allowlisted")
	}
	// Bare "now" allowlist should NOT match the schema-qualified call.
	allowBare := map[string]struct{}{"now": {}}
	if !collectFuncCallsAny(s, allowBare) {
		t.Fatalf("expected true; allowlist had \"now\" but call was \"public.now\"")
	}
}

func TestCollectFuncCallsAny_NestedArgs(t *testing.T) {
	s := extractSelectStmt(t, "SELECT to_tsvector('english', col) FROM t")
	allow := map[string]struct{}{"to_tsvector": {}}
	if collectFuncCallsAny(s, allow) {
		t.Fatalf("expected false; to_tsvector allowlisted, no other calls")
	}
}

func TestCollectFuncCallsAny_NestedFuncTrips(t *testing.T) {
	// Outer is allowlisted but inner is not — escalation must fire.
	s := extractSelectStmt(t, "SELECT to_tsvector('english', my_strip(col)) FROM t")
	allow := map[string]struct{}{"to_tsvector": {}}
	if !collectFuncCallsAny(s, allow) {
		t.Fatalf("expected true; nested my_strip() is unknown")
	}
}

func TestCollectFuncCallsAny_Mixed(t *testing.T) {
	s := extractSelectStmt(t, "SELECT now(), my_custom_fn()")
	allow := map[string]struct{}{"now": {}}
	if !collectFuncCallsAny(s, allow) {
		t.Fatalf("expected true; my_custom_fn not allowlisted")
	}
}

func TestCollectFuncCallsAny_FuncInWhere(t *testing.T) {
	s := extractSelectStmt(t, "SELECT 1 FROM t WHERE my_fn(col) > 0")
	if !collectFuncCallsAny(s, map[string]struct{}{}) {
		t.Fatalf("expected true; WHERE-clause FuncCall must be visited")
	}
}

func TestCollectFuncCallsAny_CaseInsensitive(t *testing.T) {
	// Function name case in SQL doesn't matter — allowlist is lowercase.
	s := extractSelectStmt(t, "SELECT NOW()")
	allow := map[string]struct{}{"now": {}}
	if collectFuncCallsAny(s, allow) {
		t.Fatalf("expected false; NOW lowercases to allowlisted now")
	}
}

// ---- end-to-end via classifySelect / Options ----

func TestEscalation_OptionOff_NoProcedural(t *testing.T) {
	// EscalateUnknownFunctions defaults to false; must NOT emit procedural.
	cs := classifyOne(t, "SELECT my_volatile()", SessionState{})
	for _, e := range cs.Effects {
		if e.Group == effects.GroupProcedural {
			t.Fatalf("escalation off but procedural effect present: %+v", cs.Effects)
		}
	}
}

func TestEscalation_OptionOn_UnknownFn_ProceduralEmitted(t *testing.T) {
	got, err := New(DialectPostgres).Classify(
		"SELECT my_volatile()",
		SessionState{},
		Options{EscalateUnknownFunctions: true, SafeFunctionAllowlist: map[string]struct{}{"now": {}}},
	)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d stmts want 1", len(got))
	}
	prim, ok := got[0].Primary()
	if !ok {
		t.Fatalf("no primary effect")
	}
	if prim.Group != effects.GroupProcedural {
		t.Fatalf("primary group: got %v want procedural", prim.Group)
	}
	if prim.Subtype != effects.SubtypeNone {
		// Spec calls for no Subtype on the escalation procedural effect.
		t.Fatalf("procedural escalation should have no subtype; got %v", prim.Subtype)
	}
}

func TestEscalation_OptionOn_AllowlistedFn_NoProcedural(t *testing.T) {
	got, err := New(DialectPostgres).Classify(
		"SELECT now()",
		SessionState{},
		Options{EscalateUnknownFunctions: true, SafeFunctionAllowlist: map[string]struct{}{"now": {}}},
	)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	for _, e := range got[0].Effects {
		if e.Group == effects.GroupProcedural {
			t.Fatalf("allowlisted now() should not escalate; got %+v", got[0].Effects)
		}
	}
	prim, _ := got[0].Primary()
	if prim.Group != effects.GroupRead {
		t.Fatalf("primary group: got %v want read", prim.Group)
	}
}
