package postgres

import (
	"reflect"
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestApplyStatement_SetSearchPath(t *testing.T) {
	in := SessionState{SearchPath: []string{"public"}, DefaultSearchPath: []string{"public"}}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeSetSearchPath,
			Objects: []effects.ObjectRef{
				{Kind: effects.ObjectGUC, Name: "search_path"},
			},
		}},
		RawVerb: "SET_SEARCH_PATH=app,public",
	}
	got := ApplyStatement(in, cs)
	want := []string{"app", "public"}
	if !reflect.DeepEqual(got.SearchPath, want) {
		t.Fatalf("SearchPath: got %v want %v", got.SearchPath, want)
	}
	// Input must not be mutated.
	if !reflect.DeepEqual(in.SearchPath, []string{"public"}) {
		t.Fatalf("input mutated: %v", in.SearchPath)
	}
}

func TestApplyStatement_DiscardAll(t *testing.T) {
	in := SessionState{
		SearchPath:        []string{"app", "public"},
		DefaultSearchPath: []string{"public"},
		TempTables:        map[string]struct{}{"foo": {}},
		Role:              "alice",
		DefaultRole:       "",
	}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardAll}},
		RawVerb: "DISCARD_ALL",
	}
	got := ApplyStatement(in, cs)
	if !reflect.DeepEqual(got.SearchPath, in.DefaultSearchPath) {
		t.Fatalf("DiscardAll search_path not reset: %v", got.SearchPath)
	}
	if len(got.TempTables) != 0 {
		t.Fatalf("DiscardAll temp_tables not cleared: %v", got.TempTables)
	}
	if got.Role != "" {
		t.Fatalf("DiscardAll role not reset: %q", got.Role)
	}
}

func TestApplyStatement_SetLocal_NoMutation(t *testing.T) {
	in := SessionState{
		SearchPath:        []string{"public"},
		DefaultSearchPath: []string{"public"},
		Role:              "alice",
	}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeSetLocal,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "search_path"}},
		}},
		RawVerb: "SET_LOCAL=search_path:app",
	}
	got := ApplyStatement(in, cs)
	if !reflect.DeepEqual(got.SearchPath, in.SearchPath) {
		t.Fatalf("SetLocal mutated SearchPath: got %v want %v", got.SearchPath, in.SearchPath)
	}
	if got.Role != in.Role {
		t.Fatalf("SetLocal mutated Role: got %q want %q", got.Role, in.Role)
	}
}

func TestApplyStatement_ResetSearchPath(t *testing.T) {
	in := SessionState{
		SearchPath:        []string{"app", "public"},
		DefaultSearchPath: []string{"public"},
	}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeReset,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "search_path"}},
		}},
		RawVerb: "RESET=search_path",
	}
	got := ApplyStatement(in, cs)
	if !reflect.DeepEqual(got.SearchPath, []string{"public"}) {
		t.Fatalf("ResetSearchPath: got %v want [public]", got.SearchPath)
	}
}

func TestApplyStatement_ResetAll(t *testing.T) {
	in := SessionState{
		SearchPath:        []string{"app", "public"},
		DefaultSearchPath: []string{"public"},
		Role:              "alice",
		DefaultRole:       "",
		TempTables:        map[string]struct{}{"foo": {}},
	}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeResetAll}},
		RawVerb: "RESET_ALL",
	}
	got := ApplyStatement(in, cs)
	if !reflect.DeepEqual(got.SearchPath, []string{"public"}) {
		t.Fatalf("ResetAll search_path: got %v", got.SearchPath)
	}
	if got.Role != "" {
		t.Fatalf("ResetAll role: got %q want \"\"", got.Role)
	}
	if len(got.TempTables) != 0 {
		t.Fatalf("ResetAll temp_tables not cleared: %v", got.TempTables)
	}
}

func TestApplyStatement_DiscardTemp(t *testing.T) {
	in := SessionState{
		TempTables: map[string]struct{}{"foo": {}, "bar": {}},
		Role:       "alice",
	}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardTemp}},
		RawVerb: "DISCARD_TEMP",
	}
	got := ApplyStatement(in, cs)
	if len(got.TempTables) != 0 {
		t.Fatalf("DiscardTemp not cleared: %v", got.TempTables)
	}
	if got.Role != "alice" {
		t.Fatalf("DiscardTemp must not touch role: got %q", got.Role)
	}
}

func TestApplyStatement_SetRole(t *testing.T) {
	in := SessionState{}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeSetRole,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "role"}},
		}},
		RawVerb: "SET_ROLE=alice",
	}
	got := ApplyStatement(in, cs)
	if got.Role != "alice" {
		t.Fatalf("SetRole: got %q want %q", got.Role, "alice")
	}
}

func TestApplyStatement_ResetRole(t *testing.T) {
	in := SessionState{
		Role:        "alice",
		DefaultRole: "",
	}
	// RESET role goes through the per-GUC reset path; only search_path reset
	// mutates tracked state. To clear role, the user must RESET ROLE — which
	// pg_query parses as VAR_RESET on name "role" (not search_path), so this
	// is intentionally a no-op for tracking purposes. Use DiscardAll/ResetAll
	// to clear role.
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeReset,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "role"}},
		}},
		RawVerb: "RESET=role",
	}
	got := ApplyStatement(in, cs)
	if got.Role != "alice" {
		t.Fatalf("RESET role: got %q want %q (only ResetAll/DiscardAll clear role)", got.Role, "alice")
	}
}

func TestApplyStatement_Begin(t *testing.T) {
	in := SessionState{}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupTransaction}},
		RawVerb: "BEGIN",
	}
	got := ApplyStatement(in, cs)
	if !got.InTransaction {
		t.Fatal("BEGIN: InTransaction not set")
	}
}

func TestApplyStatement_Commit(t *testing.T) {
	in := SessionState{InTransaction: true}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupTransaction}},
		RawVerb: "COMMIT",
	}
	got := ApplyStatement(in, cs)
	if got.InTransaction {
		t.Fatal("COMMIT: InTransaction still set")
	}
}

func TestApplyStatement_Rollback(t *testing.T) {
	in := SessionState{InTransaction: true}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupTransaction}},
		RawVerb: "ROLLBACK",
	}
	got := ApplyStatement(in, cs)
	if got.InTransaction {
		t.Fatal("ROLLBACK: InTransaction still set")
	}
}

func TestApplyStatement_NoEffects_Returns_Input(t *testing.T) {
	in := SessionState{SearchPath: []string{"public"}}
	got := ApplyStatement(in, effects.ClassifiedStatement{})
	if !reflect.DeepEqual(got.SearchPath, in.SearchPath) {
		t.Fatalf("no-effects: SearchPath mutated: %v", got.SearchPath)
	}
}

func TestApplyStatement_ReadEffect_NoMutation(t *testing.T) {
	in := SessionState{SearchPath: []string{"public"}, DefaultSearchPath: []string{"public"}}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupRead}},
		RawVerb: "SELECT",
	}
	got := ApplyStatement(in, cs)
	if !reflect.DeepEqual(got.SearchPath, in.SearchPath) {
		t.Fatalf("read effect mutated SearchPath: %v", got.SearchPath)
	}
}
