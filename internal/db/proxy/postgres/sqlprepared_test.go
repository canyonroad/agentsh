//go:build linux

package postgres

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/preparedcache"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

func TestSQLPrepared_Prepare_Allow_PopulatesCacheAndReturnsNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	stmts := []effects.ClassifiedStatement{{
		RawVerb:      "PREPARE_SELECT",
		PreparedName: "s1",
		Effects:      []effects.Effect{{Group: effects.GroupRead}},
	}}
	decisions := []policy.Decision{{Verb: policy.VerbAllow}}
	handled, _ := Intercept(stmts, decisions, cache, statemachine.ConnState{}, nil)
	if handled {
		t.Fatal("PREPARE allow should return Handled=false; caller forwards normally")
	}
	if _, ok := cache.Get("s1"); !ok {
		t.Fatal("cache should contain s1 after PREPARE allow")
	}
}

func TestSQLPrepared_Prepare_Deny_HandledAndDoesNotCache(t *testing.T) {
	cache := preparedcache.New(0)
	stmts := []effects.ClassifiedStatement{{
		RawVerb:      "PREPARE_DELETE",
		PreparedName: "delstmt",
		Effects:      []effects.Effect{{Group: effects.GroupDelete}},
	}}
	decisions := []policy.Decision{{Verb: policy.VerbDeny, RuleName: "block-delete"}}
	handled, acts := Intercept(stmts, decisions, cache, statemachine.ConnState{LastUpstreamRFQ: 'I'}, nil)
	if !handled {
		t.Fatal("PREPARE deny should be handled by Intercept")
	}
	if len(acts) == 0 {
		t.Fatal("expected DenyRoute actions")
	}
	if _, ok := cache.Get("delstmt"); ok {
		t.Fatal("denied PREPARE must not populate cache")
	}
}

func TestSQLPrepared_Execute_CacheHit_AllowNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("s1", preparedcache.Entry{
		Classification: effects.ClassifiedStatement{
			Effects: []effects.Effect{{Group: effects.GroupRead}},
		},
	})
	stmts := []effects.ClassifiedStatement{{
		RawVerb:      "EXECUTE",
		PreparedName: "s1",
		Effects:      []effects.Effect{{Group: effects.GroupUnknown}},
	}}
	handled, acts := Intercept(stmts, nil, cache, statemachine.ConnState{}, nil)
	if handled {
		t.Fatalf("EXECUTE with cache hit should return Handled=false; caller evaluates rewritten stmts. acts=%v", acts)
	}
	if stmts[0].Effects[0].Group != effects.GroupRead {
		t.Fatalf("stmts[0] not rewritten; Group=%v", stmts[0].Effects[0].Group)
	}
}

func TestSQLPrepared_Execute_CacheMiss_HandledWithDenyRoute(t *testing.T) {
	cache := preparedcache.New(0)
	stmts := []effects.ClassifiedStatement{{
		RawVerb:      "EXECUTE",
		PreparedName: "missing",
	}}
	handled, acts := Intercept(stmts, nil, cache, statemachine.ConnState{LastUpstreamRFQ: 'I'}, nil)
	if !handled {
		t.Fatal("EXECUTE cache miss must be handled by Intercept")
	}
	if len(acts) < 2 {
		t.Fatalf("expected SynthError + RFQ; got %d actions", len(acts))
	}
	se, ok := acts[0].(*statemachine.ActionSynthError)
	if !ok {
		t.Fatalf("acts[0]=%T want SynthError", acts[0])
	}
	if !contains(se.Message, "SQL_PREPARED_CACHE_MISS") && !contains(se.Message, "prepared statement") {
		t.Errorf("error message lacks cache-miss indication: %q", se.Message)
	}
}

func TestSQLPrepared_DeallocateNamed_EvictsAndNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("s1", preparedcache.Entry{Classification: effects.ClassifiedStatement{RawVerb: "SELECT"}})
	stmts := []effects.ClassifiedStatement{{
		RawVerb:      "DEALLOCATE",
		PreparedName: "s1",
	}}
	handled, _ := Intercept(stmts, []policy.Decision{{Verb: policy.VerbAllow}}, cache, statemachine.ConnState{}, nil)
	if handled {
		t.Error("DEALLOCATE should return Handled=false so caller forwards Q to upstream")
	}
	if _, ok := cache.Get("s1"); ok {
		t.Error("cache must not retain s1 after DEALLOCATE")
	}
}

func TestSQLPrepared_DeallocateAll_ClearsAndNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("a", preparedcache.Entry{})
	cache.Put("b", preparedcache.Entry{})
	stmts := []effects.ClassifiedStatement{{RawVerb: "DEALLOCATE", PreparedName: ""}}
	handled, _ := Intercept(stmts, []policy.Decision{{Verb: policy.VerbAllow}}, cache, statemachine.ConnState{}, nil)
	if handled {
		t.Error("DEALLOCATE ALL should not be handled (forward Q to upstream)")
	}
	if cache.Len() != 0 {
		t.Errorf("cache.Len()=%d after DEALLOCATE ALL; want 0", cache.Len())
	}
}

func TestSQLPrepared_DiscardAll_ClearsAndNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("a", preparedcache.Entry{})
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "DISCARD",
		Effects: []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardAll}},
	}}
	handled, _ := Intercept(stmts, []policy.Decision{{Verb: policy.VerbAllow}}, cache, statemachine.ConnState{}, nil)
	if handled {
		t.Error("DISCARD ALL should not be handled (forward Q to upstream)")
	}
	if cache.Len() != 0 {
		t.Errorf("cache.Len()=%d after DISCARD ALL; want 0", cache.Len())
	}
}

func TestSQLPrepared_DiscardPlans_ClearsAndNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("a", preparedcache.Entry{})
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "DISCARD",
		Effects: []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardPlans}},
	}}
	handled, _ := Intercept(stmts, []policy.Decision{{Verb: policy.VerbAllow}}, cache, statemachine.ConnState{}, nil)
	if handled {
		t.Error("DISCARD PLANS should not be handled")
	}
	if cache.Len() != 0 {
		t.Errorf("cache.Len()=%d; want 0", cache.Len())
	}
}

func TestSQLPrepared_DiscardTemp_DoesNotTouchCache(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("a", preparedcache.Entry{})
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "DISCARD",
		Effects: []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardTemp}},
	}}
	handled, _ := Intercept(stmts, []policy.Decision{{Verb: policy.VerbAllow}}, cache, statemachine.ConnState{}, nil)
	if handled {
		t.Error("DISCARD TEMP should not be handled")
	}
	if cache.Len() != 1 {
		t.Errorf("cache.Len()=%d after DISCARD TEMP; want 1 (untouched)", cache.Len())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSQLPrepared_ExpectedActionShape_DenyRouteMatch(t *testing.T) {
	cache := preparedcache.New(0)
	stmts := []effects.ClassifiedStatement{{RawVerb: "PREPARE_DELETE", PreparedName: "x", Effects: []effects.Effect{{Group: effects.GroupDelete}}}}
	decisions := []policy.Decision{{Verb: policy.VerbDeny, RuleName: "rule1"}}
	_, acts := Intercept(stmts, decisions, cache, statemachine.ConnState{LastUpstreamRFQ: 'I'}, nil)
	want := []statemachine.Action{
		&statemachine.ActionSynthError{SQLState: "42501", Message: "denied by AgentSH policy: rule1"},
		&statemachine.ActionSynthReadyForQuery{Status: 'I'},
	}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
}
