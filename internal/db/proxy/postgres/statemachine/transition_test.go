//go:build linux

package statemachine

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	rootpolicy "github.com/agentsh/agentsh/internal/policy"

	"github.com/agentsh/agentsh/internal/db/policy"
)

func dummyRules(t *testing.T) *policy.RuleSet {
	t.Helper()
	src := `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
`
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	rs, _, err := policy.Decode(p)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return rs
}

func denyDeletePolicyYAML() string {
	return `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: allow-read
    db_service: appdb
    operations: [read]
    decision: allow
  - name: block-delete
    db_service: appdb
    operations: [delete]
    decision: deny
`
}

func mustDecode(t *testing.T, yaml string) *policy.RuleSet {
	t.Helper()
	p, err := rootpolicy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	rs, _, err := policy.Decode(p)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return rs
}

// Sync handler ---------------------------------------------------------------

func TestTransition_Sync_NotAbsorbing_NotDirty(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I', Absorbing: false, UpstreamDirtySinceSync: false}
	cache := NewFakeCacheView()
	next, acts := Transition(s, &SyncFrame{}, cache, dummyRules(t), "appdb")
	want := []Action{&ActionForward{}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
	if next.Absorbing {
		t.Error("absorbing should remain false")
	}
}

func TestTransition_Sync_Absorbing_Dirty(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I', Absorbing: true, UpstreamDirtySinceSync: true}
	cache := NewFakeCacheView()
	next, acts := Transition(s, &SyncFrame{}, cache, dummyRules(t), "appdb")
	want := []Action{&ActionForward{}, &ActionDrainUntilRFQ{}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
	if next.Absorbing {
		t.Error("absorbing should reset")
	}
	if next.UpstreamDirtySinceSync {
		t.Error("dirty should reset")
	}
}

func TestTransition_Sync_Absorbing_NotDirty(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I', Absorbing: true, UpstreamDirtySinceSync: false}
	cache := NewFakeCacheView()
	next, acts := Transition(s, &SyncFrame{}, cache, dummyRules(t), "appdb")
	want := []Action{&ActionSynthReadyForQuery{Status: 'I'}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
	if next.Absorbing {
		t.Error("absorbing should reset")
	}
}

// Parse handler --------------------------------------------------------------

func TestTransition_Parse_Allow_PopulatesCacheAndForwards(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I'}
	cache := NewFakeCacheView()
	frame := &ParseFrame{Name: "s1", SQL: "SELECT id FROM users"}
	next, acts := Transition(s, frame, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	want := []Action{&ActionForward{}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
	if !next.UpstreamDirtySinceSync {
		t.Error("dirty should be true after allow Parse")
	}
	if v, ok := cache.Get("s1"); !ok || v.Verb != "SELECT" {
		t.Errorf("cache miss or wrong verb: %#v ok=%v", v, ok)
	}
}

func TestTransition_Parse_Deny_OutOfTx(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I'}
	cache := NewFakeCacheView()
	frame := &ParseFrame{Name: "del", SQL: "DELETE FROM users"}
	next, acts := Transition(s, frame, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if len(acts) < 2 {
		t.Fatalf("want >=2 actions; got %d", len(acts))
	}
	if _, ok := acts[0].(*ActionSynthError); !ok {
		t.Errorf("acts[0] = %T; want *ActionSynthError", acts[0])
	}
	if _, ok := acts[1].(*ActionSynthReadyForQuery); !ok {
		t.Errorf("acts[1] = %T; want *ActionSynthReadyForQuery", acts[1])
	}
	if !next.Absorbing {
		t.Error("absorbing should be true after deny")
	}
	if _, ok := cache.Get("del"); ok {
		t.Error("denied Parse must not populate cache")
	}
}

func TestTransition_Parse_Absorbing_Suppresses(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I', Absorbing: true}
	cache := NewFakeCacheView()
	frame := &ParseFrame{Name: "s2", SQL: "SELECT 2"}
	next, acts := Transition(s, frame, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	want := []Action{&ActionSuppress{}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
	if !next.Absorbing {
		t.Error("absorbing must remain true")
	}
}

// Bind, Describe, Execute, Flush, Close --------------------------------------

func TestTransition_Bind_CacheHit_Forwards(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I'}
	cache := NewFakeCacheView()
	cache.Put("s1", CacheValue{Verb: "SELECT"})
	next, acts := Transition(s, &BindFrame{Portal: "p1", Statement: "s1"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	want := []Action{&ActionForward{}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
	if !next.UpstreamDirtySinceSync {
		t.Error("dirty should be true after Bind forward")
	}
}

func TestTransition_Bind_CacheMiss_SynthErrorAndAbsorb(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I'}
	cache := NewFakeCacheView()
	next, acts := Transition(s, &BindFrame{Portal: "p1", Statement: "missing"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if len(acts) != 1 {
		t.Fatalf("len(acts)=%d want 1", len(acts))
	}
	se, ok := acts[0].(*ActionSynthError)
	if !ok {
		t.Fatalf("acts[0] = %T; want *ActionSynthError", acts[0])
	}
	if se.SQLState != "34000" {
		t.Errorf("SQLState=%q want 34000", se.SQLState)
	}
	if !next.Absorbing {
		t.Error("absorbing should be true")
	}
}

func TestTransition_Bind_Absorbing_Suppresses(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I', Absorbing: true}
	cache := NewFakeCacheView()
	_, acts := Transition(s, &BindFrame{Portal: "p", Statement: "x"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionSuppress{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Describe_NotAbsorbing_Forwards(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &DescribeFrame{ObjectType: 'S', Name: "s1"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionForward{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Describe_Absorbing_Suppresses(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I', Absorbing: true}, &DescribeFrame{ObjectType: 'S', Name: "s1"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionSuppress{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Execute_CacheHit_AllowForwards(t *testing.T) {
	cache := NewFakeCacheView()
	cache.Put("p1", CacheValue{Verb: "SELECT"})
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &ExecuteFrame{Portal: "p1"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionForward{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Execute_CacheMiss_SynthErrorAndAbsorb(t *testing.T) {
	cache := NewFakeCacheView()
	next, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &ExecuteFrame{Portal: "missing"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if len(acts) < 1 {
		t.Fatalf("len(acts)=%d", len(acts))
	}
	if _, ok := acts[0].(*ActionSynthError); !ok {
		t.Errorf("acts[0]=%T", acts[0])
	}
	if !next.Absorbing {
		t.Error("absorbing should be true")
	}
}

func TestTransition_Flush_NotAbsorbing_Forwards(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &FlushFrame{}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionForward{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Flush_Absorbing_Suppresses(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I', Absorbing: true}, &FlushFrame{}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionSuppress{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Close_DeletesCacheEntry(t *testing.T) {
	cache := NewFakeCacheView()
	cache.Put("s1", CacheValue{Verb: "SELECT"})
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &CloseFrame{ObjectType: 'S', Name: "s1"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionForward{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
	if _, ok := cache.Get("s1"); ok {
		t.Error("cache should not retain s1 after Close")
	}
}

// Simple Query (Q) -----------------------------------------------------------

func TestTransition_Query_AllowForwards(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &QueryFrame{SQL: "SELECT id FROM users"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionForward{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Query_DenyOutOfTx_NotDirty(t *testing.T) {
	cache := NewFakeCacheView()
	next, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &QueryFrame{SQL: "DELETE FROM users"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if len(acts) != 2 {
		t.Fatalf("len(acts)=%d want 2", len(acts))
	}
	if _, ok := acts[0].(*ActionSynthError); !ok {
		t.Errorf("acts[0]=%T", acts[0])
	}
	if _, ok := acts[1].(*ActionSynthReadyForQuery); !ok {
		t.Errorf("acts[1]=%T", acts[1])
	}
	if next.Absorbing {
		t.Error("Simple Query deny does not set Absorbing — Q is atomic per Sync")
	}
}

func TestTransition_Query_DenyInTx_TerminateDefault(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'T'}, &QueryFrame{SQL: "DELETE FROM users"}, cache, mustDecode(t, denyDeletePolicyYAML()), "appdb")
	if len(acts) != 2 {
		t.Fatalf("len(acts)=%d want 2 (SynthError + Close)", len(acts))
	}
	se, ok := acts[0].(*ActionSynthError)
	if !ok {
		t.Fatalf("acts[0]=%T", acts[0])
	}
	if se.Severity != "FATAL" {
		t.Errorf("Severity=%q want FATAL", se.Severity)
	}
	if _, ok := acts[1].(*ActionClose); !ok {
		t.Errorf("acts[1]=%T want *ActionClose", acts[1])
	}
}

func TestTransition_Query_DenyInTx_RollbackThenContinue(t *testing.T) {
	yaml := `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: allow-read
    db_service: appdb
    operations: [read]
    decision: allow
  - name: block-delete-soft
    db_service: appdb
    operations: [delete]
    decision: deny
    deny_mode_in_tx: rollback_then_continue
`
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'T'}, &QueryFrame{SQL: "DELETE FROM users"}, cache, mustDecode(t, yaml), "appdb")
	if len(acts) != 4 {
		t.Fatalf("len(acts)=%d want 4", len(acts))
	}
	wantKinds := []string{
		"*statemachine.ActionSynthError",
		"*statemachine.ActionInjectRollback",
		"*statemachine.ActionDrainUntilRFQ",
		"*statemachine.ActionSynthReadyForQuery",
	}
	for i, a := range acts {
		gotType := fmt.Sprintf("%T", a)
		if gotType != wantKinds[i] {
			t.Errorf("acts[%d] = %s; want %s", i, gotType, wantKinds[i])
		}
	}
}
