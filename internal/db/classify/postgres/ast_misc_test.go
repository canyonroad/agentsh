package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestClassifyCall(t *testing.T) {
	cs := classifyOne(t, "CALL my_proc(1)", SessionState{})
	if cs.RawVerb != "CALL" {
		t.Fatalf("RawVerb: got %q want CALL", cs.RawVerb)
	}
	prim, ok := cs.Primary()
	if !ok {
		t.Fatalf("no primary effect")
	}
	if prim.Group != effects.GroupProcedural {
		t.Fatalf("group: got %v want procedural", prim.Group)
	}
	if prim.Subtype != effects.SubtypeCall {
		t.Fatalf("subtype: got %v want call", prim.Subtype)
	}
}

func TestClassifyDo(t *testing.T) {
	cs := classifyOne(t, "DO $$ BEGIN PERFORM 1; END $$", SessionState{})
	if cs.RawVerb != "DO" {
		t.Fatalf("RawVerb: got %q want DO", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupProcedural {
		t.Fatalf("group: got %v want procedural", prim.Group)
	}
	if prim.Subtype != effects.SubtypeDoOrAnon {
		t.Fatalf("subtype: got %v want do_or_anon", prim.Subtype)
	}
}

func TestClassifyVacuum(t *testing.T) {
	cs := classifyOne(t, "VACUUM", SessionState{})
	if cs.RawVerb != "VACUUM" {
		t.Fatalf("RawVerb: got %q want VACUUM", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupMaintenance {
		t.Fatalf("group: got %v want maintenance", prim.Group)
	}
}

func TestClassifyAnalyze(t *testing.T) {
	// ANALYZE is parsed as VacuumStmt with IsVacuumcmd=false.
	cs := classifyOne(t, "ANALYZE", SessionState{})
	if cs.RawVerb != "ANALYZE" {
		t.Fatalf("RawVerb: got %q want ANALYZE", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupMaintenance {
		t.Fatalf("group: got %v want maintenance", prim.Group)
	}
}

func TestClassifyReindex(t *testing.T) {
	cs := classifyOne(t, "REINDEX TABLE foo", SessionState{})
	if cs.RawVerb != "REINDEX" {
		t.Fatalf("RawVerb: got %q want REINDEX", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupMaintenance {
		t.Fatalf("group: got %v want maintenance", prim.Group)
	}
}

func TestClassifyCluster(t *testing.T) {
	cs := classifyOne(t, "CLUSTER foo", SessionState{})
	if cs.RawVerb != "CLUSTER" {
		t.Fatalf("RawVerb: got %q want CLUSTER", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupMaintenance {
		t.Fatalf("group: got %v want maintenance", prim.Group)
	}
}

func TestClassifyCheckpoint(t *testing.T) {
	cs := classifyOne(t, "CHECKPOINT", SessionState{})
	if cs.RawVerb != "CHECKPOINT" {
		t.Fatalf("RawVerb: got %q want CHECKPOINT", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupMaintenance {
		t.Fatalf("group: got %v want maintenance", prim.Group)
	}
}

func TestClassifyLockTable_ExtractsRelations(t *testing.T) {
	cs := classifyOne(t, "LOCK TABLE customers IN ACCESS EXCLUSIVE MODE", SessionState{})
	if cs.RawVerb != "LOCK" {
		t.Fatalf("RawVerb: got %q want LOCK", cs.RawVerb)
	}
	prim, ok := cs.Primary()
	if !ok {
		t.Fatalf("no primary effect")
	}
	if prim.Group != effects.GroupLock {
		t.Fatalf("group: got %v want lock", prim.Group)
	}
	if len(prim.Objects) != 1 {
		t.Fatalf("objects: got %d want 1: %+v", len(prim.Objects), prim.Objects)
	}
	if prim.Objects[0].Kind != effects.ObjectTable {
		t.Fatalf("object kind: got %v want table", prim.Objects[0].Kind)
	}
	if prim.Objects[0].Name != "customers" {
		t.Fatalf("object name: got %q want customers", prim.Objects[0].Name)
	}
}

func TestClassifyLockTable_MultipleRelations(t *testing.T) {
	cs := classifyOne(t, "LOCK TABLE a, b IN SHARE MODE", SessionState{})
	prim, _ := cs.Primary()
	if len(prim.Objects) != 2 {
		t.Fatalf("objects: got %d want 2: %+v", len(prim.Objects), prim.Objects)
	}
	names := []string{prim.Objects[0].Name, prim.Objects[1].Name}
	if names[0] != "a" || names[1] != "b" {
		t.Fatalf("names: got %v want [a b]", names)
	}
}

func TestClassifyListen(t *testing.T) {
	cs := classifyOne(t, "LISTEN ch1", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupNotify {
		t.Fatalf("group: got %v want notify", prim.Group)
	}
	if len(prim.Objects) != 0 {
		t.Fatalf("objects: want none got %+v", prim.Objects)
	}
	if cs.RawVerb != "LISTEN=ch1" {
		t.Fatalf("RawVerb: got %q want LISTEN=ch1", cs.RawVerb)
	}
}

func TestClassifyNotify(t *testing.T) {
	cs := classifyOne(t, "NOTIFY ch1, 'payload'", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupNotify {
		t.Fatalf("group: got %v want notify", prim.Group)
	}
	if cs.RawVerb != "NOTIFY=ch1" {
		t.Fatalf("RawVerb: got %q want NOTIFY=ch1", cs.RawVerb)
	}
}

func TestClassifyUnlisten(t *testing.T) {
	cs := classifyOne(t, "UNLISTEN ch1", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupNotify {
		t.Fatalf("group: got %v want notify", prim.Group)
	}
	if cs.RawVerb != "UNLISTEN=ch1" {
		t.Fatalf("RawVerb: got %q want UNLISTEN=ch1", cs.RawVerb)
	}
}

func TestClassifyUnlisten_All(t *testing.T) {
	// UNLISTEN * — Conditionname is "*".
	cs := classifyOne(t, "UNLISTEN *", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupNotify {
		t.Fatalf("group: got %v want notify", prim.Group)
	}
}
