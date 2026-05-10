package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestClassifyCreateTable_Smoke(t *testing.T) {
	cs := classifyOne(t, "CREATE TABLE foo (id int)", SessionState{})
	if cs.RawVerb != "CREATE_TABLE" {
		t.Fatalf("RawVerb: got %q want CREATE_TABLE", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaCreate {
		t.Fatalf("primary group: got %v want schema_create", prim.Group)
	}
	if prim.Subtype != effects.SubtypeCreateTable {
		t.Fatalf("primary subtype: got %v want create_table", prim.Subtype)
	}
	if len(prim.Objects) != 1 || prim.Objects[0].Name != "foo" || prim.Objects[0].Kind != effects.ObjectTable {
		t.Fatalf("objects: got %+v want [{table foo}]", prim.Objects)
	}
}

func TestClassifyCreateTable_QualifiedHasSchema(t *testing.T) {
	cs := classifyOne(t, "CREATE TABLE public.foo (id int)", SessionState{})
	prim, _ := cs.Primary()
	if prim.Objects[0].Schema != "public" {
		t.Fatalf("schema: got %q want public", prim.Objects[0].Schema)
	}
	if prim.Resolution != effects.ResolutionQualified {
		t.Fatalf("resolution: got %v want qualified", prim.Resolution)
	}
}

func TestClassifyCreateTable_TempEncodesIntoRawVerb(t *testing.T) {
	cs := classifyOne(t, "CREATE TEMP TABLE bar (id int)", SessionState{})
	if cs.RawVerb != "CREATE_TEMP_TABLE" {
		t.Fatalf("RawVerb: got %q want CREATE_TEMP_TABLE", cs.RawVerb)
	}
	// applyTempLifecycle hook: ApplyStatement should register the table.
	out := ApplyStatement(SessionState{}, cs)
	if _, ok := out.TempTables["bar"]; !ok {
		t.Fatalf("expected bar in TempTables; got %+v", out.TempTables)
	}
}

func TestClassifyCreateIndex(t *testing.T) {
	cs := classifyOne(t, "CREATE INDEX idx_users_email ON public.users(email)", SessionState{})
	if cs.RawVerb != "CREATE_INDEX" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaCreate || prim.Subtype != effects.SubtypeCreateIndex {
		t.Fatalf("primary group/subtype: got %v/%v", prim.Group, prim.Subtype)
	}
	if prim.Objects[0].Kind != effects.ObjectIndex || prim.Objects[0].Name != "idx_users_email" {
		t.Fatalf("index object: got %+v", prim.Objects[0])
	}
	if prim.Objects[0].Schema != "public" {
		t.Fatalf("index schema: got %q want public (inherited from relation)", prim.Objects[0].Schema)
	}
}

func TestClassifyCreateView(t *testing.T) {
	cs := classifyOne(t, "CREATE VIEW v AS SELECT 1", SessionState{})
	if cs.RawVerb != "CREATE_VIEW" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeCreateView {
		t.Fatalf("primary subtype: got %v want create_view", prim.Subtype)
	}
	if prim.Objects[0].Kind != effects.ObjectView || prim.Objects[0].Name != "v" {
		t.Fatalf("view object: got %+v", prim.Objects[0])
	}
}

func TestClassifyCreateMaterializedView(t *testing.T) {
	cs := classifyOne(t, "CREATE MATERIALIZED VIEW mv AS SELECT 1", SessionState{})
	if cs.RawVerb != "CREATE_MATERIALIZED_VIEW" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaCreate {
		t.Fatalf("primary group: got %v want schema_create", prim.Group)
	}
	if prim.Subtype != effects.SubtypeCreateMaterializedView {
		t.Fatalf("primary subtype: got %v want create_materialized_view", prim.Subtype)
	}
}

func TestClassifyCreateTableAs_AddsRead(t *testing.T) {
	cs := classifyOne(t, "CREATE TABLE snap AS SELECT * FROM users", SessionState{})
	if cs.RawVerb != "CREATE_TABLE_AS" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effects count: got %d want 2: %+v", len(cs.Effects), cs.Effects)
	}
	if cs.Effects[0].Group != effects.GroupSchemaCreate {
		t.Fatalf("primary not schema_create: %v", cs.Effects[0].Group)
	}
	if cs.Effects[1].Group != effects.GroupRead {
		t.Fatalf("secondary not read: %v", cs.Effects[1].Group)
	}
	if len(cs.Effects[1].Objects) != 1 || cs.Effects[1].Objects[0].Name != "users" {
		t.Fatalf("read objects: got %+v", cs.Effects[1].Objects)
	}
}

func TestClassifyCreateSchema(t *testing.T) {
	cs := classifyOne(t, "CREATE SCHEMA app", SessionState{})
	if cs.RawVerb != "CREATE_SCHEMA" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeCreateSchema {
		t.Fatalf("subtype: got %v", prim.Subtype)
	}
	if prim.Objects[0].Kind != effects.ObjectSchema || prim.Objects[0].Name != "app" {
		t.Fatalf("schema obj: got %+v", prim.Objects[0])
	}
}

func TestClassifyCreateFunction(t *testing.T) {
	cs := classifyOne(t,
		"CREATE FUNCTION public.f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE SQL",
		SessionState{})
	if cs.RawVerb != "CREATE_FUNCTION" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeCreateFunction {
		t.Fatalf("subtype: got %v", prim.Subtype)
	}
	if prim.Objects[0].Schema != "public" || prim.Objects[0].Name != "f" {
		t.Fatalf("function obj: got %+v", prim.Objects[0])
	}
}

func TestClassifyCreateExtension(t *testing.T) {
	cs := classifyOne(t, "CREATE EXTENSION pgcrypto", SessionState{})
	if cs.RawVerb != "CREATE_EXTENSION" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeCreateExtension {
		t.Fatalf("subtype: got %v", prim.Subtype)
	}
}

func TestClassifyCreateDatabase(t *testing.T) {
	cs := classifyOne(t, "CREATE DATABASE app", SessionState{})
	if cs.RawVerb != "CREATE_DATABASE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeCreateDatabase {
		t.Fatalf("subtype: got %v", prim.Subtype)
	}
}

func TestClassifyCreatePublication(t *testing.T) {
	cs := classifyOne(t, "CREATE PUBLICATION p FOR TABLE users", SessionState{})
	if cs.RawVerb != "CREATE_PUBLICATION" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeCreatePublication {
		t.Fatalf("subtype: got %v", prim.Subtype)
	}
	if prim.Objects[0].Kind != effects.ObjectPublication || prim.Objects[0].Name != "p" {
		t.Fatalf("publication obj: got %+v", prim.Objects[0])
	}
}

func TestClassifyCreateType_GroupOnly(t *testing.T) {
	cs := classifyOne(t, "CREATE TYPE color AS ENUM ('r','g','b')", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaCreate {
		t.Fatalf("group: got %v want schema_create", prim.Group)
	}
	if prim.Subtype != effects.SubtypeNone {
		t.Fatalf("expected no subtype, got %v", prim.Subtype)
	}
}

func TestClassifyCreateSequence_GroupOnly(t *testing.T) {
	cs := classifyOne(t, "CREATE SEQUENCE s START 1", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaCreate {
		t.Fatalf("group: got %v want schema_create", prim.Group)
	}
	if prim.Subtype != effects.SubtypeNone {
		t.Fatalf("expected no subtype, got %v", prim.Subtype)
	}
	if prim.Objects[0].Kind != effects.ObjectSequence || prim.Objects[0].Name != "s" {
		t.Fatalf("sequence obj: got %+v", prim.Objects[0])
	}
}

func TestClassifyCreateTrigger_GroupOnly(t *testing.T) {
	cs := classifyOne(t,
		"CREATE TRIGGER t BEFORE INSERT ON foo FOR EACH ROW EXECUTE FUNCTION fn()",
		SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaCreate {
		t.Fatalf("group: got %v", prim.Group)
	}
	if prim.Subtype != effects.SubtypeNone {
		t.Fatalf("expected no subtype, got %v", prim.Subtype)
	}
}

func TestClassifyAlterTable(t *testing.T) {
	cs := classifyOne(t, "ALTER TABLE foo ADD COLUMN x int", SessionState{})
	if cs.RawVerb != "ALTER_TABLE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaAlter {
		t.Fatalf("group: got %v want schema_alter", prim.Group)
	}
	if prim.Objects[0].Name != "foo" {
		t.Fatalf("obj: got %+v", prim.Objects[0])
	}
}

func TestClassifyRenameTable_FallsThroughToSchemaAlter(t *testing.T) {
	cs := classifyOne(t, "ALTER TABLE foo RENAME TO bar", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaAlter {
		t.Fatalf("group: got %v want schema_alter", prim.Group)
	}
}

func TestClassifyCommentOn(t *testing.T) {
	cs := classifyOne(t, "COMMENT ON TABLE foo IS 'note'", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaAlter {
		t.Fatalf("group: got %v want schema_alter", prim.Group)
	}
	if len(prim.Objects) == 0 || prim.Objects[0].Name != "foo" {
		t.Fatalf("obj: got %+v", prim.Objects)
	}
}

func TestClassifyAlterPublication(t *testing.T) {
	cs := classifyOne(t, "ALTER PUBLICATION p ADD TABLE users", SessionState{})
	if cs.RawVerb != "ALTER_PUBLICATION" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaAlter || prim.Subtype != effects.SubtypeAlterPublication {
		t.Fatalf("primary group/subtype: got %v/%v", prim.Group, prim.Subtype)
	}
}

func TestClassifyDropTable_BareName(t *testing.T) {
	cs := classifyOne(t, "DROP TABLE foo", SessionState{})
	if cs.RawVerb != "DROP_TABLE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaDestroy || prim.Subtype != effects.SubtypeDropTable {
		t.Fatalf("primary group/subtype: got %v/%v", prim.Group, prim.Subtype)
	}
	if len(prim.Objects) != 1 || prim.Objects[0].Name != "foo" {
		t.Fatalf("obj: got %+v", prim.Objects)
	}
}

func TestClassifyDropTable_QualifiedName(t *testing.T) {
	cs := classifyOne(t, "DROP TABLE public.foo", SessionState{})
	prim, _ := cs.Primary()
	if prim.Objects[0].Schema != "public" || prim.Objects[0].Name != "foo" {
		t.Fatalf("obj: got %+v", prim.Objects[0])
	}
	if prim.Resolution != effects.ResolutionQualified {
		t.Fatalf("resolution: got %v want qualified", prim.Resolution)
	}
}

func TestClassifyDropTable_MultipleTables(t *testing.T) {
	cs := classifyOne(t, "DROP TABLE foo, bar", SessionState{})
	prim, _ := cs.Primary()
	if len(prim.Objects) != 2 {
		t.Fatalf("expected 2 objects; got %+v", prim.Objects)
	}
}

func TestClassifyDropTable_RemovesFromTempTables(t *testing.T) {
	in := SessionState{TempTables: map[string]struct{}{"foo": {}}}
	cs := classifyOne(t, "DROP TABLE foo", SessionState{})
	out := ApplyStatement(in, cs)
	if _, ok := out.TempTables["foo"]; ok {
		t.Fatalf("expected foo removed from TempTables; got %+v", out.TempTables)
	}
}

func TestClassifyDropIndex(t *testing.T) {
	cs := classifyOne(t, "DROP INDEX idx_a", SessionState{})
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeDropIndex {
		t.Fatalf("subtype: got %v want drop_index", prim.Subtype)
	}
}

func TestClassifyDropView(t *testing.T) {
	cs := classifyOne(t, "DROP VIEW v", SessionState{})
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeDropView {
		t.Fatalf("subtype: got %v", prim.Subtype)
	}
}

func TestClassifyDropFunction(t *testing.T) {
	cs := classifyOne(t, "DROP FUNCTION f(int)", SessionState{})
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeDropFunction {
		t.Fatalf("subtype: got %v", prim.Subtype)
	}
	if prim.Objects[0].Name != "f" {
		t.Fatalf("function obj: got %+v", prim.Objects[0])
	}
}

func TestClassifyDropSchema(t *testing.T) {
	cs := classifyOne(t, "DROP SCHEMA app", SessionState{})
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeDropSchema {
		t.Fatalf("subtype: got %v", prim.Subtype)
	}
}

func TestClassifyDropDatabase(t *testing.T) {
	cs := classifyOne(t, "DROP DATABASE app", SessionState{})
	if cs.RawVerb != "DROP_DATABASE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeDropDatabase {
		t.Fatalf("subtype: got %v", prim.Subtype)
	}
}

func TestClassifyDropPublication(t *testing.T) {
	cs := classifyOne(t, "DROP PUBLICATION p", SessionState{})
	prim, _ := cs.Primary()
	if prim.Subtype != effects.SubtypeDropPublication {
		t.Fatalf("subtype: got %v", prim.Subtype)
	}
}

func TestClassifyDropExtension(t *testing.T) {
	cs := classifyOne(t, "DROP EXTENSION pgcrypto", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaDestroy {
		t.Fatalf("group: got %v want schema_destroy", prim.Group)
	}
}

func TestClassifyDropSubscription_RoutedToExternalHandler(t *testing.T) {
	// DROP SUBSCRIPTION uses DropSubscriptionStmt (a different node from the
	// generic DropStmt). It routes to the dedicated handler in ast_external.go
	// which emits unsafe_io(drop_subscription) + schema_destroy.
	cs := classifyOne(t, "DROP SUBSCRIPTION s", SessionState{})
	if cs.Error != "" {
		t.Fatalf("unexpected Error: %q", cs.Error)
	}
	if len(cs.Effects) != 2 ||
		cs.Effects[0].Group != effects.GroupUnsafeIO ||
		cs.Effects[0].Subtype != effects.SubtypeDropSubscription ||
		cs.Effects[1].Group != effects.GroupSchemaDestroy {
		t.Fatalf("effects: %+v", cs.Effects)
	}
}

func TestClassifyTruncate_Single(t *testing.T) {
	cs := classifyOne(t, "TRUNCATE foo", SessionState{})
	if cs.RawVerb != "TRUNCATE" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupSchemaDestroy || prim.Subtype != effects.SubtypeTruncate {
		t.Fatalf("primary group/subtype: got %v/%v", prim.Group, prim.Subtype)
	}
	if len(prim.Objects) != 1 || prim.Objects[0].Name != "foo" {
		t.Fatalf("objects: got %+v", prim.Objects)
	}
}

func TestClassifyTruncate_Multiple(t *testing.T) {
	cs := classifyOne(t, "TRUNCATE foo, bar", SessionState{})
	prim, _ := cs.Primary()
	if len(prim.Objects) != 2 {
		t.Fatalf("expected 2 objects; got %+v", prim.Objects)
	}
}
