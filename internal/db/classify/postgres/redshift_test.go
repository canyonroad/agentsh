package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestRedshiftFirstKeyword_Unload(t *testing.T) {
	sql := "UNLOAD ('SELECT * FROM customers') TO 's3://bucket/data.csv' IAM_ROLE 'arn:aws:iam::123:role/redshift'"
	cs, ok := redshiftFirstKeyword(sql, effects.ParserBackendLibPgQuery)
	if !ok {
		t.Fatalf("expected ok=true for UNLOAD")
	}
	if cs.RawVerb != "UNLOAD" {
		t.Fatalf("RawVerb: got %q want UNLOAD", cs.RawVerb)
	}
	if cs.ParserBackend != effects.ParserBackendLibPgQuery {
		t.Fatalf("ParserBackend: got %v want libpg_query", cs.ParserBackend)
	}
	if len(cs.Effects) != 3 {
		t.Fatalf("effect count: got %d want 3", len(cs.Effects))
	}
	// Both unsafe_io and bulk_export are Critical; canonical rank within
	// Critical is unsafe_io < bulk_export, so unsafe_io is primary.
	prim, primaryOk := cs.Primary()
	if !primaryOk {
		t.Fatal("expected a primary effect")
	}
	if prim.Group != effects.GroupUnsafeIO {
		t.Fatalf("primary group: got %v want unsafe_io", prim.Group)
	}
	if cs.Effects[0].Group != effects.GroupUnsafeIO {
		t.Fatalf("effects[0]: got %v want unsafe_io", cs.Effects[0].Group)
	}
	if cs.Effects[1].Group != effects.GroupBulkExport {
		t.Fatalf("effects[1]: got %v want bulk_export", cs.Effects[1].Group)
	}
	if cs.Effects[1].Subtype != effects.SubtypeUnloadToS3 {
		t.Fatalf("effects[1].subtype: got %v want unload_to_s3", cs.Effects[1].Subtype)
	}
	if cs.Effects[2].Group != effects.GroupRead {
		t.Fatalf("effects[2]: got %v want read", cs.Effects[2].Group)
	}
	// path on both objects
	for i, idx := range []int{0, 1} {
		objs := cs.Effects[idx].Objects
		if len(objs) != 1 {
			t.Fatalf("effects[%d] object count: got %d want 1", idx, len(objs))
		}
		if objs[0].Kind != effects.ObjectFilesystemPath {
			t.Fatalf("effects[%d].obj kind: got %v want filesystem_path (case %d)", idx, objs[0].Kind, i)
		}
		if objs[0].Path != "s3://bucket/data.csv" {
			t.Fatalf("effects[%d].obj path: got %q want s3://bucket/data.csv", idx, objs[0].Path)
		}
	}
}

func TestRedshiftFirstKeyword_UnloadNoToClause(t *testing.T) {
	// UNLOAD without a TO clause still classifies (path will be empty).
	sql := "unload ('select 1')"
	cs, ok := redshiftFirstKeyword(sql, effects.ParserBackendPureGo)
	if !ok {
		t.Fatalf("expected ok=true for UNLOAD without TO")
	}
	if cs.RawVerb != "UNLOAD" {
		t.Fatalf("RawVerb: got %q", cs.RawVerb)
	}
	// Find the bulk_export effect — its single object's Path should be empty.
	var found bool
	for _, e := range cs.Effects {
		if e.Group == effects.GroupBulkExport {
			found = true
			if len(e.Objects) != 1 || e.Objects[0].Path != "" {
				t.Fatalf("bulk_export object: got %+v want single empty-path filesystem_path", e.Objects)
			}
		}
	}
	if !found {
		t.Fatal("missing bulk_export effect")
	}
}

func TestRedshiftFirstKeyword_CopyFromS3(t *testing.T) {
	sql := "COPY events FROM 's3://logs/events.json' IAM_ROLE 'arn:aws:iam::123:role/redshift'"
	cs, ok := redshiftFirstKeyword(sql, effects.ParserBackendLibPgQuery)
	if !ok {
		t.Fatalf("expected ok=true for COPY FROM s3")
	}
	if cs.RawVerb != "COPY_FROM_S3" {
		t.Fatalf("RawVerb: got %q want COPY_FROM_S3", cs.RawVerb)
	}
	if len(cs.Effects) != 1 {
		t.Fatalf("effect count: got %d want 1", len(cs.Effects))
	}
	e := cs.Effects[0]
	if e.Group != effects.GroupBulkLoad {
		t.Fatalf("group: got %v want bulk_load", e.Group)
	}
	if e.Subtype != effects.SubtypeCopyFromS3 {
		t.Fatalf("subtype: got %v want copy_from_s3", e.Subtype)
	}
	if len(e.Objects) != 2 {
		t.Fatalf("object count: got %d want 2", len(e.Objects))
	}
	if e.Objects[0].Kind != effects.ObjectTable || e.Objects[0].Name != "events" {
		t.Fatalf("objects[0]: got %+v want table/events", e.Objects[0])
	}
	if e.Objects[1].Kind != effects.ObjectFilesystemPath || e.Objects[1].Path != "s3://logs/events.json" {
		t.Fatalf("objects[1]: got %+v want filesystem_path/s3://logs/events.json", e.Objects[1])
	}
}

func TestRedshiftFirstKeyword_CopyFromS3LowercasesTable(t *testing.T) {
	sql := "COPY MySchema.Events FROM 's3://b/k' IAM_ROLE 'r'"
	cs, ok := redshiftFirstKeyword(sql, effects.ParserBackendLibPgQuery)
	if !ok {
		t.Fatalf("expected ok=true")
	}
	got := cs.Effects[0].Objects[0].Name
	if got != "myschema.events" {
		t.Fatalf("table name: got %q want myschema.events (lowercased)", got)
	}
}

func TestRedshiftFirstKeyword_Unknown(t *testing.T) {
	cases := []string{
		"WUT IS THIS",
		"",
		"   ",
		"SELECT 1",                              // valid pg syntax — never reaches the fallback in practice, but it's not Redshift-specific so fallback returns false
		"COPY events FROM 'localfile.csv'",      // not s3://
		"COPY events TO 's3://bucket/key'",      // not FROM
		"UNLOADX ('select 1') to 's3://x/y'",    // not exactly UNLOAD
	}
	for _, sql := range cases {
		if _, ok := redshiftFirstKeyword(sql, effects.ParserBackendLibPgQuery); ok {
			t.Errorf("expected ok=false for %q", sql)
		}
	}
}
