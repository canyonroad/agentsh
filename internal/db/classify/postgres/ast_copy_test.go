// Package postgres — ast_copy_test.go covers each COPY variant. Tests assert
// raw_verb, primary effect group/subtype, secondary effects, and the §20
// effect-set bypass case (COPY (DELETE ... RETURNING *) TO STDOUT).
package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestClassifyCopy_ToStdout(t *testing.T) {
	cs := classifyOne(t, "COPY users TO STDOUT", SessionState{})
	if cs.RawVerb != "COPY_TO_STDOUT" {
		t.Fatalf("RawVerb: got %q want COPY_TO_STDOUT", cs.RawVerb)
	}
	if cs.BulkOp != effects.BulkOpOut {
		t.Fatalf("BulkOp: got %v want BulkOpOut", cs.BulkOp)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d want 2: %+v", len(cs.Effects), cs.Effects)
	}
	if cs.Effects[0].Group != effects.GroupBulkExport ||
		cs.Effects[0].Subtype != effects.SubtypeCopyToStdout {
		t.Fatalf("primary: got %v/%v want bulk_export/copy_to_stdout",
			cs.Effects[0].Group, cs.Effects[0].Subtype)
	}
	if cs.Effects[1].Group != effects.GroupRead {
		t.Fatalf("secondary: got %v want read", cs.Effects[1].Group)
	}
	if len(cs.Effects[0].Objects) != 1 || cs.Effects[0].Objects[0].Name != "users" {
		t.Fatalf("primary objects: got %+v", cs.Effects[0].Objects)
	}
}

func TestClassifyCopy_FromStdin(t *testing.T) {
	cs := classifyOne(t, "COPY users FROM STDIN", SessionState{})
	if cs.RawVerb != "COPY_FROM_STDIN" {
		t.Fatalf("RawVerb: got %q want COPY_FROM_STDIN", cs.RawVerb)
	}
	if cs.BulkOp != effects.BulkOpIn {
		t.Fatalf("BulkOp: got %v want BulkOpIn", cs.BulkOp)
	}
	if len(cs.Effects) != 1 {
		t.Fatalf("effect count: got %d want 1", len(cs.Effects))
	}
	if cs.Effects[0].Group != effects.GroupBulkLoad ||
		cs.Effects[0].Subtype != effects.SubtypeCopyFromStdin {
		t.Fatalf("primary: got %v/%v want bulk_load/copy_from_stdin",
			cs.Effects[0].Group, cs.Effects[0].Subtype)
	}
	if len(cs.Effects[0].Objects) != 1 || cs.Effects[0].Objects[0].Name != "users" {
		t.Fatalf("primary objects: got %+v", cs.Effects[0].Objects)
	}
}

func TestClassifyCopy_ToPath(t *testing.T) {
	cs := classifyOne(t, "COPY users TO '/tmp/x.csv'", SessionState{})
	if cs.RawVerb != "COPY_TO_PATH" {
		t.Fatalf("RawVerb: got %q want COPY_TO_PATH", cs.RawVerb)
	}
	if cs.BulkOp != effects.BulkOpNone {
		t.Fatalf("BulkOp: got %v want BulkOpNone", cs.BulkOp)
	}
	if len(cs.Effects) != 3 {
		t.Fatalf("effect count: got %d want 3: %+v", len(cs.Effects), cs.Effects)
	}
	if cs.Effects[0].Group != effects.GroupUnsafeIO ||
		cs.Effects[0].Subtype != effects.SubtypeCopyToPath {
		t.Fatalf("primary: got %v/%v want unsafe_io/copy_to_path",
			cs.Effects[0].Group, cs.Effects[0].Subtype)
	}
	// Primary should have table + filesystem_path objects.
	if len(cs.Effects[0].Objects) != 2 {
		t.Fatalf("primary objects: got %+v want 2", cs.Effects[0].Objects)
	}
	if cs.Effects[0].Objects[0].Kind != effects.ObjectTable ||
		cs.Effects[0].Objects[0].Name != "users" {
		t.Fatalf("primary obj[0]: got %+v want table/users", cs.Effects[0].Objects[0])
	}
	if cs.Effects[0].Objects[1].Kind != effects.ObjectFilesystemPath ||
		cs.Effects[0].Objects[1].Path != "/tmp/x.csv" {
		t.Fatalf("primary obj[1]: got %+v want filesystem_path /tmp/x.csv", cs.Effects[0].Objects[1])
	}
	if cs.Effects[1].Group != effects.GroupBulkExport {
		t.Fatalf("secondary[0]: got %v want bulk_export", cs.Effects[1].Group)
	}
	if cs.Effects[2].Group != effects.GroupRead {
		t.Fatalf("secondary[1]: got %v want read", cs.Effects[2].Group)
	}
}

func TestClassifyCopy_FromPath(t *testing.T) {
	cs := classifyOne(t, "COPY users FROM '/tmp/x.csv'", SessionState{})
	if cs.RawVerb != "COPY_FROM_PATH" {
		t.Fatalf("RawVerb: got %q want COPY_FROM_PATH", cs.RawVerb)
	}
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d want 2: %+v", len(cs.Effects), cs.Effects)
	}
	if cs.Effects[0].Group != effects.GroupUnsafeIO ||
		cs.Effects[0].Subtype != effects.SubtypeCopyFromPath {
		t.Fatalf("primary: got %v/%v want unsafe_io/copy_from_path",
			cs.Effects[0].Group, cs.Effects[0].Subtype)
	}
	if len(cs.Effects[0].Objects) != 2 ||
		cs.Effects[0].Objects[1].Path != "/tmp/x.csv" {
		t.Fatalf("primary objects: got %+v", cs.Effects[0].Objects)
	}
	if cs.Effects[1].Group != effects.GroupBulkLoad {
		t.Fatalf("secondary: got %v want bulk_load", cs.Effects[1].Group)
	}
}

func TestClassifyCopy_ToProgram(t *testing.T) {
	cs := classifyOne(t, "COPY users TO PROGRAM 'gzip > /tmp/x.gz'", SessionState{})
	if cs.RawVerb != "COPY_TO_PROGRAM" {
		t.Fatalf("RawVerb: got %q want COPY_TO_PROGRAM", cs.RawVerb)
	}
	if len(cs.Effects) != 3 {
		t.Fatalf("effect count: got %d want 3: %+v", len(cs.Effects), cs.Effects)
	}
	if cs.Effects[0].Group != effects.GroupUnsafeIO ||
		cs.Effects[0].Subtype != effects.SubtypeCopyToProgram {
		t.Fatalf("primary: got %v/%v want unsafe_io/copy_to_program",
			cs.Effects[0].Group, cs.Effects[0].Subtype)
	}
	if len(cs.Effects[0].Objects) != 2 {
		t.Fatalf("primary objects: got %+v want 2", cs.Effects[0].Objects)
	}
	prog := cs.Effects[0].Objects[1]
	if prog.Kind != effects.ObjectProgram || prog.Argv0 != "gzip" {
		t.Fatalf("program object: got %+v want program/gzip", prog)
	}
	if prog.Path != "" {
		t.Fatalf("program object should leave Path empty, got %q", prog.Path)
	}
}

func TestClassifyCopy_FromProgram(t *testing.T) {
	cs := classifyOne(t, "COPY users FROM PROGRAM 'gunzip /tmp/x.gz'", SessionState{})
	if cs.RawVerb != "COPY_FROM_PROGRAM" {
		t.Fatalf("RawVerb: got %q want COPY_FROM_PROGRAM", cs.RawVerb)
	}
	if cs.BulkOp != effects.BulkOpNone {
		t.Fatalf("BulkOp: got %v want BulkOpNone", cs.BulkOp)
	}
	if cs.Effects[0].Group != effects.GroupUnsafeIO ||
		cs.Effects[0].Subtype != effects.SubtypeCopyFromProgram {
		t.Fatalf("primary: got %v/%v", cs.Effects[0].Group, cs.Effects[0].Subtype)
	}
	prog := cs.Effects[0].Objects[1]
	if prog.Kind != effects.ObjectProgram || prog.Argv0 != "gunzip" {
		t.Fatalf("program object: got %+v want program/gunzip", prog)
	}
	// Secondary is bulk_load only (FROM forms don't add a read effect).
	if len(cs.Effects) != 2 {
		t.Fatalf("effect count: got %d want 2", len(cs.Effects))
	}
	if cs.Effects[1].Group != effects.GroupBulkLoad {
		t.Fatalf("secondary: got %v want bulk_load", cs.Effects[1].Group)
	}
}

func TestClassifyCopy_QueryToStdout_Select(t *testing.T) {
	cs := classifyOne(t, "COPY (SELECT * FROM customers) TO STDOUT", SessionState{})
	if cs.RawVerb != "COPY_QUERY_TO_STDOUT" {
		t.Fatalf("RawVerb: got %q want COPY_QUERY_TO_STDOUT", cs.RawVerb)
	}
	if cs.BulkOp != effects.BulkOpOut {
		t.Fatalf("BulkOp: got %v want BulkOpOut", cs.BulkOp)
	}
	// Expect a bulk_export primary plus the inner SELECT's read effect.
	if cs.Effects[0].Group != effects.GroupBulkExport ||
		cs.Effects[0].Subtype != effects.SubtypeCopyToStdout {
		t.Fatalf("primary: got %v/%v want bulk_export/copy_to_stdout",
			cs.Effects[0].Group, cs.Effects[0].Subtype)
	}
	hasRead := false
	for _, e := range cs.Effects {
		if e.Group == effects.GroupRead {
			hasRead = true
			if len(e.Objects) != 1 || e.Objects[0].Name != "customers" {
				t.Fatalf("inner read objects: got %+v want [{customers}]", e.Objects)
			}
		}
	}
	if !hasRead {
		t.Fatalf("expected inner SELECT read effect; got %+v", cs.Effects)
	}
}

func TestClassifyCopy_QueryDeleteReturningToStdout(t *testing.T) {
	// §20 effect-set bypass case: bulk_export + delete + read.
	cs := classifyOne(t, "COPY (DELETE FROM users RETURNING *) TO STDOUT", SessionState{})
	if cs.RawVerb != "COPY_QUERY_TO_STDOUT" {
		t.Fatalf("RawVerb: got %q want COPY_QUERY_TO_STDOUT", cs.RawVerb)
	}
	// After canonical Order: bulk_export (Critical) → delete (High) → read (Low).
	if len(cs.Effects) != 3 {
		t.Fatalf("effect count: got %d want 3: %+v", len(cs.Effects), cs.Effects)
	}
	if cs.Effects[0].Group != effects.GroupBulkExport {
		t.Fatalf("effects[0]: got %v want bulk_export", cs.Effects[0].Group)
	}
	if cs.Effects[1].Group != effects.GroupDelete {
		t.Fatalf("effects[1]: got %v want delete", cs.Effects[1].Group)
	}
	if cs.Effects[2].Group != effects.GroupRead {
		t.Fatalf("effects[2]: got %v want read", cs.Effects[2].Group)
	}
}

func TestFirstWhitespaceToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"gzip > /tmp/x.gz", "gzip"},
		{"gunzip\t/tmp/x.gz", "gunzip"},
		{"cat\n/etc/passwd", "cat"},
		{"single", "single"},
		{"", ""},
	}
	for _, c := range cases {
		if got := firstWhitespaceToken(c.in); got != c.want {
			t.Errorf("firstWhitespaceToken(%q) = %q want %q", c.in, got, c.want)
		}
	}
}
