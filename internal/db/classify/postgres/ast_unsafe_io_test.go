package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// findEffect scans cs for the first effect with the given group/subtype.
// Returns the effect and a found flag.
func findEffect(cs effects.ClassifiedStatement, g effects.Group, sub effects.Subtype) (effects.Effect, bool) {
	for _, e := range cs.Effects {
		if e.Group == g && e.Subtype == sub {
			return e, true
		}
	}
	return effects.Effect{}, false
}

func TestUnsafeIO_PgReadFile_LiteralPath(t *testing.T) {
	cs := classifyOne(t, "SELECT pg_read_file('/etc/passwd')", SessionState{})
	prim, ok := cs.Primary()
	if !ok {
		t.Fatalf("no primary effect")
	}
	if prim.Group != effects.GroupUnsafeIO {
		t.Fatalf("primary group: got %v want unsafe_io", prim.Group)
	}
	if prim.Subtype != effects.SubtypeServerFileRead {
		t.Fatalf("primary subtype: got %v want server_file_read", prim.Subtype)
	}
	if len(prim.Objects) != 1 || prim.Objects[0].Kind != effects.ObjectFilesystemPath {
		t.Fatalf("primary objects: got %+v", prim.Objects)
	}
	if prim.Objects[0].Path != "/etc/passwd" {
		t.Fatalf("primary path: got %q want /etc/passwd", prim.Objects[0].Path)
	}
}

func TestUnsafeIO_PgReadBinaryFile(t *testing.T) {
	cs := classifyOne(t, "SELECT pg_read_binary_file('/etc/passwd')", SessionState{})
	if e, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeServerFileRead); !ok {
		t.Fatalf("expected unsafe_io/server_file_read effect; got %+v", cs.Effects)
	} else if len(e.Objects) != 1 || e.Objects[0].Path != "/etc/passwd" {
		t.Fatalf("objects: got %+v", e.Objects)
	}
}

func TestUnsafeIO_PgLsDir_LiteralPath(t *testing.T) {
	cs := classifyOne(t, "SELECT pg_ls_dir('/tmp')", SessionState{})
	if e, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeServerFileRead); !ok {
		t.Fatalf("expected unsafe_io/server_file_read effect; got %+v", cs.Effects)
	} else if e.Objects[0].Path != "/tmp" {
		t.Fatalf("path: got %q want /tmp", e.Objects[0].Path)
	}
}

func TestUnsafeIO_PgLsLogdir_NoArgs(t *testing.T) {
	cs := classifyOne(t, "SELECT pg_ls_logdir()", SessionState{})
	e, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeServerFileRead)
	if !ok {
		t.Fatalf("expected unsafe_io effect; got %+v", cs.Effects)
	}
	if len(e.Objects) != 1 || e.Objects[0].Path != "" {
		t.Fatalf("objects: want one empty filesystem_path got %+v", e.Objects)
	}
}

func TestUnsafeIO_PgStatFile(t *testing.T) {
	cs := classifyOne(t, "SELECT pg_stat_file('/etc/hosts')", SessionState{})
	if e, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeServerFileRead); !ok {
		t.Fatalf("missing effect; got %+v", cs.Effects)
	} else if e.Objects[0].Path != "/etc/hosts" {
		t.Fatalf("path: got %q", e.Objects[0].Path)
	}
}

func TestUnsafeIO_LoImport_FirstArgPath(t *testing.T) {
	cs := classifyOne(t, "SELECT lo_import('/var/lib/foo')", SessionState{})
	e, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeLargeObjectIO)
	if !ok {
		t.Fatalf("missing effect; got %+v", cs.Effects)
	}
	if e.Objects[0].Path != "/var/lib/foo" {
		t.Fatalf("path: got %q", e.Objects[0].Path)
	}
}

func TestUnsafeIO_LoExport_SecondArgIsPath(t *testing.T) {
	cs := classifyOne(t, "SELECT lo_export(12345, '/tmp/out')", SessionState{})
	e, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeLargeObjectIO)
	if !ok {
		t.Fatalf("missing effect; got %+v", cs.Effects)
	}
	if e.Objects[0].Path != "/tmp/out" {
		t.Fatalf("path: got %q want /tmp/out", e.Objects[0].Path)
	}
}

func TestUnsafeIO_DblinkExec_EmptyPath(t *testing.T) {
	cs := classifyOne(t, "SELECT dblink_exec('host=remote dbname=db', 'INSERT INTO t VALUES (1)')", SessionState{})
	e, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeDblinkCall)
	if !ok {
		t.Fatalf("missing effect; got %+v", cs.Effects)
	}
	if len(e.Objects) != 1 || e.Objects[0].Kind != effects.ObjectFilesystemPath || e.Objects[0].Path != "" {
		t.Fatalf("expected one empty filesystem_path object; got %+v", e.Objects)
	}
}

func TestUnsafeIO_DynamicArgUnresolved(t *testing.T) {
	cs := classifyOne(t, "SELECT pg_read_file(file_col) FROM t", SessionState{})
	e, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeServerFileRead)
	if !ok {
		t.Fatalf("missing effect; got %+v", cs.Effects)
	}
	if e.Objects[0].Path != "" {
		t.Fatalf("path: got %q want empty", e.Objects[0].Path)
	}
	if e.Resolution != effects.ResolutionUnresolved {
		t.Fatalf("resolution: got %v want unresolved", e.Resolution)
	}
}

func TestUnsafeIO_SchemaQualifiedFunctionMatches(t *testing.T) {
	cs := classifyOne(t, "SELECT public.pg_read_file('/etc/passwd')", SessionState{})
	if _, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeServerFileRead); !ok {
		t.Fatalf("schema-qualified call should match; got %+v", cs.Effects)
	}
}

func TestUnsafeIO_NotMatchedOnColumnReference(t *testing.T) {
	// "pg_read_file" appearing as a column reference (no parens) must NOT
	// fire — we match FuncCall AST nodes only.
	cs := classifyOne(t, "SELECT pg_read_file FROM t", SessionState{})
	if _, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeServerFileRead); ok {
		t.Fatalf("column ref must not produce unsafe_io effect; got %+v", cs.Effects)
	}
}

func TestUnsafeIO_CallInWhereClause(t *testing.T) {
	cs := classifyOne(t, "SELECT 1 FROM t WHERE pg_read_file('/etc/passwd') IS NOT NULL", SessionState{})
	if _, ok := findEffect(cs, effects.GroupUnsafeIO, effects.SubtypeServerFileRead); !ok {
		t.Fatalf("WHERE-clause call must be detected; got %+v", cs.Effects)
	}
}

func TestUnsafeIO_PrimaryWinsOverRead(t *testing.T) {
	cs := classifyOne(t, "SELECT pg_read_file('/etc/passwd')", SessionState{})
	prim, _ := cs.Primary()
	// unsafe_io (Critical) must outrank read (Low) after canonical ordering.
	if prim.Group != effects.GroupUnsafeIO {
		t.Fatalf("primary group: got %v want unsafe_io", prim.Group)
	}
}
