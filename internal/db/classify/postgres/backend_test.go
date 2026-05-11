package postgres

import (
	"strings"
	"testing"
)

func TestBackend_ParsesSimpleSelect(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("SELECT 1", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	if got[0].Error != "" {
		t.Fatalf("unexpected Error: %q", got[0].Error)
	}
}

func TestBackend_ParseFailureProducesUnknown(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("SELECT FROM WHERE", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify returned err for SQL-level failure: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 statement on parse failure, got %d", len(got))
	}
	if !strings.HasPrefix(got[0].Error, "parse:") {
		t.Fatalf("Error = %q, want prefix \"parse:\"", got[0].Error)
	}
}

func TestBackend_EmptyInputReturnsEmpty(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("   \n\t  ", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty SQL should produce no statements, got %d", len(got))
	}
}

func TestParser_SourceSpan_Single(t *testing.T) {
	p := New(DialectPostgres)
	sql := "SELECT 1"
	got, err := p.Classify(sql, SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d want 1", len(got))
	}
	if got[0].SourceStart != 0 {
		t.Fatalf("SourceStart=%d want 0", got[0].SourceStart)
	}
	if got[0].SourceEnd != int32(len(sql)) {
		t.Fatalf("SourceEnd=%d want %d", got[0].SourceEnd, len(sql))
	}
}

func TestParser_SourceSpan_MultiStmt(t *testing.T) {
	p := New(DialectPostgres)
	sql := "SELECT 1; SELECT 2"
	got, err := p.Classify(sql, SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d want 2", len(got))
	}
	if string(sql[got[0].SourceStart:got[0].SourceEnd]) != "SELECT 1" {
		t.Fatalf("stmt[0] span = %q want %q",
			string(sql[got[0].SourceStart:got[0].SourceEnd]), "SELECT 1")
	}
	if string(sql[got[1].SourceStart:got[1].SourceEnd]) != "SELECT 2" {
		t.Fatalf("stmt[1] span = %q want %q",
			string(sql[got[1].SourceStart:got[1].SourceEnd]), "SELECT 2")
	}
}

func TestParser_SourceSpan_TrailingStmtNoSemicolon(t *testing.T) {
	// Single statement with no trailing semicolon — libpg_query reports
	// StmtLen=0 for trailing single statements; classifyWithBackend must
	// extend SourceEnd to len(sql).
	p := New(DialectPostgres)
	sql := "SELECT 1"
	got, err := p.Classify(sql, SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d want 1", len(got))
	}
	if got[0].SourceEnd != int32(len(sql)) {
		t.Fatalf("SourceEnd=%d want %d (StmtLen=0 must extend to end)",
			got[0].SourceEnd, len(sql))
	}
	if got[0].SourceStart != 0 {
		t.Fatalf("SourceStart=%d want 0", got[0].SourceStart)
	}
}
