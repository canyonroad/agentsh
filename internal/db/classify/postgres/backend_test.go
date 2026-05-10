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
