package postgres

import (
	"strings"
	"testing"
)

func TestParser_Normalize_Literals(t *testing.T) {
	p := New(DialectPostgres)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"int literal", "SELECT 1", "SELECT $1"},
		{"string literal", "SELECT 'hello'", "SELECT $1"},
		{"two literals", "SELECT 1, 'x'", "SELECT $1, $2"},
		{"identifier preserved", "SELECT a FROM t", "SELECT a FROM t"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p.Normalize(tc.in)
			if err != nil {
				t.Fatalf("Normalize(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Normalize(%q) = %q want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParser_Normalize_MultiStatement(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Normalize("SELECT 1; SELECT 'x'")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !strings.Contains(got, "$1") || !strings.Contains(got, "$2") {
		t.Fatalf("Normalize did not redact both literals: %q", got)
	}
}

func TestParser_Normalize_Error(t *testing.T) {
	p := New(DialectPostgres)
	_, err := p.Normalize("THIS IS NOT SQL ;;;")
	if err == nil {
		t.Fatalf("Normalize on malformed SQL: want err, got nil")
	}
}
