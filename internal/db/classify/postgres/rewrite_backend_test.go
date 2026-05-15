package postgres

import (
	"strings"
	"testing"
)

func TestRewriteBackend_ParseDeparse(t *testing.T) {
	backend := NewRewriteBackend(DialectPostgres)

	tree, err := backend.Parse("SELECT * FROM public.users")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	out, err := backend.Deparse(tree)
	if err != nil {
		t.Fatalf("Deparse() error = %v", err)
	}
	if !strings.Contains(strings.ToLower(out), "public.users") {
		t.Fatalf("Deparse() = %q, want public.users", out)
	}
	if backend.Backend().String() == "" {
		t.Fatal("Backend().String() is empty")
	}
}
