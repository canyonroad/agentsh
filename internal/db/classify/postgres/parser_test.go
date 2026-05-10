package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestNew_ReturnsParserPerDialect(t *testing.T) {
	for _, d := range []Dialect{DialectPostgres, DialectAuroraPostgres, DialectCockroachDB, DialectRedshift} {
		p := New(d)
		if p == nil {
			t.Fatalf("New(%v) returned nil", d)
		}
	}
}

func TestNew_PanicsOnUnknownDialect(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on unknown dialect")
		}
	}()
	New(Dialect(99))
}

func TestApplyStatement_NoOpOnEmptyEffects(t *testing.T) {
	in := SessionState{SearchPath: []string{"public"}}
	got := ApplyStatement(in, effects.ClassifiedStatement{})
	if len(got.SearchPath) != 1 || got.SearchPath[0] != "public" {
		t.Fatalf("ApplyStatement mutated state on empty input: %+v", got)
	}
}
