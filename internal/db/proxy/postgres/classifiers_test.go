//go:build linux

package postgres

import (
	"path/filepath"
	"testing"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
)

func TestBuildClassifierMap_PerDialect(t *testing.T) {
	svcs := []Service{
		{Name: "a", Family: "postgres", Dialect: "postgres", Listen: ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "a")}},
		{Name: "b", Family: "postgres", Dialect: "postgres", Listen: ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "b")}},
		{Name: "c", Family: "postgres", Dialect: "cockroachdb", Listen: ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "c")}},
	}
	m, err := buildClassifierMap(svcs)
	if err != nil {
		t.Fatalf("buildClassifierMap: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("map size = %d want 2 (postgres, cockroachdb)", len(m))
	}
	if m["postgres"] == nil || m["cockroachdb"] == nil {
		t.Fatalf("expected entries for both dialects, got %+v", m)
	}
}

func TestBuildClassifierMap_RejectsUnknown(t *testing.T) {
	_, err := buildClassifierMap([]Service{
		{Name: "x", Family: "postgres", Dialect: "rabbitql"},
	})
	if err == nil {
		t.Fatalf("expected error for unknown dialect, got nil")
	}
}

func TestServer_ClassifierFor_TestHookOverride(t *testing.T) {
	calls := 0
	hook := func(dialect string) classify_pg.Parser {
		calls++
		return classify_pg.New(classify_pg.DialectPostgres)
	}
	// Build a Server directly without going through New (avoiding the
	// fully-populated config requirement for this isolated test).
	s := &Server{cfg: Config{classifierForTest: hook}}
	_ = s.classifierFor("postgres")
	_ = s.classifierFor("anything")
	if calls != 2 {
		t.Fatalf("hook called %d times, want 2", calls)
	}
}

func TestServer_ClassifierFor_FallsBackWhenNoPostgresDialect(t *testing.T) {
	// Only register a cockroachdb parser. classifierFor("unknown") must not
	// panic and must return a non-nil parser.
	s := &Server{
		classifiers: map[string]classify_pg.Parser{
			"cockroachdb": classify_pg.New(classify_pg.DialectCockroachDB),
		},
	}
	got := s.classifierFor("postgres")
	if got == nil {
		t.Fatalf("classifierFor on missing dialect: want non-nil fallback parser")
	}
	// Sanity: the fallback parser must actually work.
	_, err := got.Classify("SELECT 1", classify_pg.SessionState{}, classify_pg.Options{})
	if err != nil {
		t.Fatalf("fallback parser cannot classify: %v", err)
	}
}
