// Package postgres classifies PostgreSQL-family SQL into effects.ClassifiedStatement
// per docs/agentsh-db-access-spec.md §7. The package exposes a Parser interface
// (one implementation per build-tag-selected backend) plus pure helpers for
// session-state evolution. No I/O, no goroutines.
package postgres

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// Dialect dispatches between Postgres-family parsers per spec §7.7.
type Dialect uint8

const (
	DialectPostgres Dialect = iota + 1
	DialectAuroraPostgres
	DialectCockroachDB
	DialectRedshift
)

func (d Dialect) String() string {
	switch d {
	case DialectPostgres:
		return "postgres"
	case DialectAuroraPostgres:
		return "aurora_postgres"
	case DialectCockroachDB:
		return "cockroachdb"
	case DialectRedshift:
		return "redshift"
	default:
		return ""
	}
}

// ParseDialect resolves the spec's lowercase dialect name. Returns ok=false on
// unknown input.
func ParseDialect(s string) (Dialect, bool) {
	switch s {
	case "postgres":
		return DialectPostgres, true
	case "aurora_postgres":
		return DialectAuroraPostgres, true
	case "cockroachdb":
		return DialectCockroachDB, true
	case "redshift":
		return DialectRedshift, true
	default:
		return 0, false
	}
}

// Options carries per-call tunables. Defaults are zero-valued and safe.
type Options struct {
	// EscalateUnknownFunctions toggles §7.6: when true, SELECT calling a
	// function NOT in SafeFunctionAllowlist classifies as procedural rather
	// than read.
	EscalateUnknownFunctions bool
	// SafeFunctionAllowlist is consulted only when EscalateUnknownFunctions
	// is true. Lookup is case-insensitive on the canonical lowercase name
	// (e.g. "now", "to_tsvector"). Schema-qualified names use "schema.name".
	SafeFunctionAllowlist map[string]struct{}
}

// SessionState is the per-connection state the classifier consults to assign
// resolution tags per §6.1. Owned by Plan 04+ proxies; the classifier reads it
// only — ApplyStatement (a free function) evolves it after upstream success.
type SessionState struct {
	SearchPath        []string            // lowercased identifiers, in order
	DefaultSearchPath []string            // restored by RESET search_path / DISCARD ALL
	TempTables        map[string]struct{} // unqualified names
	Role              string              // SET ROLE / SET SESSION AUTHORIZATION; "" = default
	DefaultRole       string
	InTransaction     bool // hint only; Plan 05 owns authoritative tx state
}

// Clone returns a deep copy of s — call this before applying mutations if the
// caller needs to retain the pre-mutation state (corpus harness uses this).
func (s SessionState) Clone() SessionState {
	cp := SessionState{
		SearchPath:        append([]string(nil), s.SearchPath...),
		DefaultSearchPath: append([]string(nil), s.DefaultSearchPath...),
		Role:              s.Role,
		DefaultRole:       s.DefaultRole,
		InTransaction:     s.InTransaction,
	}
	if len(s.TempTables) > 0 {
		cp.TempTables = make(map[string]struct{}, len(s.TempTables))
		for k := range s.TempTables {
			cp.TempTables[k] = struct{}{}
		}
	}
	return cp
}

// Parser is the single public surface. Implementations are returned by New.
type Parser interface {
	Classify(sql string, sess SessionState, opts Options) ([]effects.ClassifiedStatement, error)
}

// New returns the parser for the given dialect, using whichever libpg_query
// embedding the active build tag selected. Panics on unknown dialect; the
// dialect set is closed and a typo at construction time is a programmer error.
func New(d Dialect) Parser {
	if d.String() == "" {
		panic(fmt.Sprintf("postgres.New: unknown dialect %d", d))
	}
	return newParser(d)
}

// ApplyStatement evolves session state after the proxy has confirmed the
// statement succeeded upstream. Pure function; see ast_session.go for the
// per-statement rules.
func ApplyStatement(s SessionState, c effects.ClassifiedStatement) SessionState {
	if len(c.Effects) == 0 {
		return s
	}
	return applySession(s, c)
}

// Temporary stubs until Tasks 3 (backends) and Task 6 (session) ship.
// Both are removed/replaced when their owning tasks land.
func newParser(d Dialect) Parser {
	panic("not implemented: backend not yet wired (Task 3)")
}
func applySession(s SessionState, c effects.ClassifiedStatement) SessionState {
	return s
}
