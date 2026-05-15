// Package postgres classifies PostgreSQL-family SQL into effects.ClassifiedStatement
// per docs/agentsh-db-access-spec.md §7. The package exposes a Parser interface
// (one implementation per build-tag-selected backend) plus pure helpers for
// session-state evolution. No I/O, no goroutines.
package postgres

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	pg_query "github.com/pganalyze/pg_query_go/v6"

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
	// Normalize returns SQL with all literal values replaced by $N placeholders.
	// On parse failure returns the parser error verbatim; callers degrade to
	// the verbatim trimmed SQL for digest computation.
	Normalize(sql string) (string, error)
}

// RewriteBackend exposes parse/deparse primitives for SQL rewrite callers.
type RewriteBackend interface {
	Parse(sql string) (*pg_query.ParseResult, error)
	Deparse(tree *pg_query.ParseResult) (string, error)
	Backend() effects.ParserBackend
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

// NewRewriteBackend returns parse/deparse primitives for the given dialect,
// using the same build-tag-selected backend as New.
func NewRewriteBackend(d Dialect) RewriteBackend {
	if d.String() == "" {
		panic(fmt.Sprintf("postgres.NewRewriteBackend: unknown dialect %d", d))
	}
	return newRewriteBackend(d)
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

// classifyWithBackend is shared between libpgquery.go and wasm.go.
// It owns the dialect-aware error path (Redshift fallback) and the
// per-RawStmt dispatch loop.
func classifyWithBackend(
	dialect Dialect,
	sql string,
	sess SessionState,
	opts Options,
	parse func(string) (*pg_query.ParseResult, error),
	backend effects.ParserBackend,
) ([]effects.ClassifiedStatement, error) {
	if strings.TrimSpace(sql) == "" {
		return nil, nil
	}

	res, err := parse(sql)
	if err != nil {
		// SQL-level parse failure for postgres / aurora / cockroachdb:
		// produce a single unknown statement carrying the parser message.
		// Redshift dialect attempts the first-keyword fallback (Task 14).
		if dialect == DialectRedshift {
			if cs, ok := redshiftFirstKeyword(sql, backend); ok {
				return []effects.ClassifiedStatement{cs}, nil
			}
		}
		return []effects.ClassifiedStatement{
			unknownStatement(backend, "parse: "+err.Error()),
		}, nil
	}

	if res == nil || len(res.Stmts) == 0 {
		return nil, nil
	}

	out := make([]effects.ClassifiedStatement, 0, len(res.Stmts))
	for _, raw := range res.Stmts {
		cs := classifyRawStmt(dialect, raw, sess, opts, backend)
		// pg_query gives StmtLen=0 for a trailing single statement; in that
		// case the statement runs from StmtLocation to end-of-input.
		start := raw.StmtLocation
		length := raw.StmtLen
		var end int32
		if length == 0 {
			end = int32(len(sql))
		} else {
			end = start + length
		}
		// Skip leading whitespace to get the actual statement boundaries.
		// libpg_query's StmtLocation can point at a separator's trailing
		// whitespace in multi-statement input. Use utf8.DecodeRuneInString
		// so multi-byte whitespace (e.g. U+00A0) is handled correctly.
		for start < end {
			r, width := utf8.DecodeRuneInString(sql[int(start):])
			if !unicode.IsSpace(r) {
				break
			}
			start += int32(width)
		}
		cs.SourceStart = start
		cs.SourceEnd = end
		out = append(out, cs)
	}
	return out, nil
}

// unknownStatement returns the spec §7.8 unknown-classification value with the
// given message.
func unknownStatement(backend effects.ParserBackend, msg string) effects.ClassifiedStatement {
	return effects.ClassifiedStatement{
		Effects: []effects.Effect{{
			Group:      effects.GroupUnknown,
			Resolution: effects.ResolutionUnresolved,
		}},
		ParserBackend: backend,
		Error:         msg,
	}
}

// redshiftFirstKeyword is implemented in redshift.go.
