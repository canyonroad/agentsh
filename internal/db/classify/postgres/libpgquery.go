//go:build linux && cgo

package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func newParser(d Dialect) Parser {
	return &cgoParser{dialect: d}
}

type cgoParser struct {
	dialect Dialect
}

func (p *cgoParser) Classify(sql string, sess SessionState, opts Options) ([]effects.ClassifiedStatement, error) {
	return classifyWithBackend(p.dialect, sql, sess, opts, parseCGO, effects.ParserBackendLibPgQuery)
}

func parseCGO(sql string) (*pg_query.ParseResult, error) {
	return pg_query.Parse(sql)
}

// parseSQL is the package-internal dispatch to the active backend. Used by
// unit tests that need raw AST access; production code goes through
// classifyWithBackend.
func parseSQL(sql string) (*pg_query.ParseResult, error) {
	return parseCGO(sql)
}
