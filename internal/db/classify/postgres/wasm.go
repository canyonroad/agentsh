//go:build !linux || !cgo

package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"
	pgquery_wasm "github.com/wasilibs/go-pgquery"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func newParser(d Dialect) Parser {
	return &wasmParser{dialect: d}
}

func newRewriteBackend(d Dialect) RewriteBackend {
	return &wasmParser{dialect: d}
}

type wasmParser struct {
	dialect Dialect
}

func (p *wasmParser) Classify(sql string, sess SessionState, opts Options) ([]effects.ClassifiedStatement, error) {
	return classifyWithBackend(p.dialect, sql, sess, opts, parseWASM, effects.ParserBackendPureGo)
}

func (p *wasmParser) Parse(sql string) (*pg_query.ParseResult, error) {
	return parseWASM(sql)
}

func (p *wasmParser) Deparse(tree *pg_query.ParseResult) (string, error) {
	return pgquery_wasm.Deparse(tree)
}

func (p *wasmParser) Backend() effects.ParserBackend {
	return effects.ParserBackendPureGo
}

// parseWASM delegates to wasilibs/go-pgquery, which loads libpg_query into a
// wazero runtime. Its Parse signature returns the same *pg_query.ParseResult
// type from github.com/pganalyze/pg_query_go/v6 (the wasilibs package imports
// pganalyze for the protobuf types), so no shim is needed.
func parseWASM(sql string) (*pg_query.ParseResult, error) {
	return pgquery_wasm.Parse(sql)
}

// parseSQL is the package-internal dispatch to the active backend. Used by
// unit tests that need raw AST access; production code goes through
// classifyWithBackend.
func parseSQL(sql string) (*pg_query.ParseResult, error) {
	return parseWASM(sql)
}
