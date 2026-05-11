//go:build linux && cgo

package postgres

import pg_query "github.com/pganalyze/pg_query_go/v6"

func (p *cgoParser) Normalize(sql string) (string, error) {
	return pg_query.Normalize(sql)
}
