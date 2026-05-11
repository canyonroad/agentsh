//go:build !linux || !cgo

package postgres

import pgquery_wasm "github.com/wasilibs/go-pgquery"

func (p *wasmParser) Normalize(sql string) (string, error) {
	return pgquery_wasm.Normalize(sql)
}
