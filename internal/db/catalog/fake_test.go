package catalog

import (
	"context"
	"fmt"
	"strings"
)

type fakeQueryer struct {
	relations [][]any
	columns   [][]any
	functions [][]any
}

func (q fakeQueryer) Query(_ context.Context, sql string, _ ...any) (Rows, error) {
	switch {
	case strings.Contains(sql, "pg_catalog.pg_attribute"):
		return &fakeRows{rows: q.columns}, nil
	case strings.Contains(sql, "pg_catalog.pg_class"):
		return &fakeRows{rows: q.relations}, nil
	case strings.Contains(sql, "pg_catalog.pg_proc"):
		return &fakeRows{rows: q.functions}, nil
	default:
		return nil, fmt.Errorf("unexpected query: %s", sql)
	}
}

type fakeRows struct {
	rows [][]any
	idx  int
}

func (r *fakeRows) Next() bool {
	return r.idx < len(r.rows)
}

func (r *fakeRows) Scan(dest ...any) error {
	if r.idx >= len(r.rows) {
		return fmt.Errorf("scan past end")
	}
	row := r.rows[r.idx]
	r.idx++
	if len(row) != len(dest) {
		return fmt.Errorf("scan got %d dests, want %d", len(dest), len(row))
	}
	for i := range row {
		switch d := dest[i].(type) {
		case *uint32:
			*d = row[i].(uint32)
		case *string:
			*d = row[i].(string)
		case *bool:
			*d = row[i].(bool)
		case *int:
			*d = row[i].(int)
		default:
			return fmt.Errorf("unsupported dest %T", dest[i])
		}
	}
	return nil
}

func (r *fakeRows) Close() error { return nil }
func (r *fakeRows) Err() error   { return nil }
