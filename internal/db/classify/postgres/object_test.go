package postgres

import (
	"testing"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// firstFromRelation pulls the first FROM-clause RangeVar out of a parsed
// SELECT statement. Returns nil if the parse tree's shape doesn't match.
func firstFromRelation(stmt *pg_query.Node) *pg_query.RangeVar {
	if stmt == nil || stmt.Node == nil {
		return nil
	}
	sel, ok := stmt.Node.(*pg_query.Node_SelectStmt)
	if !ok || sel.SelectStmt == nil {
		return nil
	}
	for _, n := range sel.SelectStmt.FromClause {
		if n == nil {
			continue
		}
		if rv, ok := n.Node.(*pg_query.Node_RangeVar); ok {
			return rv.RangeVar
		}
	}
	return nil
}

func TestExtractRelation_QualifiedAndUnqualified(t *testing.T) {
	cases := []struct {
		sql  string
		sess SessionState
		want effects.ObjectRef
		res  effects.Resolution
	}{
		{
			sql:  "SELECT * FROM public.users",
			sess: SessionState{},
			want: effects.ObjectRef{Kind: effects.ObjectTable, Schema: "public", Name: "users"},
			res:  effects.ResolutionQualified,
		},
		{
			sql:  "SELECT * FROM users",
			sess: SessionState{SearchPath: []string{"public"}, DefaultSearchPath: []string{"public"}},
			want: effects.ObjectRef{Kind: effects.ObjectTable, Name: "users"},
			res:  effects.ResolutionUnqualified,
		},
		{
			sql:  "SELECT * FROM users",
			sess: SessionState{SearchPath: []string{"app", "public"}, DefaultSearchPath: []string{"public"}},
			want: effects.ObjectRef{Kind: effects.ObjectTable, Name: "users"},
			res:  effects.ResolutionAmbiguousAfterSearchPath,
		},
		{
			sql:  "SELECT * FROM users",
			sess: SessionState{TempTables: map[string]struct{}{"users": {}}, DefaultSearchPath: []string{"public"}},
			want: effects.ObjectRef{Kind: effects.ObjectTable, Name: "users"},
			res:  effects.ResolutionMaybeTempShadowed,
		},
		{
			sql:  "SELECT * FROM users",
			sess: SessionState{},
			want: effects.ObjectRef{Kind: effects.ObjectTable, Name: "users"},
			res:  effects.ResolutionUnqualified,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.sql+"|"+tc.res.String(), func(t *testing.T) {
			res, err := parseSQL(tc.sql)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(res.Stmts) == 0 {
				t.Fatalf("no stmts parsed")
			}
			rel := firstFromRelation(res.Stmts[0].Stmt)
			if rel == nil {
				t.Fatalf("no relation found in %q", tc.sql)
			}
			obj, resn := extractRelation(rel, tc.sess, effects.ObjectTable)
			if obj.Kind != tc.want.Kind || obj.Schema != tc.want.Schema || obj.Name != tc.want.Name {
				t.Fatalf("ObjectRef mismatch: got %+v want %+v", obj, tc.want)
			}
			if resn != tc.res {
				t.Fatalf("Resolution: got %v want %v", resn, tc.res)
			}
		})
	}
}

func TestExtractRelation_NilRangeVar(t *testing.T) {
	obj, res := extractRelation(nil, SessionState{}, effects.ObjectTable)
	if obj.Kind != effects.ObjectTable {
		t.Fatalf("Kind: got %v want %v", obj.Kind, effects.ObjectTable)
	}
	if res != effects.ResolutionUnresolved {
		t.Fatalf("Resolution: got %v want %v", res, effects.ResolutionUnresolved)
	}
}

func TestEqualStringSlice(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{}, nil, true},
		{[]string{"a"}, []string{"a"}, true},
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a"}, []string{"b"}, false},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
		{[]string{"a"}, []string{"a", "b"}, false},
	}
	for _, tc := range cases {
		if got := equalStringSlice(tc.a, tc.b); got != tc.want {
			t.Fatalf("equalStringSlice(%v, %v) = %v; want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
