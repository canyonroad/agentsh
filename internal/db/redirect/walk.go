package redirect

import pg_query "github.com/pganalyze/pg_query_go/v6"

type relationRewrite struct {
	sourceSchema string
	sourceName   string
	targetSchema string
	targetName   string
}

func rewriteSelectRelations(stmt *pg_query.SelectStmt, rewrite relationRewrite) (int, error) {
	if stmt == nil {
		return 0, nil
	}

	count, err := rewriteRangeNodes(stmt.FromClause, rewrite)
	if err != nil {
		return 0, err
	}
	if stmt.Larg != nil {
		more, err := rewriteSelectRelations(stmt.Larg, rewrite)
		if err != nil {
			return 0, err
		}
		count += more
	}
	if stmt.Rarg != nil {
		more, err := rewriteSelectRelations(stmt.Rarg, rewrite)
		if err != nil {
			return 0, err
		}
		count += more
	}
	return count, nil
}

func rewriteRangeNodes(nodes []*pg_query.Node, rewrite relationRewrite) (int, error) {
	count := 0
	for _, node := range nodes {
		more, err := rewriteRangeNode(node, rewrite)
		if err != nil {
			return 0, err
		}
		count += more
	}
	return count, nil
}

func rewriteRangeNode(node *pg_query.Node, rewrite relationRewrite) (int, error) {
	if node == nil {
		return 0, nil
	}

	switch n := node.Node.(type) {
	case *pg_query.Node_RangeVar:
		if n.RangeVar == nil || !rangeVarMatches(n.RangeVar, rewrite.sourceSchema, rewrite.sourceName) {
			return 0, nil
		}
		n.RangeVar.Schemaname = rewrite.targetSchema
		n.RangeVar.Relname = rewrite.targetName
		return 1, nil
	case *pg_query.Node_JoinExpr:
		if n.JoinExpr == nil {
			return 0, nil
		}
		left, err := rewriteRangeNode(n.JoinExpr.Larg, rewrite)
		if err != nil {
			return 0, err
		}
		right, err := rewriteRangeNode(n.JoinExpr.Rarg, rewrite)
		if err != nil {
			return 0, err
		}
		return left + right, nil
	case *pg_query.Node_RangeSubselect:
		if n.RangeSubselect == nil || n.RangeSubselect.Subquery == nil {
			return 0, nil
		}
		subquery, ok := n.RangeSubselect.Subquery.Node.(*pg_query.Node_SelectStmt)
		if !ok || subquery.SelectStmt == nil {
			return 0, nil
		}
		return rewriteSelectRelations(subquery.SelectStmt, rewrite)
	case *pg_query.Node_RangeFunction:
		return 0, reject(ReasonProceduralStatement, nil)
	default:
		return 0, nil
	}
}

func rangeVarMatches(rv *pg_query.RangeVar, sourceSchema, sourceName string) bool {
	if rv.Schemaname != "" {
		return rv.Schemaname == sourceSchema && rv.Relname == sourceName
	}
	return rv.Relname == sourceName
}
