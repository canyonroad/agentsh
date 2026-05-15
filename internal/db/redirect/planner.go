package redirect

import pg_query "github.com/pganalyze/pg_query_go/v6"

func (p Planner) Plan(in Input) (Plan, error) {
	if err := validateInput(in); err != nil {
		return Plan{}, err
	}
	if p.Backend == nil {
		return Plan{}, reject(ReasonUnsupportedStatement, nil)
	}

	tree, err := p.Backend.Parse(in.SQL)
	if err != nil {
		return Plan{}, reject(ReasonUnsupportedStatement, err)
	}
	if tree == nil || len(tree.Stmts) != 1 {
		return Plan{}, reject(ReasonMultiStatement, nil)
	}

	selectStmt, err := singleSelect(tree)
	if err != nil {
		return Plan{}, err
	}
	if selectStmt.IntoClause != nil {
		return Plan{}, reject(ReasonDDLStatement, nil)
	}
	if len(selectStmt.LockingClause) > 0 {
		return Plan{}, reject(ReasonUnsupportedStatement, nil)
	}
	return Plan{}, reject(ReasonSourceNotFound, nil)
}

func singleSelect(tree *pg_query.ParseResult) (*pg_query.SelectStmt, error) {
	raw := tree.Stmts[0]
	if raw == nil || raw.Stmt == nil || raw.Stmt.Node == nil {
		return nil, reject(ReasonUnsupportedStatement, nil)
	}
	node, ok := raw.Stmt.Node.(*pg_query.Node_SelectStmt)
	if !ok || node.SelectStmt == nil {
		return nil, reject(ReasonNonSelectStatement, nil)
	}
	return node.SelectStmt, nil
}
