package redirect

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

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
	if isTopLevelUnsupportedSelectSurface(selectStmt) {
		return Plan{}, reject(ReasonUnsupportedStatement, nil)
	}
	if len(selectStmt.LockingClause) > 0 {
		return Plan{}, reject(ReasonUnsupportedStatement, nil)
	}
	if err := validateSelectRelationMetadata(selectStmt, in.Statement); err != nil {
		return Plan{}, err
	}

	sourceSchema, sourceName := splitRelation(in.Action.SourceRelation)
	targetSchema, targetName := splitRelation(in.Action.TargetRelation)
	if hasSchemaQualifiedSourceColumnRef(selectStmt, sourceSchema, sourceName) {
		return Plan{}, reject(ReasonUnsupportedStatement, nil)
	}
	count, err := rewriteSelectRelations(selectStmt, relationRewrite{
		sourceSchema: sourceSchema,
		sourceName:   sourceName,
		targetSchema: targetSchema,
		targetName:   targetName,
	})
	if err != nil {
		return Plan{}, err
	}
	switch {
	case count == 0:
		return Plan{}, reject(ReasonSourceNotFound, nil)
	case count > 1:
		return Plan{}, reject(ReasonAmbiguousRedirectSource, nil)
	}

	rewritten, err := p.Backend.Deparse(tree)
	if err != nil {
		return Plan{}, reject(ReasonDeparseFailed, err)
	}
	return Plan{
		RewrittenSQL:   rewritten,
		RuleName:       in.Action.RuleName,
		SourceRelation: in.Action.SourceRelation,
		TargetRelation: in.Action.TargetRelation,
	}, nil
}

func splitRelation(relation string) (string, string) {
	schema, name, ok := strings.Cut(strings.TrimSpace(relation), ".")
	if !ok {
		return "", strings.TrimSpace(relation)
	}
	return strings.TrimSpace(schema), strings.TrimSpace(name)
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

func isTopLevelUnsupportedSelectSurface(stmt *pg_query.SelectStmt) bool {
	return stmt != nil && len(stmt.ValuesLists) > 0
}
