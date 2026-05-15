package redirect

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type relationRewrite struct {
	sourceSchema string
	sourceName   string
	targetSchema string
	targetName   string
	cteNames     map[string]struct{}
}

func rewriteSelectRelations(stmt *pg_query.SelectStmt, rewrite relationRewrite) (int, error) {
	if stmt == nil {
		return 0, nil
	}

	if stmt.IntoClause != nil {
		return 0, reject(ReasonDDLStatement, nil)
	}
	if len(stmt.LockingClause) > 0 {
		return 0, reject(ReasonUnsupportedStatement, nil)
	}
	if stmt.WithClause != nil && stmt.WithClause.Recursive {
		return 0, reject(ReasonUnsupportedStatement, nil)
	}

	count, err := rewriteCTEs(stmt.WithClause, rewrite)
	if err != nil {
		return 0, err
	}
	scopedRewrite := rewrite.withCTENames(stmt.WithClause)
	more, err := rewriteRangeNodes(stmt.FromClause, scopedRewrite)
	if err != nil {
		return 0, err
	}
	count += more
	more, err = rewriteSelectExpressionSubqueries(stmt, scopedRewrite)
	if err != nil {
		return 0, err
	}
	count += more
	if stmt.Larg != nil {
		more, err := rewriteSelectRelations(stmt.Larg, scopedRewrite)
		if err != nil {
			return 0, err
		}
		count += more
	}
	if stmt.Rarg != nil {
		more, err := rewriteSelectRelations(stmt.Rarg, scopedRewrite)
		if err != nil {
			return 0, err
		}
		count += more
	}
	return count, nil
}

func (rewrite relationRewrite) withCTENames(withClause *pg_query.WithClause) relationRewrite {
	if withClause == nil || len(withClause.Ctes) == 0 {
		return rewrite
	}

	scoped := rewrite
	copied := false
	for _, node := range withClause.Ctes {
		if node == nil {
			continue
		}
		cteNode, ok := node.Node.(*pg_query.Node_CommonTableExpr)
		if !ok || cteNode.CommonTableExpr == nil || cteNode.CommonTableExpr.Ctename == "" {
			continue
		}
		if !copied {
			scoped.cteNames = make(map[string]struct{}, len(rewrite.cteNames)+len(withClause.Ctes))
			for name := range rewrite.cteNames {
				scoped.cteNames[name] = struct{}{}
			}
			copied = true
		}
		scoped.cteNames[cteNode.CommonTableExpr.Ctename] = struct{}{}
	}
	return scoped
}

func rewriteSelectExpressionSubqueries(stmt *pg_query.SelectStmt, rewrite relationRewrite) (int, error) {
	count, err := rewriteExpressionSubqueriesInNodes(stmt.DistinctClause, rewrite)
	if err != nil {
		return 0, err
	}
	for _, nodes := range [][]*pg_query.Node{
		stmt.TargetList,
		stmt.GroupClause,
		stmt.WindowClause,
		stmt.ValuesLists,
		stmt.SortClause,
	} {
		more, err := rewriteExpressionSubqueriesInNodes(nodes, rewrite)
		if err != nil {
			return 0, err
		}
		count += more
	}
	for _, node := range []*pg_query.Node{
		stmt.WhereClause,
		stmt.HavingClause,
		stmt.LimitOffset,
		stmt.LimitCount,
	} {
		more, err := rewriteExpressionSubqueriesInNode(node, rewrite)
		if err != nil {
			return 0, err
		}
		count += more
	}
	return count, nil
}

func rewriteCTEs(withClause *pg_query.WithClause, rewrite relationRewrite) (int, error) {
	if withClause == nil {
		return 0, nil
	}

	count := 0
	for _, node := range withClause.Ctes {
		if node == nil {
			continue
		}
		cteNode, ok := node.Node.(*pg_query.Node_CommonTableExpr)
		if !ok || cteNode.CommonTableExpr == nil || cteNode.CommonTableExpr.Ctequery == nil {
			continue
		}
		query, ok := cteNode.CommonTableExpr.Ctequery.Node.(*pg_query.Node_SelectStmt)
		if !ok || query.SelectStmt == nil {
			return 0, reject(ReasonWriteStatement, nil)
		}
		more, err := rewriteSelectRelations(query.SelectStmt, rewrite)
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
		if n.RangeVar == nil || !rangeVarMatches(n.RangeVar, rewrite) {
			return 0, nil
		}
		if n.RangeVar.Alias == nil {
			n.RangeVar.Alias = &pg_query.Alias{Aliasname: n.RangeVar.Relname}
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
		quals, err := rewriteExpressionSubqueriesInNode(n.JoinExpr.Quals, rewrite)
		if err != nil {
			return 0, err
		}
		return left + right + quals, nil
	case *pg_query.Node_RangeSubselect:
		if n.RangeSubselect == nil || n.RangeSubselect.Subquery == nil {
			return 0, nil
		}
		subquery, ok := n.RangeSubselect.Subquery.Node.(*pg_query.Node_SelectStmt)
		if !ok || subquery.SelectStmt == nil {
			return 0, nil
		}
		return rewriteSelectRelations(subquery.SelectStmt, rewrite)
	case *pg_query.Node_RangeTableSample:
		return 0, reject(ReasonUnsupportedStatement, nil)
	case *pg_query.Node_RangeFunction:
		return 0, reject(ReasonProceduralStatement, nil)
	default:
		return 0, nil
	}
}

func rewriteExpressionSubqueriesInNodes(nodes []*pg_query.Node, rewrite relationRewrite) (int, error) {
	count := 0
	for _, node := range nodes {
		more, err := rewriteExpressionSubqueriesInNode(node, rewrite)
		if err != nil {
			return 0, err
		}
		count += more
	}
	return count, nil
}

func rewriteExpressionSubqueriesInNode(node *pg_query.Node, rewrite relationRewrite) (int, error) {
	if node == nil {
		return 0, nil
	}
	return rewriteExpressionSubqueriesInMessage(node.ProtoReflect(), rewrite)
}

func rewriteExpressionSubqueriesInMessage(msg protoreflect.Message, rewrite relationRewrite) (int, error) {
	if !msg.IsValid() {
		return 0, nil
	}
	if subLink, ok := msg.Interface().(*pg_query.SubLink); ok {
		return rewriteSubLink(subLink, rewrite)
	}

	count := 0
	var err error
	msg.Range(func(fd protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if fd.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				var more int
				more, err = rewriteExpressionSubqueriesInValue(fd, list.Get(i), rewrite)
				if err != nil {
					return false
				}
				count += more
			}
			return true
		}
		more, valueErr := rewriteExpressionSubqueriesInValue(fd, value, rewrite)
		if valueErr != nil {
			err = valueErr
			return false
		}
		count += more
		return true
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

func rewriteExpressionSubqueriesInValue(fd protoreflect.FieldDescriptor, value protoreflect.Value, rewrite relationRewrite) (int, error) {
	if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
		return 0, nil
	}
	return rewriteExpressionSubqueriesInMessage(value.Message(), rewrite)
}

func rewriteSubLink(subLink *pg_query.SubLink, rewrite relationRewrite) (int, error) {
	if subLink == nil {
		return 0, nil
	}

	count, err := rewriteExpressionSubqueriesInNode(subLink.Xpr, rewrite)
	if err != nil {
		return 0, err
	}
	more, err := rewriteExpressionSubqueriesInNode(subLink.Testexpr, rewrite)
	if err != nil {
		return 0, err
	}
	count += more
	more, err = rewriteExpressionSubqueriesInNodes(subLink.OperName, rewrite)
	if err != nil {
		return 0, err
	}
	count += more

	if subLink.Subselect == nil {
		return 0, reject(ReasonUnsupportedStatement, nil)
	}
	subquery, ok := subLink.Subselect.Node.(*pg_query.Node_SelectStmt)
	if !ok || subquery.SelectStmt == nil {
		return 0, reject(ReasonUnsupportedStatement, nil)
	}
	more, err = rewriteSelectRelations(subquery.SelectStmt, rewrite)
	if err != nil {
		return 0, err
	}
	count += more
	return count, nil
}

func rangeVarMatches(rv *pg_query.RangeVar, rewrite relationRewrite) bool {
	if rv.Schemaname != "" {
		return rv.Schemaname == rewrite.sourceSchema && rv.Relname == rewrite.sourceName
	}
	if _, ok := rewrite.cteNames[rv.Relname]; ok {
		return false
	}
	return rv.Relname == rewrite.sourceName
}

func hasSchemaQualifiedSourceColumnRef(stmt *pg_query.SelectStmt, sourceSchema, sourceName string) bool {
	if stmt == nil || sourceSchema == "" || sourceName == "" {
		return false
	}
	return hasSchemaQualifiedSourceColumnRefMessage(stmt.ProtoReflect(), sourceSchema, sourceName)
}

func hasSchemaQualifiedSourceColumnRefMessage(msg protoreflect.Message, sourceSchema, sourceName string) bool {
	if !msg.IsValid() {
		return false
	}
	if columnRef, ok := msg.Interface().(*pg_query.ColumnRef); ok {
		return columnRefMatchesSourceRelation(columnRef, sourceSchema, sourceName)
	}

	found := false
	msg.Range(func(fd protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if fd.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if hasSchemaQualifiedSourceColumnRefValue(fd, list.Get(i), sourceSchema, sourceName) {
					found = true
					return false
				}
			}
			return true
		}
		found = hasSchemaQualifiedSourceColumnRefValue(fd, value, sourceSchema, sourceName)
		return !found
	})
	return found
}

func hasSchemaQualifiedSourceColumnRefValue(fd protoreflect.FieldDescriptor, value protoreflect.Value, sourceSchema, sourceName string) bool {
	if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
		return false
	}
	return hasSchemaQualifiedSourceColumnRefMessage(value.Message(), sourceSchema, sourceName)
}

func columnRefMatchesSourceRelation(columnRef *pg_query.ColumnRef, sourceSchema, sourceName string) bool {
	if columnRef == nil || len(columnRef.Fields) < 3 {
		return false
	}
	schema, ok := columnRefString(columnRef.Fields[0])
	if !ok || schema != sourceSchema {
		return false
	}
	name, ok := columnRefString(columnRef.Fields[1])
	return ok && name == sourceName
}

func columnRefString(node *pg_query.Node) (string, bool) {
	if node == nil {
		return "", false
	}
	str, ok := node.Node.(*pg_query.Node_String_)
	if !ok || str.String_ == nil {
		return "", false
	}
	return str.String_.Sval, true
}
