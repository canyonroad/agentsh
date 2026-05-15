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

	count, err := rewriteCTEs(stmt.WithClause, rewrite)
	if err != nil {
		return 0, err
	}
	more, err := rewriteRangeNodes(stmt.FromClause, rewrite)
	if err != nil {
		return 0, err
	}
	count += more
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
		if n.RangeVar == nil || !rangeVarMatches(n.RangeVar, rewrite.sourceSchema, rewrite.sourceName) {
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
