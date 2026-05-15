package redirect

import (
	"strings"

	"github.com/agentsh/agentsh/internal/db/effects"
	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func validateInput(in Input) error {
	target := strings.TrimSpace(in.Action.TargetRelation)
	if target == "" {
		return reject(ReasonMissingRedirectTarget, nil)
	}
	source := strings.TrimSpace(in.Action.SourceRelation)
	if source == "" {
		return reject(ReasonSourceNotFound, nil)
	}
	if len(in.Statement.Effects) == 0 {
		return reject(ReasonUnsupportedStatement, nil)
	}

	for _, eff := range in.Statement.Effects {
		if eff.Subtype == effects.SubtypeFunctionCallProtocol {
			return reject(ReasonFunctionCallProtocol, nil)
		}
	}

	for _, eff := range in.Statement.Effects {
		if eff.Group == effects.GroupRead {
			if eff.Resolution != effects.ResolutionCatalogResolved {
				return reject(ReasonUnresolvedObject, nil)
			}
			continue
		}
		if reason, ok := rejectionForNonReadEffect(eff.Group); ok {
			return reject(reason, nil)
		}
		return reject(ReasonUnsupportedStatement, nil)
	}

	if !sourceRelationExists(in.Statement, source) {
		return reject(ReasonSourceNotFound, nil)
	}

	for _, eff := range in.Statement.Effects {
		if eff.Group == effects.GroupRead && hasUnresolvedObject(eff.ResolvedObjects) {
			return reject(ReasonUnresolvedObject, nil)
		}
	}

	return nil
}

func sourceRelationExists(stmt effects.ClassifiedStatement, source string) bool {
	for _, eff := range stmt.Effects {
		for _, obj := range eff.ResolvedObjects {
			if obj.Source == effects.ResolvedObjectSourceCatalog &&
				obj.Kind == effects.ResolvedObjectRelation &&
				obj.UnresolvedReason == "" &&
				obj.CanonicalName() == source {
				return true
			}
		}
	}
	return false
}

func rejectionForNonReadEffect(group effects.Group) (Reason, bool) {
	switch group {
	case effects.GroupWrite, effects.GroupModify, effects.GroupDelete:
		return ReasonWriteStatement, true
	case effects.GroupSchemaCreate, effects.GroupSchemaAlter, effects.GroupSchemaDestroy, effects.GroupPrivilege:
		return ReasonDDLStatement, true
	case effects.GroupBulkLoad, effects.GroupBulkExport:
		return ReasonCopyStatement, true
	case effects.GroupProcedural, effects.GroupUnsafeIO:
		return ReasonProceduralStatement, true
	default:
		return "", false
	}
}

func hasUnresolvedObject(objects []effects.ResolvedObjectRef) bool {
	for _, obj := range objects {
		if obj.UnresolvedReason != "" {
			return true
		}
	}
	return false
}

type relationMetadata struct {
	qualified map[string]struct{}
	byName    map[string]map[string]struct{}
}

func validateSelectRelationMetadata(stmt *pg_query.SelectStmt, classified effects.ClassifiedStatement) error {
	return validateSelectRelationsCovered(stmt, collectRelationMetadata(classified), relationRewrite{})
}

func collectRelationMetadata(stmt effects.ClassifiedStatement) relationMetadata {
	metadata := relationMetadata{
		qualified: map[string]struct{}{},
		byName:    map[string]map[string]struct{}{},
	}
	for _, eff := range stmt.Effects {
		for _, obj := range eff.ResolvedObjects {
			if obj.Source != effects.ResolvedObjectSourceCatalog ||
				obj.Kind != effects.ResolvedObjectRelation ||
				obj.UnresolvedReason != "" {
				continue
			}
			canonical := obj.CanonicalName()
			metadata.qualified[canonical] = struct{}{}
			if _, ok := metadata.byName[obj.Name]; !ok {
				metadata.byName[obj.Name] = map[string]struct{}{}
			}
			metadata.byName[obj.Name][canonical] = struct{}{}
		}
	}
	return metadata
}

func validateSelectRelationsCovered(stmt *pg_query.SelectStmt, metadata relationMetadata, scope relationRewrite) error {
	if stmt == nil {
		return nil
	}

	if err := validateCTERelationMetadata(stmt.WithClause, metadata, scope); err != nil {
		return err
	}
	scoped := scope.withCTENames(stmt.WithClause)
	if err := validateRangeNodesCovered(stmt.FromClause, metadata, scoped); err != nil {
		return err
	}
	if err := validateSelectExpressionSubqueryRelationMetadata(stmt, metadata, scoped); err != nil {
		return err
	}
	if err := validateSelectRelationsCovered(stmt.Larg, metadata, scoped); err != nil {
		return err
	}
	return validateSelectRelationsCovered(stmt.Rarg, metadata, scoped)
}

func validateCTERelationMetadata(withClause *pg_query.WithClause, metadata relationMetadata, scope relationRewrite) error {
	if withClause == nil {
		return nil
	}

	bodyScope := scope
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
			return reject(ReasonWriteStatement, nil)
		}
		if err := validateSelectRelationsCovered(query.SelectStmt, metadata, bodyScope); err != nil {
			return err
		}
		bodyScope = bodyScope.withCTEName(cteNode.CommonTableExpr.Ctename)
	}
	return nil
}

func validateRangeNodesCovered(nodes []*pg_query.Node, metadata relationMetadata, scope relationRewrite) error {
	for _, node := range nodes {
		if err := validateRangeNodeCovered(node, metadata, scope); err != nil {
			return err
		}
	}
	return nil
}

func validateRangeNodeCovered(node *pg_query.Node, metadata relationMetadata, scope relationRewrite) error {
	if node == nil {
		return nil
	}

	switch n := node.Node.(type) {
	case *pg_query.Node_RangeVar:
		if n.RangeVar == nil {
			return reject(ReasonUnsupportedStatement, nil)
		}
		if rangeVarIsInScopeCTE(n.RangeVar, scope) {
			return nil
		}
		if !metadata.covers(n.RangeVar) {
			return reject(ReasonUnresolvedObject, nil)
		}
		return nil
	case *pg_query.Node_JoinExpr:
		if n.JoinExpr == nil || n.JoinExpr.Larg == nil || n.JoinExpr.Rarg == nil {
			return reject(ReasonUnsupportedStatement, nil)
		}
		if err := validateRangeNodeCovered(n.JoinExpr.Larg, metadata, scope); err != nil {
			return err
		}
		if err := validateRangeNodeCovered(n.JoinExpr.Rarg, metadata, scope); err != nil {
			return err
		}
		return validateExpressionSubqueryRelationMetadataInNode(n.JoinExpr.Quals, metadata, scope)
	case *pg_query.Node_RangeSubselect:
		if n.RangeSubselect == nil || n.RangeSubselect.Subquery == nil {
			return reject(ReasonUnsupportedStatement, nil)
		}
		subquery, ok := n.RangeSubselect.Subquery.Node.(*pg_query.Node_SelectStmt)
		if !ok || subquery.SelectStmt == nil {
			return reject(ReasonUnsupportedStatement, nil)
		}
		return validateSelectRelationsCovered(subquery.SelectStmt, metadata, scope)
	case *pg_query.Node_RangeTableSample:
		return reject(ReasonUnsupportedStatement, nil)
	case *pg_query.Node_RangeFunction:
		return reject(ReasonProceduralStatement, nil)
	case *pg_query.Node_RangeTableFunc:
		return reject(ReasonUnsupportedStatement, nil)
	default:
		return reject(ReasonUnsupportedStatement, nil)
	}
}

func (metadata relationMetadata) covers(rv *pg_query.RangeVar) bool {
	if rv == nil || rv.Catalogname != "" || rv.Relname == "" {
		return false
	}
	if rv.Schemaname != "" {
		_, ok := metadata.qualified[rv.Schemaname+"."+rv.Relname]
		return ok
	}
	return len(metadata.byName[rv.Relname]) == 1
}

func rangeVarIsInScopeCTE(rv *pg_query.RangeVar, scope relationRewrite) bool {
	if rv == nil || rv.Schemaname != "" || rv.Catalogname != "" {
		return false
	}
	_, ok := scope.cteNames[rv.Relname]
	return ok
}

func validateSelectExpressionSubqueryRelationMetadata(stmt *pg_query.SelectStmt, metadata relationMetadata, scope relationRewrite) error {
	if err := validateExpressionSubqueryRelationMetadataInNodes(stmt.DistinctClause, metadata, scope); err != nil {
		return err
	}
	for _, nodes := range [][]*pg_query.Node{
		stmt.TargetList,
		stmt.GroupClause,
		stmt.WindowClause,
		stmt.ValuesLists,
		stmt.SortClause,
	} {
		if err := validateExpressionSubqueryRelationMetadataInNodes(nodes, metadata, scope); err != nil {
			return err
		}
	}
	for _, node := range []*pg_query.Node{
		stmt.WhereClause,
		stmt.HavingClause,
		stmt.LimitOffset,
		stmt.LimitCount,
	} {
		if err := validateExpressionSubqueryRelationMetadataInNode(node, metadata, scope); err != nil {
			return err
		}
	}
	return nil
}

func validateExpressionSubqueryRelationMetadataInNodes(nodes []*pg_query.Node, metadata relationMetadata, scope relationRewrite) error {
	for _, node := range nodes {
		if err := validateExpressionSubqueryRelationMetadataInNode(node, metadata, scope); err != nil {
			return err
		}
	}
	return nil
}

func validateExpressionSubqueryRelationMetadataInNode(node *pg_query.Node, metadata relationMetadata, scope relationRewrite) error {
	if node == nil {
		return nil
	}
	return validateExpressionSubqueryRelationMetadataInMessage(node.ProtoReflect(), metadata, scope)
}

func validateExpressionSubqueryRelationMetadataInMessage(msg protoreflect.Message, metadata relationMetadata, scope relationRewrite) error {
	if !msg.IsValid() {
		return nil
	}
	if subLink, ok := msg.Interface().(*pg_query.SubLink); ok {
		return validateSubLinkRelationMetadata(subLink, metadata, scope)
	}

	var err error
	msg.Range(func(fd protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if fd.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if err = validateExpressionSubqueryRelationMetadataInValue(fd, list.Get(i), metadata, scope); err != nil {
					return false
				}
			}
			return true
		}
		err = validateExpressionSubqueryRelationMetadataInValue(fd, value, metadata, scope)
		return err == nil
	})
	return err
}

func validateExpressionSubqueryRelationMetadataInValue(fd protoreflect.FieldDescriptor, value protoreflect.Value, metadata relationMetadata, scope relationRewrite) error {
	if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
		return nil
	}
	return validateExpressionSubqueryRelationMetadataInMessage(value.Message(), metadata, scope)
}

func validateSubLinkRelationMetadata(subLink *pg_query.SubLink, metadata relationMetadata, scope relationRewrite) error {
	if subLink == nil {
		return nil
	}
	if err := validateExpressionSubqueryRelationMetadataInNode(subLink.Xpr, metadata, scope); err != nil {
		return err
	}
	if err := validateExpressionSubqueryRelationMetadataInNode(subLink.Testexpr, metadata, scope); err != nil {
		return err
	}
	if err := validateExpressionSubqueryRelationMetadataInNodes(subLink.OperName, metadata, scope); err != nil {
		return err
	}
	if subLink.Subselect == nil {
		return reject(ReasonUnsupportedStatement, nil)
	}
	subquery, ok := subLink.Subselect.Node.(*pg_query.Node_SelectStmt)
	if !ok || subquery.SelectStmt == nil {
		return reject(ReasonUnsupportedStatement, nil)
	}
	return validateSelectRelationsCovered(subquery.SelectStmt, metadata, scope)
}

func reject(reason Reason, err error) error {
	return Rejection{Reason: reason, Err: err}
}
