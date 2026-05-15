package redirect

import (
	"strings"

	"github.com/agentsh/agentsh/internal/db/effects"
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
		switch eff.Group {
		case effects.GroupRead:
			if eff.Resolution != effects.ResolutionCatalogResolved {
				return reject(ReasonUnresolvedObject, nil)
			}
		case effects.GroupWrite, effects.GroupModify, effects.GroupDelete:
			return reject(ReasonWriteStatement, nil)
		case effects.GroupSchemaCreate, effects.GroupSchemaAlter, effects.GroupSchemaDestroy, effects.GroupPrivilege:
			return reject(ReasonDDLStatement, nil)
		case effects.GroupBulkLoad, effects.GroupBulkExport:
			return reject(ReasonCopyStatement, nil)
		case effects.GroupProcedural, effects.GroupUnsafeIO:
			return reject(ReasonProceduralStatement, nil)
		default:
			return reject(ReasonUnsupportedStatement, nil)
		}
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

func hasUnresolvedObject(objects []effects.ResolvedObjectRef) bool {
	for _, obj := range objects {
		if obj.UnresolvedReason != "" {
			return true
		}
	}
	return false
}

func reject(reason Reason, err error) error {
	return Rejection{Reason: reason, Err: err}
}
