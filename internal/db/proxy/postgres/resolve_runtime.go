//go:build linux

package postgres

import (
	"strings"

	"github.com/agentsh/agentsh/internal/db/catalog"
	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
)

const catalogSessionStateChangedReason = "session_state_changed"

func resolveStatementCatalog(stmt effects.ClassifiedStatement, ctx catalogRuntimeContext) effects.ClassifiedStatement {
	out := stmt
	out.Effects = make([]effects.Effect, len(stmt.Effects))
	for i, eff := range stmt.Effects {
		out.Effects[i] = resolveEffectCatalog(eff, ctx)
	}
	return out
}

func resolveStatementsCatalog(stmts []effects.ClassifiedStatement, ctx catalogRuntimeContext) []effects.ClassifiedStatement {
	out := make([]effects.ClassifiedStatement, len(stmts))
	current := ctx
	for i := range stmts {
		out[i] = resolveStatementCatalog(stmts[i], current)
		if statementInvalidatesCatalogContext(stmts[i]) {
			current.UnavailableReason = catalogSessionStateChangedReason
			current.SearchPath = nil
		}
	}
	return out
}

func resolveEffectCatalog(eff effects.Effect, ctx catalogRuntimeContext) effects.Effect {
	out := eff
	out.ResolvedObjects = nil
	if len(eff.Objects) > 0 {
		hasRelationObject := hasCatalogRelationObject(eff.Objects)
		out.ResolvedObjects = make([]effects.ResolvedObjectRef, 0, len(eff.Objects))
		allResolved := true
		for _, obj := range eff.Objects {
			if hasRelationObject && !isCatalogRelationObject(obj.Kind) {
				continue
			}
			resolved := resolveObjectCatalog(obj, ctx)
			if resolved.UnresolvedReason != "" {
				allResolved = false
			}
			out.ResolvedObjects = append(out.ResolvedObjects, resolved)
		}
		if len(out.ResolvedObjects) > 0 {
			if ctx.UnavailableReason != "" {
				out.Resolution = effects.ResolutionCatalogUnavailable
			} else if allResolved {
				out.Resolution = effects.ResolutionCatalogResolved
			} else {
				out.Resolution = effects.ResolutionCatalogUnresolved
			}
		}
	}
	if eff.FunctionOID != nil {
		resolved := resolveFunctionOIDCatalog(*eff.FunctionOID, ctx)
		out.ResolvedObjects = append(out.ResolvedObjects, resolved)
		if ctx.UnavailableReason != "" {
			out.Resolution = effects.ResolutionCatalogUnavailable
		} else if resolved.UnresolvedReason == "" {
			out.Resolution = effects.ResolutionCatalogResolved
		} else {
			out.Resolution = effects.ResolutionCatalogUnresolved
		}
	}
	return out
}

func hasCatalogRelationObject(objects []effects.ObjectRef) bool {
	for _, obj := range objects {
		if isCatalogRelationObject(obj.Kind) {
			return true
		}
	}
	return false
}

func resolveObjectCatalog(obj effects.ObjectRef, ctx catalogRuntimeContext) effects.ResolvedObjectRef {
	if !isCatalogRelationObject(obj.Kind) {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: "unsupported",
		}
	}
	if ctx.UnavailableReason != "" {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: ctx.UnavailableReason,
		}
	}
	res := catalog.ResolveRelation(ctx.Snapshot, catalog.Name{Schema: obj.Schema, Name: obj.Name}, ctx.SearchPath)
	if !res.OK() {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: res.Reason.String(),
		}
	}
	rel := res.Relation
	return effects.ResolvedObjectRef{
		Source:       effects.ResolvedObjectSourceCatalog,
		Kind:         effects.ResolvedObjectRelation,
		OID:          uint32(rel.OID),
		Schema:       rel.Name.Schema,
		Name:         rel.Name.Name,
		RelationKind: rel.Kind.String(),
	}
}

func isCatalogRelationObject(kind effects.ObjectKind) bool {
	switch kind {
	case effects.ObjectTable, effects.ObjectView, effects.ObjectSequence:
		return true
	default:
		return false
	}
}

func resolveFunctionOIDCatalog(oid int32, ctx catalogRuntimeContext) effects.ResolvedObjectRef {
	if ctx.UnavailableReason != "" {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectFunction,
			OID:              uint32(oid),
			UnresolvedReason: ctx.UnavailableReason,
		}
	}
	res := catalog.ResolveFunctionByOID(ctx.Snapshot, catalog.OID(uint32(oid)))
	if !res.OK() {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectFunction,
			OID:              uint32(oid),
			UnresolvedReason: res.Reason.String(),
		}
	}
	fn := res.Function
	return effects.ResolvedObjectRef{
		Source:               effects.ResolvedObjectSourceCatalog,
		Kind:                 effects.ResolvedObjectFunction,
		OID:                  uint32(fn.OID),
		Schema:               fn.Name.Schema,
		Name:                 fn.Name.Name,
		FunctionIdentityArgs: fn.IdentityArgs,
		FunctionVolatility:   functionVolatilityString(fn.Volatility),
	}
}

func functionVolatilityString(v catalog.FunctionVolatility) string {
	switch v {
	case catalog.VolatilityImmutable:
		return "immutable"
	case catalog.VolatilityStable:
		return "stable"
	case catalog.VolatilityVolatile:
		return "volatile"
	default:
		return ""
	}
}

func statementInvalidatesCatalogContext(stmt effects.ClassifiedStatement) bool {
	for _, eff := range stmt.Effects {
		if effectInvalidatesCatalogContext(eff, stmt.RawVerb) {
			return true
		}
	}
	return false
}

func statementsNeedCatalogRefresh(stmts []effects.ClassifiedStatement) (searchPath bool, snapshot bool) {
	for _, stmt := range stmts {
		for _, eff := range stmt.Effects {
			needSearchPath, needSnapshot := effectCatalogRefreshNeeds(eff, stmt.RawVerb)
			searchPath = searchPath || needSearchPath
			snapshot = snapshot || needSnapshot
		}
	}
	return searchPath, snapshot
}

func effectInvalidatesCatalogContext(eff effects.Effect, rawVerb string) bool {
	searchPath, snapshot := effectCatalogRefreshNeeds(eff, rawVerb)
	return searchPath || snapshot
}

func effectCatalogRefreshNeeds(eff effects.Effect, rawVerb string) (searchPath bool, snapshot bool) {
	switch eff.Subtype {
	case effects.SubtypeSetSearchPath,
		effects.SubtypeResetAll,
		effects.SubtypeDiscardAll,
		effects.SubtypeSetRole,
		effects.SubtypeSetSessionAuthorization:
		return true, false
	case effects.SubtypeSetLocal:
		if effectHasAnyGUC(eff, "search_path", "role", "session_authorization") {
			return true, false
		}
	case effects.SubtypeReset:
		if effectHasAnyGUC(eff, "search_path", "role", "session_authorization") {
			return true, false
		}
	case effects.SubtypeDiscardTemp:
		return true, true
	case effects.SubtypeCreateTable:
		if strings.Contains(rawVerb, "TEMP") {
			return true, true
		}
		return false, true
	case effects.SubtypeCreateIndex,
		effects.SubtypeCreateView,
		effects.SubtypeCreateSchema,
		effects.SubtypeCreateFunction,
		effects.SubtypeCreateMaterializedView,
		effects.SubtypeCreateExtension,
		effects.SubtypeDropTable,
		effects.SubtypeDropSchema,
		effects.SubtypeDropIndex,
		effects.SubtypeDropView,
		effects.SubtypeDropFunction:
		return false, true
	}
	if eff.Group == effects.GroupTransaction && transactionCanRestoreLocalSearchPath(rawVerb) {
		return true, false
	}
	return false, false
}

func transactionCanRestoreLocalSearchPath(rawVerb string) bool {
	switch rawVerb {
	case "COMMIT", "ROLLBACK", "ROLLBACK_TO", "END":
		return true
	default:
		return false
	}
}

func effectHasGUC(eff effects.Effect, name string) bool {
	for _, obj := range eff.Objects {
		if obj.Kind == effects.ObjectGUC && strings.EqualFold(obj.Name, name) {
			return true
		}
	}
	return false
}

func effectHasAnyGUC(eff effects.Effect, names ...string) bool {
	for _, name := range names {
		if effectHasGUC(eff, name) {
			return true
		}
	}
	return false
}

type resolvingParser struct {
	base classify_pg.Parser
	ctx  catalogRuntimeContext
}

func (p resolvingParser) Classify(sql string, sess classify_pg.SessionState, opts classify_pg.Options) ([]effects.ClassifiedStatement, error) {
	stmts, err := p.base.Classify(sql, sess, opts)
	if err != nil {
		return stmts, err
	}
	return resolveStatementsCatalog(stmts, p.ctx), err
}

func (p resolvingParser) Normalize(sql string) (string, error) {
	return p.base.Normalize(sql)
}

func (pc *proxyConn) resolvingParser(dialect string) classify_pg.Parser {
	return resolvingParser{base: pc.srv.classifierFor(dialect), ctx: pc.state.catalog}
}
