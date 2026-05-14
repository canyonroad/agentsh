package policyexplain

import (
	"strings"

	"github.com/agentsh/agentsh/internal/db/catalog"
	"github.com/agentsh/agentsh/internal/db/effects"
)

const catalogSessionStateChangedReason = "session_state_changed"

type resolveContext struct {
	fixture                     CatalogFixture
	defaultSearchPath           []string
	snapshotUnavailableReason   string
	searchPathUnavailableReason string
	localSearchPathActive       bool
	localSearchPathBase         []string
}

func newResolveContext(fixture CatalogFixture) resolveContext {
	fixture.SearchPath = append([]string(nil), fixture.SearchPath...)
	return resolveContext{
		fixture:           fixture,
		defaultSearchPath: append([]string(nil), fixture.SearchPath...),
	}
}

func resolveStatements(stmts []effects.ClassifiedStatement, fixture CatalogFixture) []effects.ClassifiedStatement {
	out := make([]effects.ClassifiedStatement, len(stmts))
	current := newResolveContext(fixture)
	for i := range stmts {
		out[i] = resolveStatementWithContext(stmts[i], current)
		current = applyStatementCatalogContext(current, stmts[i])
	}
	return out
}

func resolveStatement(stmt effects.ClassifiedStatement, fixture CatalogFixture) effects.ClassifiedStatement {
	return resolveStatementWithContext(stmt, newResolveContext(fixture))
}

func resolveStatementWithContext(stmt effects.ClassifiedStatement, ctx resolveContext) effects.ClassifiedStatement {
	out := stmt
	out.Effects = make([]effects.Effect, len(stmt.Effects))
	for i, eff := range stmt.Effects {
		out.Effects[i] = resolveEffectWithContext(eff, ctx)
	}
	return out
}

func resolveEffect(eff effects.Effect, fixture CatalogFixture) effects.Effect {
	return resolveEffectWithContext(eff, newResolveContext(fixture))
}

func resolveEffectWithContext(eff effects.Effect, ctx resolveContext) effects.Effect {
	out := eff
	out.ResolvedObjects = nil
	resolved := make([]effects.ResolvedObjectRef, 0, len(eff.Objects)+1)
	allResolved := true
	hasUnavailable := false
	hasRelationObject := hasCatalogRelationObject(eff.Objects)
	for _, obj := range eff.Objects {
		if hasRelationObject && !isCatalogRelationObject(obj.Kind) {
			continue
		}
		ref := resolveObjectWithContext(obj, ctx)
		if ref.UnresolvedReason != "" {
			allResolved = false
			hasUnavailable = hasUnavailable || isCatalogUnavailableReason(ref.UnresolvedReason)
		}
		resolved = append(resolved, ref)
	}
	if eff.FunctionOID != nil {
		ref := resolveFunctionOIDWithContext(*eff.FunctionOID, ctx)
		if ref.UnresolvedReason != "" {
			allResolved = false
			hasUnavailable = hasUnavailable || isCatalogUnavailableReason(ref.UnresolvedReason)
		}
		resolved = append(resolved, ref)
	}
	if len(resolved) == 0 {
		return out
	}
	out.ResolvedObjects = resolved
	if hasUnavailable {
		out.Resolution = effects.ResolutionCatalogUnavailable
	} else if allResolved {
		out.Resolution = effects.ResolutionCatalogResolved
	} else {
		out.Resolution = effects.ResolutionCatalogUnresolved
	}
	return out
}

func resolveObject(obj effects.ObjectRef, fixture CatalogFixture) effects.ResolvedObjectRef {
	return resolveObjectWithContext(obj, resolveContext{fixture: fixture})
}

func resolveObjectWithContext(obj effects.ObjectRef, ctx resolveContext) effects.ResolvedObjectRef {
	if !isCatalogRelationObject(obj.Kind) {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: "unsupported",
		}
	}
	if ctx.snapshotUnavailableReason != "" {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: ctx.snapshotUnavailableReason,
		}
	}
	if obj.Schema == "" && ctx.searchPathUnavailableReason != "" {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: ctx.searchPathUnavailableReason,
		}
	}
	res := catalog.ResolveRelation(ctx.fixture.Snapshot, catalog.Name{Schema: obj.Schema, Name: obj.Name}, ctx.fixture.SearchPath)
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

func hasCatalogRelationObject(objects []effects.ObjectRef) bool {
	for _, obj := range objects {
		if isCatalogRelationObject(obj.Kind) {
			return true
		}
	}
	return false
}

func isCatalogRelationObject(kind effects.ObjectKind) bool {
	switch kind {
	case effects.ObjectTable, effects.ObjectView, effects.ObjectSequence:
		return true
	default:
		return false
	}
}

func resolveFunctionOID(oid int32, fixture CatalogFixture) effects.ResolvedObjectRef {
	return resolveFunctionOIDWithContext(oid, newResolveContext(fixture))
}

func resolveFunctionOIDWithContext(oid int32, ctx resolveContext) effects.ResolvedObjectRef {
	if ctx.snapshotUnavailableReason != "" {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectFunction,
			OID:              uint32(oid),
			UnresolvedReason: ctx.snapshotUnavailableReason,
		}
	}
	res := catalog.ResolveFunctionByOID(ctx.fixture.Snapshot, catalog.OID(uint32(oid)))
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
		FunctionVolatility:   functionVolatility(fn.Volatility),
	}
}

func functionVolatility(v catalog.FunctionVolatility) string {
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
	switch eff.Group {
	case effects.GroupSchemaCreate, effects.GroupSchemaAlter, effects.GroupSchemaDestroy:
		return false, true
	}
	return false, false
}

func applyStatementCatalogContext(ctx resolveContext, stmt effects.ClassifiedStatement) resolveContext {
	for _, eff := range stmt.Effects {
		ctx = applyEffectCatalogContext(ctx, eff, stmt.RawVerb)
	}
	return ctx
}

func applyEffectCatalogContext(ctx resolveContext, eff effects.Effect, rawVerb string) resolveContext {
	switch eff.Subtype {
	case effects.SubtypeSetSearchPath:
		if path, ok := parseSetSearchPathRawVerb(rawVerb); ok {
			ctx.fixture.SearchPath = path
			ctx.searchPathUnavailableReason = ""
		} else {
			ctx.searchPathUnavailableReason = catalogSessionStateChangedReason
			ctx.fixture.SearchPath = nil
		}
		return ctx
	case effects.SubtypeReset:
		if effectHasAnyGUC(eff, "search_path") {
			ctx.fixture.SearchPath = append([]string(nil), ctx.defaultSearchPath...)
			ctx.searchPathUnavailableReason = ""
		}
		if effectHasAnyGUC(eff, "role", "session_authorization") {
			ctx.searchPathUnavailableReason = catalogSessionStateChangedReason
			ctx.fixture.SearchPath = nil
		}
		return ctx
	case effects.SubtypeResetAll, effects.SubtypeDiscardAll:
		ctx.fixture.SearchPath = append([]string(nil), ctx.defaultSearchPath...)
		ctx.searchPathUnavailableReason = ""
		ctx.localSearchPathActive = false
		ctx.localSearchPathBase = nil
		return ctx
	case effects.SubtypeSetRole, effects.SubtypeSetSessionAuthorization:
		ctx.searchPathUnavailableReason = catalogSessionStateChangedReason
		ctx.fixture.SearchPath = nil
		return ctx
	case effects.SubtypeSetLocal:
		if effectHasAnyGUC(eff, "search_path", "role", "session_authorization") && !ctx.localSearchPathActive {
			ctx.localSearchPathActive = true
			ctx.localSearchPathBase = append([]string(nil), ctx.fixture.SearchPath...)
		}
		if effectHasAnyGUC(eff, "search_path") {
			if path, ok := parseSetLocalSearchPathRawVerb(rawVerb); ok {
				ctx.fixture.SearchPath = path
				ctx.searchPathUnavailableReason = ""
			} else {
				ctx.searchPathUnavailableReason = catalogSessionStateChangedReason
				ctx.fixture.SearchPath = nil
			}
			return ctx
		}
		if effectHasAnyGUC(eff, "role", "session_authorization") {
			ctx.searchPathUnavailableReason = catalogSessionStateChangedReason
			ctx.fixture.SearchPath = nil
			return ctx
		}
	}

	if eff.Group == effects.GroupTransaction && transactionCanRestoreLocalSearchPath(rawVerb) {
		if ctx.localSearchPathActive {
			ctx.fixture.SearchPath = append([]string(nil), ctx.localSearchPathBase...)
			ctx.searchPathUnavailableReason = ""
			ctx.localSearchPathActive = false
			ctx.localSearchPathBase = nil
		}
		return ctx
	}

	_, snapshot := effectCatalogRefreshNeeds(eff, rawVerb)
	if snapshot {
		ctx.snapshotUnavailableReason = catalogSessionStateChangedReason
	}
	return ctx
}

func parseSetSearchPathRawVerb(rawVerb string) ([]string, bool) {
	const prefix = "SET_SEARCH_PATH="
	if !strings.HasPrefix(rawVerb, prefix) {
		return nil, false
	}
	return splitSearchPathRawVerb(rawVerb[len(prefix):]), true
}

func parseSetLocalSearchPathRawVerb(rawVerb string) ([]string, bool) {
	const prefix = "SET_LOCAL=search_path:"
	if !strings.HasPrefix(rawVerb, prefix) {
		return nil, false
	}
	return splitSearchPathRawVerb(rawVerb[len(prefix):]), true
}

func splitSearchPathRawVerb(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"`)
		part = strings.ToLower(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func isCatalogUnavailableReason(reason string) bool {
	return reason == catalogSessionStateChangedReason
}

func transactionCanRestoreLocalSearchPath(rawVerb string) bool {
	switch rawVerb {
	case "COMMIT", "ROLLBACK", "ROLLBACK_TO", "END":
		return true
	default:
		return false
	}
}

func effectHasAnyGUC(eff effects.Effect, names ...string) bool {
	for _, name := range names {
		if effectHasGUC(eff, name) {
			return true
		}
	}
	return false
}

func effectHasGUC(eff effects.Effect, name string) bool {
	for _, obj := range eff.Objects {
		if obj.Kind == effects.ObjectGUC && strings.EqualFold(obj.Name, name) {
			return true
		}
	}
	return false
}
