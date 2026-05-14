package catalog

func ResolveRelation(snap Snapshot, name Name, searchPath []string) ResolvedRelation {
	if name.Schema != "" {
		rel, ok := snap.RelationByName(name)
		if !ok {
			return ResolvedRelation{Reason: UnresolvedMissing}
		}
		return ResolvedRelation{Relation: rel}
	}
	for _, schema := range searchPath {
		if rel, ok := snap.RelationByName(Name{Schema: schema, Name: name.Name}); ok {
			return ResolvedRelation{Relation: rel}
		}
	}
	candidates := snap.RelationsByUnqualifiedName(name.Name)
	switch len(candidates) {
	case 0:
		return ResolvedRelation{Reason: UnresolvedMissing}
	case 1:
		return ResolvedRelation{Relation: candidates[0]}
	default:
		return ResolvedRelation{Reason: UnresolvedAmbiguous}
	}
}

func ResolveFunctionByOID(snap Snapshot, oid OID) ResolvedFunction {
	fn, ok := snap.FunctionByOID(oid)
	if !ok {
		return ResolvedFunction{Reason: UnresolvedMissing}
	}
	return ResolvedFunction{Function: fn}
}
