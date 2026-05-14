package effects

type ResolvedObjectSource string

const (
	ResolvedObjectSourceCatalog ResolvedObjectSource = "catalog"
)

type ResolvedObjectKind string

const (
	ResolvedObjectRelation ResolvedObjectKind = "relation"
	ResolvedObjectFunction ResolvedObjectKind = "function"
)

type ResolvedObjectRef struct {
	Source               ResolvedObjectSource `json:"source,omitempty"`
	Kind                 ResolvedObjectKind   `json:"kind,omitempty"`
	OID                  uint32               `json:"oid,omitempty"`
	Schema               string               `json:"schema,omitempty"`
	Name                 string               `json:"name,omitempty"`
	RelationKind         string               `json:"relation_kind,omitempty"`
	FunctionIdentityArgs string               `json:"function_identity_args,omitempty"`
	FunctionVolatility   string               `json:"function_volatility,omitempty"`
	UnresolvedReason     string               `json:"unresolved_reason,omitempty"`
}

func (r ResolvedObjectRef) CanonicalName() string {
	if r.Schema == "" {
		return r.Name
	}
	return r.Schema + "." + r.Name
}
