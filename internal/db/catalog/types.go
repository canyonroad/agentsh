package catalog

import "fmt"

// OID is a PostgreSQL object identifier.
type OID uint32

// Name is a canonical catalog name. Schema is empty when the source reference
// is still unqualified.
type Name struct {
	Schema string
	Name   string
}

func (n Name) String() string {
	if n.Schema == "" {
		return n.Name
	}
	return fmt.Sprintf("%s.%s", n.Schema, n.Name)
}

type RelationKind uint8

const (
	RelationTable RelationKind = iota + 1
	RelationPartitionedTable
	RelationView
	RelationMaterializedView
	RelationForeignTable
	RelationSequence
)

func (k RelationKind) String() string {
	switch k {
	case RelationTable:
		return "table"
	case RelationPartitionedTable:
		return "partitioned_table"
	case RelationView:
		return "view"
	case RelationMaterializedView:
		return "materialized_view"
	case RelationForeignTable:
		return "foreign_table"
	case RelationSequence:
		return "sequence"
	default:
		return ""
	}
}

type FunctionVolatility uint8

const (
	VolatilityImmutable FunctionVolatility = iota + 1
	VolatilityStable
	VolatilityVolatile
)

type Column struct {
	Name     string
	TypeOID  OID
	NotNull  bool
	Position int
}

type Relation struct {
	OID     OID
	Name    Name
	Kind    RelationKind
	Owner   string
	Columns []Column
}

type Function struct {
	OID           OID
	Name          Name
	IdentityArgs  string
	Volatility    FunctionVolatility
	Strict        bool
	ReturnTypeOID OID
}

type UnresolvedReason uint8

const (
	UnresolvedNone UnresolvedReason = iota
	UnresolvedMissing
	UnresolvedAmbiguous
	UnresolvedUnsupported
	UnresolvedCatalogError
)

func (r UnresolvedReason) String() string {
	switch r {
	case UnresolvedMissing:
		return "missing"
	case UnresolvedAmbiguous:
		return "ambiguous"
	case UnresolvedUnsupported:
		return "unsupported"
	case UnresolvedCatalogError:
		return "catalog_error"
	default:
		return ""
	}
}

type ResolvedRelation struct {
	Relation Relation
	Reason   UnresolvedReason
}

func (r ResolvedRelation) OK() bool {
	return r.Reason == UnresolvedNone
}
