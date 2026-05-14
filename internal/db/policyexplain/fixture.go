package policyexplain

import (
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/db/catalog"
	"gopkg.in/yaml.v3"
)

type CatalogFixture struct {
	SearchPath []string
	Snapshot   catalog.Snapshot
}

type fixtureYAML struct {
	SearchPath []string          `yaml:"search_path"`
	Relations  []fixtureRelation `yaml:"relations"`
	Functions  []fixtureFunction `yaml:"functions"`
}

type fixtureRelation struct {
	OID    uint32 `yaml:"oid"`
	Schema string `yaml:"schema"`
	Name   string `yaml:"name"`
	Kind   string `yaml:"kind"`
	Owner  string `yaml:"owner"`
}

type fixtureFunction struct {
	OID           uint32 `yaml:"oid"`
	Schema        string `yaml:"schema"`
	Name          string `yaml:"name"`
	IdentityArgs  string `yaml:"identity_args"`
	Volatility    string `yaml:"volatility"`
	Strict        bool   `yaml:"strict"`
	ReturnTypeOID uint32 `yaml:"return_type_oid"`
}

func LoadCatalogFixture(path string) (CatalogFixture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CatalogFixture{}, fmt.Errorf("read catalog fixture: %w", err)
	}
	var in fixtureYAML
	if err := yaml.Unmarshal(raw, &in); err != nil {
		return CatalogFixture{}, fmt.Errorf("parse catalog fixture: %w", err)
	}
	relations := make([]catalog.Relation, 0, len(in.Relations))
	for i, rel := range in.Relations {
		kind, ok := parseRelationKind(rel.Kind)
		if !ok {
			return CatalogFixture{}, fmt.Errorf("relations[%d].kind: unknown relation kind %q", i, rel.Kind)
		}
		relations = append(relations, catalog.Relation{
			OID:   catalog.OID(rel.OID),
			Name:  catalog.Name{Schema: rel.Schema, Name: rel.Name},
			Kind:  kind,
			Owner: rel.Owner,
		})
	}
	functions := make([]catalog.Function, 0, len(in.Functions))
	for i, fn := range in.Functions {
		vol, ok := parseVolatility(fn.Volatility)
		if !ok {
			return CatalogFixture{}, fmt.Errorf("functions[%d].volatility: unknown volatility %q", i, fn.Volatility)
		}
		functions = append(functions, catalog.Function{
			OID:           catalog.OID(fn.OID),
			Name:          catalog.Name{Schema: fn.Schema, Name: fn.Name},
			IdentityArgs:  fn.IdentityArgs,
			Volatility:    vol,
			Strict:        fn.Strict,
			ReturnTypeOID: catalog.OID(fn.ReturnTypeOID),
		})
	}
	return CatalogFixture{
		SearchPath: append([]string(nil), in.SearchPath...),
		Snapshot:   catalog.NewSnapshot(relations, functions),
	}, nil
}

func parseRelationKind(s string) (catalog.RelationKind, bool) {
	switch s {
	case "table":
		return catalog.RelationTable, true
	case "partitioned_table":
		return catalog.RelationPartitionedTable, true
	case "view":
		return catalog.RelationView, true
	case "materialized_view":
		return catalog.RelationMaterializedView, true
	case "foreign_table":
		return catalog.RelationForeignTable, true
	case "sequence":
		return catalog.RelationSequence, true
	default:
		return 0, false
	}
}

func parseVolatility(s string) (catalog.FunctionVolatility, bool) {
	switch s {
	case "", "volatile":
		return catalog.VolatilityVolatile, true
	case "stable":
		return catalog.VolatilityStable, true
	case "immutable":
		return catalog.VolatilityImmutable, true
	default:
		return 0, false
	}
}
