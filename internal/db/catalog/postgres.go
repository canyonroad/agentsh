package catalog

import (
	"context"
	"fmt"
)

type Queryer interface {
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

const relationSQL = `
select c.oid, n.nspname, c.relname, c.relkind::text, pg_catalog.pg_get_userbyid(c.relowner)
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
  and n.nspname not like 'pg_toast%'
order by n.nspname, c.relname`

const columnSQL = `
select a.attrelid, a.attname, a.atttypid, a.attnotnull, a.attnum::int4
from pg_catalog.pg_attribute a
join pg_catalog.pg_class c on c.oid = a.attrelid
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
  and n.nspname not like 'pg_toast%'
  and a.attnum > 0
  and not a.attisdropped
order by a.attrelid, a.attnum`

const functionSQL = `
select p.oid, n.nspname, p.proname,
       pg_catalog.pg_get_function_identity_arguments(p.oid),
       p.provolatile::text, p.proisstrict, p.prorettype
from pg_catalog.pg_proc p
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
where n.nspname not like 'pg_toast%'
order by n.nspname, p.proname, p.oid`

func LoadPostgresSnapshot(ctx context.Context, q Queryer) (Snapshot, error) {
	relations, err := loadRelations(ctx, q)
	if err != nil {
		return Snapshot{}, err
	}
	columns, err := loadColumns(ctx, q)
	if err != nil {
		return Snapshot{}, err
	}
	for i := range relations {
		relations[i].Columns = append([]Column(nil), columns[relations[i].OID]...)
	}
	functions, err := loadFunctions(ctx, q)
	if err != nil {
		return Snapshot{}, err
	}
	return NewSnapshot(relations, functions), nil
}

func loadRelations(ctx context.Context, q Queryer) ([]Relation, error) {
	rows, err := q.Query(ctx, relationSQL)
	if err != nil {
		return nil, fmt.Errorf("query relations: %w", err)
	}
	defer rows.Close()

	var out []Relation
	for rows.Next() {
		var oid uint32
		var schema, name, relkind, owner string
		if err := rows.Scan(&oid, &schema, &name, &relkind, &owner); err != nil {
			return nil, fmt.Errorf("scan relation: %w", err)
		}
		kind, ok := parseRelationKind(relkind)
		if !ok {
			continue
		}
		out = append(out, Relation{
			OID:   OID(oid),
			Name:  Name{Schema: schema, Name: name},
			Kind:  kind,
			Owner: owner,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate relations: %w", err)
	}
	return out, nil
}

func loadColumns(ctx context.Context, q Queryer) (map[OID][]Column, error) {
	rows, err := q.Query(ctx, columnSQL)
	if err != nil {
		return nil, fmt.Errorf("query columns: %w", err)
	}
	defer rows.Close()

	out := make(map[OID][]Column)
	for rows.Next() {
		var relOID, typeOID uint32
		var name string
		var notNull bool
		var position int
		if err := rows.Scan(&relOID, &name, &typeOID, &notNull, &position); err != nil {
			return nil, fmt.Errorf("scan column: %w", err)
		}
		key := OID(relOID)
		out[key] = append(out[key], Column{
			Name:     name,
			TypeOID:  OID(typeOID),
			NotNull:  notNull,
			Position: position,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate columns: %w", err)
	}
	return out, nil
}

func loadFunctions(ctx context.Context, q Queryer) ([]Function, error) {
	rows, err := q.Query(ctx, functionSQL)
	if err != nil {
		return nil, fmt.Errorf("query functions: %w", err)
	}
	defer rows.Close()

	var out []Function
	for rows.Next() {
		var oid, ret uint32
		var schema, name, args, volatility string
		var strict bool
		if err := rows.Scan(&oid, &schema, &name, &args, &volatility, &strict, &ret); err != nil {
			return nil, fmt.Errorf("scan function: %w", err)
		}
		vol, ok := parseVolatility(volatility)
		if !ok {
			continue
		}
		out = append(out, Function{
			OID:           OID(oid),
			Name:          Name{Schema: schema, Name: name},
			IdentityArgs:  args,
			Volatility:    vol,
			Strict:        strict,
			ReturnTypeOID: OID(ret),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate functions: %w", err)
	}
	return out, nil
}

func parseRelationKind(s string) (RelationKind, bool) {
	switch s {
	case "r":
		return RelationTable, true
	case "p":
		return RelationPartitionedTable, true
	case "v":
		return RelationView, true
	case "m":
		return RelationMaterializedView, true
	case "f":
		return RelationForeignTable, true
	case "S":
		return RelationSequence, true
	default:
		return 0, false
	}
}

func parseVolatility(s string) (FunctionVolatility, bool) {
	switch s {
	case "i":
		return VolatilityImmutable, true
	case "s":
		return VolatilityStable, true
	case "v":
		return VolatilityVolatile, true
	default:
		return 0, false
	}
}
