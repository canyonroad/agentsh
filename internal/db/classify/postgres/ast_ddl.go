// Package postgres — ast_ddl.go owns the DDL handlers (CREATE / ALTER /
// DROP / TRUNCATE / RENAME / COMMENT ON) for the schema_create,
// schema_alter, and schema_destroy taxonomy blocks (spec §7.3).
//
// Each handler follows the same pattern:
//   - encode any TEMP/MATERIALIZED hint into RawVerb so applyTempLifecycle and
//     downstream consumers can route on it;
//   - call extractRelation / extractQualifiedName to build ObjectRef + resolution;
//   - emit one Effect per spec §7.3 row (group + optional subtype + objects).
//
// Forms whose pg_query.RemoveType / Objtype is owned by Task 10 (subscriptions
// / foreign servers / user mappings / tablespaces) fall through to the
// dispatcher's empty-Effects guard with a diagnostic Error.
package postgres

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// ---- CREATE ----

// classifyCreateTable maps CREATE TABLE [TEMP].
//
// Encodes TEMP into RawVerb ("CREATE_TEMP_TABLE") so applyTempLifecycle (Task 6)
// can register the table in SessionState.TempTables.
func classifyCreateTable(cs *effects.ClassifiedStatement, s *pg_query.CreateStmt, sess SessionState) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateStmt"
		return
	}
	cs.RawVerb = "CREATE_TABLE"
	if s.Relation != nil && s.Relation.Relpersistence == "t" {
		cs.RawVerb = "CREATE_TEMP_TABLE"
	}
	tgt, res := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Subtype:    effects.SubtypeCreateTable,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: res,
	}}
}

// classifyCreateTableAs maps CREATE TABLE … AS SELECT and CREATE MATERIALIZED
// VIEW. Both forms parse to a CreateTableAsStmt; the Objtype field
// disambiguates (OBJECT_TABLE vs OBJECT_MATVIEW).
//
// Spec §7.3: CTAS → primary schema_create(create_table) + secondary read.
//            CREATE MATERIALIZED VIEW → primary schema_create(create_materialized_view) + secondary read.
func classifyCreateTableAs(cs *effects.ClassifiedStatement, s *pg_query.CreateTableAsStmt, sess SessionState, opts Options) {
	if s == nil || s.Into == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateTableAsStmt"
		return
	}

	isMatView := s.Objtype == pg_query.ObjectType_OBJECT_MATVIEW
	tgtKind := effects.ObjectTable
	subtype := effects.SubtypeCreateTable
	if isMatView {
		tgtKind = effects.ObjectView
		subtype = effects.SubtypeCreateMaterializedView
		cs.RawVerb = "CREATE_MATERIALIZED_VIEW"
	} else if s.IsSelectInto {
		cs.RawVerb = "SELECT_INTO"
	} else {
		cs.RawVerb = "CREATE_TABLE_AS"
		// Honour TEMP for CTAS too.
		if s.Into.Rel != nil && s.Into.Rel.Relpersistence == "t" {
			cs.RawVerb = "CREATE_TEMP_TABLE_AS"
		}
	}

	tgt, tgtRes := extractRelation(s.Into.Rel, sess, tgtKind)
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupSchemaCreate,
		Subtype:    subtype,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
	})

	// Inner SELECT contributes a read of its source relations.
	if s.Query != nil {
		if sel, ok := s.Query.Node.(*pg_query.Node_SelectStmt); ok && sel.SelectStmt != nil {
			rels, res := walkSelectRelations(sel.SelectStmt, sess)
			if len(rels) > 0 {
				cs.Effects = append(cs.Effects, effects.Effect{
					Group:      effects.GroupRead,
					Objects:    rels,
					Resolution: res,
				})
			}
		}
	}
}

// classifyCreateIndex maps CREATE INDEX.
//
// Spec §7.3: schema_create(create_index). Index is the primary object;
// index has Schema = relation's Schema (best-effort) and Name = idxname.
func classifyCreateIndex(cs *effects.ClassifiedStatement, s *pg_query.IndexStmt, sess SessionState) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil IndexStmt"
		return
	}
	cs.RawVerb = "CREATE_INDEX"
	idx := effects.ObjectRef{
		Kind: effects.ObjectIndex,
		Name: strings.ToLower(s.Idxname),
	}
	if s.Relation != nil {
		idx.Schema = strings.ToLower(s.Relation.Schemaname)
	}
	res := resolutionFor(idx, sess)
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Subtype:    effects.SubtypeCreateIndex,
		Objects:    []effects.ObjectRef{idx},
		Resolution: res,
	}}
}

// classifyCreateView maps CREATE VIEW (ordinary or temp).
// MATERIALIZED VIEW is parsed as CreateTableAsStmt and handled separately.
func classifyCreateView(cs *effects.ClassifiedStatement, s *pg_query.ViewStmt, sess SessionState) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil ViewStmt"
		return
	}
	cs.RawVerb = "CREATE_VIEW"
	if s.View != nil && s.View.Relpersistence == "t" {
		cs.RawVerb = "CREATE_TEMP_VIEW"
	}
	tgt, res := extractRelation(s.View, sess, effects.ObjectView)
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Subtype:    effects.SubtypeCreateView,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: res,
	}}
}

// classifyCreateSchema maps CREATE SCHEMA.
func classifyCreateSchema(cs *effects.ClassifiedStatement, s *pg_query.CreateSchemaStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateSchemaStmt"
		return
	}
	cs.RawVerb = "CREATE_SCHEMA"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSchemaCreate,
		Subtype: effects.SubtypeCreateSchema,
		Objects: []effects.ObjectRef{{
			Kind: effects.ObjectSchema,
			Name: strings.ToLower(s.Schemaname),
		}},
		Resolution: effects.ResolutionQualified,
	}}
}

// classifyCreateFunction maps CREATE FUNCTION / CREATE PROCEDURE.
func classifyCreateFunction(cs *effects.ClassifiedStatement, s *pg_query.CreateFunctionStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateFunctionStmt"
		return
	}
	cs.RawVerb = "CREATE_FUNCTION"
	if s.IsProcedure {
		cs.RawVerb = "CREATE_PROCEDURE"
	}
	schema, name := splitQualifiedNameParts(s.Funcname)
	obj := effects.ObjectRef{
		Kind:   effects.ObjectFunction,
		Schema: schema,
		Name:   name,
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Subtype:    effects.SubtypeCreateFunction,
		Objects:    []effects.ObjectRef{obj},
		Resolution: schemaResolution(schema),
	}}
}

// classifyCreateExtension maps CREATE EXTENSION.
func classifyCreateExtension(cs *effects.ClassifiedStatement, s *pg_query.CreateExtensionStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateExtensionStmt"
		return
	}
	cs.RawVerb = "CREATE_EXTENSION"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSchemaCreate,
		Subtype: effects.SubtypeCreateExtension,
		// Extensions live in schemas but their identity is the bare name; we use
		// a Schema-kind ObjectRef as the closest available shape.
		Objects: []effects.ObjectRef{{
			Kind: effects.ObjectSchema,
			Name: strings.ToLower(s.Extname),
		}},
		Resolution: effects.ResolutionQualified,
	}}
}

// classifyCreateDatabase maps CREATE DATABASE.
func classifyCreateDatabase(cs *effects.ClassifiedStatement, s *pg_query.CreatedbStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreatedbStmt"
		return
	}
	cs.RawVerb = "CREATE_DATABASE"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSchemaCreate,
		Subtype: effects.SubtypeCreateDatabase,
		Objects: []effects.ObjectRef{{
			Kind: effects.ObjectSchema, // closest shape; spec uses the bare name
			Name: strings.ToLower(s.Dbname),
		}},
		Resolution: effects.ResolutionQualified,
	}}
}

// classifyCreatePublication maps CREATE PUBLICATION.
func classifyCreatePublication(cs *effects.ClassifiedStatement, s *pg_query.CreatePublicationStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreatePublicationStmt"
		return
	}
	cs.RawVerb = "CREATE_PUBLICATION"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSchemaCreate,
		Subtype: effects.SubtypeCreatePublication,
		Objects: []effects.ObjectRef{{
			Kind: effects.ObjectPublication,
			Name: strings.ToLower(s.Pubname),
		}},
		Resolution: effects.ResolutionQualified,
	}}
}

// classifyCreateSequence maps CREATE SEQUENCE → schema_create (group only).
func classifyCreateSequence(cs *effects.ClassifiedStatement, s *pg_query.CreateSeqStmt, sess SessionState) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateSeqStmt"
		return
	}
	cs.RawVerb = "CREATE_SEQUENCE"
	tgt, res := extractRelation(s.Sequence, sess, effects.ObjectSequence)
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: res,
	}}
}

// classifyCreateTrigger maps CREATE TRIGGER → schema_create (group only).
func classifyCreateTrigger(cs *effects.ClassifiedStatement, s *pg_query.CreateTrigStmt, sess SessionState) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateTrigStmt"
		return
	}
	cs.RawVerb = "CREATE_TRIGGER"
	objs := []effects.ObjectRef{{
		Kind: effects.ObjectFunction, // trigger names lack a dedicated kind; use function as nearest fit
		Name: strings.ToLower(s.Trigname),
	}}
	res := effects.ResolutionUnqualified
	if s.Relation != nil {
		// Include the parent relation so policy can match on it.
		tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
		objs = append(objs, tgt)
		res = tgtRes
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Objects:    objs,
		Resolution: res,
	}}
}

// classifyCompositeType maps CREATE TYPE … AS (…) → schema_create (group only).
func classifyCompositeType(cs *effects.ClassifiedStatement, s *pg_query.CompositeTypeStmt, sess SessionState) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CompositeTypeStmt"
		return
	}
	cs.RawVerb = "CREATE_TYPE"
	tgt, res := extractRelation(s.Typevar, sess, effects.ObjectTable)
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: res,
	}}
}

// classifyCreateEnum maps CREATE TYPE … AS ENUM → schema_create (group only).
func classifyCreateEnum(cs *effects.ClassifiedStatement, s *pg_query.CreateEnumStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateEnumStmt"
		return
	}
	cs.RawVerb = "CREATE_TYPE"
	schema, name := splitQualifiedNameParts(s.TypeName)
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Schema: schema, Name: name}},
		Resolution: schemaResolution(schema),
	}}
}

// classifyCreateDomain maps CREATE DOMAIN → schema_create (group only).
func classifyCreateDomain(cs *effects.ClassifiedStatement, s *pg_query.CreateDomainStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateDomainStmt"
		return
	}
	cs.RawVerb = "CREATE_DOMAIN"
	schema, name := splitQualifiedNameParts(s.Domainname)
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Schema: schema, Name: name}},
		Resolution: schemaResolution(schema),
	}}
}

// classifyDefine maps DefineStmt — used for CREATE AGGREGATE / OPERATOR /
// COLLATION / TYPE (base/range) / TEXT SEARCH … . Maps to schema_create
// (group only) per spec §7.3.
func classifyDefine(cs *effects.ClassifiedStatement, s *pg_query.DefineStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil DefineStmt"
		return
	}
	cs.RawVerb = "CREATE_" + strings.TrimPrefix(s.Kind.String(), "OBJECT_")
	schema, name := splitQualifiedNameParts(s.Defnames)
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectFunction, Schema: schema, Name: name}},
		Resolution: schemaResolution(schema),
	}}
}

// ---- ALTER ----

// classifyAlter maps ALTER TABLE / ALTER VIEW / ALTER MATERIALIZED VIEW /
// ALTER INDEX / ALTER SEQUENCE / ALTER FOREIGN TABLE — anything pg_query
// represents as AlterTableStmt.
//
// Per spec §7.3 these all map to schema_alter (group only, no subtype).
func classifyAlter(cs *effects.ClassifiedStatement, s *pg_query.AlterTableStmt, sess SessionState) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil AlterTableStmt"
		return
	}

	cs.RawVerb = alterRawVerb(s.Objtype)
	tgt, res := extractRelation(s.Relation, sess, alterObjectKind(s.Objtype))
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaAlter,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: res,
	}}
}

// classifyRename maps RENAME of a table/view/index/etc. → schema_alter.
func classifyRename(cs *effects.ClassifiedStatement, s *pg_query.RenameStmt, sess SessionState) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil RenameStmt"
		return
	}
	cs.RawVerb = "RENAME"
	if name := s.RenameType.String(); name != "" {
		cs.RawVerb = "RENAME_" + strings.TrimPrefix(name, "OBJECT_")
	}

	objs := []effects.ObjectRef{}
	res := effects.ResolutionUnqualified
	if s.Relation != nil {
		tgt, tgtRes := extractRelation(s.Relation, sess, alterObjectKind(s.RenameType))
		objs = append(objs, tgt)
		res = tgtRes
	} else if s.Object != nil {
		// e.g. RENAME SCHEMA / RENAME FUNCTION — Object holds a String_/List name.
		schema, name := nameFromObjectNode(s.Object)
		objs = append(objs, effects.ObjectRef{
			Kind:   alterObjectKind(s.RenameType),
			Schema: schema,
			Name:   name,
		})
		res = schemaResolution(schema)
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaAlter,
		Objects:    objs,
		Resolution: res,
	}}
}

// classifyComment maps COMMENT ON … → schema_alter.
func classifyComment(cs *effects.ClassifiedStatement, s *pg_query.CommentStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CommentStmt"
		return
	}
	cs.RawVerb = "COMMENT_ON"
	if name := s.Objtype.String(); name != "" {
		cs.RawVerb = "COMMENT_ON_" + strings.TrimPrefix(name, "OBJECT_")
	}
	objs := []effects.ObjectRef{}
	res := effects.ResolutionUnqualified
	if s.Object != nil {
		schema, name := nameFromObjectNode(s.Object)
		objs = append(objs, effects.ObjectRef{
			Kind:   alterObjectKind(s.Objtype),
			Schema: schema,
			Name:   name,
		})
		res = schemaResolution(schema)
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaAlter,
		Objects:    objs,
		Resolution: res,
	}}
}

// classifyAlterPublication maps ALTER PUBLICATION → schema_alter(alter_publication).
func classifyAlterPublication(cs *effects.ClassifiedStatement, s *pg_query.AlterPublicationStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil AlterPublicationStmt"
		return
	}
	cs.RawVerb = "ALTER_PUBLICATION"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSchemaAlter,
		Subtype: effects.SubtypeAlterPublication,
		Objects: []effects.ObjectRef{{
			Kind: effects.ObjectPublication,
			Name: strings.ToLower(s.Pubname),
		}},
		Resolution: effects.ResolutionQualified,
	}}
}

// ---- DROP ----

// classifyDrop maps DROP TABLE / INDEX / VIEW / FUNCTION / SCHEMA / etc.
// (everything pg_query represents as DropStmt, dispatched on RemoveType).
//
// Subscriptions / foreign servers / user mappings / tablespaces are owned by
// Task 10 — for those we leave Effects empty + Error set so the dispatcher's
// empty-Effects guard kicks in. (Their dedicated DropSubscriptionStmt /
// DropTableSpaceStmt / DropUserMappingStmt nodes route to Task 10 handlers.)
func classifyDrop(cs *effects.ClassifiedStatement, s *pg_query.DropStmt, sess SessionState) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil DropStmt"
		return
	}

	switch s.RemoveType {
	case pg_query.ObjectType_OBJECT_TABLE:
		emitDropPerObject(cs, s, sess, "DROP_TABLE", effects.SubtypeDropTable, effects.ObjectTable)
	case pg_query.ObjectType_OBJECT_INDEX:
		emitDropPerObject(cs, s, sess, "DROP_INDEX", effects.SubtypeDropIndex, effects.ObjectIndex)
	case pg_query.ObjectType_OBJECT_VIEW:
		emitDropPerObject(cs, s, sess, "DROP_VIEW", effects.SubtypeDropView, effects.ObjectView)
	case pg_query.ObjectType_OBJECT_MATVIEW:
		// MATERIALIZED VIEW shares the schema_destroy group; spec uses the bare
		// drop_view subtype for consistency with §7.3 schema_destroy entries.
		emitDropPerObject(cs, s, sess, "DROP_MATERIALIZED_VIEW", effects.SubtypeDropView, effects.ObjectView)
	case pg_query.ObjectType_OBJECT_SCHEMA:
		emitDropFromSimpleNames(cs, s, "DROP_SCHEMA", effects.SubtypeDropSchema, effects.ObjectSchema)
	case pg_query.ObjectType_OBJECT_FUNCTION,
		pg_query.ObjectType_OBJECT_PROCEDURE,
		pg_query.ObjectType_OBJECT_ROUTINE:
		emitDropFromObjectWithArgs(cs, s, "DROP_FUNCTION", effects.SubtypeDropFunction, effects.ObjectFunction)
	case pg_query.ObjectType_OBJECT_PUBLICATION:
		emitDropFromSimpleNames(cs, s, "DROP_PUBLICATION", effects.SubtypeDropPublication, effects.ObjectPublication)
	case pg_query.ObjectType_OBJECT_EXTENSION:
		// schema_destroy without a dedicated subtype.
		emitDropFromSimpleNames(cs, s, "DROP_EXTENSION", effects.SubtypeNone, effects.ObjectSchema)
	case pg_query.ObjectType_OBJECT_SEQUENCE:
		emitDropPerObject(cs, s, sess, "DROP_SEQUENCE", effects.SubtypeNone, effects.ObjectSequence)
	case pg_query.ObjectType_OBJECT_TYPE,
		pg_query.ObjectType_OBJECT_DOMAIN:
		emitDropFromQualifiedNames(cs, s, "DROP_TYPE", effects.SubtypeNone, effects.ObjectTable)
	case pg_query.ObjectType_OBJECT_AGGREGATE:
		emitDropFromObjectWithArgs(cs, s, "DROP_AGGREGATE", effects.SubtypeNone, effects.ObjectFunction)
	case pg_query.ObjectType_OBJECT_TRIGGER,
		pg_query.ObjectType_OBJECT_RULE,
		pg_query.ObjectType_OBJECT_POLICY:
		// These are List<schema?, parent_relation, name> in pg_query;
		// we extract the trailing name as the primary identifier.
		emitDropFromQualifiedNames(cs, s, "DROP_"+strings.TrimPrefix(s.RemoveType.String(), "OBJECT_"), effects.SubtypeNone, effects.ObjectFunction)
	default:
		// OBJECT_SUBSCRIPTION / OBJECT_FOREIGN_SERVER / OBJECT_USER_MAPPING /
		// OBJECT_TABLESPACE land in Task 10. Surface as unmapped so the
		// dispatcher's empty-Effects guard fires with a clear diagnostic.
		cs.Effects = nil
		cs.Error = "unmapped form: drop kind " + s.RemoveType.String()
	}
}

// classifyDropDatabase maps DROP DATABASE → schema_destroy(drop_database).
func classifyDropDatabase(cs *effects.ClassifiedStatement, s *pg_query.DropdbStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil DropdbStmt"
		return
	}
	cs.RawVerb = "DROP_DATABASE"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSchemaDestroy,
		Subtype: effects.SubtypeDropDatabase,
		Objects: []effects.ObjectRef{{
			Kind: effects.ObjectSchema,
			Name: strings.ToLower(s.Dbname),
		}},
		Resolution: effects.ResolutionQualified,
	}}
}

// classifyTruncate maps TRUNCATE → schema_destroy(truncate) with one
// ObjectRef per relation in s.Relations.
func classifyTruncate(cs *effects.ClassifiedStatement, s *pg_query.TruncateStmt, sess SessionState) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil TruncateStmt"
		return
	}
	cs.RawVerb = "TRUNCATE"
	objs := make([]effects.ObjectRef, 0, len(s.Relations))
	resolutions := make([]effects.Resolution, 0, len(s.Relations))
	for _, n := range s.Relations {
		if n == nil {
			continue
		}
		rv, ok := n.Node.(*pg_query.Node_RangeVar)
		if !ok || rv.RangeVar == nil {
			continue
		}
		obj, res := extractRelation(rv.RangeVar, sess, effects.ObjectTable)
		objs = append(objs, obj)
		resolutions = append(resolutions, res)
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaDestroy,
		Subtype:    effects.SubtypeTruncate,
		Objects:    objs,
		Resolution: effects.Fold(resolutions),
	}}
}

// ---- helpers ----

// emitDropPerObject builds one schema_destroy effect with one ObjectRef per
// list-of-string entry in s.Objects. Used for forms whose Objects[i] is a
// Node_List of String_ name parts (DROP TABLE / INDEX / VIEW / SEQUENCE /
// MATVIEW). Resolution is folded across objects.
func emitDropPerObject(cs *effects.ClassifiedStatement, s *pg_query.DropStmt, sess SessionState, raw string, sub effects.Subtype, kind effects.ObjectKind) {
	cs.RawVerb = raw
	objs := make([]effects.ObjectRef, 0, len(s.Objects))
	resolutions := make([]effects.Resolution, 0, len(s.Objects))
	for _, n := range s.Objects {
		schema, name := nameFromObjectNode(n)
		obj := effects.ObjectRef{Kind: kind, Schema: schema, Name: name}
		objs = append(objs, obj)
		resolutions = append(resolutions, resolutionFor(obj, sess))
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaDestroy,
		Subtype:    sub,
		Objects:    objs,
		Resolution: effects.Fold(resolutions),
	}}
}

// emitDropFromSimpleNames builds one schema_destroy effect for forms whose
// Objects[i] is a bare Node_String_ (DROP SCHEMA / EXTENSION / PUBLICATION).
func emitDropFromSimpleNames(cs *effects.ClassifiedStatement, s *pg_query.DropStmt, raw string, sub effects.Subtype, kind effects.ObjectKind) {
	cs.RawVerb = raw
	objs := make([]effects.ObjectRef, 0, len(s.Objects))
	for _, n := range s.Objects {
		_, name := nameFromObjectNode(n)
		objs = append(objs, effects.ObjectRef{Kind: kind, Name: name})
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaDestroy,
		Subtype:    sub,
		Objects:    objs,
		Resolution: effects.ResolutionQualified,
	}}
}

// emitDropFromQualifiedNames is the variant for forms whose Objects[i] is a
// Node_List of String_ name parts (DROP TYPE / DOMAIN / TRIGGER / RULE /
// POLICY) where Resolution comes from whether a schema was supplied.
func emitDropFromQualifiedNames(cs *effects.ClassifiedStatement, s *pg_query.DropStmt, raw string, sub effects.Subtype, kind effects.ObjectKind) {
	cs.RawVerb = raw
	objs := make([]effects.ObjectRef, 0, len(s.Objects))
	resolutions := make([]effects.Resolution, 0, len(s.Objects))
	for _, n := range s.Objects {
		schema, name := nameFromObjectNode(n)
		obj := effects.ObjectRef{Kind: kind, Schema: schema, Name: name}
		objs = append(objs, obj)
		resolutions = append(resolutions, schemaResolution(schema))
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaDestroy,
		Subtype:    sub,
		Objects:    objs,
		Resolution: effects.Fold(resolutions),
	}}
}

// emitDropFromObjectWithArgs is for DROP FUNCTION / DROP AGGREGATE — Objects[i]
// is a Node_ObjectWithArgs holding objname (a list of String_).
func emitDropFromObjectWithArgs(cs *effects.ClassifiedStatement, s *pg_query.DropStmt, raw string, sub effects.Subtype, kind effects.ObjectKind) {
	cs.RawVerb = raw
	objs := make([]effects.ObjectRef, 0, len(s.Objects))
	resolutions := make([]effects.Resolution, 0, len(s.Objects))
	for _, n := range s.Objects {
		var schema, name string
		if n != nil {
			if owa, ok := n.Node.(*pg_query.Node_ObjectWithArgs); ok && owa.ObjectWithArgs != nil {
				schema, name = splitQualifiedNameParts(owa.ObjectWithArgs.Objname)
			}
		}
		obj := effects.ObjectRef{Kind: kind, Schema: schema, Name: name}
		objs = append(objs, obj)
		resolutions = append(resolutions, schemaResolution(schema))
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaDestroy,
		Subtype:    sub,
		Objects:    objs,
		Resolution: effects.Fold(resolutions),
	}}
}

// nameFromObjectNode extracts (schema, name) from one of the shapes pg_query
// uses for DROP/COMMENT/RENAME's Object field:
//   - Node_String_ (single bare identifier; e.g. DROP SCHEMA s)
//   - Node_List of String_ (qualified identifier; e.g. DROP TABLE s.t)
//   - Node_ObjectWithArgs (DROP FUNCTION f(int)) — only Objname is consulted
func nameFromObjectNode(n *pg_query.Node) (schema, name string) {
	if n == nil {
		return "", ""
	}
	switch v := n.Node.(type) {
	case *pg_query.Node_String_:
		if v.String_ != nil {
			name = strings.ToLower(v.String_.Sval)
		}
	case *pg_query.Node_List:
		if v.List != nil {
			schema, name = splitQualifiedNameParts(v.List.Items)
		}
	case *pg_query.Node_ObjectWithArgs:
		if v.ObjectWithArgs != nil {
			schema, name = splitQualifiedNameParts(v.ObjectWithArgs.Objname)
		}
	}
	return
}

// splitQualifiedNameParts returns (schema, name) from a list of String_-typed
// Node parts. Two-element lists are treated as (schema, name); single-element
// lists are (empty, name); three-element lists yield (schema, name) using the
// last two parts (the leading element is the catalog/db).
func splitQualifiedNameParts(parts []*pg_query.Node) (schema, name string) {
	strs := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == nil {
			continue
		}
		if sv, ok := p.Node.(*pg_query.Node_String_); ok && sv.String_ != nil {
			strs = append(strs, strings.ToLower(sv.String_.Sval))
		}
	}
	switch len(strs) {
	case 0:
		return "", ""
	case 1:
		return "", strs[0]
	case 2:
		return strs[0], strs[1]
	default:
		return strs[len(strs)-2], strs[len(strs)-1]
	}
}

// schemaResolution returns ResolutionQualified when a schema part is present,
// else ResolutionUnqualified. DDL handlers don't perform search-path resolution
// so this is the simplest correct answer for §6.1's qualified/unqualified
// dichotomy.
func schemaResolution(schema string) effects.Resolution {
	if schema != "" {
		return effects.ResolutionQualified
	}
	return effects.ResolutionUnqualified
}

// alterRawVerb returns the canonical RawVerb for an ALTER target type.
func alterRawVerb(o pg_query.ObjectType) string {
	switch o {
	case pg_query.ObjectType_OBJECT_TABLE:
		return "ALTER_TABLE"
	case pg_query.ObjectType_OBJECT_VIEW:
		return "ALTER_VIEW"
	case pg_query.ObjectType_OBJECT_MATVIEW:
		return "ALTER_MATERIALIZED_VIEW"
	case pg_query.ObjectType_OBJECT_INDEX:
		return "ALTER_INDEX"
	case pg_query.ObjectType_OBJECT_SEQUENCE:
		return "ALTER_SEQUENCE"
	case pg_query.ObjectType_OBJECT_FOREIGN_TABLE:
		return "ALTER_FOREIGN_TABLE"
	case pg_query.ObjectType_OBJECT_TYPE:
		return "ALTER_TYPE"
	}
	if name := o.String(); name != "" {
		return "ALTER_" + strings.TrimPrefix(name, "OBJECT_")
	}
	return "ALTER"
}

// alterObjectKind maps a pg_query ObjectType to the closest effects.ObjectKind.
// Used by ALTER / RENAME / COMMENT handlers when constructing their primary
// ObjectRef.
func alterObjectKind(o pg_query.ObjectType) effects.ObjectKind {
	switch o {
	case pg_query.ObjectType_OBJECT_TABLE,
		pg_query.ObjectType_OBJECT_FOREIGN_TABLE,
		pg_query.ObjectType_OBJECT_TYPE,
		pg_query.ObjectType_OBJECT_DOMAIN:
		return effects.ObjectTable
	case pg_query.ObjectType_OBJECT_VIEW,
		pg_query.ObjectType_OBJECT_MATVIEW:
		return effects.ObjectView
	case pg_query.ObjectType_OBJECT_INDEX:
		return effects.ObjectIndex
	case pg_query.ObjectType_OBJECT_SEQUENCE:
		return effects.ObjectSequence
	case pg_query.ObjectType_OBJECT_SCHEMA:
		return effects.ObjectSchema
	case pg_query.ObjectType_OBJECT_FUNCTION,
		pg_query.ObjectType_OBJECT_PROCEDURE,
		pg_query.ObjectType_OBJECT_ROUTINE,
		pg_query.ObjectType_OBJECT_AGGREGATE,
		pg_query.ObjectType_OBJECT_TRIGGER,
		pg_query.ObjectType_OBJECT_RULE,
		pg_query.ObjectType_OBJECT_POLICY:
		return effects.ObjectFunction
	case pg_query.ObjectType_OBJECT_PUBLICATION:
		return effects.ObjectPublication
	case pg_query.ObjectType_OBJECT_SUBSCRIPTION:
		return effects.ObjectSubscription
	case pg_query.ObjectType_OBJECT_FOREIGN_SERVER:
		return effects.ObjectServer
	case pg_query.ObjectType_OBJECT_USER_MAPPING:
		return effects.ObjectUserMapping
	case pg_query.ObjectType_OBJECT_TABLESPACE:
		return effects.ObjectTablespace
	case pg_query.ObjectType_OBJECT_ROLE:
		return effects.ObjectRole
	}
	return effects.ObjectTable
}
