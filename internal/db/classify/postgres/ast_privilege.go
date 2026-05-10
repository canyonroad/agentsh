// Package postgres — ast_privilege.go owns the §7.3 privilege handlers:
// GRANT/REVOKE (table & role-membership), CREATE/ALTER/DROP ROLE (and the
// CREATE USER / ALTER USER / DROP USER spellings that pg_query parses to the
// same nodes), ALTER SYSTEM, and SECURITY LABEL.
//
// Per spec §20 disambiguation:
//   - ALTER SYSTEM emits primary group=privilege, subtype=alter_system —
//     NOT schema_alter (which is what AlterTableStmt would suggest).
//   - GRANT pg_read_server_files TO role is a role-membership grant, NOT a
//     function call; it parses to GrantRoleStmt and stays in this file.
package postgres

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// classifyGrant maps GRANT/REVOKE on tables, sequences, schemas, etc.
// IsGrant=true → SubtypeGrant; IsGrant=false → SubtypeRevoke.
//
// We extract the first target object as the primary ObjectRef so the policy
// engine can match `objects: [customers]`. Targtype/Objtype distinguish
// "ON SCHEMA s" (Targtype=ALL_IN_SCHEMA) from "ON TABLE t" — currently we
// emit the per-relation form with ObjectKind chosen by Objtype.
func classifyGrant(cs *effects.ClassifiedStatement, s *pg_query.GrantStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil GrantStmt"
		return
	}
	cs.RawVerb = "GRANT"
	subtype := effects.SubtypeGrant
	if !s.IsGrant {
		cs.RawVerb = "REVOKE"
		subtype = effects.SubtypeRevoke
	}

	kind := grantObjectKind(s.Objtype)
	objs := make([]effects.ObjectRef, 0, len(s.Objects))
	resolutions := make([]effects.Resolution, 0, len(s.Objects))
	for _, n := range s.Objects {
		if n == nil {
			continue
		}
		// GRANT … ON TABLE foo and GRANT … ON SEQUENCE s parse Objects as RangeVars.
		if rv, ok := n.Node.(*pg_query.Node_RangeVar); ok && rv.RangeVar != nil {
			obj, res := extractRelation(rv.RangeVar, SessionState{}, kind)
			objs = append(objs, obj)
			resolutions = append(resolutions, res)
			continue
		}
		// GRANT ON SCHEMA s / GRANT ON DATABASE d parse Objects as String_ nodes.
		schema, name := nameFromObjectNode(n)
		obj := effects.ObjectRef{Kind: kind, Schema: schema, Name: name}
		objs = append(objs, obj)
		resolutions = append(resolutions, schemaResolution(schema))
	}

	res := effects.ResolutionUnqualified
	if len(resolutions) > 0 {
		res = effects.Fold(resolutions)
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupPrivilege,
		Subtype:    subtype,
		Objects:    objs,
		Resolution: res,
	}}
}

// classifyGrantRole maps role-membership GRANT/REVOKE
// (e.g. `GRANT pg_read_server_files TO bob`). §20 disambiguation: this is a
// privilege change, NOT a function call.
func classifyGrantRole(cs *effects.ClassifiedStatement, s *pg_query.GrantRoleStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil GrantRoleStmt"
		return
	}
	cs.RawVerb = "GRANT_ROLE"
	subtype := effects.SubtypeGrant
	if !s.IsGrant {
		cs.RawVerb = "REVOKE_ROLE"
		subtype = effects.SubtypeRevoke
	}

	objs := make([]effects.ObjectRef, 0, len(s.GrantedRoles))
	for _, n := range s.GrantedRoles {
		if n == nil {
			continue
		}
		// GrantedRoles[i] is typically an AccessPriv whose priv_name is the
		// role being granted — see §20 example pg_read_server_files.
		switch v := n.Node.(type) {
		case *pg_query.Node_AccessPriv:
			if v.AccessPriv != nil && v.AccessPriv.PrivName != "" {
				objs = append(objs, effects.ObjectRef{
					Kind: effects.ObjectRole,
					Name: strings.ToLower(v.AccessPriv.PrivName),
				})
			}
		case *pg_query.Node_RoleSpec:
			if v.RoleSpec != nil && v.RoleSpec.Rolename != "" {
				objs = append(objs, effects.ObjectRef{
					Kind: effects.ObjectRole,
					Name: strings.ToLower(v.RoleSpec.Rolename),
				})
			}
		}
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupPrivilege,
		Subtype:    subtype,
		Objects:    objs,
		Resolution: effects.ResolutionQualified,
	}}
}

// classifyCreateRole maps CREATE ROLE / CREATE USER / CREATE GROUP.
// All three parse to CreateRoleStmt; StmtType disambiguates but the spec
// folds them all into privilege/create_role.
func classifyCreateRole(cs *effects.ClassifiedStatement, s *pg_query.CreateRoleStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateRoleStmt"
		return
	}
	cs.RawVerb = "CREATE_ROLE"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupPrivilege,
		Subtype: effects.SubtypeCreateRole,
		Objects: []effects.ObjectRef{{
			Kind: effects.ObjectRole,
			Name: strings.ToLower(s.Role),
		}},
		Resolution: effects.ResolutionQualified,
	}}
}

// classifyAlterRole maps ALTER ROLE / ALTER USER / ALTER GROUP.
func classifyAlterRole(cs *effects.ClassifiedStatement, s *pg_query.AlterRoleStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil AlterRoleStmt"
		return
	}
	cs.RawVerb = "ALTER_ROLE"
	name := ""
	if s.Role != nil {
		name = strings.ToLower(s.Role.Rolename)
	}
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupPrivilege,
		Subtype: effects.SubtypeAlterRole,
		Objects: []effects.ObjectRef{{
			Kind: effects.ObjectRole,
			Name: name,
		}},
		Resolution: effects.ResolutionQualified,
	}}
}

// classifyDropRole maps DROP ROLE / DROP USER / DROP GROUP.
func classifyDropRole(cs *effects.ClassifiedStatement, s *pg_query.DropRoleStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil DropRoleStmt"
		return
	}
	cs.RawVerb = "DROP_ROLE"
	objs := make([]effects.ObjectRef, 0, len(s.Roles))
	for _, n := range s.Roles {
		if n == nil {
			continue
		}
		if rs, ok := n.Node.(*pg_query.Node_RoleSpec); ok && rs.RoleSpec != nil {
			objs = append(objs, effects.ObjectRef{
				Kind: effects.ObjectRole,
				Name: strings.ToLower(rs.RoleSpec.Rolename),
			})
		}
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupPrivilege,
		Subtype:    effects.SubtypeDropRole,
		Objects:    objs,
		Resolution: effects.ResolutionQualified,
	}}
}

// classifyAlterSystem maps ALTER SYSTEM SET / RESET. §20 disambiguation: this
// is privilege/alter_system, NOT schema_alter (which AlterTableStmt would
// suggest at the grammar level).
//
// The GUC being set is exposed as ObjectGUC so policies can match on the name.
func classifyAlterSystem(cs *effects.ClassifiedStatement, s *pg_query.AlterSystemStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil AlterSystemStmt"
		return
	}
	cs.RawVerb = "ALTER_SYSTEM"
	objs := []effects.ObjectRef{}
	if s.Setstmt != nil && s.Setstmt.Name != "" {
		objs = append(objs, effects.ObjectRef{
			Kind: effects.ObjectGUC,
			Name: strings.ToLower(s.Setstmt.Name),
		})
	}
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupPrivilege,
		Subtype:    effects.SubtypeAlterSystem,
		Objects:    objs,
		Resolution: effects.ResolutionQualified,
	}}
}

// classifySecurityLabel maps SECURITY LABEL FOR provider ON OBJECT … IS '…'.
func classifySecurityLabel(cs *effects.ClassifiedStatement, s *pg_query.SecLabelStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil SecLabelStmt"
		return
	}
	cs.RawVerb = "SECURITY_LABEL"

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
		Group:      effects.GroupPrivilege,
		Subtype:    effects.SubtypeSecurityLabel,
		Objects:    objs,
		Resolution: res,
	}}
}

// grantObjectKind maps a GrantStmt.Objtype to the ObjectKind for the targets
// in s.Objects. Mirrors alterObjectKind but covers the GRANT-specific
// targets (TABLE, SEQUENCE, SCHEMA, FUNCTION, …).
func grantObjectKind(o pg_query.ObjectType) effects.ObjectKind {
	switch o {
	case pg_query.ObjectType_OBJECT_TABLE,
		pg_query.ObjectType_OBJECT_FOREIGN_TABLE:
		return effects.ObjectTable
	case pg_query.ObjectType_OBJECT_SEQUENCE:
		return effects.ObjectSequence
	case pg_query.ObjectType_OBJECT_SCHEMA:
		return effects.ObjectSchema
	case pg_query.ObjectType_OBJECT_FUNCTION,
		pg_query.ObjectType_OBJECT_PROCEDURE,
		pg_query.ObjectType_OBJECT_ROUTINE:
		return effects.ObjectFunction
	case pg_query.ObjectType_OBJECT_DATABASE:
		return effects.ObjectSchema
	case pg_query.ObjectType_OBJECT_TABLESPACE:
		return effects.ObjectTablespace
	case pg_query.ObjectType_OBJECT_FOREIGN_SERVER:
		return effects.ObjectServer
	case pg_query.ObjectType_OBJECT_PUBLICATION:
		return effects.ObjectPublication
	case pg_query.ObjectType_OBJECT_VIEW,
		pg_query.ObjectType_OBJECT_MATVIEW:
		return effects.ObjectView
	}
	return effects.ObjectTable
}
