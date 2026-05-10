// Package postgres — ast_external.go owns the §7.3 external-IO DDL family.
// SUBSCRIPTION / SERVER / USER MAPPING / TABLESPACE statements all open the
// door to traffic that escapes the database (logical replication, FDW
// connections, on-disk file paths). Per spec they emit a primary unsafe_io
// effect plus a secondary schema_create / schema_alter / schema_destroy /
// privilege effect. Where the SQL exposes the destination (CONNECTION
// 'host=… port=…', OPTIONS (host '…', port '…'), LOCATION '/path'), the
// primary effect carries an ObjectExternalEndpoint or ObjectFilesystemPath so
// policies can match per-target.
package postgres

import (
	"strconv"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// ---- SUBSCRIPTION ----

// classifyCreateSubscription maps CREATE SUBSCRIPTION → unsafe_io(create_subscription)
// + schema_create. Conninfo is parsed into host/port for ObjectExternalEndpoint.
func classifyCreateSubscription(cs *effects.ClassifiedStatement, s *pg_query.CreateSubscriptionStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateSubscriptionStmt"
		return
	}
	cs.RawVerb = "CREATE_SUBSCRIPTION"
	objs := []effects.ObjectRef{{
		Kind: effects.ObjectSubscription,
		Name: strings.ToLower(s.Subname),
	}}
	if host, port := libpqConn(s.Conninfo); host != "" || port != 0 {
		objs = append(objs, effects.ObjectRef{
			Kind: effects.ObjectExternalEndpoint,
			Host: host,
			Port: port,
		})
	}
	cs.Effects = []effects.Effect{
		{
			Group:      effects.GroupUnsafeIO,
			Subtype:    effects.SubtypeCreateSubscription,
			Objects:    objs,
			Resolution: effects.ResolutionQualified,
		},
		{
			Group: effects.GroupSchemaCreate,
			Objects: []effects.ObjectRef{{
				Kind: effects.ObjectSubscription,
				Name: strings.ToLower(s.Subname),
			}},
			Resolution: effects.ResolutionQualified,
		},
	}
}

// classifyAlterSubscription maps ALTER SUBSCRIPTION → unsafe_io(alter_subscription)
// + schema_alter. If the variant carries a new CONNECTION string, expose its
// host/port via ObjectExternalEndpoint.
//
// Note: ALTER SUBSCRIPTION sub OWNER TO … parses to AlterOwnerStmt, not
// AlterSubscriptionStmt; that path is handled by classifyAlterOwner once it
// lands. This handler covers SET / CONNECTION / REFRESH / ENABLE / DISABLE /
// SET PUBLICATION etc.
func classifyAlterSubscription(cs *effects.ClassifiedStatement, s *pg_query.AlterSubscriptionStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil AlterSubscriptionStmt"
		return
	}
	cs.RawVerb = "ALTER_SUBSCRIPTION"
	objs := []effects.ObjectRef{{
		Kind: effects.ObjectSubscription,
		Name: strings.ToLower(s.Subname),
	}}
	if s.Conninfo != "" {
		if host, port := libpqConn(s.Conninfo); host != "" || port != 0 {
			objs = append(objs, effects.ObjectRef{
				Kind: effects.ObjectExternalEndpoint,
				Host: host,
				Port: port,
			})
		}
	}
	cs.Effects = []effects.Effect{
		{
			Group:      effects.GroupUnsafeIO,
			Subtype:    effects.SubtypeAlterSubscription,
			Objects:    objs,
			Resolution: effects.ResolutionQualified,
		},
		{
			Group: effects.GroupSchemaAlter,
			Objects: []effects.ObjectRef{{
				Kind: effects.ObjectSubscription,
				Name: strings.ToLower(s.Subname),
			}},
			Resolution: effects.ResolutionQualified,
		},
	}
}

// classifyDropSubscription maps DROP SUBSCRIPTION → unsafe_io(drop_subscription)
// + schema_destroy.
func classifyDropSubscription(cs *effects.ClassifiedStatement, s *pg_query.DropSubscriptionStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil DropSubscriptionStmt"
		return
	}
	cs.RawVerb = "DROP_SUBSCRIPTION"
	target := effects.ObjectRef{Kind: effects.ObjectSubscription, Name: strings.ToLower(s.Subname)}
	cs.Effects = []effects.Effect{
		{
			Group:      effects.GroupUnsafeIO,
			Subtype:    effects.SubtypeDropSubscription,
			Objects:    []effects.ObjectRef{target},
			Resolution: effects.ResolutionQualified,
		},
		{
			Group:      effects.GroupSchemaDestroy,
			Objects:    []effects.ObjectRef{target},
			Resolution: effects.ResolutionQualified,
		},
	}
}

// ---- FOREIGN SERVER ----

// classifyCreateServer maps CREATE SERVER … FOREIGN DATA WRAPPER … OPTIONS (…)
// to unsafe_io(create_server) + schema_create. host/port are pulled from the
// OPTIONS DefElems (the wire destination for FDW traffic).
func classifyCreateServer(cs *effects.ClassifiedStatement, s *pg_query.CreateForeignServerStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateForeignServerStmt"
		return
	}
	cs.RawVerb = "CREATE_SERVER"
	objs := []effects.ObjectRef{{
		Kind: effects.ObjectServer,
		Name: strings.ToLower(s.Servername),
	}}
	if host, port := optionsHostPort(s.Options); host != "" || port != 0 {
		objs = append(objs, effects.ObjectRef{
			Kind: effects.ObjectExternalEndpoint,
			Host: host,
			Port: port,
		})
	}
	cs.Effects = []effects.Effect{
		{
			Group:      effects.GroupUnsafeIO,
			Subtype:    effects.SubtypeCreateServer,
			Objects:    objs,
			Resolution: effects.ResolutionQualified,
		},
		{
			Group: effects.GroupSchemaCreate,
			Objects: []effects.ObjectRef{{
				Kind: effects.ObjectServer,
				Name: strings.ToLower(s.Servername),
			}},
			Resolution: effects.ResolutionQualified,
		},
	}
}

// classifyAlterServer maps ALTER SERVER … OPTIONS (…) to
// unsafe_io(alter_server) + schema_alter. If the OPTIONS clause adds/sets a
// host or port, expose it as ObjectExternalEndpoint so policy can match.
func classifyAlterServer(cs *effects.ClassifiedStatement, s *pg_query.AlterForeignServerStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil AlterForeignServerStmt"
		return
	}
	cs.RawVerb = "ALTER_SERVER"
	objs := []effects.ObjectRef{{
		Kind: effects.ObjectServer,
		Name: strings.ToLower(s.Servername),
	}}
	if host, port := optionsHostPort(s.Options); host != "" || port != 0 {
		objs = append(objs, effects.ObjectRef{
			Kind: effects.ObjectExternalEndpoint,
			Host: host,
			Port: port,
		})
	}
	cs.Effects = []effects.Effect{
		{
			Group:      effects.GroupUnsafeIO,
			Subtype:    effects.SubtypeAlterServer,
			Objects:    objs,
			Resolution: effects.ResolutionQualified,
		},
		{
			Group: effects.GroupSchemaAlter,
			Objects: []effects.ObjectRef{{
				Kind: effects.ObjectServer,
				Name: strings.ToLower(s.Servername),
			}},
			Resolution: effects.ResolutionQualified,
		},
	}
}

// ---- USER MAPPING ----

// classifyCreateUserMapping maps CREATE USER MAPPING FOR <role> SERVER <s>
// → unsafe_io(create_user_mapping) + privilege.
//
// The user_mapping ObjectRef name is "<role>@<server>" (mirrors how PostgreSQL
// itself surfaces the pair); a separate ObjectRole references the local role
// so policies that match on roles light up too.
func classifyCreateUserMapping(cs *effects.ClassifiedStatement, s *pg_query.CreateUserMappingStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateUserMappingStmt"
		return
	}
	cs.RawVerb = "CREATE_USER_MAPPING"
	role := roleName(s.User)
	server := strings.ToLower(s.Servername)
	mappingName := role + "@" + server
	cs.Effects = []effects.Effect{
		{
			Group:   effects.GroupUnsafeIO,
			Subtype: effects.SubtypeCreateUserMapping,
			Objects: []effects.ObjectRef{
				{Kind: effects.ObjectUserMapping, Name: mappingName},
				{Kind: effects.ObjectRole, Name: role},
			},
			Resolution: effects.ResolutionQualified,
		},
		{
			Group:      effects.GroupPrivilege,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectUserMapping, Name: mappingName}},
			Resolution: effects.ResolutionQualified,
		},
	}
}

// classifyAlterUserMapping maps ALTER USER MAPPING → unsafe_io(alter_user_mapping)
// + privilege.
func classifyAlterUserMapping(cs *effects.ClassifiedStatement, s *pg_query.AlterUserMappingStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil AlterUserMappingStmt"
		return
	}
	cs.RawVerb = "ALTER_USER_MAPPING"
	role := roleName(s.User)
	server := strings.ToLower(s.Servername)
	mappingName := role + "@" + server
	cs.Effects = []effects.Effect{
		{
			Group:   effects.GroupUnsafeIO,
			Subtype: effects.SubtypeAlterUserMapping,
			Objects: []effects.ObjectRef{
				{Kind: effects.ObjectUserMapping, Name: mappingName},
				{Kind: effects.ObjectRole, Name: role},
			},
			Resolution: effects.ResolutionQualified,
		},
		{
			Group:      effects.GroupPrivilege,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectUserMapping, Name: mappingName}},
			Resolution: effects.ResolutionQualified,
		},
	}
}

// classifyDropUserMapping maps DROP USER MAPPING → unsafe_io(drop_user_mapping)
// + privilege.
func classifyDropUserMapping(cs *effects.ClassifiedStatement, s *pg_query.DropUserMappingStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil DropUserMappingStmt"
		return
	}
	cs.RawVerb = "DROP_USER_MAPPING"
	role := roleName(s.User)
	server := strings.ToLower(s.Servername)
	mappingName := role + "@" + server
	cs.Effects = []effects.Effect{
		{
			Group:   effects.GroupUnsafeIO,
			Subtype: effects.SubtypeDropUserMapping,
			Objects: []effects.ObjectRef{
				{Kind: effects.ObjectUserMapping, Name: mappingName},
				{Kind: effects.ObjectRole, Name: role},
			},
			Resolution: effects.ResolutionQualified,
		},
		{
			Group:      effects.GroupPrivilege,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectUserMapping, Name: mappingName}},
			Resolution: effects.ResolutionQualified,
		},
	}
}

// ---- TABLESPACE ----

// classifyCreateTablespace maps CREATE TABLESPACE … LOCATION '/path' to
// unsafe_io(create_tablespace) + schema_create. The path is exposed as
// ObjectFilesystemPath so policies can deny by path prefix.
func classifyCreateTablespace(cs *effects.ClassifiedStatement, s *pg_query.CreateTableSpaceStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil CreateTableSpaceStmt"
		return
	}
	cs.RawVerb = "CREATE_TABLESPACE"
	objs := []effects.ObjectRef{{
		Kind: effects.ObjectTablespace,
		Name: strings.ToLower(s.Tablespacename),
	}}
	if s.Location != "" {
		objs = append(objs, effects.ObjectRef{
			Kind: effects.ObjectFilesystemPath,
			Path: s.Location,
		})
	}
	cs.Effects = []effects.Effect{
		{
			Group:      effects.GroupUnsafeIO,
			Subtype:    effects.SubtypeCreateTablespace,
			Objects:    objs,
			Resolution: effects.ResolutionQualified,
		},
		{
			Group: effects.GroupSchemaCreate,
			Objects: []effects.ObjectRef{{
				Kind: effects.ObjectTablespace,
				Name: strings.ToLower(s.Tablespacename),
			}},
			Resolution: effects.ResolutionQualified,
		},
	}
}

// classifyAlterTablespace handles ALTER TABLESPACE … SET (…) / RESET (…).
//
// Per spec §7.3 these are pure schema_alter (no unsafe_io) — they tweak
// per-tablespace planner GUCs, not the underlying location. ALTER TABLESPACE
// RENAME / OWNER TO parse to RenameStmt / AlterOwnerStmt, not this node.
func classifyAlterTablespace(cs *effects.ClassifiedStatement, s *pg_query.AlterTableSpaceOptionsStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil AlterTableSpaceOptionsStmt"
		return
	}
	cs.RawVerb = "ALTER_TABLESPACE"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSchemaAlter,
		Subtype: effects.SubtypeAlterTablespace,
		Objects: []effects.ObjectRef{{
			Kind: effects.ObjectTablespace,
			Name: strings.ToLower(s.Tablespacename),
		}},
		Resolution: effects.ResolutionQualified,
	}}
}

// classifyDropTablespace maps DROP TABLESPACE → unsafe_io(drop_tablespace)
// + schema_destroy. Although the on-disk directory is left behind, dropping
// detaches the catalog reference and is paired with admin actions that often
// remove the path; we surface unsafe_io for symmetry with the rest of the
// family.
func classifyDropTablespace(cs *effects.ClassifiedStatement, s *pg_query.DropTableSpaceStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil DropTableSpaceStmt"
		return
	}
	cs.RawVerb = "DROP_TABLESPACE"
	target := effects.ObjectRef{Kind: effects.ObjectTablespace, Name: strings.ToLower(s.Tablespacename)}
	cs.Effects = []effects.Effect{
		{
			Group:      effects.GroupUnsafeIO,
			Subtype:    effects.SubtypeDropTablespace,
			Objects:    []effects.ObjectRef{target},
			Resolution: effects.ResolutionQualified,
		},
		{
			Group:      effects.GroupSchemaDestroy,
			Objects:    []effects.ObjectRef{target},
			Resolution: effects.ResolutionQualified,
		},
	}
}

// classifyDropServer maps DROP SERVER … (parsed as DropStmt
// RemoveType=OBJECT_FOREIGN_SERVER) → unsafe_io(drop_server) + schema_destroy.
//
// classifyDrop in ast_ddl.go falls through to this handler for foreign server
// drops; we keep the implementation here so all external-IO logic lives in
// one file.
func classifyDropServer(cs *effects.ClassifiedStatement, s *pg_query.DropStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: nil DropStmt"
		return
	}
	cs.RawVerb = "DROP_SERVER"
	objs := make([]effects.ObjectRef, 0, len(s.Objects))
	for _, n := range s.Objects {
		if n == nil {
			continue
		}
		if sv, ok := n.Node.(*pg_query.Node_String_); ok && sv.String_ != nil {
			objs = append(objs, effects.ObjectRef{
				Kind: effects.ObjectServer,
				Name: strings.ToLower(sv.String_.Sval),
			})
		}
	}
	if len(objs) == 0 {
		objs = append(objs, effects.ObjectRef{Kind: effects.ObjectServer})
	}
	dest := make([]effects.ObjectRef, len(objs))
	copy(dest, objs)
	cs.Effects = []effects.Effect{
		{
			Group:      effects.GroupUnsafeIO,
			Subtype:    effects.SubtypeDropServer,
			Objects:    objs,
			Resolution: effects.ResolutionQualified,
		},
		{
			Group:      effects.GroupSchemaDestroy,
			Objects:    dest,
			Resolution: effects.ResolutionQualified,
		},
	}
}

// ---- helpers ----

// optionsHostPort scans a DefElem list for "host" and "port" keys (CREATE
// SERVER OPTIONS / ALTER SERVER OPTIONS) and returns the first match of each.
// Values are stored as String_ nodes.
func optionsHostPort(opts []*pg_query.Node) (host string, port int) {
	for _, n := range opts {
		if n == nil {
			continue
		}
		de, ok := n.Node.(*pg_query.Node_DefElem)
		if !ok || de.DefElem == nil {
			continue
		}
		val := defElemString(de.DefElem)
		switch strings.ToLower(de.DefElem.Defname) {
		case "host":
			if host == "" {
				host = val
			}
		case "port":
			if port == 0 && val != "" {
				if n, err := strconv.Atoi(val); err == nil {
					port = n
				}
			}
		}
	}
	return
}

// defElemString returns the string payload of a DefElem.Arg when it's a
// String_ node; otherwise returns "". CREATE/ALTER SERVER OPTIONS values are
// always wrapped in String_, so this is sufficient for host/port extraction.
func defElemString(d *pg_query.DefElem) string {
	if d == nil || d.Arg == nil {
		return ""
	}
	if sv, ok := d.Arg.Node.(*pg_query.Node_String_); ok && sv.String_ != nil {
		return sv.String_.Sval
	}
	return ""
}

// roleName extracts a lowercase role name from a RoleSpec, returning "" when
// the spec is nil or carries one of the special pseudo-roles (CURRENT_USER,
// SESSION_USER, PUBLIC) — those expose no name to the policy layer at this
// pass and are the caller's responsibility to handle.
func roleName(rs *pg_query.RoleSpec) string {
	if rs == nil {
		return ""
	}
	return strings.ToLower(rs.Rolename)
}
