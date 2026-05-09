// internal/db/effects/subtype.go
package effects

// Subtype is an optional refinement on a Group, per §5.1.
// SubtypeNone (zero value) means "no subtype, group-level only".
type Subtype uint8

const (
	SubtypeNone Subtype = iota

	// session subtypes
	SubtypeSet
	SubtypeSetSearchPath
	SubtypeSetRole
	SubtypeSetSessionAuthorization
	SubtypeSetLocal
	SubtypeReset
	SubtypeResetAll
	SubtypeDiscard
	SubtypeDiscardAll
	SubtypeDiscardTemp
	SubtypeDiscardPlans
	SubtypeDiscardSequences
	SubtypeCancelRequest

	// schema_create
	SubtypeCreateTable
	SubtypeCreateIndex
	SubtypeCreateView
	SubtypeCreateSchema
	SubtypeCreateFunction
	SubtypeCreateMaterializedView
	SubtypeCreateExtension
	SubtypeCreateDatabase
	SubtypeCreatePublication

	// schema_alter
	SubtypeAlterPublication

	// schema_destroy
	SubtypeDropTable
	SubtypeDropDatabase
	SubtypeDropSchema
	SubtypeDropIndex
	SubtypeDropView
	SubtypeDropFunction
	SubtypeDropPublication
	SubtypeTruncate

	// privilege
	SubtypeGrant
	SubtypeRevoke
	SubtypeAlterRole
	SubtypeCreateRole
	SubtypeDropRole
	SubtypeAlterSystem
	SubtypeSecurityLabel

	// bulk_load
	SubtypeCopyFromStdin
	SubtypeCopyFromS3

	// bulk_export
	SubtypeCopyToStdout
	SubtypeUnloadToS3

	// procedural
	SubtypeFunctionCallProtocol
	SubtypeCall
	SubtypeDo
	SubtypeAnonymousBlock
	SubtypeDoOrAnon

	// unsafe_io
	SubtypeCreateSubscription
	SubtypeAlterSubscription
	SubtypeDropSubscription
	SubtypeCreateServer
	SubtypeAlterServer
	SubtypeDropServer
	SubtypeCreateUserMapping
	SubtypeAlterUserMapping
	SubtypeDropUserMapping
	SubtypeCreateTablespace
	SubtypeAlterTablespace
	SubtypeDropTablespace
	SubtypeCopyToPath
	SubtypeCopyFromPath
	SubtypeCopyToProgram
	SubtypeCopyFromProgram
	SubtypeLargeObjectIO
	SubtypeServerFileRead
	SubtypeDblinkCall
	SubtypeFdwAccess
)

type subtypeInfo struct {
	name   string
	parent Group
}

var subtypeTable = map[Subtype]subtypeInfo{
	SubtypeNone: {"", 0},

	SubtypeSet:                     {"set", GroupSession},
	SubtypeSetSearchPath:           {"set_search_path", GroupSession},
	SubtypeSetRole:                 {"set_role", GroupSession},
	SubtypeSetSessionAuthorization: {"set_session_authorization", GroupSession},
	SubtypeSetLocal:                {"set_local", GroupSession},
	SubtypeReset:                   {"reset", GroupSession},
	SubtypeResetAll:                {"reset_all", GroupSession},
	SubtypeDiscard:                 {"discard", GroupSession},
	SubtypeDiscardAll:              {"discard_all", GroupSession},
	SubtypeDiscardTemp:             {"discard_temp", GroupSession},
	SubtypeDiscardPlans:            {"discard_plans", GroupSession},
	SubtypeDiscardSequences:        {"discard_sequences", GroupSession},
	SubtypeCancelRequest:           {"cancel_request", GroupSession},

	SubtypeCreateTable:            {"create_table", GroupSchemaCreate},
	SubtypeCreateIndex:            {"create_index", GroupSchemaCreate},
	SubtypeCreateView:             {"create_view", GroupSchemaCreate},
	SubtypeCreateSchema:           {"create_schema", GroupSchemaCreate},
	SubtypeCreateFunction:         {"create_function", GroupSchemaCreate},
	SubtypeCreateMaterializedView: {"create_materialized_view", GroupSchemaCreate},
	SubtypeCreateExtension:        {"create_extension", GroupSchemaCreate},
	SubtypeCreateDatabase:         {"create_database", GroupSchemaCreate},
	SubtypeCreatePublication:      {"create_publication", GroupSchemaCreate},

	SubtypeAlterPublication: {"alter_publication", GroupSchemaAlter},

	SubtypeDropTable:       {"drop_table", GroupSchemaDestroy},
	SubtypeDropDatabase:    {"drop_database", GroupSchemaDestroy},
	SubtypeDropSchema:      {"drop_schema", GroupSchemaDestroy},
	SubtypeDropIndex:       {"drop_index", GroupSchemaDestroy},
	SubtypeDropView:        {"drop_view", GroupSchemaDestroy},
	SubtypeDropFunction:    {"drop_function", GroupSchemaDestroy},
	SubtypeDropPublication: {"drop_publication", GroupSchemaDestroy},
	SubtypeTruncate:        {"truncate", GroupSchemaDestroy},

	SubtypeGrant:         {"grant", GroupPrivilege},
	SubtypeRevoke:        {"revoke", GroupPrivilege},
	SubtypeAlterRole:     {"alter_role", GroupPrivilege},
	SubtypeCreateRole:    {"create_role", GroupPrivilege},
	SubtypeDropRole:      {"drop_role", GroupPrivilege},
	SubtypeAlterSystem:   {"alter_system", GroupPrivilege},
	SubtypeSecurityLabel: {"security_label", GroupPrivilege},

	SubtypeCopyFromStdin: {"copy_from_stdin", GroupBulkLoad},
	SubtypeCopyFromS3:    {"copy_from_s3", GroupBulkLoad},

	SubtypeCopyToStdout: {"copy_to_stdout", GroupBulkExport},
	SubtypeUnloadToS3:   {"unload_to_s3", GroupBulkExport},

	SubtypeFunctionCallProtocol: {"function_call_protocol", GroupProcedural},
	SubtypeCall:                 {"call", GroupProcedural},
	SubtypeDo:                   {"do", GroupProcedural},
	SubtypeAnonymousBlock:       {"anonymous_block", GroupProcedural},
	SubtypeDoOrAnon:             {"do_or_anon", GroupProcedural},

	SubtypeCreateSubscription: {"create_subscription", GroupUnsafeIO},
	SubtypeAlterSubscription:  {"alter_subscription", GroupUnsafeIO},
	SubtypeDropSubscription:   {"drop_subscription", GroupUnsafeIO},
	SubtypeCreateServer:       {"create_server", GroupUnsafeIO},
	SubtypeAlterServer:        {"alter_server", GroupUnsafeIO},
	SubtypeDropServer:         {"drop_server", GroupUnsafeIO},
	SubtypeCreateUserMapping:  {"create_user_mapping", GroupUnsafeIO},
	SubtypeAlterUserMapping:   {"alter_user_mapping", GroupUnsafeIO},
	SubtypeDropUserMapping:    {"drop_user_mapping", GroupUnsafeIO},
	SubtypeCreateTablespace:   {"create_tablespace", GroupUnsafeIO},
	SubtypeAlterTablespace:    {"alter_tablespace", GroupUnsafeIO},
	SubtypeDropTablespace:     {"drop_tablespace", GroupUnsafeIO},
	SubtypeCopyToPath:         {"copy_to_path", GroupUnsafeIO},
	SubtypeCopyFromPath:       {"copy_from_path", GroupUnsafeIO},
	SubtypeCopyToProgram:      {"copy_to_program", GroupUnsafeIO},
	SubtypeCopyFromProgram:    {"copy_from_program", GroupUnsafeIO},
	SubtypeLargeObjectIO:      {"large_object_io", GroupUnsafeIO},
	SubtypeServerFileRead:     {"server_file_read", GroupUnsafeIO},
	SubtypeDblinkCall:         {"dblink_call", GroupUnsafeIO},
	SubtypeFdwAccess:          {"fdw_access", GroupUnsafeIO},
}

func (s Subtype) String() string {
	if info, ok := subtypeTable[s]; ok {
		return info.name
	}
	return ""
}

// Group returns the parent Group this subtype refines. Returns 0 for SubtypeNone.
func (s Subtype) Group() Group {
	if info, ok := subtypeTable[s]; ok {
		return info.parent
	}
	return 0
}
