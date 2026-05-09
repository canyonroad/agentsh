// internal/db/effects/subtype_test.go
package effects

import "testing"

func TestSubtype_ParentGroup(t *testing.T) {
	cases := []struct {
		sub  Subtype
		name string
		grp  Group
	}{
		// session subtypes
		{SubtypeSet, "set", GroupSession},
		{SubtypeSetSearchPath, "set_search_path", GroupSession},
		{SubtypeSetRole, "set_role", GroupSession},
		{SubtypeSetSessionAuthorization, "set_session_authorization", GroupSession},
		{SubtypeSetLocal, "set_local", GroupSession},
		{SubtypeReset, "reset", GroupSession},
		{SubtypeResetAll, "reset_all", GroupSession},
		{SubtypeDiscard, "discard", GroupSession},
		{SubtypeDiscardAll, "discard_all", GroupSession},
		{SubtypeDiscardTemp, "discard_temp", GroupSession},
		{SubtypeDiscardPlans, "discard_plans", GroupSession},
		{SubtypeDiscardSequences, "discard_sequences", GroupSession},
		{SubtypeCancelRequest, "cancel_request", GroupSession},

		// schema_create
		{SubtypeCreateTable, "create_table", GroupSchemaCreate},
		{SubtypeCreateIndex, "create_index", GroupSchemaCreate},
		{SubtypeCreateView, "create_view", GroupSchemaCreate},
		{SubtypeCreateSchema, "create_schema", GroupSchemaCreate},
		{SubtypeCreateFunction, "create_function", GroupSchemaCreate},
		{SubtypeCreateMaterializedView, "create_materialized_view", GroupSchemaCreate},
		{SubtypeCreateExtension, "create_extension", GroupSchemaCreate},
		{SubtypeCreateDatabase, "create_database", GroupSchemaCreate},
		{SubtypeCreatePublication, "create_publication", GroupSchemaCreate},

		// schema_alter
		{SubtypeAlterPublication, "alter_publication", GroupSchemaAlter},

		// schema_destroy
		{SubtypeDropTable, "drop_table", GroupSchemaDestroy},
		{SubtypeDropDatabase, "drop_database", GroupSchemaDestroy},
		{SubtypeDropSchema, "drop_schema", GroupSchemaDestroy},
		{SubtypeDropIndex, "drop_index", GroupSchemaDestroy},
		{SubtypeDropView, "drop_view", GroupSchemaDestroy},
		{SubtypeDropFunction, "drop_function", GroupSchemaDestroy},
		{SubtypeDropPublication, "drop_publication", GroupSchemaDestroy},
		{SubtypeTruncate, "truncate", GroupSchemaDestroy},

		// privilege
		{SubtypeGrant, "grant", GroupPrivilege},
		{SubtypeRevoke, "revoke", GroupPrivilege},
		{SubtypeAlterRole, "alter_role", GroupPrivilege},
		{SubtypeCreateRole, "create_role", GroupPrivilege},
		{SubtypeDropRole, "drop_role", GroupPrivilege},
		{SubtypeAlterSystem, "alter_system", GroupPrivilege},
		{SubtypeSecurityLabel, "security_label", GroupPrivilege},

		// bulk_load
		{SubtypeCopyFromStdin, "copy_from_stdin", GroupBulkLoad},
		{SubtypeCopyFromS3, "copy_from_s3", GroupBulkLoad},

		// bulk_export
		{SubtypeCopyToStdout, "copy_to_stdout", GroupBulkExport},
		{SubtypeUnloadToS3, "unload_to_s3", GroupBulkExport},

		// procedural
		{SubtypeFunctionCallProtocol, "function_call_protocol", GroupProcedural},
		{SubtypeCall, "call", GroupProcedural},
		{SubtypeDo, "do", GroupProcedural},
		{SubtypeAnonymousBlock, "anonymous_block", GroupProcedural},
		{SubtypeDoOrAnon, "do_or_anon", GroupProcedural},

		// unsafe_io
		{SubtypeCreateSubscription, "create_subscription", GroupUnsafeIO},
		{SubtypeAlterSubscription, "alter_subscription", GroupUnsafeIO},
		{SubtypeDropSubscription, "drop_subscription", GroupUnsafeIO},
		{SubtypeCreateServer, "create_server", GroupUnsafeIO},
		{SubtypeAlterServer, "alter_server", GroupUnsafeIO},
		{SubtypeDropServer, "drop_server", GroupUnsafeIO},
		{SubtypeCreateUserMapping, "create_user_mapping", GroupUnsafeIO},
		{SubtypeAlterUserMapping, "alter_user_mapping", GroupUnsafeIO},
		{SubtypeDropUserMapping, "drop_user_mapping", GroupUnsafeIO},
		{SubtypeCreateTablespace, "create_tablespace", GroupUnsafeIO},
		{SubtypeAlterTablespace, "alter_tablespace", GroupUnsafeIO},
		{SubtypeDropTablespace, "drop_tablespace", GroupUnsafeIO},
		{SubtypeCopyToPath, "copy_to_path", GroupUnsafeIO},
		{SubtypeCopyFromPath, "copy_from_path", GroupUnsafeIO},
		{SubtypeCopyToProgram, "copy_to_program", GroupUnsafeIO},
		{SubtypeCopyFromProgram, "copy_from_program", GroupUnsafeIO},
		{SubtypeLargeObjectIO, "large_object_io", GroupUnsafeIO},
		{SubtypeServerFileRead, "server_file_read", GroupUnsafeIO},
		{SubtypeDblinkCall, "dblink_call", GroupUnsafeIO},
		{SubtypeFdwAccess, "fdw_access", GroupUnsafeIO},
	}
	for _, tc := range cases {
		if got := tc.sub.String(); got != tc.name {
			t.Errorf("Subtype(%d).String() = %q, want %q", tc.sub, got, tc.name)
		}
		if got := tc.sub.Group(); got != tc.grp {
			t.Errorf("%s.Group() = %s, want %s", tc.name, got, tc.grp)
		}
	}
}

func TestSubtype_NoneIsZero(t *testing.T) {
	var s Subtype
	if s != SubtypeNone {
		t.Errorf("zero Subtype should equal SubtypeNone, got %v", s)
	}
	if s.String() != "" {
		t.Errorf("SubtypeNone.String() should be empty, got %q", s.String())
	}
}
