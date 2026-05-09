// internal/db/effects/subtype_test.go
package effects

import "testing"

func TestSubtype_ParentGroup(t *testing.T) {
	cases := []struct {
		sub  Subtype
		name string
		grp  Group
	}{
		{SubtypeSet, "set", GroupSession},
		{SubtypeSetSearchPath, "set_search_path", GroupSession},
		{SubtypeDiscardPlans, "discard_plans", GroupSession},
		{SubtypeCancelRequest, "cancel_request", GroupSession},
		{SubtypeCreateTable, "create_table", GroupSchemaCreate},
		{SubtypeCreatePublication, "create_publication", GroupSchemaCreate},
		{SubtypeAlterPublication, "alter_publication", GroupSchemaAlter},
		{SubtypeDropTable, "drop_table", GroupSchemaDestroy},
		{SubtypeTruncate, "truncate", GroupSchemaDestroy},
		{SubtypeGrant, "grant", GroupPrivilege},
		{SubtypeAlterSystem, "alter_system", GroupPrivilege},
		{SubtypeCopyFromStdin, "copy_from_stdin", GroupBulkLoad},
		{SubtypeCopyFromS3, "copy_from_s3", GroupBulkLoad},
		{SubtypeCopyToStdout, "copy_to_stdout", GroupBulkExport},
		{SubtypeUnloadToS3, "unload_to_s3", GroupBulkExport},
		{SubtypeFunctionCallProtocol, "function_call_protocol", GroupProcedural},
		{SubtypeCall, "call", GroupProcedural},
		{SubtypeDoOrAnon, "do_or_anon", GroupProcedural},
		{SubtypeCreateSubscription, "create_subscription", GroupUnsafeIO},
		{SubtypeCopyToPath, "copy_to_path", GroupUnsafeIO},
		{SubtypeCopyToProgram, "copy_to_program", GroupUnsafeIO},
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
