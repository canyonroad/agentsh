package effects

import "testing"

func TestGroup_RiskTierAndString(t *testing.T) {
	cases := []struct {
		group Group
		name  string
		tier  RiskTier
	}{
		{GroupRead, "read", Low},
		{GroupWrite, "write", Medium},
		{GroupModify, "modify", Medium},
		{GroupDelete, "delete", High},
		{GroupBulkLoad, "bulk_load", High},
		{GroupBulkExport, "bulk_export", Critical},
		{GroupSchemaCreate, "schema_create", High},
		{GroupSchemaAlter, "schema_alter", High},
		{GroupSchemaDestroy, "schema_destroy", Critical},
		{GroupPrivilege, "privilege", Critical},
		{GroupTransaction, "transaction", Low},
		{GroupSession, "session", Low},
		{GroupMaintenance, "maintenance", Medium},
		{GroupLock, "lock", Medium},
		{GroupNotify, "notify", Low},
		{GroupProcedural, "procedural", High},
		{GroupUnsafeIO, "unsafe_io", Critical},
		{GroupUnknown, "unknown", Critical},
	}
	for _, tc := range cases {
		if got := tc.group.String(); got != tc.name {
			t.Errorf("Group(%d).String() = %q, want %q", tc.group, got, tc.name)
		}
		if got := tc.group.RiskTier(); got != tc.tier {
			t.Errorf("%s.RiskTier() = %s, want %s", tc.name, got, tc.tier)
		}
	}
}

func TestParseGroup(t *testing.T) {
	g, ok := ParseGroup("unsafe_io")
	if !ok || g != GroupUnsafeIO {
		t.Fatalf("ParseGroup(unsafe_io) = %v, %v; want GroupUnsafeIO, true", g, ok)
	}
	if _, ok := ParseGroup("garbage"); ok {
		t.Fatal("ParseGroup(garbage) should fail")
	}
}
