// internal/db/effects/alias_test.go
package effects

import (
	"reflect"
	"sort"
	"testing"
)

func sortedGroups(gs []Group) []Group {
	out := append([]Group(nil), gs...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestExpandAliases_SimpleAliases(t *testing.T) {
	cases := []struct {
		alias string
		want  []Group
	}{
		{"READ", []Group{GroupRead}},
		{"INSERT", []Group{GroupWrite}},
		{"UPDATE", []Group{GroupModify}},
		{"DELETE", []Group{GroupDelete}},
		{"REMOVE", []Group{GroupDelete}},
		{"CREATE", []Group{GroupSchemaCreate}}, // R23: NOT INSERT
		{"DROP", []Group{GroupSchemaDestroy}},
		{"ALTER", []Group{GroupSchemaAlter}},
		{"TRUNCATE", []Group{GroupSchemaDestroy}}, // also tracks subtype but expansion is to group
		{"LOAD", []Group{GroupBulkLoad}},
		{"MAINTENANCE", []Group{GroupMaintenance}},
		{"LOCK_TABLES", []Group{GroupLock}},
		{"LISTEN_NOTIFY", []Group{GroupNotify}},
	}
	for _, tc := range cases {
		got, ok := ExpandAlias(tc.alias)
		if !ok {
			t.Fatalf("ExpandAlias(%q) returned ok=false", tc.alias)
		}
		if !reflect.DeepEqual(sortedGroups(got), sortedGroups(tc.want)) {
			t.Errorf("ExpandAlias(%q) = %v, want %v", tc.alias, got, tc.want)
		}
	}
}

func TestExpandAliases_CompoundAliases(t *testing.T) {
	cases := []struct {
		alias string
		want  []Group
	}{
		{"EXPORT", []Group{GroupBulkExport, GroupUnsafeIO}},
		{"MUTATE", []Group{GroupWrite, GroupModify, GroupDelete}},
		{"SCHEMA", []Group{GroupSchemaCreate, GroupSchemaAlter, GroupSchemaDestroy}},
		{"DANGEROUS", []Group{GroupSchemaDestroy, GroupPrivilege, GroupUnsafeIO, GroupProcedural, GroupBulkExport, GroupLock}},
	}
	for _, tc := range cases {
		got, ok := ExpandAlias(tc.alias)
		if !ok {
			t.Fatalf("ExpandAlias(%q) returned ok=false", tc.alias)
		}
		if !reflect.DeepEqual(sortedGroups(got), sortedGroups(tc.want)) {
			t.Errorf("ExpandAlias(%q) = %v, want %v", tc.alias, got, tc.want)
		}
	}
}

func TestExpandAliases_Wildcard(t *testing.T) {
	got, ok := ExpandAlias("*")
	if !ok {
		t.Fatal("ExpandAlias(*) returned ok=false")
	}
	for _, g := range got {
		if g == GroupUnknown {
			t.Errorf("ExpandAlias(*) must not include GroupUnknown")
		}
	}
	if len(got) != 17 { // 18 groups minus unknown
		t.Errorf("ExpandAlias(*) returned %d groups, want 17", len(got))
	}
}

func TestExpandAliases_CanonicalGroupNamePassthrough(t *testing.T) {
	// A canonical lowercase group name like "read" should be a valid token too.
	got, ok := ExpandAlias("read")
	if !ok {
		t.Fatal("canonical lowercase group name should resolve")
	}
	if !reflect.DeepEqual(got, []Group{GroupRead}) {
		t.Errorf("ExpandAlias(read) = %v, want [GroupRead]", got)
	}
}

func TestExpandAliases_Unknown(t *testing.T) {
	if _, ok := ExpandAlias("FAKE"); ok {
		t.Error("ExpandAlias(FAKE) should fail")
	}
}
