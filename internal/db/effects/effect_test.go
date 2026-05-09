// internal/db/effects/effect_test.go
package effects

import (
	"reflect"
	"testing"
)

func e(g Group, sub Subtype) Effect {
	return Effect{Group: g, Subtype: sub, Resolution: ResolutionQualified}
}

func groupsOf(es []Effect) []Group {
	out := make([]Group, len(es))
	for i, eff := range es {
		out[i] = eff.Group
	}
	return out
}

func TestEffect_OrderHighestTierFirst(t *testing.T) {
	// COPY (SELECT * FROM customers) TO STDOUT → bulk_export (critical) beats read (low)
	in := []Effect{e(GroupRead, SubtypeNone), e(GroupBulkExport, SubtypeCopyToStdout)}
	Order(in)
	want := []Group{GroupBulkExport, GroupRead}
	if !reflect.DeepEqual(groupsOf(in), want) {
		t.Errorf("got %v, want %v", groupsOf(in), want)
	}
}

func TestEffect_OrderTieBreakCritical(t *testing.T) {
	// COPY customers TO '/tmp/dump.csv' → unsafe_io and bulk_export both critical;
	// canonical group order puts unsafe_io first.
	in := []Effect{
		e(GroupBulkExport, SubtypeNone),
		e(GroupUnsafeIO, SubtypeCopyToPath),
		e(GroupRead, SubtypeNone),
	}
	Order(in)
	want := []Group{GroupUnsafeIO, GroupBulkExport, GroupRead}
	if !reflect.DeepEqual(groupsOf(in), want) {
		t.Errorf("got %v, want %v", groupsOf(in), want)
	}
}

func TestEffect_OrderTieBreakHigh(t *testing.T) {
	// CTE delete + create_table both high tier; delete > schema_create per §5.2.
	in := []Effect{e(GroupSchemaCreate, SubtypeNone), e(GroupDelete, SubtypeNone)}
	Order(in)
	want := []Group{GroupDelete, GroupSchemaCreate}
	if !reflect.DeepEqual(groupsOf(in), want) {
		t.Errorf("got %v, want %v", groupsOf(in), want)
	}
}

func TestEffect_OrderUnknownIsHighestCritical(t *testing.T) {
	// unknown leads even other critical groups
	in := []Effect{e(GroupUnsafeIO, SubtypeNone), e(GroupUnknown, SubtypeNone)}
	Order(in)
	want := []Group{GroupUnknown, GroupUnsafeIO}
	if !reflect.DeepEqual(groupsOf(in), want) {
		t.Errorf("got %v, want %v", groupsOf(in), want)
	}
}

func TestEffect_OrderStableForEqualPriority(t *testing.T) {
	// Two effects with the exact same group keep input order (AST traversal stability).
	a := Effect{Group: GroupRead, Subtype: SubtypeNone, Objects: []ObjectRef{{Kind: ObjectTable, Name: "a"}}}
	b := Effect{Group: GroupRead, Subtype: SubtypeNone, Objects: []ObjectRef{{Kind: ObjectTable, Name: "b"}}}
	in := []Effect{a, b}
	Order(in)
	if in[0].Objects[0].Name != "a" || in[1].Objects[0].Name != "b" {
		t.Errorf("stable order broken: %v", in)
	}
}

func TestEffect_OrderEmpty(t *testing.T) {
	Order(nil) // must not panic
	Order([]Effect{})
}
