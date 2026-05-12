// internal/db/effects/effect_test.go
package effects

import (
	"encoding/json"
	"reflect"
	"strings"
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

func TestEffect_FunctionOID_RoundTrip(t *testing.T) {
	oid := int32(12345)
	in := Effect{
		Group:       GroupProcedural,
		Subtype:     SubtypeFunctionCallProtocol,
		FunctionOID: &oid,
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(bs), `"function_oid":12345`) {
		t.Fatalf("missing function_oid: %s", bs)
	}
	var out Effect
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.FunctionOID == nil || *out.FunctionOID != 12345 {
		t.Fatalf("FunctionOID round-trip lost value: %v", out.FunctionOID)
	}
}

func TestEffect_FunctionOID_OmitEmpty(t *testing.T) {
	in := Effect{Group: GroupRead}
	bs, _ := json.Marshal(in)
	if strings.Contains(string(bs), "function_oid") {
		t.Fatalf("function_oid should be omitted; got %s", bs)
	}
}
