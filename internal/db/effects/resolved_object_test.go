package effects

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResolvedObjectRef_JSONRoundTripRelation(t *testing.T) {
	in := ResolvedObjectRef{
		Source:       ResolvedObjectSourceCatalog,
		Kind:         ResolvedObjectRelation,
		OID:          1259,
		Schema:       "public",
		Name:         "users",
		RelationKind: "table",
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out ResolvedObjectRef
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Source != ResolvedObjectSourceCatalog || out.Kind != ResolvedObjectRelation || out.OID != 1259 {
		t.Fatalf("round trip = %+v", out)
	}
	if out.CanonicalName() != "public.users" {
		t.Fatalf("CanonicalName = %q", out.CanonicalName())
	}
}

func TestResolvedObjectRef_JSONRoundTripFunction(t *testing.T) {
	in := ResolvedObjectRef{
		Source:               ResolvedObjectSourceCatalog,
		Kind:                 ResolvedObjectFunction,
		OID:                  42,
		Schema:               "public",
		Name:                 "normalize_email",
		FunctionIdentityArgs: "text",
		FunctionVolatility:   "immutable",
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out ResolvedObjectRef
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.FunctionIdentityArgs != "text" || out.FunctionVolatility != "immutable" {
		t.Fatalf("function metadata = %+v", out)
	}
}

func TestEffectResolvedObjectsOmitWhenEmpty(t *testing.T) {
	raw, err := json.Marshal(Effect{Group: GroupRead})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(raw) == "" || string(raw) == "null" {
		t.Fatalf("unexpected raw JSON: %s", raw)
	}
	if strings.Contains(string(raw), `"resolved_objects"`) {
		t.Fatalf("resolved_objects should be omitted when empty: %s", raw)
	}
}
