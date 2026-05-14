// internal/db/effects/resolution_test.go
package effects

import "testing"

func TestResolution_String(t *testing.T) {
	cases := []struct {
		r Resolution
		s string
	}{
		{ResolutionQualified, "qualified_syntactic"},
		{ResolutionUnqualified, "unqualified_syntactic"},
		{ResolutionAmbiguousAfterSearchPath, "ambiguous_after_search_path"},
		{ResolutionMaybeTempShadowed, "maybe_temp_shadowed"},
		{ResolutionUnresolved, "unresolved"},
	}
	for _, tc := range cases {
		if got := tc.r.String(); got != tc.s {
			t.Errorf("Resolution(%d).String() = %q, want %q", tc.r, got, tc.s)
		}
	}
}

func TestResolution_Fold(t *testing.T) {
	cases := []struct {
		in   []Resolution
		want Resolution
	}{
		{[]Resolution{ResolutionQualified}, ResolutionQualified},
		{[]Resolution{ResolutionQualified, ResolutionUnqualified}, ResolutionUnqualified},
		{[]Resolution{ResolutionQualified, ResolutionMaybeTempShadowed, ResolutionAmbiguousAfterSearchPath}, ResolutionMaybeTempShadowed},
		{[]Resolution{ResolutionUnresolved, ResolutionQualified}, ResolutionUnresolved},
	}
	for _, tc := range cases {
		if got := Fold(tc.in); got != tc.want {
			t.Errorf("Fold(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestResolution_FoldEmptyIsQualified(t *testing.T) {
	// empty effect list = no objects = best-case confidence; fold should not panic
	if got := Fold(nil); got != ResolutionQualified {
		t.Errorf("Fold(nil) = %s, want qualified_syntactic", got)
	}
}

func TestParseResolution(t *testing.T) {
	cases := []struct {
		in   string
		want Resolution
		ok   bool
	}{
		{"qualified_syntactic", ResolutionQualified, true},
		{"unqualified_syntactic", ResolutionUnqualified, true},
		{"ambiguous_after_search_path", ResolutionAmbiguousAfterSearchPath, true},
		{"maybe_temp_shadowed", ResolutionMaybeTempShadowed, true},
		{"unresolved", ResolutionUnresolved, true},
		{"", 0, false},
		{"nonsense", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseResolution(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseResolution(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestResolutionCatalogTags(t *testing.T) {
	cases := map[string]Resolution{
		"catalog_resolved":    ResolutionCatalogResolved,
		"catalog_unresolved":  ResolutionCatalogUnresolved,
		"catalog_unavailable": ResolutionCatalogUnavailable,
	}
	for name, want := range cases {
		got, ok := ParseResolution(name)
		if !ok || got != want {
			t.Fatalf("ParseResolution(%q) = %v, %v; want %v, true", name, got, ok, want)
		}
		if got := want.String(); got != name {
			t.Fatalf("%v.String() = %q, want %q", want, got, name)
		}
	}
}

func TestFoldResolutionUsesCatalogConfidenceRank(t *testing.T) {
	if got := Fold([]Resolution{ResolutionCatalogResolved, ResolutionQualified}); got != ResolutionQualified {
		t.Fatalf("Fold(catalog_resolved, qualified_syntactic) = %v, want qualified_syntactic", got)
	}
	if got := Fold([]Resolution{ResolutionUnresolved, ResolutionCatalogUnavailable}); got != ResolutionCatalogUnavailable {
		t.Fatalf("Fold(unresolved, catalog_unavailable) = %v, want catalog_unavailable", got)
	}
	if got := Fold([]Resolution{ResolutionCatalogResolved}); got != ResolutionCatalogResolved {
		t.Fatalf("Fold(catalog_resolved) = %v", got)
	}
}
