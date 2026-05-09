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
