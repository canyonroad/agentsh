// internal/db/effects/statement_test.go
package effects

import "testing"

func TestClassifiedStatement_Primary(t *testing.T) {
	s := ClassifiedStatement{
		Effects: []Effect{
			{Group: GroupBulkExport, Subtype: SubtypeCopyToStdout},
			{Group: GroupRead},
		},
		ParserBackend: ParserBackendLibPgQuery,
	}
	p, ok := s.Primary()
	if !ok || p.Group != GroupBulkExport {
		t.Errorf("Primary = %v, ok=%v; want bulk_export, true", p, ok)
	}
}

func TestClassifiedStatement_PrimaryEmpty(t *testing.T) {
	var s ClassifiedStatement
	if _, ok := s.Primary(); ok {
		t.Error("Primary on empty statement should return ok=false")
	}
}

func TestClassifiedStatement_FoldResolution(t *testing.T) {
	s := ClassifiedStatement{
		Effects: []Effect{
			{Group: GroupWrite, Resolution: ResolutionQualified},
			{Group: GroupRead, Resolution: ResolutionAmbiguousAfterSearchPath},
		},
	}
	if got := s.FoldResolution(); got != ResolutionAmbiguousAfterSearchPath {
		t.Errorf("FoldResolution() = %s, want ambiguous_after_search_path", got)
	}
}

func TestParserBackend_String(t *testing.T) {
	cases := map[ParserBackend]string{
		ParserBackendLibPgQuery: "libpg_query",
		ParserBackendPureGo:     "pure_go",
		ParserBackendUnknown:    "",
	}
	for b, name := range cases {
		if got := b.String(); got != name {
			t.Errorf("ParserBackend(%d).String() = %q, want %q", b, got, name)
		}
	}
}
