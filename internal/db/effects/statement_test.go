// internal/db/effects/statement_test.go
package effects

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

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

func TestClassifiedStatement_ErrorField(t *testing.T) {
	t.Run("zero value is empty string", func(t *testing.T) {
		var cs ClassifiedStatement
		if cs.Error != "" {
			t.Fatalf("zero value Error = %q, want \"\"", cs.Error)
		}
	})

	t.Run("JSON omits empty Error", func(t *testing.T) {
		cs := ClassifiedStatement{Effects: []Effect{{Group: GroupRead}}}
		b, err := json.Marshal(cs)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if bytes.Contains(b, []byte(`"error"`)) {
			t.Fatalf("empty Error leaked into JSON: %s", b)
		}
	})

	t.Run("JSON round-trips populated Error", func(t *testing.T) {
		in := ClassifiedStatement{
			Effects: []Effect{{Group: GroupUnknown}},
			Error:   "parse: syntax error at end of input",
		}
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var out ClassifiedStatement
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if out.Error != in.Error {
			t.Fatalf("Error round-trip: got %q want %q", out.Error, in.Error)
		}
	})
}

func TestClassifiedStatement_SourceSpan_RoundTrip(t *testing.T) {
	in := ClassifiedStatement{
		Effects:     []Effect{{Group: GroupRead, Resolution: ResolutionQualified}},
		RawVerb:     "SELECT",
		SourceStart: 7,
		SourceEnd:   23,
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out ClassifiedStatement
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.SourceStart != in.SourceStart || out.SourceEnd != in.SourceEnd {
		t.Fatalf("span lost: got (%d,%d) want (%d,%d)",
			out.SourceStart, out.SourceEnd, in.SourceStart, in.SourceEnd)
	}
}

func TestClassifiedStatement_SourceSpan_ZeroOmitted(t *testing.T) {
	in := ClassifiedStatement{
		Effects: []Effect{{Group: GroupRead, Resolution: ResolutionQualified}},
		RawVerb: "SELECT",
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(bs), "source_start") || strings.Contains(string(bs), "source_end") {
		t.Fatalf("zero span fields must be omitted: %s", bs)
	}
}
