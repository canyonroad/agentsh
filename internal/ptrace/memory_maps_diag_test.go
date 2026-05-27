//go:build linux

package ptrace

import "testing"

func TestParseMapStartsAndNewRanges(t *testing.T) {
	before := []byte(
		"55000000-55001000 r--p 00000000 00:00 0 \n" +
			"7f0000000000-7f0000001000 rw-p 00000000 00:00 0 \n")
	after := []byte(
		"55000000-55001000 r--p 00000000 00:00 0 \n" +
			"7f0000000000-7f0000001000 rw-p 00000000 00:00 0 \n" +
			"5616ca43d000-5616ca43e000 rw-p 00000000 00:00 0 \n")

	starts := parseMapStarts(before)
	if len(starts) != 2 {
		t.Fatalf("parseMapStarts: got %d starts, want 2", len(starts))
	}
	if _, ok := starts[0x55000000]; !ok {
		t.Fatal("expected 0x55000000 among before starts")
	}

	newR := parseNewMapRanges(after, starts)
	if len(newR) != 1 || newR[0] != "5616ca43d000-5616ca43e000" {
		t.Fatalf("parseNewMapRanges: got %v, want [5616ca43d000-5616ca43e000]", newR)
	}

	// No new mappings when after == before set.
	if got := parseNewMapRanges(before, starts); len(got) != 0 {
		t.Fatalf("parseNewMapRanges(before): got %v, want empty", got)
	}
}

func TestParseMapStarts_MalformedLinesSkipped(t *testing.T) {
	data := []byte("garbage\n-\nzz-zz perms\n7f00-7f01 rw-p 0 0:0 0\n")
	starts := parseMapStarts(data)
	if len(starts) != 1 {
		t.Fatalf("got %d starts, want 1 (only the valid line)", len(starts))
	}
	if _, ok := starts[0x7f00]; !ok {
		t.Fatal("expected 0x7f00 from the one valid line")
	}
}
