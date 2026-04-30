package seccomp

import (
	"testing"
)

func TestParseFamily_Names(t *testing.T) {
	cases := []struct {
		in     string
		wantNr int
	}{
		{"AF_ALG", 38},
		{"AF_VSOCK", 40},
		{"AF_RDS", 21},
		{"AF_TIPC", 30},
		{"AF_KCM", 41},
		{"AF_X25", 9},
		{"AF_AX25", 3},
		{"AF_NETROM", 6},
		{"AF_ROSE", 11},
		{"AF_DECnet", 12},
		{"AF_APPLETALK", 5},
		{"AF_IPX", 4},
		{"AF_INET", 2},
		{"AF_INET6", 10},
		{"AF_UNIX", 1},
		{"AF_NETLINK", 16},
		{"AF_PACKET", 17},
		{"AF_BLUETOOTH", 31},
		{"AF_CAN", 29},
	}
	for _, c := range cases {
		nr, name, ok := ParseFamily(c.in)
		if !ok {
			t.Errorf("ParseFamily(%q): ok=false, want true", c.in)
			continue
		}
		if nr != c.wantNr {
			t.Errorf("ParseFamily(%q): nr=%d, want %d", c.in, nr, c.wantNr)
		}
		if name != c.in {
			t.Errorf("ParseFamily(%q): name=%q, want %q", c.in, name, c.in)
		}
	}
}

func TestParseFamily_NumericFallback(t *testing.T) {
	nr, name, ok := ParseFamily("38")
	if !ok || nr != 38 || name != "" {
		t.Errorf("ParseFamily(\"38\"): got (%d, %q, %v), want (38, \"\", true)", nr, name, ok)
	}
	nr, _, ok = ParseFamily("63") // upper edge of valid range
	if !ok || nr != 63 {
		t.Errorf("ParseFamily(\"63\"): got (%d, _, %v), want (63, _, true)", nr, ok)
	}
}

func TestParseFamily_Invalid(t *testing.T) {
	cases := []string{"", "AF_ALGOG", "AF_NOT_A_THING", "-1", "64", "1000", "abc"}
	for _, in := range cases {
		if _, _, ok := ParseFamily(in); ok {
			t.Errorf("ParseFamily(%q): ok=true, want false", in)
		}
	}
}

func TestDefaultBlockedFamilies(t *testing.T) {
	defaults := DefaultBlockedFamilies()
	if len(defaults) == 0 {
		t.Fatal("DefaultBlockedFamilies returned empty list")
	}
	// AF_ALG must be in defaults — copy.fail mitigation.
	found := false
	for _, bf := range defaults {
		if bf.Name == "AF_ALG" && bf.Family == 38 {
			found = true
			if bf.Action != OnBlockErrno {
				t.Errorf("AF_ALG default action = %s, want errno", bf.Action)
			}
		}
	}
	if !found {
		t.Error("AF_ALG missing from DefaultBlockedFamilies")
	}
	// All defaults must use errno.
	for _, bf := range defaults {
		if bf.Action != OnBlockErrno {
			t.Errorf("default %s action = %s, want errno", bf.Name, bf.Action)
		}
	}
}
