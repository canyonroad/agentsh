package service

import "testing"

func TestUnavoidability_StringAndParse(t *testing.T) {
	tests := []struct {
		s    string
		want Unavoidability
		ok   bool
	}{
		{"off", UnavoidabilityOff, true},
		{"observe", UnavoidabilityObserve, true},
		{"enforce", UnavoidabilityEnforce, true},
		{"", UnavoidabilityOff, false},
		{"OFF", UnavoidabilityOff, false},        // case-sensitive
		{"unknown", UnavoidabilityOff, false},
	}
	for _, tc := range tests {
		got, ok := ParseUnavoidability(tc.s)
		if ok != tc.ok || got != tc.want {
			t.Errorf("ParseUnavoidability(%q) = (%v,%v), want (%v,%v)", tc.s, got, ok, tc.want, tc.ok)
		}
		if ok && got.String() != tc.s {
			t.Errorf("Unavoidability(%v).String() = %q, want %q", got, got.String(), tc.s)
		}
	}
}

func TestUnavoidability_ZeroValueIsOff(t *testing.T) {
	var u Unavoidability
	if u != UnavoidabilityOff {
		t.Fatalf("zero-value Unavoidability is %v, want UnavoidabilityOff", u)
	}
}
