//go:build linux

package netmonitor

import "testing"

func TestNatOutputRules_LoopbackDNATBeforeLoopbackReturn(t *testing.T) {
	rules := natOutputRules("10.0.0.1", "10.0.0.1:5000", "10.0.0.1:5300", []int{9050, 9150})

	idxReturn := -1
	idx9050, idx9150 := -1, -1
	for i, r := range rules {
		joined := ""
		for _, a := range r {
			joined += a + " "
		}
		switch {
		case contains(r, "127.0.0.0/8") && contains(r, "RETURN"):
			idxReturn = i
		case contains(r, "127.0.0.1") && contains(r, "9050"):
			idx9050 = i
		case contains(r, "127.0.0.1") && contains(r, "9150"):
			idx9150 = i
		}
		_ = joined
	}
	if idx9050 < 0 || idx9150 < 0 || idxReturn < 0 {
		t.Fatalf("missing rules: dnat9050=%d dnat9150=%d return=%d", idx9050, idx9150, idxReturn)
	}
	if idx9050 >= idxReturn || idx9150 >= idxReturn {
		t.Fatalf("loopback DNAT must precede 127.0.0.0/8 RETURN: dnat9050=%d dnat9150=%d return=%d", idx9050, idx9150, idxReturn)
	}
}

func TestNatOutputRules_NoTorPorts_NoLoopbackDNAT(t *testing.T) {
	rules := natOutputRules("10.0.0.1", "10.0.0.1:5000", "10.0.0.1:5300", nil)
	for _, r := range rules {
		if contains(r, "127.0.0.1") && contains(r, "DNAT") {
			t.Fatal("no Tor ports → no loopback DNAT rule expected")
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
