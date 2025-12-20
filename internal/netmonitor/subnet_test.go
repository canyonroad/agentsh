package netmonitor

import "testing"

func TestAllocateSubnetDeterministic(t *testing.T) {
	a, b, c, hostIf, nsIf := AllocateSubnet("10.250.0.0/16", "ns-one")
	a2, b2, c2, hostIf2, nsIf2 := AllocateSubnet("10.250.0.0/16", "ns-one")
	if a != a2 || b != b2 || c != c2 || hostIf != hostIf2 || nsIf != nsIf2 {
		t.Fatalf("expected deterministic outputs, got %v %v %v %v %v vs %v %v %v %v %v", a, b, c, hostIf, nsIf, a2, b2, c2, hostIf2, nsIf2)
	}
	if hostIf == nsIf {
		t.Fatalf("host and ns interface names should differ")
	}
}

func TestAllocateSubnetFallbackOnInvalidBase(t *testing.T) {
	subnet, host, ns, _, _ := AllocateSubnet("invalid", "ns-two")
	if subnet == "" || host == "" || ns == "" {
		t.Fatalf("expected non-empty outputs on fallback")
	}
}
