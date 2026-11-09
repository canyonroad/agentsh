package api

import (
	"net"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestBuildAllowedEndpoints_StrictExactDomain(t *testing.T) {
	t.Cleanup(func() { resolveDomainWithTTL = resolveDomainTTL })
	resolveDomainWithTTL = func(_ string, _ time.Duration) ([]net.IP, time.Duration) {
		return []net.IP{net.ParseIP("1.1.1.1")}, 30 * time.Second
	}
	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-google",
				Domains:  []string{"www.google.com"},
				Ports:    []int{443},
				Decision: "allow",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}
	entries, cidrs, deny, denyCIDRs, strict, _, _ := buildAllowedEndpoints(engine, 60*time.Second)
	if !strict {
		t.Fatalf("expected strict enforcement when only exact domains are present")
	}
	if len(entries) == 0 && len(cidrs) == 0 {
		t.Fatalf("expected entries for resolved domain")
	}
	if len(deny) != 0 || len(denyCIDRs) != 0 {
		t.Fatalf("expected no deny entries")
	}
}

func TestBuildAllowedEndpoints_NonStrictOnWildcard(t *testing.T) {
	t.Cleanup(func() { resolveDomainWithTTL = resolveDomainTTL })
	resolveDomainWithTTL = func(_ string, _ time.Duration) ([]net.IP, time.Duration) {
		return []net.IP{net.ParseIP("1.1.1.1")}, 30 * time.Second
	}
	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-wild",
				Domains:  []string{"*.example.com"},
				Decision: "allow",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, strict, _, _ := buildAllowedEndpoints(engine, 60*time.Second)
	if strict {
		t.Fatalf("wildcard domains should disable strict/default-deny")
	}
}

func TestBuildAllowedEndpoints_NonStrictOnCIDR(t *testing.T) {
	t.Cleanup(func() { resolveDomainWithTTL = resolveDomainTTL })
	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-cidr",
				CIDRs:    []string{"10.0.0.0/8"},
				Decision: "allow",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}
	_, cidrs, _, _, strict, _, _ := buildAllowedEndpoints(engine, 60*time.Second)
	if !strict {
		t.Fatalf("CIDR rules should allow strict/default-deny now that LPM is used")
	}
	if len(cidrs) == 0 {
		t.Fatalf("expected cidr to be included")
	}
}

func TestBuildAllowedEndpoints_PreservesCIDRPorts(t *testing.T) {
	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-cidr-ports",
				CIDRs:    []string{"10.0.0.0/8"},
				Ports:    []int{80, 443},
				Decision: "allow",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}

	_, cidrs, _, _, _, _, _ := buildAllowedEndpoints(engine, 60*time.Second)
	if len(cidrs) != 2 {
		t.Fatalf("CIDR entries = %d, want 2", len(cidrs))
	}
	ports := map[uint16]bool{}
	for _, cidr := range cidrs {
		ports[cidr.Dport] = true
	}
	if !ports[80] || !ports[443] {
		t.Fatalf("CIDR ports = %v, want 80 and 443", ports)
	}
}
