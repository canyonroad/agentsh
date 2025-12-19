package api

import (
	"net"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestBuildAllowedEndpoints_MixedRules(t *testing.T) {
	t.Cleanup(func() { resolveDomainWithTTL = resolveDomainTTL })
	resolveDomainWithTTL = func(domain string, _ time.Duration) ([]net.IP, time.Duration) {
		switch domain {
		case "a.example.com":
			return []net.IP{net.ParseIP("1.2.3.4")}, 30 * time.Second
		case "b.example.com":
			return []net.IP{net.ParseIP("2001:db8::1")}, 45 * time.Second
		default:
			return nil, 0
		}
	}

	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-a",
				Domains:  []string{"a.example.com"},
				Ports:    []int{443},
				Decision: "allow",
			},
			{
				Name:     "allow-b-cidr",
				CIDRs:    []string{"10.0.0.0/8"},
				Ports:    []int{80},
				Decision: "allow",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false)
	if err != nil {
		t.Fatal(err)
	}
	keys, cidrs, deny, denyCIDRs, strict, hasDomains, ttl := buildAllowedEndpoints(engine, 60*time.Second)
	if !strict {
		t.Fatalf("expected strict for exact domains+cidr")
	}
	if !hasDomains {
		t.Fatalf("expected hasDomains true")
	}
	if ttl == 0 {
		t.Fatalf("expected ttl hint > 0")
	}
	if len(keys) == 0 {
		t.Fatalf("expected resolved domain keys")
	}
	foundIPv4 := false
	foundCIDR := false
	for _, k := range keys {
		if k.Family == 2 && k.Dport == 443 {
			foundIPv4 = true
		}
	}
	if !foundIPv4 {
		t.Fatalf("expected ipv4 allow entry for a.example.com:443")
	}
	for _, c := range cidrs {
		if c.Family == 2 && c.PrefixLen == 8 && c.Dport == 80 {
			foundCIDR = true
		}
	}
	if !foundCIDR {
		t.Fatalf("expected CIDR entry for 10.0.0.0/8:80")
	}
	if len(deny) != 0 || len(denyCIDRs) != 0 {
		t.Fatalf("expected no deny entries")
	}
}

func TestBuildAllowedEndpoints_WildcardForcesNonStrict(t *testing.T) {
	t.Cleanup(func() { resolveDomainWithTTL = resolveDomainTTL })
	resolveDomainWithTTL = func(_ string, _ time.Duration) ([]net.IP, time.Duration) {
		return []net.IP{net.ParseIP("1.1.1.1")}, 10 * time.Second
	}
	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "wild",
				Domains:  []string{"*.example.com"},
				Decision: "allow",
			},
		},
	}
	engine, _ := policy.NewEngine(pol, false)
	_, _, _, _, strict, _, _ := buildAllowedEndpoints(engine, 60*time.Second)
	if strict {
		t.Fatalf("wildcard should keep non-strict (default-deny off)")
	}
}
