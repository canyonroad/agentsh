//go:build linux

package ptrace

import "testing"

func TestNetworkContextDNSFields(t *testing.T) {
	nc := NetworkContext{
		PID:       1,
		Operation: "dns",
		Domain:    "example.com",
		QueryType: 1, // A record
	}
	if nc.Domain != "example.com" {
		t.Fatal("Domain field not set")
	}
	if nc.QueryType != 1 {
		t.Fatal("QueryType field not set")
	}
}

func TestNetworkResultDNSFields(t *testing.T) {
	r := NetworkResult{
		Allow:            false,
		RedirectUpstream: "10.0.0.1:53",
		Records: []DNSRecord{
			{Type: 1, Value: "93.184.216.34", TTL: 300},
		},
	}
	if r.RedirectUpstream != "10.0.0.1:53" {
		t.Fatal("RedirectUpstream field not set")
	}
	if len(r.Records) != 1 {
		t.Fatal("Records field not set")
	}
}
