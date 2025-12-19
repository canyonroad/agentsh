//go:build linux

package ebpf

import (
	"testing"
)

// Ensure PopulateAllowlist inserts CIDR entries into LPM maps.
func TestPopulateAllowlistCIDR(t *testing.T) {
	coll, err := LoadConnectProgram()
	if err != nil {
		t.Skipf("load bpf object: %v", err)
	}
	defer coll.Close()

	cgid := uint64(1234)
	cidrs := []AllowCIDR{{
		Family:    2,
		PrefixLen: 24,
		Dport:     443,
	}}
	copy(cidrs[0].Addr[:4], []byte{10, 1, 2, 0})

	if err := PopulateAllowlist(coll, cgid, nil, cidrs, nil, nil, false); err != nil {
		t.Fatalf("populate: %v", err)
	}

	lpm4 := coll.Maps["lpm4_allow"]
	if lpm4 == nil {
		t.Fatalf("lpm4_allow missing")
	}

	type lpm4Key struct {
		Prefixlen uint32
		CgroupID  uint64
		Addr      [4]byte
		Dport     uint16
	}
	key := lpm4Key{Prefixlen: 64 + 24 + 16, CgroupID: cgid, Addr: [4]byte{10, 1, 2, 3}, Dport: 443}
	var val uint8
	if err := lpm4.Lookup(key, &val); err != nil {
		t.Fatalf("lookup lpm: %v", err)
	}
	if val != 1 {
		t.Fatalf("expected value 1, got %d", val)
	}

	// Should not match other port
	key.Dport = 80
	if err := lpm4.Lookup(key, &val); err == nil {
		t.Fatalf("expected miss for different port")
	}
}
