//go:build linux

package ebpf

import (
	"errors"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
)

func TestPopulateRefreshAndCleanupCIDRs(t *testing.T) {
	coll, err := LoadConnectProgram()
	if err != nil {
		t.Skipf("load bpf object: %v", err)
	}
	defer coll.Close()

	const (
		cgroupID      = uint64(1234)
		otherCgroupID = uint64(5678)
	)
	allowCIDRs := []AllowCIDR{
		{Family: 2, PrefixLen: 24, Dport: 443, Addr: [16]byte{10, 1, 2, 0}},
		{Family: 10, PrefixLen: 64, Dport: 443, Addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1}},
	}
	denyCIDRs := []AllowCIDR{
		{Family: 2, PrefixLen: 24, Dport: 80, Addr: [16]byte{10, 2, 3, 0}},
		{Family: 10, PrefixLen: 64, Dport: 80, Addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 2}},
	}

	for _, cgroupID := range []uint64{cgroupID, otherCgroupID} {
		if err := PopulateAllowlist(coll, cgroupID, nil, allowCIDRs, nil, denyCIDRs, true); err != nil {
			t.Fatalf("populate cgroup %d: %v", cgroupID, err)
		}
	}

	maps := []struct {
		name string
		key  any
	}{
		{name: "lpm4_allow", key: lpm4Key{Prefixlen: lpm4LookupPrefixBits, CgroupID: cgroupID, Dport: 443, Addr: [4]byte{10, 1, 2, 3}}},
		{name: "lpm6_allow", key: lpm6Key{Prefixlen: lpm6LookupPrefixBits, CgroupID: cgroupID, Dport: 443, Addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}}},
		{name: "lpm4_deny", key: lpm4Key{Prefixlen: lpm4LookupPrefixBits, CgroupID: cgroupID, Dport: 80, Addr: [4]byte{10, 2, 3, 3}}},
		{name: "lpm6_deny", key: lpm6Key{Prefixlen: lpm6LookupPrefixBits, CgroupID: cgroupID, Dport: 80, Addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}}},
	}
	for _, tt := range maps {
		expectLPMMapEntry(t, coll.Maps[tt.name], tt.key, true)
	}

	if err := PopulateAllowlist(coll, cgroupID, nil, nil, nil, nil, false); err != nil {
		t.Fatalf("refresh cgroup: %v", err)
	}
	for _, tt := range maps {
		expectLPMMapEntry(t, coll.Maps[tt.name], tt.key, false)
		otherKey := lpmKeyWithCgroup(t, tt.key, otherCgroupID)
		expectLPMMapEntry(t, coll.Maps[tt.name], otherKey, true)
	}

	if err := PopulateAllowlist(coll, cgroupID, nil, allowCIDRs, nil, denyCIDRs, true); err != nil {
		t.Fatalf("repopulate cgroup: %v", err)
	}
	if err := CleanupAllowlist(coll, cgroupID); err != nil {
		t.Fatalf("cleanup cgroup: %v", err)
	}
	if err := CleanupAllowlist(coll, cgroupID); err != nil {
		t.Fatalf("repeat cleanup cgroup: %v", err)
	}
	for _, tt := range maps {
		expectLPMMapEntry(t, coll.Maps[tt.name], tt.key, false)
		otherKey := lpmKeyWithCgroup(t, tt.key, otherCgroupID)
		expectLPMMapEntry(t, coll.Maps[tt.name], otherKey, true)
	}
}

func expectLPMMapEntry(t *testing.T, m *ciliumebpf.Map, key any, want bool) {
	t.Helper()
	if m == nil {
		t.Fatal("LPM map is missing")
	}
	var value uint8
	err := m.Lookup(key, &value)
	if want {
		if err != nil {
			t.Fatalf("lookup %T: %v", key, err)
		}
		if value != 1 {
			t.Fatalf("lookup %T value = %d, want 1", key, value)
		}
		return
	}
	if !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		t.Fatalf("lookup %T error = %v, want ErrKeyNotExist", key, err)
	}
}

func lpmKeyWithCgroup(t *testing.T, key any, cgroupID uint64) any {
	t.Helper()
	switch key := key.(type) {
	case lpm4Key:
		key.CgroupID = cgroupID
		return key
	case lpm6Key:
		key.CgroupID = cgroupID
		return key
	default:
		t.Fatalf("unsupported LPM key type %T", key)
		return nil
	}
}
