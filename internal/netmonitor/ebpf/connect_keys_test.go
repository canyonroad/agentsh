//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

// lookupLPM4 mirrors the program's two lookups: exact port first, then the
// any-port entry (dport = 0), both with prefix cgroup_id || dport || addr.
func lookupLPM4(t *testing.T, m *ebpf.Map, cgid uint64, addr [4]byte, dport uint16) bool {
	t.Helper()
	var val uint8
	for _, p := range []uint16{dport, 0} {
		k := lpm4Key{Prefixlen: lpmPrefixLen(32), CgroupID: cgid, Dport: p, Addr: addr}
		if err := m.Lookup(k, &val); err == nil {
			return true
		}
	}
	return false
}

func lookupLPM6(t *testing.T, m *ebpf.Map, cgid uint64, addr [16]byte, dport uint16) bool {
	t.Helper()
	var val uint8
	for _, p := range []uint16{dport, 0} {
		k := lpm6Key{Prefixlen: lpmPrefixLen(128), CgroupID: cgid, Dport: p, Addr: addr}
		if err := m.Lookup(k, &val); err == nil {
			return true
		}
	}
	return false
}

func cidr4(a, b, c, d byte, prefix uint32, dport uint16) AllowCIDR {
	x := AllowCIDR{Family: 2, PrefixLen: prefix, Dport: dport}
	copy(x.Addr[:4], []byte{a, b, c, d})
	return x
}

// Ensure PopulateAllowlist inserts CIDR entries into the LPM maps and that
// the kernel matches them with the semantics the policy intends.
func TestPopulateAllowlistCIDR(t *testing.T) {
	coll, err := LoadConnectProgram()
	if err != nil {
		t.Skipf("load bpf object: %v", err)
	}
	defer coll.Close()

	cgid := uint64(1234)
	allow := []AllowCIDR{
		cidr4(10, 1, 2, 0, 24, 443),   // port-specific subnet
		cidr4(127, 0, 0, 1, 32, 0),    // any-port host
		cidr4(192, 168, 7, 9, 32, 22), // port-specific host
	}
	var v6 AllowCIDR
	v6.Family, v6.PrefixLen = 10, 64
	copy(v6.Addr[:], []byte{0x20, 0x01, 0x0d, 0xb8})
	allow = append(allow, v6)
	deny := []AllowCIDR{cidr4(10, 9, 0, 0, 16, 0)}

	if err := PopulateAllowlist(coll, cgid, nil, allow, nil, deny, false); err != nil {
		t.Fatalf("populate: %v", err)
	}
	lpm4, lpm6, lpm4deny := coll.Maps["lpm4_allow"], coll.Maps["lpm6_allow"], coll.Maps["lpm4_deny"]
	if lpm4 == nil || lpm6 == nil || lpm4deny == nil {
		t.Fatalf("lpm maps missing")
	}

	cases := []struct {
		name  string
		addr  [4]byte
		dport uint16
		want  bool
	}{
		{"subnet+port inside", [4]byte{10, 1, 2, 3}, 443, true},
		{"subnet, other port", [4]byte{10, 1, 2, 3}, 80, false},
		{"outside subnet", [4]byte{10, 1, 3, 3}, 443, false},
		{"any-port host, port 9480", [4]byte{127, 0, 0, 1}, 9480, true},
		{"any-port host, port 22", [4]byte{127, 0, 0, 1}, 22, true},
		{"/32 must not cover neighbour", [4]byte{127, 0, 0, 2}, 9480, false},
		{"port-specific host", [4]byte{192, 168, 7, 9}, 22, true},
		{"port-specific host, other port", [4]byte{192, 168, 7, 9}, 23, false},
		{"other cgroup's address space", [4]byte{8, 8, 8, 8}, 443, false},
	}
	for _, tc := range cases {
		if got := lookupLPM4(t, lpm4, cgid, tc.addr, tc.dport); got != tc.want {
			t.Errorf("allow %s: %v:%d matched=%v, want %v", tc.name, tc.addr, tc.dport, got, tc.want)
		}
	}
	if lookupLPM4(t, lpm4, cgid+1, [4]byte{127, 0, 0, 1}, 9480) {
		t.Errorf("entry leaked to another cgroup")
	}
	if !lookupLPM4(t, lpm4deny, cgid, [4]byte{10, 9, 200, 1}, 5432) {
		t.Errorf("deny /16 any-port did not match")
	}
	if lookupLPM4(t, lpm4deny, cgid, [4]byte{10, 8, 200, 1}, 5432) {
		t.Errorf("deny /16 matched outside its range")
	}

	in6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	out6 := [16]byte{0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if !lookupLPM6(t, lpm6, cgid, in6, 443) {
		t.Errorf("v6 /64 any-port did not match")
	}
	if lookupLPM6(t, lpm6, cgid, out6, 443) {
		t.Errorf("v6 /64 matched outside its range")
	}
}
