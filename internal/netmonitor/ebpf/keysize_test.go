package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// TestAllowKey_BinarySizeMatchesBPFMap asserts that AllowKey marshals to the
// same number of bytes as the kernel BPF map's declared key_size for
// `struct allow_key` in connect.bpf.c.
//
// The C struct compiles to 32 bytes because the trailing 16-byte addr is
// followed by an implicit pad up to __u64 alignment (the leading
// cgroup_id field). encoding/binary, used by cilium/ebpf for plain Go
// structs that do not implement BinaryMarshaler, emits no trailing
// padding — so without an explicit `_ [4]byte` tail, AllowKey marshals
// to 28 bytes and cilium/ebpf rejects every Put with
// "ebpf.AllowKey doesn't marshal to 32 bytes", silently disabling
// connect-filter enforcement at runtime.
//
// See issue #349.
func TestAllowKey_BinarySizeMatchesBPFMap(t *testing.T) {
	const wantBytes = 32
	got := binary.Size(AllowKey{})
	if got != wantBytes {
		t.Errorf("binary.Size(AllowKey{}) = %d, want %d (kernel BPF map declares key_size=32 due to __u64 alignment)", got, wantBytes)
	}
}

// TestMapKeys_MatchEmbeddedObjects checks every Go map key type against the
// key_size each embedded BPF object (x86 and arm64) declares for its map.
// It needs no privileges, unlike the kernel-backed tests in
// connect_keys_test.go, which skip when the program cannot load.
//
// Without it, lpm4Key (18 bytes) vs the kernel's padded `struct lpm4_key`
// (24 bytes) went unnoticed: every CIDR rule failed with
// "lpm4Key doesn't marshal to 24 bytes" once eBPF enforcement was on.
func TestMapKeys_MatchEmbeddedObjects(t *testing.T) {
	keys := map[string]int{
		"allowlist":  binary.Size(AllowKey{}),
		"denylist":   binary.Size(AllowKey{}),
		"lpm4_allow": binary.Size(lpm4Key{}),
		"lpm4_deny":  binary.Size(lpm4Key{}),
		"lpm6_allow": binary.Size(lpm6Key{}),
		"lpm6_deny":  binary.Size(lpm6Key{}),
	}
	for name, obj := range map[string][]byte{"connect_bpfel.o": bpfObjBytes, "connect_bpfel_arm64.o": bpfObjBytesArm64} {
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
		if err != nil {
			t.Fatalf("%s: load spec: %v", name, err)
		}
		for m, goSize := range keys {
			ms := spec.Maps[m]
			if ms == nil {
				t.Fatalf("%s: map %s missing", name, m)
			}
			if int(ms.KeySize) != goSize {
				t.Errorf("%s: map %s key_size=%d, Go key marshals to %d bytes", name, m, ms.KeySize, goSize)
			}
		}
	}
}

func TestNewLPMKeys(t *testing.T) {
	c := AllowCIDR{Family: 2, PrefixLen: 20, Dport: 443}
	copy(c.Addr[:4], []byte{10, 1, 0xff, 7})
	k := newLPM4Key(77, c)
	if k.Prefixlen != 64+16+20 || k.CgroupID != 77 || k.Dport != 443 {
		t.Fatalf("unexpected key %+v", k)
	}
	if k.Addr != [4]byte{10, 1, 0xf0, 0} {
		t.Fatalf("host bits not masked: %v", k.Addr)
	}

	c6 := AllowCIDR{Family: 10, PrefixLen: 200}
	for i := range c6.Addr {
		c6.Addr[i] = 0xff
	}
	k6 := newLPM6Key(1, c6)
	if k6.Prefixlen != 64+16+128 || k6.Dport != 0 || k6.Addr[15] != 0xff {
		t.Fatalf("unexpected v6 key %+v", k6)
	}
}
