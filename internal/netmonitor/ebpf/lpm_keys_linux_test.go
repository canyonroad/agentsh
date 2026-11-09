//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestLPMKeyMarshalSizesMatchEmbeddedMaps(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObjBytes))
	if err != nil {
		t.Fatalf("load embedded BPF collection spec: %v", err)
	}

	tests := []struct {
		mapName     string
		key         any
		wantKeySize int
	}{
		{mapName: "lpm4_allow", key: lpm4Key{}, wantKeySize: 24},
		{mapName: "lpm6_allow", key: lpm6Key{}, wantKeySize: 40},
		{mapName: "lpm4_deny", key: lpm4Key{}, wantKeySize: 24},
		{mapName: "lpm6_deny", key: lpm6Key{}, wantKeySize: 40},
	}
	for _, tt := range tests {
		t.Run(tt.mapName, func(t *testing.T) {
			mapSpec, ok := spec.Maps[tt.mapName]
			if !ok {
				t.Fatalf("embedded BPF map %q is missing", tt.mapName)
			}
			if got := int(mapSpec.KeySize); got != tt.wantKeySize {
				t.Fatalf(
					"embedded map key_size = %d, want %d",
					got,
					tt.wantKeySize,
				)
			}
			if got, want := binary.Size(tt.key), int(mapSpec.KeySize); got != want {
				t.Fatalf(
					"binary.Size(%T) = %d, embedded map key_size = %d",
					tt.key,
					got,
					want,
				)
			}
			keyStruct, ok := btf.UnderlyingType(mapSpec.Key).(*btf.Struct)
			if !ok {
				t.Fatalf("embedded map key type = %T, want *btf.Struct", mapSpec.Key)
			}
			assertBTFMemberOffset(t, keyStruct, "dport", 16)
			assertBTFMemberOffset(t, keyStruct, "addr", 18)
		})
	}
}

func assertBTFMemberOffset(t *testing.T, keyStruct *btf.Struct, name string, want uint32) {
	t.Helper()
	for _, member := range keyStruct.Members {
		if member.Name != name {
			continue
		}
		if got := member.Offset.Bytes(); got != want {
			t.Fatalf("embedded %s.%s offset = %d, want %d", keyStruct.Name, name, got, want)
		}
		return
	}
	t.Fatalf("embedded %s key has no %q member", keyStruct.Name, name)
}

func TestLPMPrefixlenIncludesAlignedCgroupOffset(t *testing.T) {
	tests := []struct {
		name        string
		addressBits uint32
		want        uint32
	}{
		{name: "ipv4 partial", addressBits: 24, want: 32 + 64 + 16 + 24},
		{name: "ipv4 exact", addressBits: 32, want: 32 + 64 + 16 + 32},
		{name: "ipv6 partial", addressBits: 64, want: 32 + 64 + 16 + 64},
		{name: "ipv6 exact", addressBits: 128, want: 32 + 64 + 16 + 128},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lpmPrefixlen(tt.addressBits); got != tt.want {
				t.Fatalf("lpmPrefixlen(%d) = %d, want %d", tt.addressBits, got, tt.want)
			}
		})
	}
}

func TestLPMKeyFieldOffsets(t *testing.T) {
	v4 := lpm4Key{}
	if got, want := unsafe.Offsetof(v4.Dport), uintptr(16); got != want {
		t.Fatalf("lpm4Key.Dport offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(v4.Addr), uintptr(18); got != want {
		t.Fatalf("lpm4Key.Addr offset = %d, want %d", got, want)
	}

	v6 := lpm6Key{}
	if got, want := unsafe.Offsetof(v6.Dport), uintptr(16); got != want {
		t.Fatalf("lpm6Key.Dport offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(v6.Addr), uintptr(18); got != want {
		t.Fatalf("lpm6Key.Addr offset = %d, want %d", got, want)
	}
}

func TestLPMLookupPrefixesUseFullMapDataWidth(t *testing.T) {
	if got, want := lpm4LookupPrefixBits, uint32((binary.Size(lpm4Key{})-4)*8); got != want {
		t.Fatalf("lpm4 lookup prefix = %d, want %d", got, want)
	}
	if got, want := lpm6LookupPrefixBits, uint32((binary.Size(lpm6Key{})-4)*8); got != want {
		t.Fatalf("lpm6 lookup prefix = %d, want %d", got, want)
	}
}

func TestLPMCIDRPortPrefixSemantics(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		stored := lpm4Key{
			Prefixlen: lpmPrefixlen(24),
			CgroupID:  1234,
			Dport:     443,
			Addr:      [4]byte{10, 1, 2, 0},
		}
		tests := []struct {
			name  string
			key   lpm4Key
			match bool
		}{
			{
				name:  "inside first host",
				key:   lpm4Key{Prefixlen: lpm4LookupPrefixBits, CgroupID: 1234, Dport: 443, Addr: [4]byte{10, 1, 2, 3}},
				match: true,
			},
			{
				name:  "inside second host",
				key:   lpm4Key{Prefixlen: lpm4LookupPrefixBits, CgroupID: 1234, Dport: 443, Addr: [4]byte{10, 1, 2, 99}},
				match: true,
			},
			{
				name: "outside cidr",
				key:  lpm4Key{Prefixlen: lpm4LookupPrefixBits, CgroupID: 1234, Dport: 443, Addr: [4]byte{10, 1, 3, 3}},
			},
			{
				name: "wrong port",
				key:  lpm4Key{Prefixlen: lpm4LookupPrefixBits, CgroupID: 1234, Dport: 80, Addr: [4]byte{10, 1, 2, 3}},
			},
			{
				name: "wrong cgroup",
				key:  lpm4Key{Prefixlen: lpm4LookupPrefixBits, CgroupID: 5678, Dport: 443, Addr: [4]byte{10, 1, 2, 3}},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := lpmKeyPrefixMatches(t, stored, tt.key); got != tt.match {
					t.Fatalf("prefix match = %v, want %v", got, tt.match)
				}
			})
		}

		anyPort := stored
		anyPort.Dport = 0
		fallback := tests[0].key
		fallback.Dport = 0
		if !lpmKeyPrefixMatches(t, anyPort, fallback) {
			t.Fatal("port-zero fallback did not match IPv4 any-port CIDR")
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		stored := lpm6Key{
			Prefixlen: lpmPrefixlen(64),
			CgroupID:  1234,
			Dport:     443,
			Addr:      [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1},
		}
		inside := lpm6Key{
			Prefixlen: lpm6LookupPrefixBits,
			CgroupID:  1234,
			Dport:     443,
			Addr:      [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99},
		}
		if !lpmKeyPrefixMatches(t, stored, inside) {
			t.Fatal("IPv6 address inside /64 did not match")
		}

		outside := inside
		outside.Addr[7] = 1
		if lpmKeyPrefixMatches(t, stored, outside) {
			t.Fatal("IPv6 address outside /64 matched")
		}

		wrongPort := inside
		wrongPort.Dport = 80
		if lpmKeyPrefixMatches(t, stored, wrongPort) {
			t.Fatal("IPv6 CIDR matched the wrong port")
		}

		anyPort := stored
		anyPort.Dport = 0
		fallback := inside
		fallback.Dport = 0
		if !lpmKeyPrefixMatches(t, anyPort, fallback) {
			t.Fatal("port-zero fallback did not match IPv6 any-port CIDR")
		}
	})
}

func lpmKeyPrefixMatches(t *testing.T, stored, lookup any) bool {
	t.Helper()
	storedBytes := marshalLPMTestKey(t, stored)
	lookupBytes := marshalLPMTestKey(t, lookup)
	prefixlen := binary.NativeEndian.Uint32(storedBytes[:4])
	if lookupPrefixlen := binary.NativeEndian.Uint32(lookupBytes[:4]); lookupPrefixlen < prefixlen {
		return false
	}

	storedData := storedBytes[4:]
	lookupData := lookupBytes[4:]
	fullBytes := prefixlen / 8
	if !bytes.Equal(storedData[:fullBytes], lookupData[:fullBytes]) {
		return false
	}
	remaining := prefixlen % 8
	if remaining == 0 {
		return true
	}
	mask := byte(0xff << (8 - remaining))
	return storedData[fullBytes]&mask == lookupData[fullBytes]&mask
}

func marshalLPMTestKey(t *testing.T, key any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, key); err != nil {
		t.Fatalf("marshal LPM key: %v", err)
	}
	return buf.Bytes()
}
