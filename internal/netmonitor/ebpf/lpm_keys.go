package ebpf

// Keys of the lpm4_* / lpm6_* LPM trie maps. Field order and sizes must match
// `struct lpm4_key` / `struct lpm6_key` in connect.bpf.c, which are packed:
// encoding/binary (used by cilium/ebpf for plain structs) emits no padding, so
// these marshal to exactly the kernel key_size (18 and 30 bytes).
//
// The trie compares the first Prefixlen bits after Prefixlen, i.e. of
// CgroupID || Dport || Addr. A CIDR entry for a specific port therefore uses
// prefix 64+16+N; an any-port entry stores Dport = 0 with the same prefix and
// is found by the program's second lookup with dport = 0.
type lpm4Key struct {
	Prefixlen uint32
	CgroupID  uint64
	Dport     uint16
	Addr      [4]byte
}

type lpm6Key struct {
	Prefixlen uint32
	CgroupID  uint64
	Dport     uint16
	Addr      [16]byte
}

// lpmPrefixLen is the trie prefix length for a CIDR with addrBits prefix bits.
func lpmPrefixLen(addrBits uint32) uint32 {
	return 64 + 16 + addrBits
}

// maskAddr zeroes address bits beyond the prefix so equal CIDRs map to one
// trie node regardless of host bits in the configured address.
func maskAddr(addr []byte, prefixBits uint32) {
	for i := range addr {
		bit := uint32(i) * 8
		switch {
		case bit >= prefixBits:
			addr[i] = 0
		case bit+8 > prefixBits:
			addr[i] &= byte(0xff << (8 - (prefixBits - bit)))
		}
	}
}

func newLPM4Key(cgroupID uint64, c AllowCIDR) lpm4Key {
	prefix := c.PrefixLen
	if prefix > 32 {
		prefix = 32
	}
	k := lpm4Key{Prefixlen: lpmPrefixLen(prefix), CgroupID: cgroupID, Dport: c.Dport}
	copy(k.Addr[:], c.Addr[:4])
	maskAddr(k.Addr[:], prefix)
	return k
}

func newLPM6Key(cgroupID uint64, c AllowCIDR) lpm6Key {
	prefix := c.PrefixLen
	if prefix > 128 {
		prefix = 128
	}
	k := lpm6Key{Prefixlen: lpmPrefixLen(prefix), CgroupID: cgroupID, Dport: c.Dport}
	copy(k.Addr[:], c.Addr[:])
	maskAddr(k.Addr[:], prefix)
	return k
}
