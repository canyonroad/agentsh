//go:build linux

package ebpf

const (
	// LPM data starts after Prefixlen and includes the C alignment pad.
	lpmFixedPrefixBits   uint32 = 32 + 64 + 16
	lpm4LookupPrefixBits uint32 = 160
	lpm6LookupPrefixBits uint32 = 288
)

// These explicit pads keep encoding/binary aligned with the embedded BPF ABI.
type lpm4Key struct {
	Prefixlen uint32
	_         [4]byte
	CgroupID  uint64
	Dport     uint16
	Addr      [4]byte
	_         [2]byte
}

type lpm6Key struct {
	Prefixlen uint32
	_         [4]byte
	CgroupID  uint64
	Dport     uint16
	Addr      [16]byte
	_         [6]byte
}

func lpmPrefixlen(addressBits uint32) uint32 {
	return lpmFixedPrefixBits + addressBits
}
