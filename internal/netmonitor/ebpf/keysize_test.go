package ebpf

import (
	"encoding/binary"
	"testing"
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
