package ebpf

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
)

// Ensures map size overrides are applied at load time.
func TestLoadConnectProgram_MapOverrides(t *testing.T) {
	resetOverrides()
	SetMapSizeOverrides(10, 9, 11, 8, 12)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObjBytes))
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	applyMapOverrides(spec)
	check := func(name string, want uint32) {
		m := spec.Maps[name]
		if m == nil {
			t.Fatalf("%s map missing", name)
		}
		if m.MaxEntries != want {
			t.Fatalf("%s MaxEntries=%d want %d", name, m.MaxEntries, want)
		}
	}
	check("allowlist", 10)
	check("lpm4_allow", 11)
	check("lpm6_allow", 11)
	check("denylist", 9)
	check("lpm4_deny", 8)
	check("lpm6_deny", 8)
	check("default_deny", 12)
}
