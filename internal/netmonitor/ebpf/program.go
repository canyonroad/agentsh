package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
)

// connect_bpfel.o is the CO-RE compiled object for connect hooks.
// TODO: replace placeholder with real object during build packaging.
//
//go:embed connect_bpfel.o
var bpfObjBytes []byte

//go:embed connect_bpfel_arm64.o
var bpfObjBytesArm64 []byte

var (
	mapAllowOverride   uint32
	mapDenyOverride    uint32
	mapLPMOverride     uint32
	mapLPMDenyOverride uint32
	mapDefaultOverride uint32
	mapOverrideOnce    sync.Once
)

type MapOverrides struct {
	Allow   uint32
	Deny    uint32
	LPM     uint32
	LPMDeny uint32
	Default uint32
}

// SetMapSizeOverrides sets runtime map size overrides for allowlist/LPM/default maps (0 = keep embedded default).
func SetMapSizeOverrides(allow, deny, lpm, lpmDeny, def uint32) {
	mapOverrideOnce.Do(func() {
		mapAllowOverride = allow
		mapDenyOverride = deny
		mapLPMOverride = lpm
		mapLPMDenyOverride = lpmDeny
		mapDefaultOverride = def
	})
}

func GetMapOverrides() MapOverrides {
	return MapOverrides{
		Allow:   mapAllowOverride,
		Deny:    mapDenyOverride,
		LPM:     mapLPMOverride,
		LPMDeny: mapLPMDenyOverride,
		Default: mapDefaultOverride,
	}
}

// EmbeddedMapDefaults returns MaxEntries from the embedded CO-RE object.
func EmbeddedMapDefaults() (MapOverrides, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObjBytes))
	if err != nil {
		return MapOverrides{}, err
	}
	get := func(name string) uint32 {
		if m, ok := spec.Maps[name]; ok {
			return m.MaxEntries
		}
		return 0
	}
	return MapOverrides{
		Allow:   get("allowlist"),
		Deny:    get("denylist"),
		LPM:     get("lpm4_allow"), // assume same for lpm6
		LPMDeny: get("lpm4_deny"),  // assume same for lpm6
		Default: get("default_deny"),
	}, nil
}

// LoadConnectProgram loads the embedded CO-RE BPF object, applying map size overrides if provided.
// Caller must attach the programs (handle_connect4/handle_connect6) and close the collection.
func LoadConnectProgram() (*ebpf.Collection, error) {
	obj := bpfObjBytes
	if runtime.GOARCH == "arm64" {
		if len(bpfObjBytesArm64) == 0 {
			return nil, fmt.Errorf("ebpf object missing (connect_bpfel_arm64.o)")
		}
		obj = bpfObjBytesArm64
	}
	if len(obj) == 0 {
		return nil, fmt.Errorf("ebpf object missing (connect_bpfel.o)")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}

	applyMapOverrides(spec)

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create bpf collection: %w", err)
	}
	return coll, nil
}

func applyMapOverrides(spec *ebpf.CollectionSpec) {
	if spec == nil {
		return
	}
	override := func(name string, v uint32) {
		if v == 0 {
			return
		}
		if m, ok := spec.Maps[name]; ok {
			m.MaxEntries = v
		}
	}
	override("allowlist", mapAllowOverride)
	override("denylist", mapDenyOverride)
	override("lpm4_allow", mapLPMOverride)
	override("lpm6_allow", mapLPMOverride)
	override("lpm4_deny", mapLPMDenyOverride)
	override("lpm6_deny", mapLPMDenyOverride)
	override("default_deny", mapDefaultOverride)
}

// AllowKey mirrors the BPF allow_key.
type AllowKey struct {
	CgroupID uint64
	Family   uint8
	Protocol uint8 // IPPROTO_TCP (6) or IPPROTO_UDP (17), 0 = any
	Dport    uint16
	Addr     [16]byte
}

// AllowCIDR represents a CIDR prefix allowed for a cgroup.
type AllowCIDR struct {
	CgroupID  uint64
	Family    uint8
	Protocol  uint8  // IPPROTO_TCP (6) or IPPROTO_UDP (17), 0 = any
	PrefixLen uint32
	Dport     uint16 // 0 means any port
	Addr      [16]byte
}
