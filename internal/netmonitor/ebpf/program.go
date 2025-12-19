package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
)

// connect_bpfel.o is the CO-RE compiled object for connect hooks.
// TODO: replace placeholder with real object during build packaging.
//
//go:embed connect_bpfel.o
var bpfObjBytes []byte

// LoadConnectProgram loads the embedded CO-RE BPF object.
// Caller must attach the programs (handle_connect4/handle_connect6) and close the collection.
func LoadConnectProgram() (*ebpf.Collection, error) {
	if len(bpfObjBytes) == 0 {
		return nil, fmt.Errorf("ebpf object missing (connect_bpfel.o)")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObjBytes))
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create bpf collection: %w", err)
	}
	return coll, nil
}
