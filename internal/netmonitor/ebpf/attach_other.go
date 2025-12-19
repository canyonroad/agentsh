//go:build !linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// AttachConnectToCgroup is not supported on non-Linux platforms.
func AttachConnectToCgroup(_ string) (*ebpf.Collection, func() error, error) {
	return nil, nil, fmt.Errorf("ebpf attach not supported on this platform")
}
