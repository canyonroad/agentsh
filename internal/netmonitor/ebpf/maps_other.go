//go:build !linux

package ebpf

import "fmt"

type MapCounts struct {
	AllowCgroup    uint64
	AllowTotal     uint64
	DenyCgroup     uint64
	DenyTotal      uint64
	LpmAllowCgroup uint64
	LpmAllowTotal  uint64
	LpmDenyCgroup  uint64
	LpmDenyTotal   uint64
}

func PopulateAllowlist(_ any, _ uint64, _ []AllowKey, _ []AllowCIDR, _ []AllowKey, _ []AllowCIDR, _ bool) error {
	return fmt.Errorf("ebpf maps not supported on this platform")
}

func CleanupAllowlist(_ any, _ uint64) error {
	return nil
}

// GetLastMapCounts returns zeros on non-Linux platforms.
func GetLastMapCounts() MapCounts {
	return MapCounts{}
}
