//go:build !linux

package ebpf

import "fmt"

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
