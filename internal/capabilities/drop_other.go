//go:build !linux

package capabilities

import "errors"

// isAlwaysDrop returns false on non-Linux platforms.
func isAlwaysDrop(cap string) bool {
	return false
}

// ValidateCapabilityAllowList is a no-op on non-Linux platforms.
func ValidateCapabilityAllowList(allow []string) error {
	return nil
}

// DropCapabilities is not supported on non-Linux platforms.
func DropCapabilities(allow []string) error {
	return errors.New("capability dropping only supported on Linux")
}
