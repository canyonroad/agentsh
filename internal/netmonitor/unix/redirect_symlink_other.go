//go:build (!linux || !cgo) && !windows

package unix

import "errors"

// CreateStubSymlink is not supported on non-Linux platforms.
func CreateStubSymlink(stubBinaryPath string) (string, func(), error) {
	return "", nil, errors.New("stub symlink not supported on this platform")
}
