//go:build !linux || !cgo

package api

// registerFUSEMount is a no-op on non-Linux platforms.
// The MountRegistry and seccomp file monitoring are Linux-only features.
func registerFUSEMount(sessionID, sourcePath string) {}

// deregisterFUSEMount is a no-op on non-Linux platforms.
func deregisterFUSEMount(sessionID, sourcePath string) {}
