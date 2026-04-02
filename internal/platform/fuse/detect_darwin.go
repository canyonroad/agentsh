// internal/platform/fuse/detect_darwin.go
//go:build darwin

package fuse

// macOS uses the Endpoint Security Framework (via system extension) for file
// monitoring instead of FUSE. FUSE mounting is not used on macOS.

func checkAvailable() bool {
	return false
}

func detectImplementation() string {
	return "none"
}
