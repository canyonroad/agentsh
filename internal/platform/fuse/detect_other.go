// internal/platform/fuse/detect_other.go
//go:build !darwin && !windows

package fuse

func checkAvailable() bool {
	return false
}

func detectImplementation() string {
	return "none"
}
