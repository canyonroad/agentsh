// internal/platform/fuse/detect_darwin.go
//go:build darwin

package fuse

import "os"

// FUSE-T detection paths
var fuseTpaths = []string{
	"/usr/local/lib/libfuse-t.dylib",
	"/opt/homebrew/lib/libfuse-t.dylib",
	"/Library/Frameworks/FUSE-T.framework",
}

// macFUSE detection paths (fallback)
var macFUSEpaths = []string{
	"/Library/Filesystems/macfuse.fs",
	"/Library/Frameworks/macFUSE.framework",
}

func checkAvailable() bool {
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	for _, path := range macFUSEpaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func detectImplementation() string {
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			return "fuse-t"
		}
	}
	for _, path := range macFUSEpaths {
		if _, err := os.Stat(path); err == nil {
			return "macfuse"
		}
	}
	return "none"
}
