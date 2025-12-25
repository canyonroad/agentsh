//go:build !linux && !darwin && !windows

package trash

import (
	"os"
)

// capturePlatformMetadata is a no-op on unsupported platforms.
func capturePlatformMetadata(path string, info os.FileInfo, entry *Entry, cfg Config) error {
	// No platform-specific metadata on unsupported platforms
	return nil
}

// restorePlatformMetadata is a no-op on unsupported platforms.
func restorePlatformMetadata(path string, entry *Entry) error {
	// No platform-specific metadata on unsupported platforms
	return nil
}
