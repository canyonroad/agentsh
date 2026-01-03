//go:build !darwin

package platform

// isLimaAvailable returns false on non-Darwin platforms.
// Lima is a macOS-only virtualization solution.
func isLimaAvailable() bool {
	return false
}
