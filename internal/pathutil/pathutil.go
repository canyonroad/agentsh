// Package pathutil provides path boundary checking helpers shared across
// packages that need to determine whether a filesystem path is under a root.
package pathutil

import (
	"os"
	"runtime"
	"strings"
)

// IsUnderRoot checks if a virtual path (using forward slashes) is equal to or
// under root. Returns false for empty root (fail closed). Handles root=="/"
// and Windows case-insensitive comparison.
func IsUnderRoot(path, root string) bool {
	if root == "" {
		return false
	}
	if root == "/" {
		return strings.HasPrefix(path, "/")
	}
	if runtime.GOOS == "windows" {
		lp, lr := strings.ToLower(path), strings.ToLower(root)
		if strings.HasSuffix(lr, "/") {
			return strings.HasPrefix(lp, lr)
		}
		return lp == lr || strings.HasPrefix(lp, lr+"/")
	}
	return path == root || strings.HasPrefix(path, root+"/")
}

// IsRealPathUnder checks if a real filesystem path is equal to or under root,
// using os.PathSeparator for boundary checks. Returns false for empty root
// (fail closed). Handles root=="/" or volume roots like "C:\" where root
// already ends with the separator. On Windows, comparisons are case-insensitive.
func IsRealPathUnder(path, root string) bool {
	if root == "" {
		return false
	}
	sep := string(os.PathSeparator)
	if root == "/" || root == sep {
		return true
	}
	if runtime.GOOS == "windows" {
		lp, lr := strings.ToLower(path), strings.ToLower(root)
		if strings.HasSuffix(lr, sep) {
			return strings.HasPrefix(lp, lr)
		}
		return lp == lr || strings.HasPrefix(lp, lr+sep)
	}
	if strings.HasSuffix(root, sep) {
		return strings.HasPrefix(path, root)
	}
	return path == root || strings.HasPrefix(path, root+sep)
}

// TrimRootPrefix removes root from the front of path. On Windows, uses
// case-insensitive matching.
func TrimRootPrefix(path, root string) string {
	if runtime.GOOS == "windows" && len(path) >= len(root) {
		if strings.EqualFold(path[:len(root)], root) {
			return path[len(root):]
		}
	}
	return strings.TrimPrefix(path, root)
}
