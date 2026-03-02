package fsmonitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// isRealPathUnder checks if a real filesystem path is equal to or under root,
// using os.PathSeparator for boundary checks.  Handles root=="/" or root==sep.
func isRealPathUnder(path, root string) bool {
	sep := string(os.PathSeparator)
	if root == "/" || root == sep {
		return true
	}
	return path == root || strings.HasPrefix(path, root+sep)
}

// resolveRealPathUnderRoot maps a virtual path (under virtualRoot) to a real path under realRoot and verifies
// it does not escape via ".." components or symlinks.
//
// If mustExist is true, the target is expected to exist and will be evaluated directly.
// If mustExist is false, the parent directory is evaluated for symlink escape and the final path may not exist yet.
func resolveRealPathUnderRoot(realRoot string, virtPath string, mustExist bool, virtualRoot string) (string, error) {
	virtPath = filepath.ToSlash(virtPath)
	// Boundary-safe check: handle virtualRoot=="/" where root+"/" would be "//"
	underRoot := func(path, root string) bool {
		if root == "/" {
			return strings.HasPrefix(path, "/")
		}
		return path == root || strings.HasPrefix(path, root+"/")
	}
	if !underRoot(virtPath, virtualRoot) {
		return "", fmt.Errorf("path must be under %s", virtualRoot)
	}
	rel := strings.TrimPrefix(virtPath, virtualRoot)
	rel = strings.TrimPrefix(rel, "/")

	// Resolve symlinks on root path to handle macOS /var -> /private/var etc.
	rootClean, err := filepath.EvalSymlinks(filepath.Clean(realRoot))
	if err != nil {
		rootClean = filepath.Clean(realRoot) // fallback if root doesn't exist yet
	}
	candidate := filepath.Join(rootClean, filepath.FromSlash(rel))

	// Fast ".." escape check before touching the filesystem.
	cleanCandidate := filepath.Clean(candidate)
	if !isRealPathUnder(cleanCandidate, rootClean) {
		return "", fmt.Errorf("path escapes workspace root")
	}

	if mustExist {
		resolved, err := filepath.EvalSymlinks(cleanCandidate)
		if err != nil {
			return "", err
		}
		resolved = filepath.Clean(resolved)
		if !isRealPathUnder(resolved, rootClean) {
			return "", fmt.Errorf("symlink escape outside workspace root")
		}
		return resolved, nil
	}

	parent := filepath.Dir(cleanCandidate)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	resolvedParent = filepath.Clean(resolvedParent)
	if !isRealPathUnder(resolvedParent, rootClean) {
		return "", fmt.Errorf("symlink escape outside workspace root")
	}
	out := filepath.Join(resolvedParent, filepath.Base(cleanCandidate))
	out = filepath.Clean(out)
	if !isRealPathUnder(out, rootClean) {
		return "", fmt.Errorf("path escapes workspace root")
	}
	return out, nil
}
