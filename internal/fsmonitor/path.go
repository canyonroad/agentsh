package fsmonitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveRealPathUnderRoot maps a virtual "/workspace/..." path to a real path under realRoot and verifies
// it does not escape via ".." components or symlinks.
//
// If mustExist is true, the target is expected to exist and will be evaluated directly.
// If mustExist is false, the parent directory is evaluated for symlink escape and the final path may not exist yet.
func resolveRealPathUnderRoot(realRoot string, virtPath string, mustExist bool) (string, error) {
	virtPath = filepath.ToSlash(virtPath)
	if !strings.HasPrefix(virtPath, "/workspace") {
		return "", fmt.Errorf("path must be under /workspace")
	}
	rel := strings.TrimPrefix(virtPath, "/workspace")
	rel = strings.TrimPrefix(rel, "/")

	rootClean := filepath.Clean(realRoot)
	candidate := filepath.Join(rootClean, filepath.FromSlash(rel))

	// Fast ".." escape check before touching the filesystem.
	cleanCandidate := filepath.Clean(candidate)
	if cleanCandidate != rootClean && !strings.HasPrefix(cleanCandidate, rootClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes workspace root")
	}

	if mustExist {
		resolved, err := filepath.EvalSymlinks(cleanCandidate)
		if err != nil {
			return "", err
		}
		resolved = filepath.Clean(resolved)
		if resolved != rootClean && !strings.HasPrefix(resolved, rootClean+string(os.PathSeparator)) {
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
	if resolvedParent != rootClean && !strings.HasPrefix(resolvedParent, rootClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("symlink escape outside workspace root")
	}
	out := filepath.Join(resolvedParent, filepath.Base(cleanCandidate))
	out = filepath.Clean(out)
	if out != rootClean && !strings.HasPrefix(out, rootClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes workspace root")
	}
	return out, nil
}
