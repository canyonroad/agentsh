package fsmonitor

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/internal/pathutil"
)

// resolveRealPathUnderRoot maps a virtual path (under virtualRoot) to a real path under realRoot and verifies
// it does not escape via ".." components or symlinks.
//
// If mustExist is true, the target is expected to exist and will be evaluated directly.
// If mustExist is false, the parent directory is evaluated for symlink escape and the final path may not exist yet.
func resolveRealPathUnderRoot(realRoot string, virtPath string, mustExist bool, virtualRoot string) (string, error) {
	virtPath = filepath.ToSlash(virtPath)
	if !pathutil.IsUnderRoot(virtPath, virtualRoot) {
		return "", fmt.Errorf("path must be under %s", virtualRoot)
	}
	rel := pathutil.TrimRootPrefix(virtPath, virtualRoot)
	rel = strings.TrimPrefix(rel, "/")

	// Resolve symlinks on root path to handle macOS /var -> /private/var etc.
	rootClean, err := filepath.EvalSymlinks(filepath.Clean(realRoot))
	if err != nil {
		rootClean = filepath.Clean(realRoot) // fallback if root doesn't exist yet
	}
	candidate := filepath.Join(rootClean, filepath.FromSlash(rel))

	// Fast ".." escape check before touching the filesystem.
	cleanCandidate := filepath.Clean(candidate)
	if !pathutil.IsRealPathUnder(cleanCandidate, rootClean) {
		return "", fmt.Errorf("path escapes workspace root")
	}

	if mustExist {
		resolved, err := filepath.EvalSymlinks(cleanCandidate)
		if err != nil {
			return "", err
		}
		resolved = filepath.Clean(resolved)
		if !pathutil.IsRealPathUnder(resolved, rootClean) {
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
	if !pathutil.IsRealPathUnder(resolvedParent, rootClean) {
		return "", fmt.Errorf("symlink escape outside workspace root")
	}
	out := filepath.Join(resolvedParent, filepath.Base(cleanCandidate))
	out = filepath.Clean(out)
	if !pathutil.IsRealPathUnder(out, rootClean) {
		return "", fmt.Errorf("path escapes workspace root")
	}
	return out, nil
}

// evalEscapedSymlink resolves virtPath fully through symlinks when the
// in-workspace candidate path resolves, via a symlink, to a target
// outside realRoot. Returns the cleaned real target, or the empty
// string if this is not a legitimate symlink-target escape (broken
// link, missing parent, or a "..":-style path escape).
//
// Used by checkWithExist to fall back from a blanket "workspace-escape"
// deny to a regular policy evaluation when the only "escape" is via a
// symlink whose target is outside the workspace. Lets a policy
// explicitly govern common system symlink targets (e.g. /usr/bin/python3
// for Python venvs, /usr/lib for venv/lib64) via the usual file_rules
// instead of agentsh's hardcoded blanket deny.
//
// Important: only *symlink-target* escapes fall through. A "..":-style
// path escape (e.g. /workspace/../outside/secret) must NOT, even when
// the sibling exists on disk -- otherwise a broad rule like /** would
// allow reading arbitrary sibling paths. filepath.Join cleans the
// candidate, so such a path lands outside rootClean before any symlink
// resolution; we check containment of the pre-resolution candidate and
// bail (returning "" -> caller keeps the workspace-escape deny) when it
// is not under rootClean. This mirrors the fast ".." escape check in
// resolveRealPathUnderRoot.
func evalEscapedSymlink(realRoot, virtPath, virtualRoot string) string {
	if !pathutil.IsUnderRoot(virtPath, virtualRoot) {
		return ""
	}
	rel := pathutil.TrimRootPrefix(virtPath, virtualRoot)
	rel = strings.TrimPrefix(rel, "/")
	rootClean, err := filepath.EvalSymlinks(filepath.Clean(realRoot))
	if err != nil {
		rootClean = filepath.Clean(realRoot)
	}
	candidate := filepath.Join(rootClean, filepath.FromSlash(rel))
	// Reject ".."-style escapes before touching the filesystem: the
	// candidate itself must stay under the workspace root. Only the
	// final symlink *target* is allowed to point outside (handled by
	// the resolve below). filepath.Join has already cleaned candidate,
	// so an escaping rel has consumed the root prefix here.
	if !pathutil.IsRealPathUnder(candidate, rootClean) {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return ""
	}
	return filepath.Clean(resolved)
}
