package policy

import (
	"os"
	"path/filepath"
)

// ProjectRoots holds detected project root paths.
type ProjectRoots struct {
	ProjectRoot string // Nearest project marker or workspace
	GitRoot     string // Nearest .git, or empty if not in git repo
}

// DefaultProjectMarkers returns the default set of project markers to detect.
func DefaultProjectMarkers() []string {
	return []string{
		".git",
		"go.mod",
		"package.json",
		"Cargo.toml",
		"pyproject.toml",
	}
}

// DetectProjectRoots walks up from workspace to find project markers.
// Returns ProjectRoot (nearest language marker or workspace) and GitRoot (nearest .git).
func DetectProjectRoots(workspace string, markers []string) (*ProjectRoots, error) {
	// Resolve to absolute path
	absWorkspace, err := filepath.Abs(workspace)
	if err != nil {
		return nil, err
	}

	// Resolve symlinks
	absWorkspace, err = filepath.EvalSymlinks(absWorkspace)
	if err != nil {
		return nil, err
	}

	roots := &ProjectRoots{
		ProjectRoot: absWorkspace, // Default to workspace
	}

	// Walk up looking for markers
	dir := absWorkspace
	foundLanguageMarker := false

	for {
		for _, marker := range markers {
			markerPath := filepath.Join(dir, marker)
			if _, err := os.Stat(markerPath); err == nil {
				if marker == ".git" {
					if roots.GitRoot == "" {
						roots.GitRoot = dir
					}
					// If no language marker found yet, git root is also project root
					if !foundLanguageMarker {
						roots.ProjectRoot = dir
					}
				} else {
					// Language marker - this is the project root
					if !foundLanguageMarker {
						roots.ProjectRoot = dir
						foundLanguageMarker = true
					}
				}
			}
		}

		// .git marks the project boundary — don't walk above it.
		if roots.GitRoot != "" {
			break
		}

		// Move to parent
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}

	return roots, nil
}
