// internal/policy/detect_test.go
package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectProjectRoots(t *testing.T) {
	// Create temp directory structure
	base := t.TempDir()
	// Resolve symlinks for macOS /var -> /private/var
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		base = resolved
	}

	// /base/repo/.git
	// /base/repo/services/api/go.mod
	// /base/repo/services/api/cmd/  <- workspace

	repoDir := filepath.Join(base, "repo")
	gitDir := filepath.Join(repoDir, ".git")
	apiDir := filepath.Join(repoDir, "services", "api")
	cmdDir := filepath.Join(apiDir, "cmd")

	require.NoError(t, os.MkdirAll(gitDir, 0755))
	require.NoError(t, os.MkdirAll(cmdDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(apiDir, "go.mod"), []byte("module api"), 0644))

	markers := DefaultProjectMarkers()
	roots, err := DetectProjectRoots(cmdDir, markers)
	require.NoError(t, err)

	assert.Equal(t, apiDir, roots.ProjectRoot)
	assert.Equal(t, repoDir, roots.GitRoot)
}

func TestDetectProjectRoots_NoMarkers(t *testing.T) {
	// Create temp directory with no markers
	base := t.TempDir()
	// Resolve symlinks for macOS /var -> /private/var
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		base = resolved
	}
	workspace := filepath.Join(base, "some", "dir")
	require.NoError(t, os.MkdirAll(workspace, 0755))

	// Use custom markers that won't exist anywhere in the filesystem,
	// so the test isn't affected by stray files in parent directories.
	markers := []string{".nonexistent_test_marker_aef3b2", ".nonexistent_test_marker_c7d4e1"}
	roots, err := DetectProjectRoots(workspace, markers)
	require.NoError(t, err)

	// Should fall back to workspace
	assert.Equal(t, workspace, roots.ProjectRoot)
	assert.Equal(t, "", roots.GitRoot)
}

func TestDetectProjectRoots_GitOnly(t *testing.T) {
	base := t.TempDir()
	// Resolve symlinks for macOS /var -> /private/var
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		base = resolved
	}
	repoDir := filepath.Join(base, "repo")
	gitDir := filepath.Join(repoDir, ".git")
	subDir := filepath.Join(repoDir, "src")

	require.NoError(t, os.MkdirAll(gitDir, 0755))
	require.NoError(t, os.MkdirAll(subDir, 0755))

	markers := DefaultProjectMarkers()
	roots, err := DetectProjectRoots(subDir, markers)
	require.NoError(t, err)

	// Both should be the git root
	assert.Equal(t, repoDir, roots.ProjectRoot)
	assert.Equal(t, repoDir, roots.GitRoot)
}

func TestDetectProjectRoots_NonExistentPath(t *testing.T) {
	_, err := DetectProjectRoots("/nonexistent/path", DefaultProjectMarkers())
	require.Error(t, err)
}
