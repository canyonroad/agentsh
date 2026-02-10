//go:build linux && cgo

package unix

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateStubSymlink(t *testing.T) {
	// Create a fake stub binary to point to
	stubDir := t.TempDir()
	stubPath := filepath.Join(stubDir, "agentsh-stub")
	require.NoError(t, os.WriteFile(stubPath, []byte("#!/bin/sh\n"), 0755))

	symlinkPath, cleanup, err := CreateStubSymlink(stubPath)
	require.NoError(t, err)
	require.NotEmpty(t, symlinkPath)
	defer cleanup()

	// Symlink should exist and point to stub
	target, err := os.Readlink(symlinkPath)
	require.NoError(t, err)
	assert.Equal(t, stubPath, target)

	// Symlink path should be reasonably short (< 30 chars)
	assert.Less(t, len(symlinkPath), 30, "symlink path should be short: %s", symlinkPath)

	// Parent dir should have restricted permissions
	info, err := os.Stat(filepath.Dir(symlinkPath))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
}

func TestCreateStubSymlink_Cleanup(t *testing.T) {
	stubDir := t.TempDir()
	stubPath := filepath.Join(stubDir, "agentsh-stub")
	require.NoError(t, os.WriteFile(stubPath, []byte("#!/bin/sh\n"), 0755))

	symlinkPath, cleanup, err := CreateStubSymlink(stubPath)
	require.NoError(t, err)

	// Verify it exists
	_, err = os.Lstat(symlinkPath)
	require.NoError(t, err)

	// Cleanup should remove symlink and parent dir
	cleanup()
	_, err = os.Lstat(symlinkPath)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Dir(symlinkPath))
	assert.True(t, os.IsNotExist(err))
}
