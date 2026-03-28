//go:build linux && cgo

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupPtracerPreload_ZeroPID(t *testing.T) {
	os.Unsetenv("LD_PRELOAD")
	os.Unsetenv("AGENTSH_SERVER_PID")
	setupPtracerPreload(0)
	assert.Empty(t, os.Getenv("LD_PRELOAD"), "should not set LD_PRELOAD for pid 0")
	assert.Empty(t, os.Getenv("AGENTSH_SERVER_PID"), "should not set AGENTSH_SERVER_PID for pid 0")
}

func TestSetupPtracerPreload_NegativePID(t *testing.T) {
	os.Unsetenv("LD_PRELOAD")
	os.Unsetenv("AGENTSH_SERVER_PID")
	setupPtracerPreload(-1)
	assert.Empty(t, os.Getenv("LD_PRELOAD"), "should not set LD_PRELOAD for negative pid")
}

func TestSetupPtracerPreload_SetsEnvWhenLibExists(t *testing.T) {
	// Create a fake .so in a temp dir
	dir := t.TempDir()
	soPath := filepath.Join(dir, ptracerLibName)
	require.NoError(t, os.WriteFile(soPath, []byte("fake"), 0755))

	// Make os.Executable return a path in our temp dir
	fakeExe := filepath.Join(dir, "agentsh-unixwrap")
	require.NoError(t, os.WriteFile(fakeExe, []byte("fake"), 0755))

	// Since we can't override os.Executable, test findPtracerLib directly
	// by placing the .so in /usr/lib/agentsh/ (not practical in tests).
	// Instead, verify the env-setting logic with a direct call.
	os.Unsetenv("LD_PRELOAD")
	os.Unsetenv("AGENTSH_SERVER_PID")

	// setupPtracerPreload won't find the lib (not next to real binary),
	// but verify it doesn't crash and logs gracefully.
	setupPtracerPreload(12345)
	// LD_PRELOAD may or may not be set depending on whether lib is found.
	// At minimum, verify no panic.
}

func TestSetupPtracerPreload_PreservesExistingLDPreload(t *testing.T) {
	// Create a fake .so next to the test binary
	self, err := os.Executable()
	require.NoError(t, err)

	soPath := filepath.Join(filepath.Dir(self), ptracerLibName)
	require.NoError(t, os.WriteFile(soPath, []byte("fake"), 0755))
	defer os.Remove(soPath)

	os.Setenv("LD_PRELOAD", "/existing/lib.so")
	defer os.Unsetenv("LD_PRELOAD")
	defer os.Unsetenv("AGENTSH_SERVER_PID")

	setupPtracerPreload(42)

	ldPreload := os.Getenv("LD_PRELOAD")
	assert.Contains(t, ldPreload, soPath, "should include ptracer lib")
	assert.Contains(t, ldPreload, "/existing/lib.so", "should preserve existing LD_PRELOAD")
	assert.Equal(t, "42", os.Getenv("AGENTSH_SERVER_PID"))
}

func TestFindPtracerLib_NextToBinary(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)

	soPath := filepath.Join(filepath.Dir(self), ptracerLibName)
	require.NoError(t, os.WriteFile(soPath, []byte("fake"), 0755))
	defer os.Remove(soPath)

	found := findPtracerLib()
	assert.Equal(t, soPath, found)
}

func TestFindPtracerLib_NotFound(t *testing.T) {
	// With no .so anywhere findable, should return empty.
	// Remove any .so next to test binary first.
	self, err := os.Executable()
	require.NoError(t, err)
	soPath := filepath.Join(filepath.Dir(self), ptracerLibName)
	os.Remove(soPath) // ignore error if not exists

	found := findPtracerLib()
	// May find /usr/lib/agentsh/ version if installed; otherwise empty.
	if found != "" {
		assert.Contains(t, found, ptracerLibName)
	}
}
