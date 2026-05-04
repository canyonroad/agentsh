//go:build linux && cgo

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupPtracerPreload_ZeroPID(t *testing.T) {
	os.Unsetenv("LD_PRELOAD")
	os.Unsetenv("AGENTSH_SERVER_PID")
	setupPtracerPreload(0, true)
	assert.Empty(t, os.Getenv("LD_PRELOAD"), "should not set LD_PRELOAD for pid 0")
	assert.Empty(t, os.Getenv("AGENTSH_SERVER_PID"), "should not set AGENTSH_SERVER_PID for pid 0")
}

func TestSetupPtracerPreload_NegativePID(t *testing.T) {
	os.Unsetenv("LD_PRELOAD")
	os.Unsetenv("AGENTSH_SERVER_PID")
	setupPtracerPreload(-1, true)
	assert.Empty(t, os.Getenv("LD_PRELOAD"), "should not set LD_PRELOAD for negative pid")
}

func TestSetupPtracerPreload_SetsEnvWhenLibExists(t *testing.T) {
	// Place a fake .so next to the test binary so findPtracerLib discovers it.
	self, err := os.Executable()
	require.NoError(t, err)

	soPath := filepath.Join(filepath.Dir(self), ptracerLibName)
	require.NoError(t, os.WriteFile(soPath, []byte("fake"), 0755))
	defer os.Remove(soPath)

	os.Unsetenv("LD_PRELOAD")
	os.Unsetenv("AGENTSH_SERVER_PID")
	defer os.Unsetenv("LD_PRELOAD")
	defer os.Unsetenv("AGENTSH_SERVER_PID")

	setupPtracerPreload(12345, true)

	assert.Equal(t, soPath, os.Getenv("LD_PRELOAD"), "should set LD_PRELOAD to ptracer lib path")
	assert.Equal(t, "12345", os.Getenv("AGENTSH_SERVER_PID"), "should set AGENTSH_SERVER_PID")
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

	setupPtracerPreload(42, true)

	ldPreload := os.Getenv("LD_PRELOAD")
	assert.Contains(t, ldPreload, soPath, "should include ptracer lib")
	assert.Contains(t, ldPreload, "/existing/lib.so", "should preserve existing LD_PRELOAD")
	assert.Equal(t, "42", os.Getenv("AGENTSH_SERVER_PID"))
}

// TestSetupPtracerPreload_YamaInactive_NoLog asserts that when Yama is not
// active, setupPtracerPreload returns silently — even if the .so is missing.
// This is the regression behind issue #281: the unconditional "ptracer: ...
// not found" log emitted noise during routine wrapper invocations on
// non-Yama kernels (where the library is irrelevant), which the v0.19.1
// shim kernel-install path surfaced in many more contexts than v0.19.0.
func TestSetupPtracerPreload_YamaInactive_NoLog(t *testing.T) {
	// Ensure no .so is discoverable next to the test binary.
	self, err := os.Executable()
	require.NoError(t, err)
	soPath := filepath.Join(filepath.Dir(self), ptracerLibName)
	_ = os.Remove(soPath)

	os.Unsetenv("LD_PRELOAD")
	os.Unsetenv("AGENTSH_SERVER_PID")
	defer os.Unsetenv("LD_PRELOAD")
	defer os.Unsetenv("AGENTSH_SERVER_PID")

	var buf bytes.Buffer
	origOut := log.Default().Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	setupPtracerPreload(123, false)

	assert.NotContains(t, buf.String(), "ptracer:", "must not log ptracer warning when Yama is inactive")
	assert.Empty(t, os.Getenv("LD_PRELOAD"), "must not modify LD_PRELOAD when Yama is inactive")
}

// TestSetupPtracerPreload_YamaActive_LogsWhenLibMissing asserts that when
// Yama IS active and the .so is not discoverable, the warning still fires —
// in that case the message is actionable (children may fail under Yama).
func TestSetupPtracerPreload_YamaActive_LogsWhenLibMissing(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)
	soPath := filepath.Join(filepath.Dir(self), ptracerLibName)
	_ = os.Remove(soPath)

	// Force findPtracerLib to return "" by also stubbing the system path lookup
	// via a test that runs in environments where /usr/lib/agentsh/ does not
	// contain the .so. If it does, skip — we can't reliably assert "not found".
	if _, statErr := os.Stat(filepath.Join("/usr/lib/agentsh", ptracerLibName)); statErr == nil {
		t.Skip("/usr/lib/agentsh ptracer lib present; cannot assert not-found path")
	}

	os.Unsetenv("LD_PRELOAD")
	os.Unsetenv("AGENTSH_SERVER_PID")
	defer os.Unsetenv("LD_PRELOAD")
	defer os.Unsetenv("AGENTSH_SERVER_PID")

	var buf bytes.Buffer
	origOut := log.Default().Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	setupPtracerPreload(123, true)

	assert.Contains(t, buf.String(), "ptracer:", "must log ptracer warning when Yama is active and lib is missing")
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
