//go:build darwin

package fuse

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFuseTPathsExist(t *testing.T) {
	// Verify the FUSE-T detection paths are defined
	assert.NotEmpty(t, fuseTpaths)

	// Check expected paths are present
	expectedPaths := []string{
		"/usr/local/lib/libfuse-t.dylib",
		"/opt/homebrew/lib/libfuse-t.dylib",
		"/Library/Frameworks/FUSE-T.framework",
	}
	for _, expected := range expectedPaths {
		found := false
		for _, p := range fuseTpaths {
			if p == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "expected FUSE-T path %q to be in fuseTpaths", expected)
	}
}

func TestMacFUSEPathsExist(t *testing.T) {
	// Verify the macFUSE detection paths are defined
	assert.NotEmpty(t, macFUSEpaths)

	// Check expected paths are present
	expectedPaths := []string{
		"/Library/Filesystems/macfuse.fs",
		"/Library/Frameworks/macFUSE.framework",
	}
	for _, expected := range expectedPaths {
		found := false
		for _, p := range macFUSEpaths {
			if p == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "expected macFUSE path %q to be in macFUSEpaths", expected)
	}
}

func TestCheckAvailable(t *testing.T) {
	// This test verifies the function runs without error
	// The result depends on whether FUSE is installed
	result := checkAvailable()

	// If any FUSE path exists, result should be true
	anyExists := false
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			anyExists = true
			break
		}
	}
	if !anyExists {
		for _, path := range macFUSEpaths {
			if _, err := os.Stat(path); err == nil {
				anyExists = true
				break
			}
		}
	}

	assert.Equal(t, anyExists, result)
}

func TestDetectImplementation(t *testing.T) {
	result := detectImplementation()

	// Result should be one of: "fuse-t", "macfuse", or "none"
	validResults := []string{"fuse-t", "macfuse", "none"}
	found := false
	for _, valid := range validResults {
		if result == valid {
			found = true
			break
		}
	}
	assert.True(t, found, "detectImplementation() returned unexpected value: %q", result)
}

func TestDetectImplementation_PreferseFuseT(t *testing.T) {
	// Check if FUSE-T is installed
	fuseTInstalled := false
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			fuseTInstalled = true
			break
		}
	}

	if fuseTInstalled {
		// If FUSE-T is installed, it should be preferred
		result := detectImplementation()
		assert.Equal(t, "fuse-t", result, "FUSE-T should be preferred when installed")
	} else {
		t.Log("FUSE-T not installed, skipping preference test")
	}
}

func TestDetectImplementation_ReturnsMacFUSE(t *testing.T) {
	// Check if only macFUSE is installed (not FUSE-T)
	fuseTInstalled := false
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			fuseTInstalled = true
			break
		}
	}

	macFUSEInstalled := false
	for _, path := range macFUSEpaths {
		if _, err := os.Stat(path); err == nil {
			macFUSEInstalled = true
			break
		}
	}

	if !fuseTInstalled && macFUSEInstalled {
		result := detectImplementation()
		assert.Equal(t, "macfuse", result, "macFUSE should be detected when only macFUSE is installed")
	} else if fuseTInstalled {
		t.Log("FUSE-T is installed, skipping macFUSE-only test")
	} else {
		t.Log("Neither FUSE implementation installed, skipping test")
	}
}

func TestDetectImplementation_ReturnsNone(t *testing.T) {
	// If no FUSE is installed, verify "none" is returned
	anyInstalled := checkAvailable()
	if !anyInstalled {
		result := detectImplementation()
		assert.Equal(t, "none", result)
	} else {
		t.Log("FUSE is installed, skipping 'none' test")
	}
}

func TestCheckAvailable_MatchesDetect(t *testing.T) {
	// checkAvailable should return true iff detectImplementation returns something other than "none"
	available := checkAvailable()
	impl := detectImplementation()

	if available {
		assert.NotEqual(t, "none", impl, "if checkAvailable() is true, implementation should not be 'none'")
	} else {
		assert.Equal(t, "none", impl, "if checkAvailable() is false, implementation should be 'none'")
	}
}

func TestFuseDetection_Integration(t *testing.T) {
	// Integration test that logs the actual detection result
	available := checkAvailable()
	impl := detectImplementation()

	t.Logf("FUSE available: %v", available)
	t.Logf("FUSE implementation: %s", impl)

	// Log which paths exist
	t.Log("FUSE-T paths:")
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			t.Logf("  [EXISTS] %s", path)
		} else {
			t.Logf("  [MISSING] %s", path)
		}
	}

	t.Log("macFUSE paths:")
	for _, path := range macFUSEpaths {
		if _, err := os.Stat(path); err == nil {
			t.Logf("  [EXISTS] %s", path)
		} else {
			t.Logf("  [MISSING] %s", path)
		}
	}
}
