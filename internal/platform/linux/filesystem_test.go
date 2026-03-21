//go:build linux

package linux

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestDetectMountMethod(t *testing.T) {
	method := detectMountMethod()
	if _, err := os.Open("/dev/fuse"); err == nil {
		assert.NotEmpty(t, method, "should detect a mount method when /dev/fuse exists")
		assert.Contains(t, []string{"fusermount", "new-api", "direct"}, method)
	}
}

func TestCheckNewMountAPI(t *testing.T) {
	result := checkNewMountAPI()
	_ = result // just verify no panic
}

func TestFilesystem_MountMethod(t *testing.T) {
	fs := NewFilesystem()
	if fs.Available() {
		assert.NotEmpty(t, fs.MountMethod())
	} else {
		assert.Empty(t, fs.MountMethod())
	}
}

func TestMountFUSEViaNewAPI_ErrorCleanup(t *testing.T) {
	if !checkNewMountAPI() {
		t.Skip("new mount API not available")
	}
	_, err := mountFUSEViaNewAPI("/nonexistent/path/that/cannot/exist", true, 0)
	assert.Error(t, err, "should fail with nonexistent mountpoint")
}

func TestMountFUSEViaNewAPI_FsopenProbe(t *testing.T) {
	if !checkNewMountAPI() {
		t.Skip("new mount API not available")
	}
	fd, err := unix.Fsopen("fuse", 0)
	if err != nil {
		t.Fatalf("fsopen failed: %v", err)
	}
	unix.Close(fd)
}

func TestMountFUSEViaNewAPI_Integration(t *testing.T) {
	if !checkNewMountAPI() {
		t.Skip("new mount API not available")
	}
	if os.Getuid() != 0 {
		t.Skip("requires root for FUSE mount")
	}

	// Create a temp directory as the mount point
	mountDir, err := os.MkdirTemp("", "fuse-newapi-test")
	require.NoError(t, err)
	defer os.RemoveAll(mountDir)

	// Mount FUSE via new API
	fuseFD, err := mountFUSEViaNewAPI(mountDir, true, 0)
	require.NoError(t, err)
	defer unix.Close(fuseFD)

	// Verify mount appears in /proc/mounts
	mounts, err := os.ReadFile("/proc/mounts")
	require.NoError(t, err)
	assert.Contains(t, string(mounts), mountDir, "mount should appear in /proc/mounts")

	// Unmount
	err = unix.Unmount(mountDir, 0)
	assert.NoError(t, err)

	// Verify unmounted
	mounts2, _ := os.ReadFile("/proc/mounts")
	assert.NotContains(t, string(mounts2), mountDir, "mount should be gone after unmount")
}
