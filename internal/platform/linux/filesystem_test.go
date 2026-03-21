//go:build linux

package linux

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
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
