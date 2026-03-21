//go:build linux

package linux

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
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
