//go:build linux

package unix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMountRegistry_RegisterAndCheck(t *testing.T) {
	r := NewMountRegistry()

	r.Register("sess-1", "/home/user/proj")

	// Exact match should return true.
	assert.True(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj"))

	// Child path should return true.
	assert.True(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj/src/main.go"))

	// Non-child path should return false.
	assert.False(t, r.IsUnderFUSEMount("sess-1", "/home/user/other"))

	// Different session should return false.
	assert.False(t, r.IsUnderFUSEMount("sess-2", "/home/user/proj"))
}

func TestMountRegistry_Deregister(t *testing.T) {
	r := NewMountRegistry()

	r.Register("sess-1", "/home/user/proj")

	// Should match before deregister.
	assert.True(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj"))

	r.Deregister("sess-1", "/home/user/proj")

	// Should not match after deregister.
	assert.False(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj"))
}

func TestMountRegistry_MultipleMounts(t *testing.T) {
	r := NewMountRegistry()

	r.Register("sess-1", "/home/user/proj-a")
	r.Register("sess-1", "/home/user/proj-b")

	// Both should match.
	assert.True(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj-a"))
	assert.True(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj-b"))

	// Child of each should match.
	assert.True(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj-a/file.txt"))
	assert.True(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj-b/file.txt"))

	// Deregister one, the other should still match.
	r.Deregister("sess-1", "/home/user/proj-a")
	assert.False(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj-a"))
	assert.True(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj-b"))
}

func TestMountRegistry_PrefixBoundary(t *testing.T) {
	r := NewMountRegistry()

	r.Register("sess-1", "/home/user/proj")

	// "/home/user/project/file" must NOT match "/home/user/proj" — boundary check.
	assert.False(t, r.IsUnderFUSEMount("sess-1", "/home/user/project/file"))

	// "/home/user/proj-extra" must NOT match either.
	assert.False(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj-extra"))

	// But "/home/user/proj/file" should match.
	assert.True(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj/file"))
}

func TestMountRegistry_EmptyRegistry(t *testing.T) {
	r := NewMountRegistry()

	// Empty registry should return false for any path.
	assert.False(t, r.IsUnderFUSEMount("sess-1", "/home/user/proj"))
	assert.False(t, r.IsUnderFUSEMount("", ""))
	assert.False(t, r.IsUnderFUSEMount("sess-1", "/"))
}
