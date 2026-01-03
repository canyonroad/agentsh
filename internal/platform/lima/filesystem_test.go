//go:build darwin

package lima

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewFilesystem(t *testing.T) {
	p := &Platform{instance: "default"}
	fs := NewFilesystem(p)

	if fs == nil {
		t.Fatal("NewFilesystem() returned nil")
	}

	if fs.platform != p {
		t.Error("platform not set correctly")
	}

	if fs.implementation != "fuse3" {
		t.Errorf("implementation = %q, want fuse3", fs.implementation)
	}

	if fs.mounts == nil {
		t.Error("mounts map should be initialized")
	}
}

func TestFilesystem_Implementation(t *testing.T) {
	p := &Platform{instance: "default"}
	fs := NewFilesystem(p)

	if got := fs.Implementation(); got != "fuse3" {
		t.Errorf("Implementation() = %q, want fuse3", got)
	}
}

func TestFilesystem_Available(t *testing.T) {
	p := &Platform{instance: "default"}
	fs := &Filesystem{
		platform:  p,
		available: true,
		mounts:    make(map[string]*Mount),
	}

	if !fs.Available() {
		t.Error("Available() should return true when available is true")
	}

	fs.available = false
	if fs.Available() {
		t.Error("Available() should return false when available is false")
	}
}

func TestFilesystem_Mount_NotAvailable(t *testing.T) {
	p := &Platform{instance: "default"}
	fs := &Filesystem{
		platform:  p,
		available: false,
		mounts:    make(map[string]*Mount),
	}

	cfg := platform.FSConfig{
		SourcePath: "/Users/test/source",
		MountPoint: "/Users/test/mount",
	}

	_, err := fs.Mount(cfg)
	if err == nil {
		t.Error("Mount() should error when FUSE not available")
	}
}

func TestFilesystem_Mount_AlreadyMounted(t *testing.T) {
	// This test can only run when Lima is actually available
	t.Skip("Requires real Lima environment")
}

func TestFilesystem_Mount_Success(t *testing.T) {
	// This test can only run when Lima is actually available
	t.Skip("Requires real Lima environment")
}

func TestFilesystem_Unmount_InvalidType(t *testing.T) {
	p := &Platform{instance: "default"}
	fs := NewFilesystem(p)

	// Create a fake mount that's not the right type
	err := fs.Unmount(&fakeMount{})
	if err == nil {
		t.Error("Unmount() should error with invalid mount type")
	}
}

type fakeMount struct{}

func (f *fakeMount) Path() string            { return "" }
func (f *fakeMount) SourcePath() string      { return "" }
func (f *fakeMount) Stats() platform.FSStats { return platform.FSStats{} }
func (f *fakeMount) Close() error            { return nil }

func TestMount_Path(t *testing.T) {
	m := &Mount{
		macMount:   "/Users/test/mount",
		mountPoint: "/Users/test/mount",
	}

	if got := m.Path(); got != "/Users/test/mount" {
		t.Errorf("Path() = %q, want /Users/test/mount", got)
	}
}

func TestMount_SourcePath(t *testing.T) {
	m := &Mount{
		macSource:  "/Users/test/source",
		sourcePath: "/Users/test/source",
	}

	if got := m.SourcePath(); got != "/Users/test/source" {
		t.Errorf("SourcePath() = %q, want /Users/test/source", got)
	}
}

func TestMount_LimaPath(t *testing.T) {
	m := &Mount{
		mountPoint: "/Users/test/mount",
	}

	if got := m.LimaPath(); got != "/Users/test/mount" {
		t.Errorf("LimaPath() = %q, want /Users/test/mount", got)
	}
}

func TestMount_LimaSourcePath(t *testing.T) {
	m := &Mount{
		sourcePath: "/Users/test/source",
	}

	if got := m.LimaSourcePath(); got != "/Users/test/source" {
		t.Errorf("LimaSourcePath() = %q, want /Users/test/source", got)
	}
}

func TestMount_Stats(t *testing.T) {
	mountTime := time.Now()
	m := &Mount{
		mountedAt: mountTime,
	}
	stats := m.Stats()

	if stats.MountedAt != mountTime {
		t.Errorf("MountedAt = %v, want %v", stats.MountedAt, mountTime)
	}
}

func TestMount_Close_NilFilesystem(t *testing.T) {
	m := &Mount{}

	// Should not error when filesystem is nil
	if err := m.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestMount_Close_NilPlatform(t *testing.T) {
	m := &Mount{
		filesystem: &Filesystem{},
	}

	// Should not error when platform is nil
	if err := m.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestMount_Close_WithPlatform(t *testing.T) {
	// This test can only run when Lima is actually available
	t.Skip("Requires real Lima environment")
}

func TestFilesystem_InterfaceCompliance(t *testing.T) {
	var _ platform.FilesystemInterceptor = (*Filesystem)(nil)
	var _ platform.FSMount = (*Mount)(nil)
}
