//go:build windows

package wsl2

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewFilesystem(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
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
}

func TestFilesystem_Implementation(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	fs := NewFilesystem(p)

	if got := fs.Implementation(); got != "fuse3" {
		t.Errorf("Implementation() = %q, want fuse3", got)
	}
}

func TestFilesystem_Available(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	fs := &Filesystem{
		platform:  p,
		available: true,
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
	p := &Platform{distro: "Ubuntu"}
	fs := &Filesystem{
		platform:  p,
		available: false,
	}

	cfg := platform.FSConfig{
		SourcePath: `C:\Users\test`,
		MountPoint: `C:\mnt\test`,
	}

	_, err := fs.Mount(cfg)
	if err == nil {
		t.Error("Mount() should error when FUSE not available")
	}
}

func TestFilesystem_Unmount_InvalidType(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	fs := NewFilesystem(p)

	// Create a fake mount that's not the right type
	err := fs.Unmount(&fakeMount{})
	if err == nil {
		t.Error("Unmount() should error with invalid mount type")
	}
}

type fakeMount struct{}

func (f *fakeMount) Path() string                { return "" }
func (f *fakeMount) SourcePath() string          { return "" }
func (f *fakeMount) Stats() platform.FSStats     { return platform.FSStats{} }
func (f *fakeMount) Close() error                { return nil }

func TestMount_Path(t *testing.T) {
	m := &Mount{
		winMount:   `C:\mnt\test`,
		mountPoint: "/mnt/c/mnt/test",
	}

	if got := m.Path(); got != `C:\mnt\test` {
		t.Errorf("Path() = %q, want C:\\mnt\\test", got)
	}
}

func TestMount_SourcePath(t *testing.T) {
	m := &Mount{
		winSource:  `C:\Users\test`,
		sourcePath: "/mnt/c/Users/test",
	}

	if got := m.SourcePath(); got != `C:\Users\test` {
		t.Errorf("SourcePath() = %q, want C:\\Users\\test", got)
	}
}

func TestMount_WSLPath(t *testing.T) {
	m := &Mount{
		mountPoint: "/mnt/c/mnt/test",
	}

	if got := m.WSLPath(); got != "/mnt/c/mnt/test" {
		t.Errorf("WSLPath() = %q, want /mnt/c/mnt/test", got)
	}
}

func TestMount_WSLSourcePath(t *testing.T) {
	m := &Mount{
		sourcePath: "/mnt/c/Users/test",
	}

	if got := m.WSLSourcePath(); got != "/mnt/c/Users/test" {
		t.Errorf("WSLSourcePath() = %q, want /mnt/c/Users/test", got)
	}
}

func TestMount_Stats(t *testing.T) {
	m := &Mount{}
	stats := m.Stats()

	// Should return empty stats
	if stats.TotalOps != 0 {
		t.Errorf("TotalOps = %d, want 0", stats.TotalOps)
	}
}

func TestMount_Close(t *testing.T) {
	m := &Mount{}

	// Should not error (stub implementation)
	if err := m.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestFilesystem_InterfaceCompliance(t *testing.T) {
	var _ platform.FilesystemInterceptor = (*Filesystem)(nil)
	var _ platform.FSMount = (*Mount)(nil)
}
