//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewFilesystem(t *testing.T) {
	fs := NewFilesystem()
	if fs == nil {
		t.Fatal("NewFilesystem() returned nil")
	}

	t.Logf("Available: %v", fs.Available())
	t.Logf("Implementation: %s", fs.Implementation())
}

func TestFilesystem_Available(t *testing.T) {
	fs := NewFilesystem()

	// Available() now checks both O_RDWR access to /dev/fuse and
	// CAP_SYS_ADMIN capability via canMountFUSE(), so the expected
	// value must match that same logic, not just /dev/fuse existence.
	expectAvailable := canMountFUSE()

	if fs.Available() != expectAvailable {
		t.Errorf("Available() = %v, expected %v from canMountFUSE()", fs.Available(), expectAvailable)
	}
}

func TestFilesystem_Mount_RequiresFUSE(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("FUSE not available: %v", err)
	}

	fs := NewFilesystem()
	if !fs.Available() {
		t.Skip("Filesystem reports unavailable")
	}

	backing := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	cfg := platform.FSConfig{
		SourcePath: backing,
		MountPoint: mountPoint,
	}

	mount, err := fs.Mount(cfg)
	if err != nil {
		t.Skipf("Mount failed (may require privileges): %v", err)
	}
	defer mount.Close()

	// Verify mount properties
	if mount.Path() != mountPoint {
		t.Errorf("mount.Path() = %q, want %q", mount.Path(), mountPoint)
	}
	if mount.SourcePath() != backing {
		t.Errorf("mount.SourcePath() = %q, want %q", mount.SourcePath(), backing)
	}

	// Verify can write through mount
	testFile := filepath.Join(mountPoint, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0644); err != nil {
		t.Fatalf("Failed to write through mount: %v", err)
	}

	// Verify file exists in backing dir
	backingFile := filepath.Join(backing, "test.txt")
	data, err := os.ReadFile(backingFile)
	if err != nil {
		t.Fatalf("Failed to read backing file: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("backing file content = %q, want %q", string(data), "hello")
	}

	// Verify stats
	stats := mount.Stats()
	t.Logf("Mount stats: TotalOps=%d, AllowedOps=%d, DeniedOps=%d",
		stats.TotalOps, stats.AllowedOps, stats.DeniedOps)
}

func TestFilesystem_Mount_DuplicateFails(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("FUSE not available: %v", err)
	}

	fs := NewFilesystem()
	if !fs.Available() {
		t.Skip("Filesystem reports unavailable")
	}

	backing := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	cfg := platform.FSConfig{
		SourcePath: backing,
		MountPoint: mountPoint,
	}

	mount1, err := fs.Mount(cfg)
	if err != nil {
		t.Skipf("First mount failed: %v", err)
	}
	defer mount1.Close()

	// Second mount to same point should fail
	_, err = fs.Mount(cfg)
	if err == nil {
		t.Error("Expected error when mounting to same mount point twice")
	}
}

func TestFilesystem_Unmount(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("FUSE not available: %v", err)
	}

	fs := NewFilesystem()
	if !fs.Available() {
		t.Skip("Filesystem reports unavailable")
	}

	backing := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	cfg := platform.FSConfig{
		SourcePath: backing,
		MountPoint: mountPoint,
	}

	mount, err := fs.Mount(cfg)
	if err != nil {
		t.Skipf("Mount failed: %v", err)
	}

	// Unmount via Filesystem.Unmount
	if err := fs.Unmount(mount); err != nil {
		t.Errorf("Unmount failed: %v", err)
	}

	// Second unmount should work via Close
	// (may or may not error depending on implementation)
}

func TestNewPlatform(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() failed: %v", err)
	}
	if p == nil {
		t.Fatal("NewPlatform() returned nil")
	}
	if p.Name() != "linux" {
		t.Errorf("Name() = %q, want 'linux'", p.Name())
	}
}

func TestPlatform_Capabilities(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() failed: %v", err)
	}

	caps := p.Capabilities()

	// Linux should always have namespace support
	if !caps.HasMountNamespace {
		t.Error("Expected HasMountNamespace to be true on Linux")
	}
	if !caps.HasPIDNamespace {
		t.Error("Expected HasPIDNamespace to be true on Linux")
	}
	if !caps.HasNetworkNamespace {
		t.Error("Expected HasNetworkNamespace to be true on Linux")
	}

	// IsolationLevel should be Full on Linux
	if caps.IsolationLevel != platform.IsolationFull {
		t.Errorf("IsolationLevel = %v, want IsolationFull", caps.IsolationLevel)
	}
}

func TestPlatform_Filesystem(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() failed: %v", err)
	}

	// Get filesystem twice - should be same instance
	fs1 := p.Filesystem()
	fs2 := p.Filesystem()

	if fs1 == nil {
		t.Fatal("Filesystem() returned nil")
	}
	if fs1 != fs2 {
		t.Error("Filesystem() should return same instance")
	}
}

// Compile-time check that interfaces are implemented
var (
	_ platform.FilesystemInterceptor = (*Filesystem)(nil)
	_ platform.FSMount               = (*Mount)(nil)
)
