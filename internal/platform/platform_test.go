//go:build linux

package platform_test

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
	// Import linux package to trigger init() registration
	_ "github.com/agentsh/agentsh/internal/platform/linux"
)

func TestNew_ReturnsLinuxOnLinux(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if p == nil {
		t.Fatal("New() returned nil platform")
	}
	if p.Name() != "linux" {
		t.Errorf("expected platform name 'linux', got %q", p.Name())
	}
}

func TestNewWithMode_LinuxNative(t *testing.T) {
	p, err := platform.NewWithMode(platform.ModeLinuxNative)
	if err != nil {
		t.Fatalf("NewWithMode(ModeLinuxNative) failed: %v", err)
	}
	if p.Name() != "linux" {
		t.Errorf("expected platform name 'linux', got %q", p.Name())
	}
}

func TestPlatform_Capabilities(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	caps := p.Capabilities()

	// On Linux, we expect certain capabilities
	// FUSE should be detected (may or may not be available)
	t.Logf("HasFUSE: %v (implementation: %s)", caps.HasFUSE, caps.FUSEImplementation)
	t.Logf("HasNetworkIntercept: %v (implementation: %s)", caps.HasNetworkIntercept, caps.NetworkImplementation)
	t.Logf("HasSeccomp: %v", caps.HasSeccomp)
	t.Logf("HasCgroups: %v", caps.HasCgroups)
	t.Logf("IsolationLevel: %v", caps.IsolationLevel)

	// Linux should always report full isolation capability
	if caps.IsolationLevel != platform.IsolationFull {
		t.Errorf("expected IsolationFull on Linux, got %v", caps.IsolationLevel)
	}
}

func TestPlatform_FilesystemInterceptor(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	fs := p.Filesystem()
	if fs == nil {
		t.Fatal("Filesystem() returned nil")
	}

	t.Logf("Filesystem available: %v", fs.Available())
	t.Logf("Filesystem implementation: %s", fs.Implementation())
}

func TestDetect(t *testing.T) {
	mode, caps, err := platform.Detect()
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}

	if mode != platform.ModeLinuxNative {
		t.Errorf("expected ModeLinuxNative, got %v", mode)
	}

	t.Logf("Detected mode: %v", mode)
	t.Logf("Capabilities: HasFUSE=%v, HasSeccomp=%v, HasCgroups=%v",
		caps.HasFUSE, caps.HasSeccomp, caps.HasCgroups)
}

func TestMustNew_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustNew() panicked: %v", r)
		}
	}()

	p := platform.MustNew()
	if p == nil {
		t.Error("MustNew() returned nil")
	}
}

func TestPlatformMode_String(t *testing.T) {
	tests := []struct {
		mode platform.PlatformMode
		want string
	}{
		{platform.ModeAuto, "auto"},
		{platform.ModeLinuxNative, "linux-native"},
		{platform.ModeDarwinNative, "darwin-native"},
		{platform.ModeDarwinLima, "darwin-lima"},
		{platform.ModeWindowsNative, "windows-native"},
		{platform.ModeWindowsWSL2, "windows-wsl2"},
	}

	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("PlatformMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}
