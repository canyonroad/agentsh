//go:build darwin

package lima

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestMacOSToLimaPath(t *testing.T) {
	tests := []struct {
		macPath string
		want    string
	}{
		{"/Users/foo/project", "/Users/foo/project"},
		{"/Volumes/External/data", "/Volumes/External/data"},
		{"/tmp/test", "/tmp/test"},
		{"/var/folders/xyz", "/var/folders/xyz"},
		{"/opt/homebrew/bin", "/opt/homebrew/bin"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.macPath, func(t *testing.T) {
			got := MacOSToLimaPath(tt.macPath)
			if got != tt.want {
				t.Errorf("MacOSToLimaPath(%q) = %q, want %q", tt.macPath, got, tt.want)
			}
		})
	}
}

func TestLimaToMacOSPath(t *testing.T) {
	tests := []struct {
		limaPath string
		want     string
	}{
		{"/Users/foo/project", "/Users/foo/project"},
		{"/Volumes/External/data", "/Volumes/External/data"},
		{"/tmp/test", "/tmp/test"},
		{"/var/folders/xyz", "/var/folders/xyz"},
		{"/home/lima/work", "/home/lima/work"}, // Non-mounted path stays as-is
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.limaPath, func(t *testing.T) {
			got := LimaToMacOSPath(tt.limaPath)
			if got != tt.want {
				t.Errorf("LimaToMacOSPath(%q) = %q, want %q", tt.limaPath, got, tt.want)
			}
		})
	}
}

func TestPathRoundTrip(t *testing.T) {
	// Lima mounts /Users, /Volumes, /tmp by default so round trips should work
	paths := []string{
		"/Users/test/Documents",
		"/Volumes/Data/projects",
		"/tmp/workspace",
	}

	for _, path := range paths {
		lima := MacOSToLimaPath(path)
		back := LimaToMacOSPath(lima)
		if back != path {
			t.Errorf("Round trip failed: %q -> %q -> %q", path, lima, back)
		}
	}
}

func TestNewPlatform(t *testing.T) {
	// This test will skip if Lima is not available
	p, err := NewPlatform()
	if err != nil {
		t.Skipf("Lima not available: %v", err)
	}

	if p == nil {
		t.Fatal("NewPlatform() returned nil without error")
	}

	lp, ok := p.(*Platform)
	if !ok {
		t.Fatal("NewPlatform() did not return *Platform")
	}

	if lp.instance == "" {
		t.Error("instance should not be empty")
	}
}

func TestPlatform_Name(t *testing.T) {
	p := &Platform{instance: "default"}
	if got := p.Name(); got != "darwin-lima" {
		t.Errorf("Name() = %q, want darwin-lima", got)
	}
}

func TestPlatform_Instance(t *testing.T) {
	p := &Platform{instance: "dev-vm"}
	if got := p.Instance(); got != "dev-vm" {
		t.Errorf("Instance() = %q, want dev-vm", got)
	}
}

func TestPlatform_Capabilities(t *testing.T) {
	p := &Platform{
		instance: "default",
		caps: platform.Capabilities{
			HasFUSE:             true,
			FUSEImplementation:  "fuse3",
			HasMountNamespace:   true,
			HasNetworkNamespace: true,
			HasPIDNamespace:     true,
			HasSeccomp:          true,
			HasCgroups:          true,
			IsolationLevel:      platform.IsolationFull,
		},
	}

	caps := p.Capabilities()

	// Lima should have full Linux capabilities
	if !caps.HasMountNamespace {
		t.Error("HasMountNamespace should be true for Lima")
	}
	if !caps.HasNetworkNamespace {
		t.Error("HasNetworkNamespace should be true for Lima")
	}
	if !caps.HasPIDNamespace {
		t.Error("HasPIDNamespace should be true for Lima")
	}
	if caps.IsolationLevel != platform.IsolationFull {
		t.Errorf("IsolationLevel = %v, want IsolationFull", caps.IsolationLevel)
	}
	if caps.FUSEImplementation != "fuse3" {
		t.Errorf("FUSEImplementation = %q, want fuse3", caps.FUSEImplementation)
	}
}

func TestPlatform_Initialize(t *testing.T) {
	p := &Platform{instance: "default"}

	ctx := context.Background()
	cfg := platform.Config{}

	if err := p.Initialize(ctx, cfg); err != nil {
		t.Errorf("Initialize() error = %v", err)
	}

	if !p.initialized {
		t.Error("initialized should be true after Initialize()")
	}

	// Initialize again should error
	if err := p.Initialize(ctx, cfg); err == nil {
		t.Error("Initialize() should error when already initialized")
	}
}

func TestPlatform_Shutdown(t *testing.T) {
	p := &Platform{instance: "default", initialized: true}

	ctx := context.Background()

	if err := p.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	if p.initialized {
		t.Error("initialized should be false after Shutdown()")
	}
}

func TestPlatform_Filesystem(t *testing.T) {
	p := &Platform{instance: "default"}

	fs := p.Filesystem()
	if fs == nil {
		t.Error("Filesystem() returned nil")
	}

	// Should return same instance
	fs2 := p.Filesystem()
	if p.fs != fs2.(*Filesystem) {
		t.Error("Filesystem() should return same instance")
	}
}

func TestPlatform_Network(t *testing.T) {
	p := &Platform{instance: "default"}

	net := p.Network()
	if net == nil {
		t.Error("Network() returned nil")
	}

	// Should return same instance
	net2 := p.Network()
	if p.net != net2.(*Network) {
		t.Error("Network() should return same instance")
	}
}

func TestPlatform_Sandbox(t *testing.T) {
	p := &Platform{instance: "default"}

	sb := p.Sandbox()
	if sb == nil {
		t.Error("Sandbox() returned nil")
	}

	// Should return same instance
	sb2 := p.Sandbox()
	if p.sandbox != sb2.(*SandboxManager) {
		t.Error("Sandbox() should return same instance")
	}
}

func TestPlatform_Resources(t *testing.T) {
	p := &Platform{instance: "default"}

	res := p.Resources()
	if res == nil {
		t.Error("Resources() returned nil")
	}

	// Should return same instance
	res2 := p.Resources()
	if p.resources != res2.(*ResourceLimiter) {
		t.Error("Resources() should return same instance")
	}
}

func TestPlatform_InterfaceCompliance(t *testing.T) {
	var _ platform.Platform = (*Platform)(nil)
}

func TestDetectDefaultInstance(t *testing.T) {
	// Just verify it returns something
	instance := detectDefaultInstance()
	if instance == "" {
		t.Error("detectDefaultInstance() returned empty string")
	}
}
