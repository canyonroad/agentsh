//go:build windows

package windows

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewPlatform(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	wp, ok := p.(*Platform)
	if !ok {
		t.Fatal("NewPlatform() did not return *Platform")
	}

	if wp.Name() != "windows" {
		t.Errorf("Name() = %q, want windows", wp.Name())
	}
}

func TestPlatform_Capabilities(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	caps := p.Capabilities()

	// Windows lacks Linux namespaces
	if caps.HasMountNamespace {
		t.Error("HasMountNamespace should be false on Windows")
	}
	if caps.HasNetworkNamespace {
		t.Error("HasNetworkNamespace should be false on Windows")
	}
	if caps.HasPIDNamespace {
		t.Error("HasPIDNamespace should be false on Windows")
	}
	if caps.HasUserNamespace {
		t.Error("HasUserNamespace should be false on Windows")
	}
	if caps.HasSeccomp {
		t.Error("HasSeccomp should be false on Windows")
	}
	if caps.HasCgroups {
		t.Error("HasCgroups should be false on Windows")
	}

	// Windows should have Job Objects
	if !caps.HasJobObjects {
		t.Error("HasJobObjects should be true on Windows")
	}

	// Windows should have registry monitoring
	if !caps.HasRegistryMonitoring {
		t.Error("HasRegistryMonitoring should be true on Windows")
	}
}

func TestPlatform_Initialize(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	ctx := context.Background()
	cfg := platform.Config{}

	if err := p.Initialize(ctx, cfg); err != nil {
		t.Errorf("Initialize() error = %v", err)
	}

	wp := p.(*Platform)
	if !wp.initialized {
		t.Error("initialized should be true after Initialize()")
	}

	// Initialize again should error
	if err := p.Initialize(ctx, cfg); err == nil {
		t.Error("Initialize() should error when already initialized")
	}
}

func TestPlatform_Shutdown(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	ctx := context.Background()
	cfg := platform.Config{}

	if err := p.Initialize(ctx, cfg); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	if err := p.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	wp := p.(*Platform)
	if wp.initialized {
		t.Error("initialized should be false after Shutdown()")
	}
}

func TestPlatform_Filesystem(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	fs := p.Filesystem()
	if fs == nil {
		t.Error("Filesystem() returned nil")
	}

	// Should return same instance
	fs2 := p.Filesystem()
	wp := p.(*Platform)
	if wp.fs != fs2.(*Filesystem) {
		t.Error("Filesystem() should return same instance")
	}
}

func TestPlatform_Network(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	net := p.Network()
	if net == nil {
		t.Error("Network() returned nil")
	}

	// Should return same instance
	net2 := p.Network()
	wp := p.(*Platform)
	if wp.net != net2.(*Network) {
		t.Error("Network() should return same instance")
	}
}

func TestPlatform_Sandbox(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	sb := p.Sandbox()
	if sb == nil {
		t.Error("Sandbox() returned nil")
	}

	// Should return same instance
	sb2 := p.Sandbox()
	wp := p.(*Platform)
	if wp.sandbox != sb2.(*SandboxManager) {
		t.Error("Sandbox() should return same instance")
	}
}

func TestPlatform_Resources(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	res := p.Resources()
	if res == nil {
		t.Error("Resources() returned nil")
	}

	// Should return same instance
	res2 := p.Resources()
	wp := p.(*Platform)
	if wp.resources != res2.(*ResourceLimiter) {
		t.Error("Resources() should return same instance")
	}
}

func TestPlatformCapabilities(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	caps := p.Capabilities()

	if !caps.HasAppContainer {
		t.Error("HasAppContainer should be true on Windows 8+")
	}
}

func TestPlatform_InterfaceCompliance(t *testing.T) {
	var _ platform.Platform = (*Platform)(nil)
}
