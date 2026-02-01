//go:build windows

package wsl2

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestWindowsToWSLPath(t *testing.T) {
	tests := []struct {
		winPath string
		want    string
	}{
		{`C:\Users\foo`, "/mnt/c/Users/foo"},
		{`D:\Projects\myapp`, "/mnt/d/Projects/myapp"},
		{`C:\`, "/mnt/c/"},
		{`c:\lowercase`, "/mnt/c/lowercase"},
		{`/already/unix`, "/already/unix"},
		{`relative\path`, "relative/path"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.winPath, func(t *testing.T) {
			got := WindowsToWSLPath(tt.winPath)
			if got != tt.want {
				t.Errorf("WindowsToWSLPath(%q) = %q, want %q", tt.winPath, got, tt.want)
			}
		})
	}
}

func TestWSLToWindowsPath(t *testing.T) {
	tests := []struct {
		wslPath string
		want    string
	}{
		{"/mnt/c/Users/foo", `C:\Users\foo`},
		{"/mnt/d/Projects/myapp", `D:\Projects\myapp`},
		{"/mnt/c/", `C:\`},
		{"/home/user", `\home\user`}, // Non-mounted path
		{"/mnt/", `\mnt\`},           // Too short
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.wslPath, func(t *testing.T) {
			got := WSLToWindowsPath(tt.wslPath)
			if got != tt.want {
				t.Errorf("WSLToWindowsPath(%q) = %q, want %q", tt.wslPath, got, tt.want)
			}
		})
	}
}

func TestPathRoundTrip(t *testing.T) {
	paths := []string{
		`C:\Users\test\Documents`,
		`D:\Projects\app\src`,
		`E:\Data`,
	}

	for _, path := range paths {
		wsl := WindowsToWSLPath(path)
		back := WSLToWindowsPath(wsl)
		if back != path {
			t.Errorf("Round trip failed: %q -> %q -> %q", path, wsl, back)
		}
	}
}

func TestNewPlatform(t *testing.T) {
	// This test will skip if WSL2 is not available
	p, err := NewPlatform()
	if err != nil {
		t.Skipf("WSL2 not available: %v", err)
	}

	if p == nil {
		t.Fatal("NewPlatform() returned nil without error")
	}

	wp, ok := p.(*Platform)
	if !ok {
		t.Fatal("NewPlatform() did not return *Platform")
	}

	if wp.distro == "" {
		t.Error("distro should not be empty")
	}
}

func TestPlatform_Name(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	if got := p.Name(); got != "windows-wsl2" {
		t.Errorf("Name() = %q, want windows-wsl2", got)
	}
}

func TestPlatform_Distro(t *testing.T) {
	p := &Platform{distro: "Ubuntu-22.04"}
	if got := p.Distro(); got != "Ubuntu-22.04" {
		t.Errorf("Distro() = %q, want Ubuntu-22.04", got)
	}
}

func TestPlatform_Capabilities(t *testing.T) {
	p := &Platform{
		distro: "Ubuntu",
		caps: platform.Capabilities{
			HasFUSE:             true,
			HasMountNamespace:   true,
			HasNetworkNamespace: true,
			HasPIDNamespace:     true,
			HasSeccomp:          true,
			HasCgroups:          true,
			IsolationLevel:      platform.IsolationFull,
		},
	}

	caps := p.Capabilities()

	// WSL2 should have full Linux capabilities
	if !caps.HasMountNamespace {
		t.Error("HasMountNamespace should be true for WSL2")
	}
	if !caps.HasNetworkNamespace {
		t.Error("HasNetworkNamespace should be true for WSL2")
	}
	if !caps.HasPIDNamespace {
		t.Error("HasPIDNamespace should be true for WSL2")
	}
	if caps.IsolationLevel != platform.IsolationFull {
		t.Errorf("IsolationLevel = %v, want IsolationFull", caps.IsolationLevel)
	}
}

func TestPlatform_Initialize(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}

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
	p := &Platform{distro: "Ubuntu", initialized: true}

	ctx := context.Background()

	if err := p.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}

	if p.initialized {
		t.Error("initialized should be false after Shutdown()")
	}
}

func TestPlatform_Filesystem(t *testing.T) {
	skipIfWSLUnavailable(t)
	p := &Platform{distro: "Ubuntu"}

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
	skipIfWSLUnavailable(t)
	p := &Platform{distro: "Ubuntu"}

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
	skipIfWSLUnavailable(t)
	p := &Platform{distro: "Ubuntu"}

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
	skipIfWSLUnavailable(t)
	p := &Platform{distro: "Ubuntu"}

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

func TestDetectDefaultDistro(t *testing.T) {
	// Just verify it returns something
	distro := detectDefaultDistro()
	if distro == "" {
		t.Error("detectDefaultDistro() returned empty string")
	}
}
