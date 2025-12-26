//go:build darwin

package darwin

import (
	"context"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewPlatform(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	dp, ok := p.(*Platform)
	if !ok {
		t.Fatal("NewPlatform() did not return *Platform")
	}

	if dp.permissions == nil {
		t.Error("permissions is nil")
	}
}

func TestPlatform_Name(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	name := p.Name()
	if !strings.HasPrefix(name, "darwin-") {
		t.Errorf("Name() = %q, want prefix 'darwin-'", name)
	}

	// Check it contains a valid tier name
	tiers := []string{"enterprise", "full", "network-only", "monitor-only", "minimal"}
	found := false
	for _, tier := range tiers {
		if strings.Contains(name, tier) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Name() = %q, does not contain a valid tier", name)
	}
}

func TestPlatform_Capabilities(t *testing.T) {
	p, err := NewPlatform()
	if err != nil {
		t.Fatalf("NewPlatform() error = %v", err)
	}

	caps := p.Capabilities()

	// macOS lacks Linux namespace features
	if caps.HasMountNamespace {
		t.Error("HasMountNamespace should be false on macOS")
	}
	if caps.HasNetworkNamespace {
		t.Error("HasNetworkNamespace should be false on macOS")
	}
	if caps.HasPIDNamespace {
		t.Error("HasPIDNamespace should be false on macOS")
	}
	if caps.HasUserNamespace {
		t.Error("HasUserNamespace should be false on macOS")
	}
	if caps.HasSeccomp {
		t.Error("HasSeccomp should be false on macOS")
	}
	if caps.HasCgroups {
		t.Error("HasCgroups should be false on macOS")
	}
	if caps.IsolationLevel != platform.IsolationNone {
		t.Errorf("IsolationLevel = %v, want IsolationNone", caps.IsolationLevel)
	}
}

func TestPlatform_detectCapabilities_ByTier(t *testing.T) {
	tests := []struct {
		tier                  PermissionTier
		wantFUSE              bool
		wantFUSEImpl          string
		wantNetworkIntercept  bool
		wantNetworkImpl       string
		wantCanRedirectTraffic bool
	}{
		{
			tier:                   TierEnterprise,
			wantFUSE:               true,
			wantFUSEImpl:           "endpoint-security",
			wantNetworkIntercept:   true,
			wantNetworkImpl:        "network-extension",
			wantCanRedirectTraffic: true,
		},
		{
			tier:                   TierFull,
			wantFUSE:               true,
			wantFUSEImpl:           "fuse-t",
			wantNetworkIntercept:   true,
			wantNetworkImpl:        "pf",
			wantCanRedirectTraffic: true,
		},
		{
			tier:                   TierNetworkOnly,
			wantFUSE:               false,
			wantFUSEImpl:           "fsevents-observe",
			wantNetworkIntercept:   true,
			wantNetworkImpl:        "pf",
			wantCanRedirectTraffic: true,
		},
		{
			tier:                   TierMonitorOnly,
			wantFUSE:               false,
			wantFUSEImpl:           "fsevents-observe",
			wantNetworkIntercept:   false,
			wantNetworkImpl:        "pcap-observe",
			wantCanRedirectTraffic: false,
		},
		{
			tier:                   TierMinimal,
			wantFUSE:               false,
			wantFUSEImpl:           "",
			wantNetworkIntercept:   false,
			wantNetworkImpl:        "",
			wantCanRedirectTraffic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			p := &Platform{
				permissions: &Permissions{Tier: tt.tier},
			}
			caps := p.detectCapabilities()

			if caps.HasFUSE != tt.wantFUSE {
				t.Errorf("HasFUSE = %v, want %v", caps.HasFUSE, tt.wantFUSE)
			}
			if caps.FUSEImplementation != tt.wantFUSEImpl {
				t.Errorf("FUSEImplementation = %q, want %q", caps.FUSEImplementation, tt.wantFUSEImpl)
			}
			if caps.HasNetworkIntercept != tt.wantNetworkIntercept {
				t.Errorf("HasNetworkIntercept = %v, want %v", caps.HasNetworkIntercept, tt.wantNetworkIntercept)
			}
			if caps.NetworkImplementation != tt.wantNetworkImpl {
				t.Errorf("NetworkImplementation = %q, want %q", caps.NetworkImplementation, tt.wantNetworkImpl)
			}
			if caps.CanRedirectTraffic != tt.wantCanRedirectTraffic {
				t.Errorf("CanRedirectTraffic = %v, want %v", caps.CanRedirectTraffic, tt.wantCanRedirectTraffic)
			}
		})
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
	dp := p.(*Platform)
	if dp.fs != fs2.(*Filesystem) {
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
	dp := p.(*Platform)
	if dp.net != net2.(*Network) {
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
	dp := p.(*Platform)
	if dp.sandbox != sb2.(*SandboxManager) {
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
	dp := p.(*Platform)
	if dp.resources != res2.(*ResourceLimiter) {
		t.Error("Resources() should return same instance")
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

	dp := p.(*Platform)
	if !dp.initialized {
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

	dp := p.(*Platform)
	if dp.initialized {
		t.Error("initialized should be false after Shutdown()")
	}
}

func TestPlatform_InterfaceCompliance(t *testing.T) {
	var _ platform.Platform = (*Platform)(nil)
}

func TestGetMacOSVersion(t *testing.T) {
	version := getMacOSVersion()
	// Just verify it returns something (either a version or "unknown")
	if version == "" {
		t.Error("getMacOSVersion() returned empty string")
	}
}
