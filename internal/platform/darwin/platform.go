//go:build darwin

// Package darwin provides the macOS platform implementation for agentsh.
// It uses FUSE-T for filesystem interception and pf for network redirection.
// Note: macOS lacks namespace isolation and cgroups, so those features are unavailable.
package darwin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/agentsh/agentsh/internal/platform"
)

func init() {
	// Register the Darwin platform constructor with the factory
	platform.RegisterDarwin(NewPlatform)
}

// Platform implements platform.Platform for macOS.
type Platform struct {
	config      platform.Config
	permissions *Permissions
	fs          *Filesystem
	net         *Network
	sandbox     *SandboxManager
	resources   *ResourceLimiter
	caps        platform.Capabilities
	initialized bool
}

// NewPlatform creates a new macOS platform.
func NewPlatform() (platform.Platform, error) {
	p := &Platform{}
	p.permissions = DetectPermissions()
	p.caps = p.detectCapabilities()
	return p, nil
}

// Name returns the platform identifier including tier.
func (p *Platform) Name() string {
	return fmt.Sprintf("darwin-%s", p.permissions.Tier.String())
}

// Capabilities returns what this platform supports.
func (p *Platform) Capabilities() platform.Capabilities {
	return p.caps
}

// Permissions returns the detected permission state.
func (p *Platform) Permissions() *Permissions {
	return p.permissions
}

// detectCapabilities checks what's available on this macOS system.
func (p *Platform) detectCapabilities() platform.Capabilities {
	tier := p.permissions.Tier

	caps := platform.Capabilities{
		// Isolation - macOS lacks Linux namespaces
		HasMountNamespace:   false,
		HasNetworkNamespace: false,
		HasPIDNamespace:     false,
		HasUserNamespace:    false,
		IsolationLevel:      platform.IsolationNone,

		// Syscall filtering - no seccomp on macOS
		HasSeccomp: false,

		// Resource control - no cgroups on macOS
		HasCgroups:           false,
		CanLimitCPU:          false,
		CanLimitMemory:       false,
		CanLimitDiskIO:       false,
		CanLimitNetworkBW:    false,
		CanLimitProcessCount: false,

		// macOS-specific frameworks
		HasEndpointSecurity: p.permissions.HasEndpointSecurity,
		HasNetworkExtension: p.permissions.HasNetworkExtension,
	}

	// Set capabilities based on tier
	switch tier {
	case TierEnterprise:
		caps.HasFUSE = true
		caps.FUSEImplementation = "endpoint-security"
		caps.HasNetworkIntercept = true
		caps.NetworkImplementation = "network-extension"
		caps.CanRedirectTraffic = true
		caps.CanInspectTLS = true

	case TierFull:
		caps.HasFUSE = true
		caps.FUSEImplementation = "fuse-t"
		caps.HasNetworkIntercept = true
		caps.NetworkImplementation = "pf"
		caps.CanRedirectTraffic = true
		caps.CanInspectTLS = true

	case TierNetworkOnly:
		caps.HasFUSE = false
		caps.FUSEImplementation = "fsevents-observe"
		caps.HasNetworkIntercept = true
		caps.NetworkImplementation = "pf"
		caps.CanRedirectTraffic = true
		caps.CanInspectTLS = true

	case TierMonitorOnly:
		caps.HasFUSE = false
		caps.FUSEImplementation = "fsevents-observe"
		caps.HasNetworkIntercept = false
		caps.NetworkImplementation = "pcap-observe"
		caps.CanRedirectTraffic = false
		caps.CanInspectTLS = false

	case TierMinimal:
		caps.HasFUSE = false
		caps.HasNetworkIntercept = false
	}

	return caps
}

// Filesystem returns the filesystem interceptor.
func (p *Platform) Filesystem() platform.FilesystemInterceptor {
	if p.fs == nil {
		p.fs = NewFilesystem()
	}
	return p.fs
}

// Network returns the network interceptor.
func (p *Platform) Network() platform.NetworkInterceptor {
	if p.net == nil {
		p.net = NewNetwork()
	}
	return p.net
}

// Sandbox returns the sandbox manager.
func (p *Platform) Sandbox() platform.SandboxManager {
	if p.sandbox == nil {
		p.sandbox = NewSandboxManager()
	}
	return p.sandbox
}

// Resources returns the resource limiter.
func (p *Platform) Resources() platform.ResourceLimiter {
	if p.resources == nil {
		p.resources = NewResourceLimiter()
	}
	return p.resources
}

// Initialize sets up the platform.
func (p *Platform) Initialize(ctx context.Context, config platform.Config) error {
	if p.initialized {
		return fmt.Errorf("platform already initialized")
	}
	p.config = config
	p.initialized = true

	// Log permission status
	fmt.Fprintln(os.Stderr, p.permissions.LogStatus())

	return nil
}

// Shutdown cleans up platform resources.
func (p *Platform) Shutdown(ctx context.Context) error {
	// Teardown network if configured
	if p.net != nil && p.net.configured {
		if err := p.net.Teardown(); err != nil {
			return fmt.Errorf("network teardown: %w", err)
		}
	}

	p.initialized = false
	return nil
}

// getMacOSVersion returns the macOS version string.
func getMacOSVersion() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// Compile-time interface check
var _ platform.Platform = (*Platform)(nil)
