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
	p.caps = p.detectCapabilities()
	return p, nil
}

// Name returns the platform identifier.
func (p *Platform) Name() string {
	return "darwin"
}

// Capabilities returns what this platform supports.
func (p *Platform) Capabilities() platform.Capabilities {
	return p.caps
}

// detectCapabilities checks what's available on this macOS system.
func (p *Platform) detectCapabilities() platform.Capabilities {
	caps := platform.Capabilities{
		// Filesystem - check for FUSE-T
		HasFUSE:            p.checkFuseT(),
		FUSEImplementation: p.detectFuseImplementation(),

		// Network - pf is always available on macOS
		HasNetworkIntercept:   p.checkPf(),
		NetworkImplementation: "pf",
		CanRedirectTraffic:    true,
		CanInspectTLS:         true,

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

		// macOS-specific frameworks (require entitlements)
		HasEndpointSecurity: p.checkEndpointSecurity(),
		HasNetworkExtension: p.checkNetworkExtension(),
	}

	return caps
}

// checkFuseT checks if FUSE-T is installed.
func (p *Platform) checkFuseT() bool {
	// FUSE-T installation paths
	paths := []string{
		"/usr/local/lib/libfuse-t.dylib",
		"/opt/homebrew/lib/libfuse-t.dylib",
		"/Library/Frameworks/FUSE-T.framework",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// detectFuseImplementation returns the FUSE implementation name.
func (p *Platform) detectFuseImplementation() string {
	// Check for FUSE-T first (preferred)
	fuseTpaths := []string{
		"/usr/local/lib/libfuse-t.dylib",
		"/opt/homebrew/lib/libfuse-t.dylib",
		"/Library/Frameworks/FUSE-T.framework",
	}
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			return "fuse-t"
		}
	}

	// Check for macFUSE (deprecated but may be present)
	macFUSEpaths := []string{
		"/Library/Filesystems/macfuse.fs",
		"/Library/Frameworks/macFUSE.framework",
	}
	for _, path := range macFUSEpaths {
		if _, err := os.Stat(path); err == nil {
			return "macfuse"
		}
	}

	return ""
}

// checkPf checks if pf (packet filter) is available.
func (p *Platform) checkPf() bool {
	// pf is always available on macOS, but we need root to use it
	// Check if pfctl exists
	_, err := exec.LookPath("pfctl")
	return err == nil
}

// checkEndpointSecurity checks if Endpoint Security framework is usable.
// Note: Actually using it requires entitlements signed by Apple.
func (p *Platform) checkEndpointSecurity() bool {
	// Check if the framework exists
	if _, err := os.Stat("/System/Library/Frameworks/EndpointSecurity.framework"); err == nil {
		return true
	}
	return false
}

// checkNetworkExtension checks if Network Extension framework is usable.
// Note: Actually using it requires entitlements signed by Apple.
func (p *Platform) checkNetworkExtension() bool {
	// Check if the framework exists
	if _, err := os.Stat("/System/Library/Frameworks/NetworkExtension.framework"); err == nil {
		return true
	}
	return false
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
	return nil
}

// Shutdown cleans up platform resources.
func (p *Platform) Shutdown(ctx context.Context) error {
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
