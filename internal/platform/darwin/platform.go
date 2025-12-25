//go:build darwin

// Package darwin provides the macOS platform implementation for agentsh.
// Currently this is a stub implementation that reports capabilities as unavailable.
// Full implementation requires FUSE-T for filesystem and pf for network interception.
package darwin

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

func init() {
	// Register the Darwin platform constructor with the factory
	platform.RegisterDarwin(NewPlatform)
}

// Platform implements platform.Platform for macOS.
type Platform struct {
	config      platform.Config
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
// Currently returns minimal capabilities as this is a stub.
func (p *Platform) Capabilities() platform.Capabilities {
	return p.caps
}

// detectCapabilities checks what's available on this macOS system.
func (p *Platform) detectCapabilities() platform.Capabilities {
	// Stub implementation - report everything as unavailable
	// TODO: Implement detection for FUSE-T, pf, Endpoint Security, etc.
	return platform.Capabilities{
		HasFUSE:               false,
		FUSEImplementation:    "",
		HasNetworkIntercept:   false,
		NetworkImplementation: "",
		CanRedirectTraffic:    false,
		CanInspectTLS:         false,
		HasMountNamespace:     false,
		HasNetworkNamespace:   false,
		HasPIDNamespace:       false,
		HasUserNamespace:      false,
		IsolationLevel:        platform.IsolationNone,
		HasSeccomp:            false,
		HasCgroups:            false,
		CanLimitCPU:           false,
		CanLimitMemory:        false,
		CanLimitDiskIO:        false,
		CanLimitNetworkBW:     false,
		CanLimitProcessCount:  false,
		HasEndpointSecurity:   false,
		HasNetworkExtension:   false,
	}
}

// Filesystem returns the filesystem interceptor.
func (p *Platform) Filesystem() platform.FilesystemInterceptor {
	return &stubFilesystem{}
}

// Network returns the network interceptor.
func (p *Platform) Network() platform.NetworkInterceptor {
	return nil
}

// Sandbox returns the sandbox manager.
func (p *Platform) Sandbox() platform.SandboxManager {
	return nil
}

// Resources returns the resource limiter.
func (p *Platform) Resources() platform.ResourceLimiter {
	return nil
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

// stubFilesystem is a stub FilesystemInterceptor that reports as unavailable.
type stubFilesystem struct{}

func (f *stubFilesystem) Mount(config platform.FSConfig) (platform.FSMount, error) {
	return nil, fmt.Errorf("filesystem interception not yet implemented on macOS; install FUSE-T and rebuild")
}

func (f *stubFilesystem) Unmount(mount platform.FSMount) error {
	return fmt.Errorf("filesystem interception not available on macOS")
}

func (f *stubFilesystem) Available() bool {
	return false
}

func (f *stubFilesystem) Implementation() string {
	return "none"
}

// Compile-time interface checks
var (
	_ platform.Platform              = (*Platform)(nil)
	_ platform.FilesystemInterceptor = (*stubFilesystem)(nil)
)
