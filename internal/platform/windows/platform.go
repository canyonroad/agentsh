//go:build windows

// Package windows provides the Windows platform implementation for agentsh.
// Currently this is a stub implementation that reports capabilities as unavailable.
// Full implementation requires WinFsp for filesystem and WinDivert for network interception.
package windows

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

func init() {
	// Register the Windows platform constructor with the factory
	platform.RegisterWindows(NewPlatform)
}

// Platform implements platform.Platform for Windows.
type Platform struct {
	config      platform.Config
	caps        platform.Capabilities
	initialized bool
}

// NewPlatform creates a new Windows platform.
func NewPlatform() (platform.Platform, error) {
	p := &Platform{}
	p.caps = p.detectCapabilities()
	return p, nil
}

// Name returns the platform identifier.
func (p *Platform) Name() string {
	return "windows"
}

// Capabilities returns what this platform supports.
// Currently returns minimal capabilities as this is a stub.
func (p *Platform) Capabilities() platform.Capabilities {
	return p.caps
}

// detectCapabilities checks what's available on this Windows system.
func (p *Platform) detectCapabilities() platform.Capabilities {
	// Stub implementation - report everything as unavailable
	// TODO: Implement detection for WinFsp, WinDivert, AppContainer, Job Objects, etc.
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
		HasAppContainer:       false,
		IsolationLevel:        platform.IsolationNone,
		HasSeccomp:            false,
		HasCgroups:            false,
		HasJobObjects:         false,
		CanLimitCPU:           false,
		CanLimitMemory:        false,
		CanLimitDiskIO:        false,
		CanLimitNetworkBW:     false,
		CanLimitProcessCount:  false,
		HasRegistryMonitoring: false,
		HasRegistryBlocking:   false,
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
	return nil, fmt.Errorf("filesystem interception not yet implemented on Windows; install WinFsp and rebuild")
}

func (f *stubFilesystem) Unmount(mount platform.FSMount) error {
	return fmt.Errorf("filesystem interception not available on Windows")
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
