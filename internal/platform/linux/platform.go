//go:build linux

// Package linux provides the Linux platform implementation for agentsh.
// It uses FUSE for filesystem interception, iptables for network interception,
// namespaces for process isolation, seccomp for syscall filtering, and
// cgroups v2 for resource limiting.
package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/agentsh/agentsh/internal/platform"
)

func init() {
	// Register the Linux platform constructor with the factory
	platform.RegisterLinux(NewPlatform)
}

// Platform implements platform.Platform for Linux.
type Platform struct {
	config      platform.Config
	fs          *Filesystem
	net         *Network
	sandbox     *SandboxManager
	resources   *ResourceLimiter
	caps        platform.Capabilities
	initialized bool
}

// NewPlatform creates a new Linux platform.
func NewPlatform() (platform.Platform, error) {
	p := &Platform{}
	p.caps = p.detectCapabilities()
	return p, nil
}

// Name returns the platform identifier.
func (p *Platform) Name() string {
	return "linux"
}

// Capabilities returns what this platform supports.
func (p *Platform) Capabilities() platform.Capabilities {
	return p.caps
}

// detectCapabilities checks what's available on this Linux system.
func (p *Platform) detectCapabilities() platform.Capabilities {
	caps := platform.Capabilities{
		// Filesystem - FUSE is typically available on Linux
		HasFUSE:            p.checkFUSE(),
		FUSEImplementation: p.detectFUSEVersion(),

		// Network - iptables is standard on Linux
		HasNetworkIntercept:   p.checkIptables(),
		NetworkImplementation: "iptables",
		CanRedirectTraffic:    true,
		CanInspectTLS:         true,

		// Isolation - namespaces are core Linux features
		HasMountNamespace:   true,
		HasNetworkNamespace: true,
		HasPIDNamespace:     true,
		HasUserNamespace:    p.checkUserNamespace(),
		IsolationLevel:      platform.IsolationFull,

		// Syscall filtering
		HasSeccomp: p.checkSeccomp(),

		// Resource control
		HasCgroups:           p.checkCgroups(),
		CanLimitCPU:          true,
		CanLimitMemory:       true,
		CanLimitDiskIO:       true,
		CanLimitNetworkBW:    true,
		CanLimitProcessCount: true,
	}

	return caps
}

// checkFUSE checks if FUSE is available and mountable.
func (p *Platform) checkFUSE() bool {
	return canMountFUSE()
}

// detectFUSEVersion returns the FUSE implementation version.
func (p *Platform) detectFUSEVersion() string {
	// Check for FUSE3
	if _, err := exec.LookPath("fusermount3"); err == nil {
		return "fuse3"
	}
	// Fall back to FUSE2
	if _, err := exec.LookPath("fusermount"); err == nil {
		return "fuse2"
	}
	return ""
}

// checkIptables checks if iptables is available.
func (p *Platform) checkIptables() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

// checkUserNamespace checks if user namespaces are enabled.
func (p *Platform) checkUserNamespace() bool {
	// Try to read max_user_namespaces
	data, err := os.ReadFile("/proc/sys/user/max_user_namespaces")
	if err != nil {
		return false
	}
	// If it's > 0, user namespaces are enabled
	return strings.TrimSpace(string(data)) != "0"
}

// checkSeccomp checks if seccomp is available.
func (p *Platform) checkSeccomp() bool {
	// Check /proc/sys/kernel/seccomp
	if _, err := os.Stat("/proc/sys/kernel/seccomp"); err == nil {
		return true
	}
	// Alternative: check if seccomp mode is in status
	data, err := os.ReadFile("/proc/self/status")
	if err == nil && strings.Contains(string(data), "Seccomp:") {
		return true
	}
	return false
}

// checkCgroups checks if cgroups v2 is available.
func (p *Platform) checkCgroups() bool {
	// Check for cgroup2 mount
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "cgroup2")
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

// Initialize sets up the platform with the given configuration.
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
	if !p.initialized {
		return nil
	}

	// Clean up filesystem mounts
	if p.fs != nil {
		// Mounts are cleaned up individually via FSMount.Close()
	}

	p.initialized = false
	return nil
}
