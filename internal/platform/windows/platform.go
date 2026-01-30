//go:build windows

// Package windows provides the Windows platform implementation for agentsh.
// It uses WinFsp for filesystem interception and WinDivert for network redirection.
// Sandboxing uses AppContainer and resource limits use Job Objects.
package windows

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/internal/platform"
)

func init() {
	// Register the Windows platform constructor with the factory
	platform.RegisterWindows(NewPlatform)
}

// Platform implements platform.Platform for Windows.
type Platform struct {
	config      platform.Config
	fs          *Filesystem
	net         *Network
	sandbox     *SandboxManager
	resources   *ResourceLimiter
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
func (p *Platform) Capabilities() platform.Capabilities {
	return p.caps
}

// detectCapabilities checks what's available on this Windows system.
func (p *Platform) detectCapabilities() platform.Capabilities {
	caps := platform.Capabilities{
		// Filesystem - check for WinFsp
		HasFUSE:            p.checkWinFsp(),
		FUSEImplementation: p.detectFuseImplementation(),

		// Network - check for WinDivert
		HasNetworkIntercept:   p.checkWinDivert(),
		NetworkImplementation: "windivert",
		CanRedirectTraffic:    true,
		CanInspectTLS:         true,

		// Isolation - Windows uses different mechanisms
		HasMountNamespace:   false, // No mount namespaces
		HasNetworkNamespace: false, // No network namespaces
		HasPIDNamespace:     false, // No PID namespaces
		HasUserNamespace:    false, // No user namespaces
		HasAppContainer:     p.checkAppContainer(),
		IsolationLevel:      p.detectIsolationLevel(),

		// Syscall filtering - no seccomp on Windows
		HasSeccomp: false,

		// Resource control - Job Objects instead of cgroups
		HasCgroups:           false,
		HasJobObjects:        p.checkJobObjects(),
		CanLimitCPU:          true,  // Job Objects support CPU limits
		CanLimitMemory:       true,  // Job Objects support memory limits
		CanLimitDiskIO:       false, // Limited IO control in Job Objects
		CanLimitNetworkBW:    false, // No native network BW limiting
		CanLimitProcessCount: true,  // Job Objects support process limits

		// Windows-specific capabilities
		HasRegistryMonitoring: p.checkRegistryMonitoring(),
		HasRegistryBlocking:   false, // Requires kernel driver
	}

	return caps
}

// checkWinFsp checks if WinFsp is installed.
func (p *Platform) checkWinFsp() bool {
	// Check common WinFsp installation paths
	paths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "WinFsp", "bin", "winfsp-x64.dll"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "WinFsp", "bin", "winfsp-x86.dll"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "winfsp-x64.dll"),
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Check registry for WinFsp installation
	cmd := exec.Command("reg", "query", `HKLM\SOFTWARE\WinFsp`, "/ve")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

// detectFuseImplementation returns the FUSE implementation name.
func (p *Platform) detectFuseImplementation() string {
	if p.checkWinFsp() {
		return "winfsp"
	}
	return ""
}

// checkWinDivert checks if WinDivert is installed.
func (p *Platform) checkWinDivert() bool {
	// Check for WinDivert driver
	paths := []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "WinDivert.sys"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "WinDivert64.sys"),
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Also check for WinDivert DLL
	dllPaths := []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "WinDivert.dll"),
	}

	for _, path := range dllPaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

// checkAppContainer checks if AppContainer is available.
// AppContainer is available on Windows 8+ and provides sandboxing.
func (p *Platform) checkAppContainer() bool {
	// AppContainer is available on Windows 8 and later
	// Check Windows version via ver command
	cmd := exec.Command("cmd", "/c", "ver")
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	// Parse version - AppContainer requires Windows 8+ (version 6.2+)
	version := strings.TrimSpace(string(out))
	// Version string format: "Microsoft Windows [Version 10.0.xxxxx]"
	if strings.Contains(version, "Version 10.") ||
		strings.Contains(version, "Version 6.3") || // Windows 8.1
		strings.Contains(version, "Version 6.2") { // Windows 8
		return true
	}

	return false
}

// detectIsolationLevel determines what isolation is available.
func (p *Platform) detectIsolationLevel() platform.IsolationLevel {
	if p.checkAppContainer() {
		return platform.IsolationPartial // AppContainer provides partial isolation (capability-based)
	}
	return platform.IsolationNone
}

// checkJobObjects checks if Job Objects are available.
// Job Objects are available on all modern Windows versions.
func (p *Platform) checkJobObjects() bool {
	// Job Objects are available on Windows 2000 and later
	// They're always available on any Windows version we'd support
	return true
}

// checkRegistryMonitoring checks if registry monitoring is available.
func (p *Platform) checkRegistryMonitoring() bool {
	// Registry change notifications are available on all Windows versions
	// We can use RegNotifyChangeKeyValue for monitoring
	return true
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

// getWindowsVersion returns the Windows version string.
func getWindowsVersion() string {
	cmd := exec.Command("cmd", "/c", "ver")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// Compile-time interface check
var _ platform.Platform = (*Platform)(nil)
