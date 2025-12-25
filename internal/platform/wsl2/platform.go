//go:build windows

// Package wsl2 provides the Windows WSL2 platform implementation for agentsh.
// WSL2 runs a real Linux kernel, providing full Linux capabilities including
// FUSE3, iptables, namespaces, seccomp, and cgroups v2.
package wsl2

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

func init() {
	// Register the WSL2 platform constructor with the factory
	platform.RegisterWindowsWSL2(NewPlatform)
}

// Platform implements platform.Platform for Windows WSL2.
type Platform struct {
	config      platform.Config
	distro      string
	caps        platform.Capabilities
	fs          *Filesystem
	net         *Network
	sandbox     *SandboxManager
	resources   *ResourceLimiter
	initialized bool
	mu          sync.Mutex
}

// NewPlatform creates a new Windows WSL2 platform.
func NewPlatform() (platform.Platform, error) {
	p := &Platform{
		distro: detectDefaultDistro(),
	}

	if !p.checkWSL2Available() {
		return nil, fmt.Errorf("WSL2 not available; enable with: wsl --install")
	}

	p.caps = p.detectCapabilities()
	return p, nil
}

// detectDefaultDistro finds the default WSL2 distro.
func detectDefaultDistro() string {
	cmd := exec.Command("wsl", "-l", "-q")
	out, err := cmd.Output()
	if err != nil {
		return "Ubuntu"
	}

	// First line is the default distro
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 0 {
		// Remove any null bytes (UTF-16 artifacts)
		distro := strings.ReplaceAll(lines[0], "\x00", "")
		if distro != "" {
			return strings.TrimSpace(distro)
		}
	}

	return "Ubuntu"
}

// Name returns the platform identifier.
func (p *Platform) Name() string {
	return "windows-wsl2"
}

// Capabilities returns what this platform supports.
func (p *Platform) Capabilities() platform.Capabilities {
	return p.caps
}

// checkWSL2Available checks if WSL2 is available and running.
func (p *Platform) checkWSL2Available() bool {
	// Check if wsl command exists
	if _, err := exec.LookPath("wsl"); err != nil {
		return false
	}

	// Check WSL status
	cmd := exec.Command("wsl", "--status")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Try alternative check - list distros
		listCmd := exec.Command("wsl", "-l", "-q")
		if listCmd.Run() != nil {
			return false
		}
		return true
	}

	output := string(out)
	// Check for WSL2 indicators
	return strings.Contains(output, "Default Version: 2") ||
		strings.Contains(output, "WSL version") ||
		strings.Contains(output, "Kernel version")
}

// detectCapabilities checks what's available in WSL2.
// WSL2 runs a real Linux kernel, so it has full Linux capabilities.
func (p *Platform) detectCapabilities() platform.Capabilities {
	caps := platform.Capabilities{
		// WSL2 runs real Linux kernel with FUSE3 support
		HasFUSE:            p.checkFUSEInWSL(),
		FUSEImplementation: "fuse3",

		// WSL2 has iptables
		HasNetworkIntercept:   p.checkIptablesInWSL(),
		NetworkImplementation: "iptables",
		CanRedirectTraffic:    true,
		CanInspectTLS:         true,

		// WSL2 has full Linux namespace support
		HasMountNamespace:   true,
		HasNetworkNamespace: true,
		HasPIDNamespace:     true,
		HasUserNamespace:    p.checkUserNamespaceInWSL(),
		IsolationLevel:      platform.IsolationFull,

		// WSL2 has seccomp
		HasSeccomp: p.checkSeccompInWSL(),

		// WSL2 has cgroups v2
		HasCgroups:           p.checkCgroupsInWSL(),
		CanLimitCPU:          true,
		CanLimitMemory:       true,
		CanLimitDiskIO:       true,
		CanLimitNetworkBW:    false, // tc requires additional setup
		CanLimitProcessCount: true,
	}

	return caps
}

// checkFUSEInWSL checks if FUSE is available in WSL2.
func (p *Platform) checkFUSEInWSL() bool {
	_, err := p.runInWSL("test", "-e", "/dev/fuse")
	return err == nil
}

// checkIptablesInWSL checks if iptables is available in WSL2.
func (p *Platform) checkIptablesInWSL() bool {
	_, err := p.runInWSL("which", "iptables")
	return err == nil
}

// checkUserNamespaceInWSL checks if user namespaces work in WSL2.
func (p *Platform) checkUserNamespaceInWSL() bool {
	_, err := p.runInWSL("unshare", "--user", "true")
	return err == nil
}

// checkSeccompInWSL checks if seccomp is available in WSL2.
func (p *Platform) checkSeccompInWSL() bool {
	out, err := p.runInWSL("cat", "/proc/sys/kernel/seccomp/actions_avail")
	if err != nil {
		return false
	}
	return strings.Contains(out, "kill")
}

// checkCgroupsInWSL checks if cgroups v2 is available in WSL2.
func (p *Platform) checkCgroupsInWSL() bool {
	out, err := p.runInWSL("cat", "/proc/filesystems")
	if err != nil {
		return false
	}
	return strings.Contains(out, "cgroup2")
}

// runInWSL executes a command inside WSL2 and returns the output.
func (p *Platform) runInWSL(args ...string) (string, error) {
	wslArgs := append([]string{"-d", p.distro, "--"}, args...)
	cmd := exec.Command("wsl", wslArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("%s: %w", stderr.String(), err)
	}

	return stdout.String(), nil
}

// Filesystem returns the filesystem interceptor.
func (p *Platform) Filesystem() platform.FilesystemInterceptor {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.fs == nil {
		p.fs = NewFilesystem(p)
	}
	return p.fs
}

// Network returns the network interceptor.
func (p *Platform) Network() platform.NetworkInterceptor {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.net == nil {
		p.net = NewNetwork(p)
	}
	return p.net
}

// Sandbox returns the sandbox manager.
func (p *Platform) Sandbox() platform.SandboxManager {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.sandbox == nil {
		p.sandbox = NewSandboxManager(p)
	}
	return p.sandbox
}

// Resources returns the resource limiter.
func (p *Platform) Resources() platform.ResourceLimiter {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.resources == nil {
		p.resources = NewResourceLimiter(p)
	}
	return p.resources
}

// Initialize sets up the platform.
func (p *Platform) Initialize(ctx context.Context, config platform.Config) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.initialized {
		return fmt.Errorf("platform already initialized")
	}
	p.config = config
	p.initialized = true
	return nil
}

// Shutdown cleans up platform resources.
func (p *Platform) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.initialized = false
	return nil
}

// Distro returns the WSL2 distribution name.
func (p *Platform) Distro() string {
	return p.distro
}

// RunInWSL exposes the ability to run commands in WSL2.
func (p *Platform) RunInWSL(args ...string) (string, error) {
	return p.runInWSL(args...)
}

// Compile-time interface check
var _ platform.Platform = (*Platform)(nil)

// Path translation utilities

// WindowsToWSLPath converts a Windows path to WSL path.
// Example: C:\Users\foo -> /mnt/c/Users/foo
func WindowsToWSLPath(winPath string) string {
	if len(winPath) >= 2 && winPath[1] == ':' {
		drive := strings.ToLower(string(winPath[0]))
		rest := filepath.ToSlash(winPath[2:])
		return "/mnt/" + drive + rest
	}
	return filepath.ToSlash(winPath)
}

// WSLToWindowsPath converts a WSL path to Windows path.
// Example: /mnt/c/Users/foo -> C:\Users\foo
func WSLToWindowsPath(wslPath string) string {
	if strings.HasPrefix(wslPath, "/mnt/") && len(wslPath) >= 6 {
		drive := strings.ToUpper(string(wslPath[5]))
		rest := wslPath[6:]
		return drive + ":" + filepath.FromSlash(rest)
	}
	return filepath.FromSlash(wslPath)
}
