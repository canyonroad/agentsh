//go:build darwin

// Package lima provides the macOS Lima VM platform implementation for agentsh.
// Lima runs a real Linux kernel in a lightweight VM, providing full Linux capabilities
// including FUSE3, iptables, namespaces, seccomp, and cgroups v2.
package lima

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

func init() {
	// Register the Lima platform constructor with the factory
	platform.RegisterDarwinLima(NewPlatform)
}

// Platform implements platform.Platform for macOS with Lima VM.
type Platform struct {
	config      platform.Config
	instance    string
	caps        platform.Capabilities
	fs          *Filesystem
	net         *Network
	sandbox     *SandboxManager
	resources   *ResourceLimiter
	initialized bool
	mu          sync.Mutex
}

// limaInstance represents a Lima VM instance from limactl list --json.
type limaInstance struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Arch   string `json:"arch"`
	CPUs   int    `json:"cpus"`
	Memory int64  `json:"memory"`
	Disk   int64  `json:"disk"`
	Dir    string `json:"dir"`
}

// NewPlatform creates a new macOS Lima platform.
func NewPlatform() (platform.Platform, error) {
	instance := detectDefaultInstance()

	p := &Platform{
		instance: instance,
	}

	if !p.checkLimaAvailable() {
		return nil, fmt.Errorf("Lima not available; install with: brew install lima")
	}

	p.caps = p.detectCapabilities()
	return p, nil
}

// detectDefaultInstance finds the default or first running Lima instance.
func detectDefaultInstance() string {
	limactlPath, err := exec.LookPath("limactl")
	if err != nil {
		return "default"
	}

	cmd := exec.Command(limactlPath, "list", "--json")
	out, err := cmd.Output()
	if err != nil {
		return "default"
	}

	var instances []limaInstance
	if err := json.Unmarshal(out, &instances); err != nil {
		return "default"
	}

	// Return first running instance, or "default" if none
	for _, inst := range instances {
		if inst.Status == "Running" {
			return inst.Name
		}
	}

	return "default"
}

// Name returns the platform identifier.
func (p *Platform) Name() string {
	return "darwin-lima"
}

// Capabilities returns what this platform supports.
func (p *Platform) Capabilities() platform.Capabilities {
	return p.caps
}

// checkLimaAvailable checks if Lima is available with a running instance.
func (p *Platform) checkLimaAvailable() bool {
	// Check if limactl command exists
	if _, err := exec.LookPath("limactl"); err != nil {
		return false
	}

	// Check if instance is running
	out, err := p.runInLima("true")
	return err == nil && out != ""
}

// detectCapabilities checks what's available in the Lima VM.
// Lima runs a real Linux kernel, so it has full Linux capabilities.
func (p *Platform) detectCapabilities() platform.Capabilities {
	caps := platform.Capabilities{
		// Lima runs real Linux kernel with FUSE3 support
		HasFUSE:            p.checkFUSEInLima(),
		FUSEImplementation: "fuse3",

		// Lima has iptables
		HasNetworkIntercept:   p.checkIptablesInLima(),
		NetworkImplementation: "iptables",
		CanRedirectTraffic:    true,
		CanInspectTLS:         true,

		// Lima has full Linux namespace support
		HasMountNamespace:   true,
		HasNetworkNamespace: true,
		HasPIDNamespace:     true,
		HasUserNamespace:    p.checkUserNamespaceInLima(),
		IsolationLevel:      platform.IsolationFull,

		// Lima has seccomp
		HasSeccomp: p.checkSeccompInLima(),

		// Lima has cgroups v2
		HasCgroups:           p.checkCgroupsInLima(),
		CanLimitCPU:          true,
		CanLimitMemory:       true,
		CanLimitDiskIO:       true,
		CanLimitNetworkBW:    false, // tc requires additional setup
		CanLimitProcessCount: true,
	}

	return caps
}

// checkFUSEInLima checks if FUSE is available in the Lima VM.
func (p *Platform) checkFUSEInLima() bool {
	_, err := p.runInLima("test", "-e", "/dev/fuse")
	return err == nil
}

// checkIptablesInLima checks if iptables is available in the Lima VM.
func (p *Platform) checkIptablesInLima() bool {
	_, err := p.runInLima("which", "iptables")
	return err == nil
}

// checkUserNamespaceInLima checks if user namespaces work in the Lima VM.
func (p *Platform) checkUserNamespaceInLima() bool {
	_, err := p.runInLima("unshare", "--user", "true")
	return err == nil
}

// checkSeccompInLima checks if seccomp is available in the Lima VM.
func (p *Platform) checkSeccompInLima() bool {
	out, err := p.runInLima("cat", "/proc/sys/kernel/seccomp/actions_avail")
	if err != nil {
		return false
	}
	return strings.Contains(out, "kill")
}

// checkCgroupsInLima checks if cgroups v2 is available in the Lima VM.
func (p *Platform) checkCgroupsInLima() bool {
	out, err := p.runInLima("cat", "/proc/filesystems")
	if err != nil {
		return false
	}
	return strings.Contains(out, "cgroup2")
}

// runInLima executes a command inside the Lima VM and returns the output.
func (p *Platform) runInLima(args ...string) (string, error) {
	limaArgs := append([]string{"shell", p.instance, "--"}, args...)
	cmd := exec.Command("limactl", limaArgs...)

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

// Instance returns the Lima instance name.
func (p *Platform) Instance() string {
	return p.instance
}

// RunInLima exposes the ability to run commands in the Lima VM.
func (p *Platform) RunInLima(args ...string) (string, error) {
	return p.runInLima(args...)
}

// Compile-time interface check
var _ platform.Platform = (*Platform)(nil)

// Path translation utilities

// MacOSToLimaPath converts a macOS path to Lima VM path.
// Lima uses virtiofs/9p to mount the host filesystem.
// By default, /Users is mounted at /Users in the VM.
func MacOSToLimaPath(macPath string) string {
	// Lima mounts /Users, /Volumes, /tmp, /var/folders by default
	// Most paths work as-is
	if strings.HasPrefix(macPath, "/Users") ||
		strings.HasPrefix(macPath, "/Volumes") ||
		strings.HasPrefix(macPath, "/tmp") ||
		strings.HasPrefix(macPath, "/var/folders") {
		return macPath
	}

	// For other paths, they might not be accessible in the VM
	return macPath
}

// LimaToMacOSPath converts a Lima VM path to macOS path.
func LimaToMacOSPath(limaPath string) string {
	// Lima paths under /Users, /Volumes, etc. map directly
	if strings.HasPrefix(limaPath, "/Users") ||
		strings.HasPrefix(limaPath, "/Volumes") ||
		strings.HasPrefix(limaPath, "/tmp") ||
		strings.HasPrefix(limaPath, "/var/folders") {
		return limaPath
	}

	return filepath.FromSlash(limaPath)
}
