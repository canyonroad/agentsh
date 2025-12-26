//go:build darwin

package darwin

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// PermissionTier represents the security capability level of the macOS platform.
type PermissionTier int

const (
	// TierEnterprise requires Apple entitlements (ESF + Network Extension).
	TierEnterprise PermissionTier = iota
	// TierFull uses FUSE-T + pf (most common for open-source deployment).
	TierFull
	// TierNetworkOnly has pf but no FUSE (file monitoring is observation-only).
	TierNetworkOnly
	// TierMonitorOnly observes via FSEvents/pcap but cannot block.
	TierMonitorOnly
	// TierMinimal provides only command execution logging.
	TierMinimal
)

// String returns the tier name.
func (t PermissionTier) String() string {
	switch t {
	case TierEnterprise:
		return "enterprise"
	case TierFull:
		return "full"
	case TierNetworkOnly:
		return "network-only"
	case TierMonitorOnly:
		return "monitor-only"
	case TierMinimal:
		return "minimal"
	default:
		return "unknown"
	}
}

// SecurityScore returns a percentage representing the security coverage.
func (t PermissionTier) SecurityScore() int {
	switch t {
	case TierEnterprise:
		return 95
	case TierFull:
		return 75
	case TierNetworkOnly:
		return 50
	case TierMonitorOnly:
		return 25
	case TierMinimal:
		return 10
	default:
		return 0
	}
}

// Permissions holds detected macOS permission state.
type Permissions struct {
	// Apple Entitlements (Tier 0 - Enterprise)
	HasEndpointSecurity bool
	HasNetworkExtension bool

	// FUSE Options (Tier 1)
	HasFuseT     bool
	FuseTVersion string
	HasMacFUSE   bool // Deprecated but may be present

	// Basic Permissions
	HasRootAccess     bool
	HasFullDiskAccess bool

	// Fallbacks
	CanUsePF     bool
	HasFSEvents  bool // Always true on macOS
	HasLibpcap   bool

	// Computed
	Tier               PermissionTier
	MissingPermissions []MissingPermission
	DetectedAt         time.Time
}

// MissingPermission describes a permission that could enhance security.
type MissingPermission struct {
	Name        string
	Description string
	Impact      string
	HowToEnable string
	Required    bool
}

// DetectPermissions checks all available permissions on macOS.
func DetectPermissions() *Permissions {
	p := &Permissions{
		HasFSEvents: true, // Always available on macOS
		DetectedAt:  time.Now(),
	}

	// Check Apple entitlements (Tier 0)
	p.HasEndpointSecurity = checkEntitlement("endpoint-security.client")
	p.HasNetworkExtension = checkEntitlement("networking.networkextension")

	// Check FUSE options (Tier 1)
	p.HasFuseT, p.FuseTVersion = checkFuseT()
	p.HasMacFUSE = checkMacFUSE()

	// Check basic permissions
	p.HasRootAccess = os.Geteuid() == 0
	p.HasFullDiskAccess = checkFullDiskAccess()
	p.CanUsePF = p.HasRootAccess && checkPFAvailable()
	p.HasLibpcap = checkLibpcapAvailable()

	// Compute tier and missing permissions
	p.computeTier()
	p.computeMissingPermissions()

	return p
}

// checkEntitlement checks if the running binary has a specific Apple entitlement.
func checkEntitlement(name string) bool {
	cmd := exec.Command("codesign", "-d", "--entitlements", "-", os.Args[0])
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), name)
}

// checkFuseT checks for FUSE-T installation.
func checkFuseT() (bool, string) {
	paths := []string{
		"/opt/homebrew/lib/libfuse-t.dylib",  // Apple Silicon Homebrew
		"/usr/local/lib/libfuse-t.dylib",     // Intel Homebrew
		"/Library/Frameworks/FUSE-T.framework",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			// Try to get version via brew
			cmd := exec.Command("brew", "info", "fuse-t", "--json")
			if output, err := cmd.Output(); err == nil && len(output) > 0 {
				// Parse version from brew info JSON if needed
				return true, "installed"
			}
			return true, "installed"
		}
	}
	return false, ""
}

// checkMacFUSE checks for deprecated macFUSE installation.
func checkMacFUSE() bool {
	paths := []string{
		"/Library/Filesystems/macfuse.fs",
		"/Library/Frameworks/macFUSE.framework",
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// checkFullDiskAccess tests if we can access protected directories.
func checkFullDiskAccess() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	// Try to read a protected directory
	testPath := homeDir + "/Library/Mail"
	_, err = os.ReadDir(testPath)
	return err == nil
}

// checkPFAvailable checks if pf is available and accessible.
func checkPFAvailable() bool {
	return exec.Command("pfctl", "-s", "info").Run() == nil
}

// checkLibpcapAvailable checks if libpcap is available.
func checkLibpcapAvailable() bool {
	_, err := exec.LookPath("tcpdump")
	return err == nil
}

// computeTier determines the operating tier based on available permissions.
func (p *Permissions) computeTier() {
	switch {
	case p.HasEndpointSecurity && p.HasNetworkExtension:
		p.Tier = TierEnterprise
	case p.HasFuseT && p.HasRootAccess && p.CanUsePF:
		p.Tier = TierFull
	case p.HasRootAccess && p.CanUsePF:
		p.Tier = TierNetworkOnly
	case p.HasFSEvents && (p.HasLibpcap || p.HasRootAccess):
		p.Tier = TierMonitorOnly
	default:
		p.Tier = TierMinimal
	}
}

// computeMissingPermissions builds the list of permissions that could be enabled.
func (p *Permissions) computeMissingPermissions() {
	p.MissingPermissions = []MissingPermission{}

	if !p.HasFuseT {
		p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
			Name:        "FUSE-T",
			Description: "Userspace filesystem for file interception (no kernel extension needed)",
			Impact:      "Cannot intercept or block file operations. File monitoring will be observation-only via FSEvents.",
			HowToEnable: "Install via Homebrew:\n  brew install fuse-t\n\nNo restart or security approval required!",
			Required:    false,
		})
	}

	if !p.HasRootAccess {
		p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
			Name:        "Root Access",
			Description: "Administrator privileges for pf network interception",
			Impact:      "Cannot use pf for network interception. Network policy enforcement disabled.",
			HowToEnable: "Run agentsh with sudo:\n  sudo agentsh server",
			Required:    false,
		})
	}

	if !p.HasFullDiskAccess {
		p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
			Name:        "Full Disk Access",
			Description: "Access to protected directories (Mail, Messages, Safari, etc.)",
			Impact:      "Cannot monitor file operations in protected system directories.",
			HowToEnable: "1. Open System Settings > Privacy & Security > Full Disk Access\n" +
				"2. Click '+' and add Terminal.app or the agentsh binary\n" +
				"3. Restart agentsh",
			Required: false,
		})
	}

	if !p.HasEndpointSecurity {
		p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
			Name:        "Endpoint Security Framework",
			Description: "Apple's official security monitoring API with full system visibility",
			Impact:      "Not using Apple's most comprehensive security API. Current tier provides good coverage.",
			HowToEnable: "Requires Apple Developer Program membership and approval:\n" +
				"1. Apply for com.apple.developer.endpoint-security.client entitlement\n" +
				"2. Provide business justification to Apple\n" +
				"3. Build and notarize with approved provisioning profile",
			Required: false,
		})
	}
}

// AvailableFeatures returns the list of features enabled at this tier.
func (p *Permissions) AvailableFeatures() []string {
	switch p.Tier {
	case TierEnterprise:
		return []string{
			"file_read_interception (ESF - can block)",
			"file_write_interception (ESF - can block)",
			"process_exec_blocking (ESF)",
			"network_interception (NE - can block)",
			"per_app_network_filtering (NE)",
			"dns_interception",
			"tls_inspection",
			"kernel_event_monitoring",
			"command_logging",
		}
	case TierFull:
		return []string{
			"file_read_interception (FUSE - can block)",
			"file_write_interception (FUSE - can block)",
			"network_interception (pf - can block)",
			"dns_interception",
			"tls_inspection",
			"command_logging",
		}
	case TierNetworkOnly:
		return []string{
			"file_monitoring (FSEvents - observe only)",
			"network_interception (pf - can block)",
			"dns_interception",
			"tls_inspection",
			"command_logging",
		}
	case TierMonitorOnly:
		return []string{
			"file_monitoring (FSEvents - observe only)",
			"network_monitoring (pcap - observe only)",
			"command_logging",
		}
	case TierMinimal:
		return []string{
			"command_logging",
		}
	default:
		return []string{}
	}
}

// DisabledFeatures returns features not available at this tier.
func (p *Permissions) DisabledFeatures() []string {
	switch p.Tier {
	case TierEnterprise:
		return []string{}
	case TierFull:
		return []string{"process_blocking", "per_app_filtering", "kernel_events"}
	case TierNetworkOnly:
		return []string{"file_blocking", "process_blocking", "per_app_filtering", "kernel_events"}
	case TierMonitorOnly:
		return []string{"file_blocking", "network_blocking", "process_blocking", "per_app_filtering", "kernel_events"}
	case TierMinimal:
		return []string{"file_monitoring", "file_blocking", "network_monitoring", "network_blocking", "process_blocking", "per_app_filtering", "kernel_events"}
	default:
		return []string{}
	}
}

// LogStatus returns a formatted status string for logging.
func (p *Permissions) LogStatus() string {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("                    macOS Permission Status                     \n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("Operating Tier: %d (%s) - Security Score: %d%%\n\n",
		p.Tier, p.Tier.String(), p.Tier.SecurityScore()))

	// Apple Entitlements
	sb.WriteString("Apple Entitlements (Tier 0 - Enterprise):\n")
	sb.WriteString(formatPermission("Endpoint Security", p.HasEndpointSecurity, "System-wide file/process monitoring"))
	sb.WriteString(formatPermission("Network Extension", p.HasNetworkExtension, "Deep network inspection"))
	sb.WriteString("\n")

	// FUSE Options
	sb.WriteString("Filesystem Interception (Tier 1):\n")
	sb.WriteString(formatPermission("FUSE-T", p.HasFuseT, "NFS-based FUSE (recommended, no kext)"))
	if p.HasMacFUSE {
		sb.WriteString("  ⚠️  macFUSE (deprecated, requires kext)\n")
	}
	sb.WriteString("\n")

	// Basic Permissions
	sb.WriteString("Basic Permissions:\n")
	sb.WriteString(formatPermission("Root Access", p.HasRootAccess, "Required for pf network interception"))
	sb.WriteString(formatPermission("Full Disk Access", p.HasFullDiskAccess, "Access to protected directories"))
	sb.WriteString(formatPermission("pf Available", p.CanUsePF, "Packet filter for network"))
	sb.WriteString(formatPermission("libpcap", p.HasLibpcap, "Fallback network observation"))
	sb.WriteString("\n")

	// Feature availability
	sb.WriteString("Feature Availability:\n")
	for _, feature := range p.AvailableFeatures() {
		sb.WriteString(fmt.Sprintf("  ✅ %s\n", feature))
	}
	for _, feature := range p.DisabledFeatures() {
		sb.WriteString(fmt.Sprintf("  ❌ %s\n", feature))
	}
	sb.WriteString("\n")

	// Missing permissions
	if len(p.MissingPermissions) > 0 && p.Tier > TierEnterprise {
		sb.WriteString("To enable more features:\n")
		for i, mp := range p.MissingPermissions {
			if mp.Required || p.Tier > TierFull {
				sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, mp.Name))
				sb.WriteString(fmt.Sprintf("     %s\n", mp.HowToEnable))
			}
		}
	}

	sb.WriteString("═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

func formatPermission(name string, available bool, description string) string {
	status := "❌"
	if available {
		status = "✅"
	}
	return fmt.Sprintf("  %s %s - %s\n", status, name, description)
}
