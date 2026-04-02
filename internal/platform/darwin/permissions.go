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
	// TierEnterprise requires the agentsh system extension (ESF + Network Extension).
	TierEnterprise PermissionTier = iota
	// TierStandard uses root + pf, no system extension.
	TierStandard
	// TierMinimal provides only command execution logging.
	TierMinimal
)

// String returns the tier name.
func (t PermissionTier) String() string {
	switch t {
	case TierEnterprise:
		return "enterprise"
	case TierStandard:
		return "standard"
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
	case TierStandard:
		return 50
	case TierMinimal:
		return 10
	default:
		return 0
	}
}

// Permissions holds detected macOS permission state.
type Permissions struct {
	HasSystemExtension bool

	// Basic Permissions
	HasRootAccess     bool
	HasFullDiskAccess bool

	// Fallbacks
	CanUsePF    bool
	HasFSEvents bool // Always true on macOS
	HasLibpcap  bool

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

	// Check system extension
	p.HasSystemExtension = CheckSysExtInstalled()

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

// CheckSysExtInstalled checks if the agentsh system extension is installed and activated.
func CheckSysExtInstalled() bool {
	cmd := exec.Command("systemextensionsctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "ai.canyonroad.agentsh.SysExt") &&
		strings.Contains(string(output), "activated enabled")
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
	case p.HasSystemExtension:
		p.Tier = TierEnterprise
	case p.HasRootAccess && p.CanUsePF:
		p.Tier = TierStandard
	default:
		p.Tier = TierMinimal
	}
}

// computeMissingPermissions builds the list of permissions that could be enabled.
func (p *Permissions) computeMissingPermissions() {
	p.MissingPermissions = []MissingPermission{}

	if !p.HasSystemExtension {
		p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
			Name:        "System Extension",
			Description: "ESF-based file/process monitoring and Network Extension filtering",
			Impact:      "Cannot intercept or block file operations. File monitoring unavailable.",
			HowToEnable: "Install the agentsh macOS app bundle which includes the system extension.\n" +
				"After installation, approve it in System Settings > Privacy & Security.",
			Required: false,
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
	case TierStandard:
		return []string{
			"file_monitoring (FSEvents - observe only)",
			"network_interception (pf - can block)",
			"dns_interception",
			"tls_inspection",
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
	case TierStandard:
		return []string{"file_blocking", "process_blocking", "per_app_filtering", "kernel_events"}
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

	// System Extension
	sb.WriteString("System Extension:\n")
	sb.WriteString(formatPermission("System Extension", p.HasSystemExtension, "ESF-based file/process monitoring and Network Extension filtering"))
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
			if mp.Required || p.Tier > TierStandard {
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
