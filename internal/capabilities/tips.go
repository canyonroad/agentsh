//go:build linux || darwin || windows

package capabilities

import "fmt"

// tipDefinition defines a tip for a missing capability.
type tipDefinition struct {
	Feature  string
	Impact   string
	Action   string
	CheckKey string // capability key to check
}

var linuxTips = []tipDefinition{
	{
		Feature:  "fuse",
		CheckKey: "fuse",
		Impact:   "Fine-grained filesystem control disabled",
		Action:   "Install FUSE3: apt install fuse3 (Debian/Ubuntu), dnf install fuse3 (Fedora), or pacman -S fuse3 (Arch)",
	},
	{
		Feature:  "seccomp",
		CheckKey: "seccomp",
		Impact:   "Syscall filtering disabled (likely nested container)",
		Action:   "Run in privileged container or on host for full seccomp support",
	},
	{
		Feature:  "landlock_network",
		CheckKey: "landlock_network",
		Impact:   "Kernel-level network restrictions disabled",
		Action:   "Requires kernel 6.7+ (Landlock ABI v4). Upgrade kernel or use proxy-based network control.",
	},
	{
		Feature:  "ebpf",
		CheckKey: "ebpf",
		Impact:   "Network monitoring disabled",
		Action:   "Requires CAP_BPF and cgroups v2. Run as root or with elevated privileges.",
	},
	{
		Feature:  "cgroups_v2",
		CheckKey: "cgroups_v2",
		Impact:   "Resource limits unavailable",
		Action:   "Enable cgroups v2 in kernel or container runtime",
	},
	{
		Feature:  "ptrace",
		CheckKey: "ptrace",
		Impact:   "Syscall-level enforcement via ptrace unavailable",
		Action:   "Add SYS_PTRACE capability to enable ptrace-based enforcement for restricted runtimes",
	},
}

var darwinTips = []tipDefinition{
	{
		Feature:  "esf",
		CheckKey: "esf",
		Impact:   "Using sandbox-exec instead of Endpoint Security",
		Action:   "Install the agentsh macOS app bundle which includes the system extension.",
	},
	{
		Feature:  "lima_available",
		CheckKey: "lima_available",
		Impact:   "No Linux VM isolation available",
		Action:   "Install Lima: brew install lima && limactl start default",
	},
}

var windowsTips = []tipDefinition{
	{
		Feature:  "winfsp",
		CheckKey: "winfsp",
		Impact:   "FUSE-style filesystem mounting disabled",
		Action:   "Install WinFsp: winget install WinFsp.WinFsp",
	},
	{
		Feature:  "minifilter",
		CheckKey: "minifilter",
		Impact:   "No kernel-level file interception",
		Action:   "Install agentsh minifilter driver (requires Administrator)",
	},
	{
		Feature:  "windivert",
		CheckKey: "windivert",
		Impact:   "Transparent network interception disabled",
		Action:   "Install WinDivert for transparent TCP/DNS proxy",
	},
}

// GenerateTips creates actionable tips based on missing capabilities.
func GenerateTips(platform string, caps map[string]any) []Tip {
	var definitions []tipDefinition

	switch platform {
	case "linux":
		definitions = linuxTips
	case "darwin":
		definitions = darwinTips
	case "windows":
		definitions = windowsTips
	default:
		return nil
	}

	var tips []Tip
	for _, def := range definitions {
		val, exists := caps[def.CheckKey]
		if !exists {
			continue
		}

		// Check if capability is missing/false
		isMissing := false
		switch v := val.(type) {
		case bool:
			isMissing = !v
		case int:
			isMissing = v == 0
		}

		if isMissing {
			tips = append(tips, Tip{
				Feature: def.Feature,
				Status:  "unavailable",
				Impact:  def.Impact,
				Action:  def.Action,
			})
		}
	}

	return tips
}

// tipsByBackend maps backend names to tip definitions.
var tipsByBackend = map[string]Tip{
	// Linux
	"fuse":             {Feature: "fuse", Impact: "Fine-grained filesystem control disabled", Action: "Install FUSE3: apt install fuse3 (Debian/Ubuntu), dnf install fuse3 (Fedora)"},
	"seccomp-execve":   {Feature: "seccomp", Impact: "Syscall filtering disabled (likely nested container)", Action: "Run in privileged container or on host for full seccomp support"},
	"seccomp-notify":   {Feature: "seccomp-notify", Impact: "Seccomp-based file enforcement disabled", Action: "Run in privileged container or on host for seccomp support"},
	"landlock-network": {Feature: "landlock-network", Impact: "Kernel-level network restrictions disabled", Action: "Requires kernel 6.7+ (Landlock ABI v4)"},
	"ebpf":             {Feature: "ebpf", Impact: "Network monitoring disabled", Action: "Requires CAP_BPF and cgroups v2. Run as root or with elevated privileges."},
	"cgroups-v2":       {Feature: "cgroups-v2", Impact: "Resource limits unavailable", Action: "Enable cgroups v2 in kernel or container runtime"},
	"ptrace":           {Feature: "ptrace", Impact: "Syscall-level enforcement via ptrace unavailable", Action: "Add SYS_PTRACE capability"},
	"pid-namespace":    {Feature: "pid-namespace", Impact: "Process isolation unavailable", Action: "Run in a PID namespace (docker run --pid=host or unshare -p)"},
	"capability-drop":  {Feature: "capability-drop", Impact: "Process retains full Linux capabilities (privilege reduction inactive)", Action: "Start the process with a reduced capability set (e.g. systemd CapabilityBoundingSet=, docker run --cap-drop=ALL, or call capabilities.DropCapabilities at startup)"},
	// Darwin
	"esf":               {Feature: "esf", Impact: "Endpoint Security Framework unavailable", Action: "Install the agentsh macOS app bundle with system extension"},
	"network-extension": {Feature: "network-extension", Impact: "Network filtering unavailable", Action: "Requires network extension entitlement from Apple"},
	// Windows
	"winfsp":     {Feature: "winfsp", Impact: "Filesystem interception unavailable", Action: "Install WinFsp: https://winfsp.dev/"},
	"minifilter": {Feature: "minifilter", Impact: "Kernel-level file filtering unavailable", Action: "Install agentsh minifilter driver"},
	"windivert":  {Feature: "windivert", Impact: "Network interception unavailable", Action: "Install WinDivert: https://reqrypt.org/windivert.html"},
}

func lookupTip(backendName string) *Tip {
	if tip, ok := tipsByBackend[backendName]; ok {
		copy := tip // don't modify the map entry
		return &copy
	}
	return nil
}

// GenerateTipsFromDomains generates tips only for domains that score 0.
// Domains that already have at least one available backend don't generate tips
// (additional backends provide redundancy, not extra points).
func GenerateTipsFromDomains(domains []ProtectionDomain) []Tip {
	var tips []Tip
	for _, d := range domains {
		if d.Score > 0 {
			continue // domain already covered
		}
		for _, b := range d.Backends {
			if b.Available {
				continue
			}
			tip := lookupTip(b.Name)
			if tip != nil {
				tip.Impact = fmt.Sprintf("%s (+%d pts)", tip.Impact, d.Weight)
				tips = append(tips, *tip)
			}
		}
	}
	return tips
}
