//go:build linux || darwin || windows

package capabilities

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
}

var darwinTips = []tipDefinition{
	{
		Feature:  "fuse_t",
		CheckKey: "fuse_t",
		Impact:   "File policy enforcement limited to observation-only",
		Action:   "Install FUSE-T: brew install fuse-t",
	},
	{
		Feature:  "esf",
		CheckKey: "esf",
		Impact:   "Using sandbox-exec instead of Endpoint Security",
		Action:   "ESF requires Apple developer approval. Submit business justification to Apple.",
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
