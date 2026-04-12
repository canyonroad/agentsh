//go:build linux || darwin || windows

package capabilities

import (
	"fmt"
	"strings"
)

// tipDefinition defines a tip for a missing capability.
type tipDefinition struct {
	Feature  string
	Impact   string
	Action   string
	CheckKey string // capability key to check
}

// reasonTip pairs a substring filter with a tip. When looking up a tip for
// a backend, the first entry whose Contains is a non-empty substring of
// DetectedBackend.Detail wins. An entry with Contains == "" is the fallback.
type reasonTip struct {
	Contains string
	Tip      Tip
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

// tipsByBackend maps backend names to an ordered slice of reason-sensitive
// tips. Entries are scanned in order; the first whose Contains is a
// non-empty substring of DetectedBackend.Detail wins. An entry with
// Contains == "" acts as the fallback. Place more-specific substrings
// before less-specific ones (e.g. "kernel version unknown" before "kernel").
var tipsByBackend = map[string][]reasonTip{
	// Linux
	"fuse":           {{Tip: Tip{Feature: "fuse", Impact: "Fine-grained filesystem control disabled", Action: "Install FUSE3: apt install fuse3 (Debian/Ubuntu), dnf install fuse3 (Fedora)"}}},
	"seccomp-execve": {{Tip: Tip{Feature: "seccomp", Impact: "Syscall filtering disabled (likely nested container)", Action: "Run in privileged container or on host for full seccomp support"}}},
	"seccomp-notify": {{Tip: Tip{Feature: "seccomp-notify", Impact: "Seccomp-based file enforcement disabled", Action: "Run in privileged container or on host for seccomp support"}}},
	"landlock-network": {{Tip: Tip{Feature: "landlock-network", Impact: "Kernel-level network restrictions disabled", Action: "Requires kernel 6.7+ (Landlock ABI v4)"}}},
	"ebpf": {
		{Contains: "btf not present", Tip: Tip{Feature: "ebpf", Impact: "Network monitoring disabled", Action: "Kernel was built without CONFIG_DEBUG_INFO_BTF=y; cilium/ebpf CO-RE programs cannot relocate types without BTF. Rebuild the kernel with CONFIG_DEBUG_INFO_BTF=y (and ideally CONFIG_DEBUG_INFO_BTF_MODULES=y)."}},
		{Contains: "cgroup v2 not available", Tip: Tip{Feature: "ebpf", Impact: "Network monitoring disabled", Action: "eBPF socket association requires cgroups v2. Mount a unified cgroup hierarchy or switch to a systemd-based init."}},
		{Contains: "kernel version unknown", Tip: Tip{Feature: "ebpf", Impact: "Network monitoring disabled", Action: "Could not determine kernel version. eBPF network monitoring requires kernel 5.8+."}},
		{Contains: "kernel", Tip: Tip{Feature: "ebpf", Impact: "Network monitoring disabled", Action: "eBPF network monitoring requires kernel 5.8+ for BPF ring buffer and CO-RE support. Upgrade your kernel."}},
		{Tip: Tip{Feature: "ebpf", Impact: "Network monitoring disabled", Action: "Requires CAP_BPF (or CAP_SYS_ADMIN) and cgroups v2. Run as root or with elevated privileges."}},
	},
	"cgroups-v2":      {{Tip: Tip{Feature: "cgroups-v2", Impact: "Resource limits unavailable", Action: "Enable cgroups v2 in kernel or container runtime"}}},
	"ptrace":          {{Tip: Tip{Feature: "ptrace", Impact: "Syscall-level enforcement via ptrace unavailable", Action: "Add SYS_PTRACE capability"}}},
	"pid-namespace":   {{Tip: Tip{Feature: "pid-namespace", Impact: "Process isolation unavailable", Action: "Run in a PID namespace (docker run --pid=host or unshare -p)"}}},
	"capability-drop": {{Tip: Tip{Feature: "capability-drop", Impact: "Process retains full Linux capabilities (privilege reduction inactive)", Action: "Start the process with a reduced capability set using systemd CapabilityBoundingSet= + User=, docker run --cap-drop=ALL, or an unprivileged user. Note: capabilities.DropCapabilities() only narrows the bounding set for exec'd children via PR_CAPBSET_DROP and does not lower the running process's permitted/effective sets, so calling it from inside the server is not a substitute for the startup-time mechanisms above."}}},
	// Darwin
	"esf":               {{Tip: Tip{Feature: "esf", Impact: "Endpoint Security Framework unavailable", Action: "Install the agentsh macOS app bundle with system extension"}}},
	"network-extension": {{Tip: Tip{Feature: "network-extension", Impact: "Network filtering unavailable", Action: "Requires network extension entitlement from Apple"}}},
	// Windows
	"winfsp":     {{Tip: Tip{Feature: "winfsp", Impact: "Filesystem interception unavailable", Action: "Install WinFsp: https://winfsp.dev/"}}},
	"minifilter": {{Tip: Tip{Feature: "minifilter", Impact: "Kernel-level file filtering unavailable", Action: "Install agentsh minifilter driver"}}},
	"windivert":  {{Tip: Tip{Feature: "windivert", Impact: "Network interception unavailable", Action: "Install WinDivert: https://reqrypt.org/windivert.html"}}},
}

func lookupTip(backendName, detail string) *Tip {
	reasons, ok := tipsByBackend[backendName]
	if !ok {
		return nil
	}
	for _, r := range reasons {
		if r.Contains != "" && strings.Contains(detail, r.Contains) {
			copy := r.Tip
			return &copy
		}
	}
	// Fallback: first entry with empty Contains.
	for _, r := range reasons {
		if r.Contains == "" {
			copy := r.Tip
			return &copy
		}
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
			tip := lookupTip(b.Name, b.Detail)
			if tip != nil {
				tip.Impact = fmt.Sprintf("%s (+%d pts)", tip.Impact, d.Weight)
				tips = append(tips, *tip)
			}
		}
	}
	return tips
}
