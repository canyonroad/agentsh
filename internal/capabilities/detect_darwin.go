//go:build darwin

package capabilities

import (
	"os"
	"os/exec"
)

func buildDarwinDomains(caps map[string]any) []ProtectionDomain {
	fuseT, _ := caps["fuse_t"].(bool)
	esf, _ := caps["esf"].(bool)
	networkExt, _ := caps["network_extension"].(bool)
	hasMacwrap := checkMacwrap()

	fuseDetail := "not installed"
	if fuseT {
		fuseDetail = "FUSE-T"
	}

	macwrapDetail := "not found"
	if hasMacwrap {
		macwrapDetail = "dynamic seatbelt"
	}

	return []ProtectionDomain{
		{
			Name: "File Protection", Weight: WeightFileProtection,
			Backends: []DetectedBackend{
				{Name: "fuse-t", Available: fuseT, Detail: fuseDetail, Description: "filesystem interception", CheckMethod: "binary"},
				{Name: "esf", Available: esf, Detail: "", Description: "Endpoint Security Framework", CheckMethod: "entitlement"},
			},
		},
		{
			Name: "Command Control", Weight: WeightCommandControl,
			Backends: []DetectedBackend{
				{Name: "esf", Available: esf, Detail: "", Description: "process execution control", CheckMethod: "entitlement"},
				{Name: "dynamic-seatbelt", Available: hasMacwrap, Detail: macwrapDetail, Description: "policy-driven exec restriction", CheckMethod: "binary"},
				{Name: "sandbox-exec", Available: true, Detail: "", Description: "macOS sandbox", CheckMethod: "builtin"},
			},
			Active: func() string {
				if esf {
					return "esf"
				}
				if hasMacwrap {
					return "dynamic-seatbelt"
				}
				return "sandbox-exec"
			}(),
		},
		{
			Name: "Network", Weight: WeightNetwork,
			Backends: []DetectedBackend{
				{Name: "network-extension", Available: networkExt, Detail: "", Description: "network filtering", CheckMethod: "entitlement"},
			},
		},
		{
			Name: "Resource Limits", Weight: WeightResourceLimits,
			Backends: []DetectedBackend{
				{Name: "launchd-limits", Available: true, Detail: "", Description: "launchd resource limits", CheckMethod: "builtin"},
			},
			Active: "launchd-limits",
		},
		{
			Name: "Isolation", Weight: WeightIsolation,
			Backends: []DetectedBackend{
				{Name: "dynamic-seatbelt", Available: hasMacwrap, Detail: macwrapDetail, Description: "deny-default sandbox", CheckMethod: "binary"},
				{Name: "sandbox-exec", Available: true, Detail: "", Description: "process isolation", CheckMethod: "builtin"},
			},
			Active: func() string {
				if hasMacwrap {
					return "dynamic-seatbelt"
				}
				return "sandbox-exec"
			}(),
		},
	}
}

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	caps := map[string]any{
		"sandbox_exec":      true,
		"fuse_t":            checkFuseT(),
		"esf":               checkESF(),
		"network_extension": checkNetworkExtension(),
		"lima_available":    checkLima(),
	}

	mode, _ := selectDarwinMode(caps)
	domains := buildDarwinDomains(caps)
	score := ComputeScore(domains)

	var available, unavailable []string
	for _, d := range domains {
		for _, b := range d.Backends {
			if b.Available {
				available = append(available, b.Name)
			} else {
				unavailable = append(unavailable, b.Name)
			}
		}
	}

	tips := GenerateTipsFromDomains(domains)

	return &DetectResult{
		Platform:        "darwin",
		SecurityMode:    mode,
		ProtectionScore: score,
		Domains:         domains,
		Capabilities:    caps,
		Summary:         DetectSummary{Available: available, Unavailable: unavailable},
		Tips:            tips,
	}, nil
}

func checkFuseT() bool {
	// Check if FUSE-T is installed via Homebrew
	_, err := os.Stat("/usr/local/lib/libfuse-t.dylib")
	if err == nil {
		return true
	}
	// Also check ARM64 Homebrew path
	_, err = os.Stat("/opt/homebrew/lib/libfuse-t.dylib")
	return err == nil
}

func checkESF() bool {
	// ESF requires entitlement - check if we're running as entitled app
	// For now, return false as most CLI tools won't have ESF
	return false
}

func checkNetworkExtension() bool {
	// Network Extension is available if app is properly entitled
	// For CLI detection, assume false
	return false
}

func checkLima() bool {
	// Check if limactl is available
	_, err := exec.LookPath("limactl")
	return err == nil
}

func checkMacwrap() bool {
	_, err := exec.LookPath("agentsh-macwrap")
	return err == nil
}

func selectDarwinMode(caps map[string]any) (string, int) {
	if esf, _ := caps["esf"].(bool); esf {
		return "esf", 90
	}
	if lima, _ := caps["lima_available"].(bool); lima {
		return "lima", 85
	}

	hasMacwrap := checkMacwrap()
	fuset, _ := caps["fuse_t"].(bool)

	if hasMacwrap && fuset {
		return "dynamic-seatbelt-fuse", 75
	}
	if fuset {
		return "fuse-t", 70
	}
	if hasMacwrap {
		return "dynamic-seatbelt", 65
	}
	return "sandbox-exec", 60
}
