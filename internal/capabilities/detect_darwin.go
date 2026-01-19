//go:build darwin

package capabilities

import (
	"os"
	"os/exec"
)

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	caps := map[string]any{
		"sandbox_exec":      true, // Always available on macOS
		"fuse_t":            checkFuseT(),
		"esf":               checkESF(),
		"network_extension": checkNetworkExtension(),
		"lima_available":    checkLima(),
	}

	mode, score := selectDarwinMode(caps)

	// Build summary
	var available, unavailable []string
	for k, v := range caps {
		if val, ok := v.(bool); ok {
			if val {
				available = append(available, k)
			} else {
				unavailable = append(unavailable, k)
			}
		}
	}

	tips := GenerateTips("darwin", caps)

	return &DetectResult{
		Platform:        "darwin",
		SecurityMode:    mode,
		ProtectionScore: score,
		Capabilities:    caps,
		Summary: DetectSummary{
			Available:   available,
			Unavailable: unavailable,
		},
		Tips: tips,
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

func selectDarwinMode(caps map[string]any) (string, int) {
	if esf, _ := caps["esf"].(bool); esf {
		return "esf", 90
	}
	if fuset, _ := caps["fuse_t"].(bool); fuset {
		return "fuse-t", 70
	}
	if lima, _ := caps["lima_available"].(bool); lima {
		return "lima", 85
	}
	return "sandbox-exec", 60
}
