//go:build linux

package capabilities

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	// Use existing detection
	secCaps := DetectSecurityCapabilities()

	caps := map[string]any{
		"seccomp":             secCaps.Seccomp,
		"seccomp_user_notify": secCaps.Seccomp,
		"seccomp_basic":       secCaps.SeccompBasic,
		"landlock":            secCaps.Landlock,
		"landlock_abi":        secCaps.LandlockABI,
		"landlock_network":    secCaps.LandlockNetwork,
		"ebpf":                secCaps.EBPF,
		"fuse":                secCaps.FUSE,
		"cgroups_v2":          checkCgroupsV2().Available,
		"pid_namespace":       secCaps.PIDNamespace,
		"capabilities_drop":   secCaps.Capabilities,
	}

	mode := secCaps.SelectMode()
	score := modeToScore(mode)

	// Build summary
	var available, unavailable []string
	for k, v := range caps {
		if k == "landlock_abi" {
			continue // Skip ABI version in summary
		}
		switch val := v.(type) {
		case bool:
			if val {
				available = append(available, k)
			} else {
				unavailable = append(unavailable, k)
			}
		case int:
			if val > 0 {
				available = append(available, k)
			} else {
				unavailable = append(unavailable, k)
			}
		}
	}

	tips := GenerateTips("linux", caps)

	return &DetectResult{
		Platform:        "linux",
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

func modeToScore(mode string) int {
	switch mode {
	case ModeFull:
		return 100
	case ModeLandlock:
		return 85
	case ModeLandlockOnly:
		return 80
	case ModeMinimal:
		return 50
	default:
		return 0
	}
}
