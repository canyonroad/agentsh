//go:build linux

package capabilities

// detectFileEnforcementBackend returns the best available file enforcement backend.
func detectFileEnforcementBackend(caps *SecurityCapabilities) string {
	if caps.Landlock {
		return "landlock"
	}
	if caps.FUSE {
		return "fuse"
	}
	if caps.Seccomp {
		return "seccomp-notify"
	}
	return "none"
}

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	// Use existing detection
	secCaps := DetectSecurityCapabilities()
	secCaps.FileEnforcement = detectFileEnforcementBackend(secCaps)

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
		"ptrace":              secCaps.Ptrace,
		"file_enforcement":    secCaps.FileEnforcement,
	}

	// Determine FUSE mount method for observability
	fuseMountMethod := "none"
	if secCaps.FUSE {
		if hasFusermount() {
			fuseMountMethod = "fusermount"
		} else if checkNewMountAPIAvailable() {
			fuseMountMethod = "new-api"
		} else {
			fuseMountMethod = "direct"
		}
	}
	caps["fuse_mount_method"] = fuseMountMethod

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
	case ModePtrace:
		return 90
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
