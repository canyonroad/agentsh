//go:build linux

package capabilities

import "fmt"

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

// buildLinuxDomains builds the five protection domains from cached probe results and capability flags.
func buildLinuxDomains(caps *SecurityCapabilities) []ProtectionDomain {
	fuseMountMethod := "none"
	if caps.FUSE {
		if hasFusermount() {
			fuseMountMethod = "fusermount"
		} else if checkNewMountAPIAvailable() {
			fuseMountMethod = "new-api"
		} else {
			fuseMountMethod = "direct"
		}
	}

	landlockDetail := "not available"
	if caps.Landlock {
		landlockDetail = fmt.Sprintf("ABI v%d", caps.LandlockABI)
	}

	mode := caps.SelectMode()
	commandActive := "seccomp-execve"
	if mode == ModePtrace {
		commandActive = "ptrace"
	}

	networkActive := ""
	if caps.EBPFProbe.Available {
		networkActive = "ebpf"
	} else if caps.LandlockNetwork {
		networkActive = "landlock-network"
	}

	resourceActive := ""
	if caps.CgroupProbe.Available {
		resourceActive = "cgroups-v2"
	}

	isoActive := ""
	// CapabilitiesActive is the single behavioural source of truth
	// after the #198 mechanism/active split. CapProbe.Detail is still
	// read below for the explanatory text ("0/42 caps dropped", etc.)
	// but the available flag must not come from CapProbe.Available
	// directly — otherwise a caller that synthesises a
	// SecurityCapabilities (tests, future callers) could set
	// CapabilitiesActive to a value that disagrees with what the
	// detect domains report.
	if caps.CapabilitiesActive {
		isoActive = "capability-drop"
	}
	if caps.PIDNSProbe.Available {
		isoActive = "pid-namespace"
	}

	return []ProtectionDomain{
		{
			Name: "File Protection", Weight: WeightFileProtection,
			Backends: []DetectedBackend{
				{Name: "fuse", Available: caps.FUSE, Detail: fuseMountMethod, Description: "file interception, soft-delete, redirect", CheckMethod: "probe"},
				{Name: "landlock", Available: caps.Landlock, Detail: landlockDetail, Description: "kernel path restrictions", CheckMethod: "syscall"},
				{Name: "seccomp-notify", Available: caps.Seccomp, Detail: "", Description: "openat/stat enforcement", CheckMethod: "probe"},
			},
			Active: caps.FileEnforcement,
		},
		{
			Name: "Command Control", Weight: WeightCommandControl,
			Backends: []DetectedBackend{
				{Name: "seccomp-execve", Available: caps.Seccomp, Detail: "", Description: "execve interception", CheckMethod: "probe"},
				{Name: "ptrace", Available: caps.Ptrace, Detail: "", Description: "syscall tracing", CheckMethod: "probe"},
			},
			Active: commandActive,
		},
		{
			Name: "Network", Weight: WeightNetwork,
			Backends: []DetectedBackend{
				{Name: "ebpf", Available: caps.EBPFProbe.Available, Detail: caps.EBPFProbe.Detail, Description: "network monitoring", CheckMethod: "probe"},
				{Name: "landlock-network", Available: caps.LandlockNetwork, Detail: "", Description: "TCP bind/connect filtering", CheckMethod: "syscall"},
			},
			Active: networkActive,
		},
		{
			Name: "Resource Limits", Weight: WeightResourceLimits,
			Backends: []DetectedBackend{
				{Name: "cgroups-v2", Available: caps.CgroupProbe.Available, Detail: caps.CgroupProbe.Detail, Description: "CPU/memory/process limits", CheckMethod: "probe"},
			},
			Active: resourceActive,
		},
		{
			Name: "Isolation", Weight: WeightIsolation,
			Backends: []DetectedBackend{
				{Name: "pid-namespace", Available: caps.PIDNSProbe.Available, Detail: caps.PIDNSProbe.Detail, Description: "process isolation", CheckMethod: "probe"},
				// Available reads CapabilitiesActive (the single
				// behavioural source of truth); Detail still pulls
				// the human-readable text from CapProbe for
				// "0/42 caps dropped" etc.
				{Name: "capability-drop", Available: caps.CapabilitiesActive, Detail: caps.CapProbe.Detail, Description: "privilege reduction", CheckMethod: "probe"},
			},
			Active: isoActive,
		},
	}
}

// backwardCompatCaps builds the flat capabilities map for backward compatibility.
func backwardCompatCaps(caps *SecurityCapabilities, domains []ProtectionDomain) map[string]any {
	m := map[string]any{
		"seccomp":             caps.Seccomp,
		"seccomp_user_notify": caps.Seccomp,
		"seccomp_basic":       caps.SeccompBasic,
		"landlock":            caps.Landlock,
		"landlock_abi":        caps.LandlockABI,
		"landlock_network":    caps.LandlockNetwork,
		"fuse":                caps.FUSE,
		"ptrace":              caps.Ptrace,
		"file_enforcement":    caps.FileEnforcement,
	}
	for _, d := range domains {
		for _, b := range d.Backends {
			switch b.Name {
			case "ebpf":
				m["ebpf"] = b.Available
			case "cgroups-v2":
				m["cgroups_v2"] = b.Available
			case "pid-namespace":
				m["pid_namespace"] = b.Available
			case "capability-drop":
				m["capabilities_drop"] = b.Available
			case "fuse":
				if b.Available {
					m["fuse_mount_method"] = b.Detail
				}
			}
		}
	}
	if _, ok := m["fuse_mount_method"]; !ok {
		m["fuse_mount_method"] = "none"
	}

	// Enrich the cgroups_v2 view with probe details (issue #197).
	if p := LastCgroupProbe(); p != nil {
		m["cgroups_v2_mode"] = string(p.Mode)
		m["cgroups_v2_reason"] = p.Reason
		m["cgroups_v2_own_cgroup"] = p.OwnCgroup
		if p.SliceDir != "" {
			m["cgroups_v2_slice_dir"] = p.SliceDir
		}
		m["cgroups_v2_io_available"] = p.IOAvailable
	}

	return m
}

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	secCaps := DetectSecurityCapabilities()
	secCaps.FileEnforcement = detectFileEnforcementBackend(secCaps)

	domains := buildLinuxDomains(secCaps)
	score := ComputeScore(domains)
	mode := secCaps.SelectMode()

	caps := backwardCompatCaps(secCaps, domains)

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
		Platform:        "linux",
		SecurityMode:    mode,
		ProtectionScore: score,
		Domains:         domains,
		Capabilities:    caps,
		Summary:         DetectSummary{Available: available, Unavailable: unavailable},
		Tips:            tips,
	}, nil
}
