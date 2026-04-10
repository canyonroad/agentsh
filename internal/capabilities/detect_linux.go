//go:build linux

package capabilities

import (
	"fmt"
	"os/exec"
)

// wrapperLookPath is the function used to check if the wrapper binary exists.
// Package-level var for testability (matches checkPtrace pattern in check.go).
var wrapperLookPath = exec.LookPath

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

// wrapperDependentBackends lists backends that require agentsh-unixwrap.
// These are marked unavailable when the wrapper binary is not on PATH.
var wrapperDependentBackends = map[string]bool{
	"seccomp-notify":  true,
	"landlock":        true,
	"seccomp-execve":  true,
	"landlock-network": true,
}

// applyWrapperAvailability checks if agentsh-unixwrap is on PATH and marks
// wrapper-dependent backends as unavailable if it's missing. Also updates
// secCaps.FileEnforcement and domain Active fields for consistency.
// Returns true if the wrapper was found.
//
// Note: this checks the default wrapper binary name. The server config allows
// overriding via sandbox.unix_sockets.wrapper_bin, but Detect() is intentionally
// config-agnostic — it probes system capabilities, not config state. Config-aware
// validation lives in CheckConfig().
func applyWrapperAvailability(domains []ProtectionDomain, secCaps *SecurityCapabilities) bool {
	_, err := wrapperLookPath("agentsh-unixwrap")
	if err == nil {
		return true
	}

	// Wrapper missing — clear secCaps fields for wrapper-dependent capabilities
	// so SelectMode() and backwardCompatCaps() reflect the real state.
	// These must be cleared before the domain loop because SelectMode() and
	// the Active derivation read from secCaps.
	secCaps.Seccomp = false
	secCaps.Landlock = false
	secCaps.LandlockNetwork = false

	// Update FileEnforcement before the domain loop since File Protection
	// reads it for Active derivation.
	switch secCaps.FileEnforcement {
	case "landlock", "seccomp-notify":
		if secCaps.FUSE {
			secCaps.FileEnforcement = "fuse"
		} else {
			secCaps.FileEnforcement = "none"
		}
	}

	// Disable dependent backends in domains and re-derive Active
	for i := range domains {
		activeDisabled := false
		for j := range domains[i].Backends {
			if wrapperDependentBackends[domains[i].Backends[j].Name] {
				if domains[i].Backends[j].Name == domains[i].Active {
					activeDisabled = true
				}
				domains[i].Backends[j].Available = false
			}
		}
		if activeDisabled {
			domains[i].Active = ""
			// Re-derive Active using capability-aware logic rather than
			// blindly picking first available (e.g., ptrace should only
			// be active when PtraceEnabled is true and mode selects it).
			mode := secCaps.SelectMode()
			switch domains[i].Name {
			case "File Protection":
				domains[i].Active = secCaps.FileEnforcement
			case "Command Control":
				if mode == ModePtrace {
					domains[i].Active = "ptrace"
				}
				// otherwise remains "" — no active command control
			case "Network":
				if secCaps.EBPFProbe.Available {
					domains[i].Active = "ebpf"
				}
				// landlock-network disabled, so no fallback
			default:
				// Other domains: pick first available
				for _, b := range domains[i].Backends {
					if b.Available {
						domains[i].Active = b.Name
						break
					}
				}
			}
		}
	}

	return false
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

	// Check wrapper availability before scoring — marks seccomp/landlock
	// backends unavailable if agentsh-unixwrap is not on PATH.
	//
	// This check lives in Detect() rather than DetectSecurityCapabilities()
	// because the server already handles wrapper absence at runtime via
	// setupSeccompWrapper() in core.go (its own LookPath + graceful
	// degradation). Moving it into DetectSecurityCapabilities() would change
	// the contract for all callers. Detect() is the user-facing capability
	// report where accuracy matters most.
	wrapperFound := applyWrapperAvailability(domains, secCaps)

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

	// When the wrapper is missing, suppress generic backend tips for
	// wrapper-dependent backends (e.g., "run privileged" for seccomp).
	// The wrapper-specific tip below is the actionable remediation.
	//
	// We build the suppress set from tipsByBackend because tip.Feature
	// doesn't always match the backend name (e.g., seccomp-execve backend
	// emits a tip with Feature "seccomp").
	if !wrapperFound {
		suppressFeatures := make(map[string]bool)
		for name := range wrapperDependentBackends {
			if tip, ok := tipsByBackend[name]; ok {
				suppressFeatures[tip.Feature] = true
			}
		}

		filtered := tips[:0]
		for _, tip := range tips {
			if !suppressFeatures[tip.Feature] {
				filtered = append(filtered, tip)
			}
		}
		tips = filtered

		// Add wrapper-specific tip regardless of domain score (FUSE may keep
		// File Protection scored, but the missing wrapper is still actionable).
		tips = append(tips, Tip{
			Feature: "seccomp-wrapper",
			Status:  "missing",
			Impact:  "seccomp and Landlock enforcement disabled — processes run without kernel-level interception",
			Action:  "install agentsh-unixwrap or rebuild the package with CGO_ENABLED=1",
		})
	}

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
