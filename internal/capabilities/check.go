//go:build linux

// Package capabilities provides runtime checks for kernel and system
// capabilities required by agentsh sandbox features.
package capabilities

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/limits"
)

// CheckResult represents the result of a single capability check.
type CheckResult struct {
	Feature    string // e.g., "seccomp-user-notify"
	ConfigKey  string // e.g., "sandbox.unix_sockets.enabled"
	Available  bool
	Error      error
	Suggestion string // e.g., "Set sandbox.unix_sockets.enabled: false"
}

// Check function type for capability checks.
type Check func() CheckResult

// Check function variables - can be replaced in tests.
var (
	checkSeccompUserNotify       = realCheckSeccompUserNotify
	checkPtrace                  = realCheckPtrace
	checkCgroupsV2ResourceLimits = realCheckCgroupsV2ResourceLimits
	checkeBPF                    = realCheckeBPF
	checkEBPFCgroupAttach        = realCheckEBPFCgroupAttach
	checkWrapperBinary           = realCheckWrapperBinary
)

func realCheckSeccompUserNotify() CheckResult {
	probe := probeSeccompUserNotify()
	r := CheckResult{Feature: "seccomp-user-notify", Available: probe.Available}
	if !probe.Available {
		r.Error = fmt.Errorf("kernel does not support SECCOMP_RET_USER_NOTIF: %s", probe.Detail)
	}
	return r
}

func realCheckPtrace() CheckResult {
	available := checkPtraceCapability()
	r := CheckResult{Feature: "ptrace", Available: available}
	if !available {
		r.Error = fmt.Errorf("ptrace not available (PTRACE_SEIZE probe failed — blocked by seccomp, gVisor, or missing CAP_SYS_PTRACE)")
	}
	return r
}

func realCheckCgroupsV2ResourceLimits() CheckResult {
	// Populate the cache on the first call so that detect output can read it.
	// If the cache was already set (e.g., by another check or a test fixture)
	// we skip the probe — the cached value wins.
	if LastCgroupProbe() == nil {
		probeCgroupsV2()
	}
	available := false
	if last := LastCgroupProbe(); last != nil {
		available = last.Mode == limits.ModeNested || last.Mode == limits.ModeTopLevel
	}
	return CheckResult{Feature: "cgroups_v2_resource_limits", Available: available}
}

func realCheckeBPF() CheckResult {
	probe := probeEBPF()
	return CheckResult{Feature: "ebpf", Available: probe.Available}
}

func realCheckEBPFCgroupAttach() CheckResult {
	ebpfResult := checkeBPF()
	var mode limits.CgroupMode = limits.ModeUnavailable
	if last := LastCgroupProbe(); last != nil {
		mode = last.Mode
	}
	available := ebpfResult.Available &&
		(mode == limits.ModeNested || mode == limits.ModeTopLevel || mode == limits.ModeAttachOnly)
	r := CheckResult{
		Feature:   "ebpf_cgroup_attach",
		Available: available,
	}
	if !available {
		switch {
		case !ebpfResult.Available:
			r.Error = fmt.Errorf("eBPF kernel support unavailable: %v", ebpfResult.Error)
		default:
			r.Error = fmt.Errorf("cgroup attach feasibility unavailable: probe mode is %q", mode)
		}
	}
	return r
}

func realCheckWrapperBinary(binaryPath string) CheckResult {
	if binaryPath == "" {
		binaryPath = "agentsh-unixwrap"
	}
	_, err := exec.LookPath(binaryPath)
	if err != nil {
		return CheckResult{
			Feature:   "seccomp-wrapper-binary",
			Available: false,
			Error:     fmt.Errorf("wrapper binary %q not found in PATH: %w", binaryPath, err),
		}
	}
	return CheckResult{
		Feature:   "seccomp-wrapper-binary",
		Available: true,
	}
}

// CheckAll runs all capability checks based on enabled features in the config.
// It returns nil if all checks pass, or an error describing all failures.
func CheckAll(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}

	var failures []CheckResult

	// Check unix_sockets.enabled -> requires seccomp user-notify
	if cfg.Sandbox.UnixSockets.Enabled != nil && *cfg.Sandbox.UnixSockets.Enabled {
		result := checkSeccompUserNotify()
		result.ConfigKey = "sandbox.unix_sockets.enabled"
		result.Suggestion = "Set 'sandbox.unix_sockets.enabled: false' in your config"
		if !result.Available {
			failures = append(failures, result)
		}
	}

	// Check cgroups.enabled -> requires cgroups v2 + ptrace
	if cfg.Sandbox.Cgroups.Enabled {
		// Check cgroups v2
		cgResult := checkCgroupsV2ResourceLimits()
		cgResult.ConfigKey = "sandbox.cgroups.enabled"
		cgResult.Suggestion = "Set 'sandbox.cgroups.enabled: false' in your config"
		if !cgResult.Available {
			failures = append(failures, cgResult)
		}

		// Check ptrace
		ptraceResult := checkPtrace()
		ptraceResult.ConfigKey = "sandbox.cgroups.enabled"
		ptraceResult.Suggestion = "Set 'sandbox.cgroups.enabled: false' in your config"
		if !ptraceResult.Available {
			failures = append(failures, ptraceResult)
		}
	}

	// Check seccomp.enabled -> requires seccomp user-notify
	if cfg.Sandbox.Seccomp.Enabled {
		result := checkSeccompUserNotify()
		result.ConfigKey = "sandbox.seccomp.enabled"
		result.Suggestion = "Set 'sandbox.seccomp.enabled: false' in your config"
		if !result.Available {
			failures = append(failures, result)
		}
	}

	// Check network.ebpf.enabled -> requires eBPF
	if cfg.Sandbox.Network.EBPF.Enabled {
		result := checkeBPF()
		result.ConfigKey = "sandbox.network.ebpf.enabled"
		result.Suggestion = "Set 'sandbox.network.ebpf.enabled: false' in your config"
		if !result.Available {
			failures = append(failures, result)
		}
	}

	// Check ebpf cgroup attach feasibility (eBPF kernel support + attach-capable cgroup mode).
	// Only recorded as a fatal failure when ebpf.required=true; enabled=true alone is best-effort.
	if cfg.Sandbox.Network.EBPF.Enabled || cfg.Sandbox.Network.EBPF.Enforce || cfg.Sandbox.Network.EBPF.Required {
		result := checkEBPFCgroupAttach()
		result.ConfigKey = "sandbox.network.ebpf.enabled"
		result.Suggestion = "See docs/ebpf.md for capability requirements (CAP_BPF, /sys/fs/bpf, CONFIG_CGROUP_BPF)"
		if !result.Available && cfg.Sandbox.Network.EBPF.Required {
			failures = append(failures, result)
		}
	}

	// Check ptrace capability when enabled
	if cfg.Sandbox.Ptrace.Enabled {
		result := checkPtrace()
		result.ConfigKey = "sandbox.ptrace.enabled"
		result.Suggestion = "Set 'sandbox.ptrace.enabled: false' or add SYS_PTRACE capability"
		if !result.Available {
			failures = append(failures, result)
		}
	}

	// Check if seccomp wrapper binary is required and available
	// The agentsh-unixwrap binary is required for:
	// - unix_sockets.enabled (seccomp-based socket filtering)
	// - seccomp.execve.enabled (execve interception)
	unixEnabled := cfg.Sandbox.UnixSockets.Enabled != nil && *cfg.Sandbox.UnixSockets.Enabled
	execveEnabled := cfg.Sandbox.Seccomp.Execve.Enabled
	if unixEnabled || execveEnabled {
		wrapperBin := strings.TrimSpace(cfg.Sandbox.UnixSockets.WrapperBin)
		if wrapperBin == "" {
			wrapperBin = "agentsh-unixwrap"
		}
		result := checkWrapperBinary(wrapperBin)
		if unixEnabled {
			result.ConfigKey = "sandbox.unix_sockets.enabled"
		} else {
			result.ConfigKey = "sandbox.seccomp.execve.enabled"
		}
		result.Suggestion = fmt.Sprintf(
			"Install the agentsh-unixwrap binary, or disable the feature by setting '%s: false' in your config.\n"+
				"          The agentsh-unixwrap binary is required for seccomp/execve interception.\n"+
				"          It may be missing if you're using a CGO-disabled build.",
			result.ConfigKey,
		)
		if !result.Available {
			failures = append(failures, result)
		}
	}

	if len(failures) == 0 {
		return nil
	}

	return formatErrors(failures)
}

// formatErrors formats multiple check failures into a single error message.
func formatErrors(failures []CheckResult) error {
	var sb strings.Builder
	sb.WriteString("agentsh: capability check failed\n")

	for _, f := range failures {
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("  Feature:     %s\n", f.Feature))
		sb.WriteString(fmt.Sprintf("  Config:      %s = true\n", f.ConfigKey))
		if f.Error != nil {
			sb.WriteString(fmt.Sprintf("  Error:       %s\n", f.Error.Error()))
		}
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("  To fix: %s\n", f.Suggestion))
		// Only suggest kernel upgrade for kernel features, not missing binaries
		if f.Feature != "seccomp-wrapper-binary" {
			sb.WriteString("          or upgrade to a kernel that supports this feature.\n")
		}
	}

	return fmt.Errorf("%s", sb.String())
}
