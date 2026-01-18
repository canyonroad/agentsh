//go:build linux

// Package capabilities provides runtime checks for kernel and system
// capabilities required by agentsh sandbox features.
package capabilities

import (
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/config"
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
	checkSeccompUserNotify = realCheckSeccompUserNotify
	checkPtrace            = realCheckPtrace
	checkCgroupsV2         = realCheckCgroupsV2
	checkeBPF              = realCheckeBPF
)

// Stub implementations - real implementations will be in separate files.

func realCheckSeccompUserNotify() CheckResult {
	return CheckResult{
		Feature:   "seccomp-user-notify",
		Available: true,
	}
}

func realCheckPtrace() CheckResult {
	return CheckResult{
		Feature:   "ptrace",
		Available: true,
	}
}

func realCheckCgroupsV2() CheckResult {
	return CheckResult{
		Feature:   "cgroups-v2",
		Available: true,
	}
}

func realCheckeBPF() CheckResult {
	return CheckResult{
		Feature:   "ebpf",
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
		cgResult := checkCgroupsV2()
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
		sb.WriteString("          or upgrade to a kernel that supports this feature.\n")
	}

	return fmt.Errorf("%s", sb.String())
}
