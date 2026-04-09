//go:build linux

package limits

import "fmt"

// EnableControllersError is returned by enableControllers (and enableControllersFS)
// when writing to cgroup.subtree_control fails. It carries the parent cgroup
// directory, the controller that failed (or "*" when the file could not be
// opened at all), and the underlying OS error.
type EnableControllersError struct {
	ParentDir  string
	Controller string
	Err        error
}

func (e *EnableControllersError) Error() string {
	return fmt.Sprintf("enable cgroup controller %q in %s: %v", e.Controller, e.ParentDir, e.Err)
}

func (e *EnableControllersError) Unwrap() error { return e.Err }

// CgroupUnavailableError is returned by CgroupManager.Apply when the manager's
// probed mode is ModeUnavailable and the caller's policy requires one or more
// non-zero resource limits. The error carries the probe reason and the
// requested limits so that audit events can record the refusal context.
type CgroupUnavailableError struct {
	Reason string
	Limits CgroupV2Limits
}

func (e *CgroupUnavailableError) Error() string {
	return fmt.Sprintf(
		"cgroup enforcement unavailable (%s); policy requires %s — refusing command",
		e.Reason, e.Limits.Summary())
}

// Summary returns a compact human-readable description of non-zero limits.
func (l CgroupV2Limits) Summary() string {
	parts := []string{}
	if l.MaxMemoryBytes > 0 {
		parts = append(parts, fmt.Sprintf("memory.max=%d", l.MaxMemoryBytes))
	}
	if l.PidsMax > 0 {
		parts = append(parts, fmt.Sprintf("pids.max=%d", l.PidsMax))
	}
	if l.CPUQuotaPct > 0 {
		parts = append(parts, fmt.Sprintf("cpu.quota=%d%%", l.CPUQuotaPct))
	}
	if len(parts) == 0 {
		return "no limits"
	}
	return joinComma(parts)
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// IsEmpty reports whether the limits struct contains no enforceable values.
// A caller can skip cgroup creation entirely when IsEmpty is true.
func (l CgroupV2Limits) IsEmpty() bool {
	return l.MaxMemoryBytes <= 0 && l.CPUQuotaPct <= 0 && l.PidsMax <= 0
}
