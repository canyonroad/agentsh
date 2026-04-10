//go:build !linux

package limits

import (
	"context"
	"fmt"
)

type CgroupV2Limits struct {
	MaxMemoryBytes int64
	CPUQuotaPct    int
	PidsMax        int
}

type CgroupV2 struct {
	Path string
}

func DetectCgroupV2() bool { return false }

func CurrentCgroupDir() (string, error) { return "", fmt.Errorf("cgroups not supported") }

func (c *CgroupV2) Close(ctx context.Context) error { return nil }

// CgroupMode names an operating mode for cgroup v2 enforcement.
type CgroupMode string

const (
	ModeNested      CgroupMode = "nested"
	ModeTopLevel    CgroupMode = "top-level"
	ModeUnavailable CgroupMode = "unavailable"
)

// CgroupProbeResult is the output of ProbeCgroupsV2.
type CgroupProbeResult struct {
	Mode          CgroupMode
	Reason        string
	OwnCgroup     string
	SliceDir      string
	IOAvailable   bool
	OrphansReaped []string
	// LeafMoved is true if the process resides in OwnCgroup/leaf
	LeafMoved bool
}

// CgroupManager is the per-process cgroup v2 enforcement manager.
type CgroupManager struct{}

// NewCgroupManager is not supported on non-Linux platforms.
func NewCgroupManager(ctx context.Context, ownHint string) (*CgroupManager, error) {
	return nil, fmt.Errorf("cgroups not supported on this platform")
}

// Probe returns the immutable probe result captured at construction.
func (m *CgroupManager) Probe() *CgroupProbeResult { return nil }

// Apply creates a per-command cgroup and attaches the given pid.
func (m *CgroupManager) Apply(name string, pid int, lim CgroupV2Limits) (*CgroupV2, error) {
	return nil, fmt.Errorf("cgroups not supported on this platform")
}

// ProbeCgroupsV2Default runs the default probe (not supported on non-Linux).
func ProbeCgroupsV2Default(ctx context.Context) (*CgroupProbeResult, error) {
	return nil, fmt.Errorf("cgroups not supported on this platform")
}

// CgroupUnavailableError is returned when cgroup enforcement is unavailable
// but the policy requires resource limits.
type CgroupUnavailableError struct {
	Reason string
	Limits CgroupV2Limits
}

func (e *CgroupUnavailableError) Error() string {
	return fmt.Sprintf("cgroup enforcement unavailable (%s)", e.Reason)
}

// Summary returns a compact human-readable description of non-zero limits.
func (l CgroupV2Limits) Summary() string { return "no limits" }

// IsEmpty reports whether the limits struct contains no enforceable values.
func (l CgroupV2Limits) IsEmpty() bool { return true }

// EnableControllersError is returned when writing to cgroup.subtree_control fails.
type EnableControllersError struct {
	ParentDir  string
	Controller string
	Err        error
}

func (e *EnableControllersError) Error() string {
	return fmt.Sprintf("enable controller %q in %s: %v", e.Controller, e.ParentDir, e.Err)
}

func (e *EnableControllersError) Unwrap() error { return e.Err }
