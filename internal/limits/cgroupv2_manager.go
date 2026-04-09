//go:build linux

package limits

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"syscall"
)

// CgroupManager is the production entry point for per-command cgroup v2 enforcement.
// Construct one at server startup via NewCgroupManager; all per-exec calls go through Apply.
//
// The manager captures an immutable probe result at construction time. If the
// environment changes mid-run, restart agentsh.
type CgroupManager struct {
	fs    cgroupFS
	probe *CgroupProbeResult
}

// NewCgroupManager runs ProbeCgroupsV2 once and returns a manager bound to the result.
// ownHint is the optional user-configured cgroup base path (cfg.Sandbox.Cgroups.BasePath).
// Pass an empty string to have the probe discover the process's own cgroup.
//
// NewCgroupManager never fails for expected reasons — environment gaps are reflected
// in the probed mode, not in the return error. An error is only returned if the
// process cannot even determine its own cgroup path.
func NewCgroupManager(ctx context.Context, ownHint string) (*CgroupManager, error) {
	return newCgroupManagerFS(ctx, osCgroupFS{}, ownHint)
}

// newCgroupManagerFS is the FS-injectable form used by unit tests.
func newCgroupManagerFS(ctx context.Context, fs cgroupFS, ownHint string) (*CgroupManager, error) {
	probe, err := ProbeCgroupsV2(ctx, fs, ownHint)
	if err != nil {
		return nil, fmt.Errorf("probe cgroups v2: %w", err)
	}
	return &CgroupManager{fs: fs, probe: probe}, nil
}

// Probe returns the immutable probe result captured at construction.
func (m *CgroupManager) Probe() *CgroupProbeResult { return m.probe }

// Apply creates a per-command cgroup (named `name`), writes the non-zero limits,
// and attaches `pid`. It returns a handle whose Close() removes the cgroup when
// the command exits.
//
// If the manager's probed mode is ModeUnavailable and any limit in lim is non-zero,
// Apply returns *CgroupUnavailableError without creating anything. This is the
// fail-closed path.
func (m *CgroupManager) Apply(name string, pid int, lim CgroupV2Limits) (*CgroupV2, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid %d", pid)
	}

	// Fail-closed: if limits are required but enforcement is unavailable, refuse.
	if m.probe.Mode == ModeUnavailable {
		if !lim.IsEmpty() {
			return nil, &CgroupUnavailableError{Reason: m.probe.Reason, Limits: lim}
		}
		// No limits requested: allow the command but create no cgroup.
		return nil, nil
	}

	parent := m.parentDir()
	safe := sanitizeCgroupName(name)
	dir := filepath.Join(parent, safe)

	if err := m.fs.Mkdir(dir, 0o755); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("mkdir cgroup (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
	}

	if lim.MaxMemoryBytes > 0 {
		if err := m.fs.WriteFile(filepath.Join(dir, "memory.max"), []byte(strconv.FormatInt(lim.MaxMemoryBytes, 10)), 0o644); err != nil {
			return nil, fmt.Errorf("write memory.max (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
		}
	}
	if lim.PidsMax > 0 {
		if err := m.fs.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.Itoa(lim.PidsMax)), 0o644); err != nil {
			return nil, fmt.Errorf("write pids.max (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
		}
	}
	if lim.CPUQuotaPct > 0 {
		q, p := cpuMaxFromPct(lim.CPUQuotaPct)
		if err := m.fs.WriteFile(filepath.Join(dir, "cpu.max"), []byte(fmt.Sprintf("%d %d", q, p)), 0o644); err != nil {
			return nil, fmt.Errorf("write cpu.max (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
		}
	}

	if err := m.fs.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return nil, fmt.Errorf("attach pid (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
	}

	return &CgroupV2{Path: dir}, nil
}

// parentDir returns the directory under which per-command cgroups are created.
func (m *CgroupManager) parentDir() string {
	if m.probe.Mode == ModeTopLevel {
		return m.probe.SliceDir
	}
	return m.probe.OwnCgroup
}
