//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/platform"
)

// cgroupResourceLimiter implements platform.ResourceLimiter by delegating to
// limits.CgroupManager. The CgroupManager is created lazily on the first
// Apply() call because the platform is constructed before the cgroup probe runs.
type cgroupResourceLimiter struct {
	mu      sync.Mutex
	mgr     *limits.CgroupManager
	initErr error
	inited  bool
}

func (r *cgroupResourceLimiter) Available() bool {
	return limits.DetectCgroupV2()
}

func (r *cgroupResourceLimiter) SupportedLimits() []platform.ResourceType {
	if !r.Available() {
		return nil
	}
	return []platform.ResourceType{
		platform.ResourceCPU,
		platform.ResourceMemory,
		platform.ResourceProcessCount,
	}
}

func (r *cgroupResourceLimiter) ensureManager() (*limits.CgroupManager, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inited {
		return r.mgr, r.initErr
	}
	r.inited = true
	r.mgr, r.initErr = limits.NewCgroupManager(context.Background(), "")
	return r.mgr, r.initErr
}

func (r *cgroupResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
	if config.MaxDiskReadMBps > 0 || config.MaxDiskWriteMBps > 0 {
		return nil, fmt.Errorf("disk IO limiting not supported (no io controller in CgroupV2Limits)")
	}
	if config.MaxNetworkMbps > 0 {
		return nil, fmt.Errorf("network bandwidth limiting not supported (requires tc/qdisc)")
	}

	mgr, err := r.ensureManager()
	if err != nil {
		return nil, fmt.Errorf("cgroup manager init: %w", err)
	}

	lim := limits.CgroupV2Limits{
		MaxMemoryBytes: int64(config.MaxMemoryMB) * 1024 * 1024,
		CPUQuotaPct:    int(config.MaxCPUPercent),
		PidsMax:        int(config.MaxProcesses),
	}

	return &cgroupResourceHandle{
		mgr:  mgr,
		name: config.Name,
		lim:  lim,
	}, nil
}

// cgroupResourceHandle implements platform.ResourceHandle by wrapping a
// CgroupManager and a lazily-created CgroupV2.
type cgroupResourceHandle struct {
	mu      sync.Mutex
	mgr     *limits.CgroupManager
	name    string
	lim     limits.CgroupV2Limits
	cg      *limits.CgroupV2
	created bool
}

func (h *cgroupResourceHandle) AssignProcess(pid int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.created {
		h.created = true
		cg, err := h.mgr.Apply(h.name, pid, h.lim)
		if err != nil {
			return err
		}
		h.cg = cg // may be nil if mode is unavailable with empty limits
		return nil
	}

	if h.cg == nil {
		return nil
	}

	return os.WriteFile(
		filepath.Join(h.cg.Path, "cgroup.procs"),
		[]byte(strconv.Itoa(pid)),
		0o644,
	)
}

func (h *cgroupResourceHandle) Stats() platform.ResourceStats {
	return platform.ResourceStats{}
}

func (h *cgroupResourceHandle) Release() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cg == nil {
		return nil
	}
	err := h.cg.Close(context.Background())
	h.cg = nil
	return err
}
