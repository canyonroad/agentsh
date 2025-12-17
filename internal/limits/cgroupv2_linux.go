//go:build linux

package limits

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type CgroupV2Limits struct {
	MaxMemoryBytes int64
	CPUQuotaPct    int // percentage of one core
	PidsMax        int
}

type CgroupV2 struct {
	Path string
}

func DetectCgroupV2() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

// CurrentCgroupDir returns the cgroup v2 directory for the current process (under /sys/fs/cgroup).
func CurrentCgroupDir() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	// v2 unified format: "0::/path"
	line := strings.TrimSpace(string(b))
	if line == "" {
		return "", fmt.Errorf("empty /proc/self/cgroup")
	}
	parts := strings.Split(line, ":")
	if len(parts) < 3 {
		return "", fmt.Errorf("unexpected /proc/self/cgroup: %q", line)
	}
	p := parts[len(parts)-1]
	if p == "" {
		p = "/"
	}
	return filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(p, "/")), nil
}

func ApplyCgroupV2(parentDir string, name string, pid int, lim CgroupV2Limits) (*CgroupV2, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid %d", pid)
	}
	if !DetectCgroupV2() {
		return nil, fmt.Errorf("cgroup v2 not detected")
	}

	if parentDir == "" {
		cg, err := CurrentCgroupDir()
		if err != nil {
			return nil, fmt.Errorf("current cgroup: %w", err)
		}
		parentDir = cg
	}

	safe := sanitizeCgroupName(name)
	dir := filepath.Join(parentDir, safe)

	// Best-effort: enable controllers for children at the parent.
	_ = enableControllers(parentDir, []string{"cpu", "memory", "pids"})

	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("mkdir cgroup: %w", err)
	}

	// Apply limits before moving tasks.
	if lim.MaxMemoryBytes > 0 {
		if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte(strconv.FormatInt(lim.MaxMemoryBytes, 10)), 0o644); err != nil {
			return nil, fmt.Errorf("set memory.max: %w", err)
		}
	}
	if lim.PidsMax > 0 {
		if err := os.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.Itoa(lim.PidsMax)), 0o644); err != nil {
			return nil, fmt.Errorf("set pids.max: %w", err)
		}
	}
	if lim.CPUQuotaPct > 0 {
		q, p := cpuMaxFromPct(lim.CPUQuotaPct)
		if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte(fmt.Sprintf("%d %d", q, p)), 0o644); err != nil {
			return nil, fmt.Errorf("set cpu.max: %w", err)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return nil, fmt.Errorf("attach pid: %w", err)
	}

	return &CgroupV2{Path: dir}, nil
}

func (c *CgroupV2) Close(ctx context.Context) error {
	if c == nil || c.Path == "" {
		return nil
	}
	// Wait briefly for the cgroup to become unpopulated before removing.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := cgroupUnpopulated(c.Path); ok {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	if err := os.Remove(c.Path); err != nil && !errors.Is(err, syscall.ENOENT) {
		return err
	}
	return nil
}

func cpuMaxFromPct(pct int) (quota int, period int) {
	period = 100000 // 100ms
	if pct <= 0 {
		return 0, period
	}
	if pct > 1000 {
		pct = 1000
	}
	quota = period * pct / 100
	if quota < 1000 {
		quota = 1000
	}
	return quota, period
}

func sanitizeCgroupName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "agentsh"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	out = strings.Trim(out, "._-")
	if out == "" {
		return "agentsh"
	}
	return out
}

func enableControllers(parentDir string, ctrls []string) error {
	path := filepath.Join(parentDir, "cgroup.subtree_control")
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, c := range ctrls {
		if _, err := f.WriteString("+" + c); err != nil {
			// Ignore EBUSY etc; best effort.
			continue
		}
	}
	return nil
}

func cgroupUnpopulated(dir string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.events"))
	if err != nil {
		return false, err
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "populated ") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "populated "))
			return v == "0", nil
		}
	}
	return false, nil
}
