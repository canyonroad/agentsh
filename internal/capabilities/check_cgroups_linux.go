//go:build linux

package capabilities

import (
	"context"

	"github.com/agentsh/agentsh/internal/limits"
	"golang.org/x/sys/unix"
)

const cgroup2SuperMagic = 0x63677270

// cgroupProbeCache stores the most recent rich probe result so that
// detect_linux.go can pull structured fields into the flat capabilities map.
// Updated by probeCgroupsV2; read by backwardCompatCaps via LastCgroupProbe.
var cgroupProbeCache *limits.CgroupProbeResult

func cacheCgroupProbe(r *limits.CgroupProbeResult) {
	cgroupProbeCache = r
}

// LastCgroupProbe returns the most recent probe result, or nil if the probe
// has not been run in this process. Exposed for detect output formatting.
func LastCgroupProbe() *limits.CgroupProbeResult {
	return cgroupProbeCache
}

func probeCgroupsV2() ProbeResult {
	// Quick sanity: is cgroup2 even mounted?
	var statfs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &statfs); err != nil {
		return ProbeResult{Available: false, Detail: "not mounted"}
	}
	if statfs.Type != cgroup2SuperMagic {
		return ProbeResult{Available: false, Detail: "cgroup v1"}
	}

	// Run the full probe from the limits package.
	if !limits.DetectCgroupV2() {
		return ProbeResult{Available: false, Detail: "cgroup2 not mounted"}
	}
	res, err := limits.ProbeCgroupsV2Default(context.Background())
	if err != nil {
		return ProbeResult{Available: false, Detail: "probe error: " + err.Error()}
	}
	cacheCgroupProbe(res)
	return ProbeResult{
		Available: res.Mode != limits.ModeUnavailable,
		Detail:    string(res.Mode) + ": " + res.Reason,
	}
}
