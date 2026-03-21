//go:build linux

package capabilities

import (
	"os"

	"golang.org/x/sys/unix"
)

const cgroup2SuperMagic = 0x63677270

func probeCgroupsV2() ProbeResult {
	var statfs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &statfs); err != nil {
		return ProbeResult{Available: false, Detail: "not mounted"}
	}
	if statfs.Type != cgroup2SuperMagic {
		return ProbeResult{Available: false, Detail: "cgroup v1"}
	}
	f, err := os.OpenFile("/sys/fs/cgroup/cgroup.procs", os.O_RDONLY, 0)
	if err != nil {
		return ProbeResult{Available: false, Detail: "not readable"}
	}
	f.Close()
	return ProbeResult{Available: true, Detail: "cgroup2"}
}
