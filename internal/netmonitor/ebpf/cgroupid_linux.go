//go:build linux

package ebpf

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// CgroupID returns the cgroup inode id for the given cgroup path.
// This matches the identifier returned by bpf_get_current_cgroup_id in the kernel.
func CgroupID(path string) (uint64, error) {
	if path == "" {
		return 0, fmt.Errorf("empty cgroup path")
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	if st.Ino == 0 {
		return 0, fmt.Errorf("inode is zero for %s", path)
	}
	return st.Ino, nil
}
