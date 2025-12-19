//go:build !linux

package ebpf

import "fmt"

func CgroupID(_ string) (uint64, error) {
	return 0, fmt.Errorf("cgroup id not supported on this platform")
}
