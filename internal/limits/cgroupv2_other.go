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

func ApplyCgroupV2(parentDir string, name string, pid int, lim CgroupV2Limits) (*CgroupV2, error) {
	return nil, fmt.Errorf("cgroups not supported")
}

func (c *CgroupV2) Close(ctx context.Context) error { return nil }
