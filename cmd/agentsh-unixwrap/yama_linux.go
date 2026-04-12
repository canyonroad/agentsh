//go:build linux && cgo

package main

import "os"

// yamaPtraceScopePath is the sysctl that exists when Yama LSM is loaded.
// Package-level var for testability.
var yamaPtraceScopePath = "/proc/sys/kernel/yama/ptrace_scope"

// isYamaActive returns true if the Yama LSM is loaded and active.
// When Yama is not loaded, PR_SET_PTRACER is meaningless (returns EINVAL)
// and ProcessVMReadv permissions fall back to standard Unix DAC.
func isYamaActive() bool {
	_, err := os.Stat(yamaPtraceScopePath)
	return err == nil
}
