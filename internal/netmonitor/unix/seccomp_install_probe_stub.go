//go:build !linux || !cgo

package unix

import "syscall"

// InstallProbeResult mirrors the cgo type so callers compile on every target.
type InstallProbeResult struct {
	Installable bool
	Errno       syscall.Errno
	Detail      string
}

// ProbeSeccompInstall is a stub for non-Linux / linux-without-cgo builds: there
// is no probe-child handler compiled in, so there is nothing to re-exec.
func ProbeSeccompInstall() InstallProbeResult {
	return InstallProbeResult{Installable: false, Detail: "seccomp install probe unavailable (no cgo / unsupported OS)"}
}
