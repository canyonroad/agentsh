//go:build linux

package capabilities

import "golang.org/x/sys/unix"

func probeCapabilityDrop() ProbeResult {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return ProbeResult{Available: false, Detail: "capget failed: " + err.Error()}
	}
	_, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_READ, 0, 0, 0, 0, 0)
	if errno != 0 {
		return ProbeResult{Available: false, Detail: "prctl failed: " + errno.Error()}
	}
	return ProbeResult{Available: true, Detail: "capget+prctl"}
}
