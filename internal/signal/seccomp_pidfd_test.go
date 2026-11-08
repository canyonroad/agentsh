//go:build linux && cgo

package signal

import (
	"testing"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// pidfd_send_signal(2) was missing from the signal filter, so a process could
// signal any same-uid target (including the supervisor) with no policy check.
func TestDefaultSignalFilterCoversPidfd(t *testing.T) {
	found := false
	for _, nr := range DefaultSignalFilterConfig().Syscalls {
		if nr == unix.SYS_PIDFD_SEND_SIGNAL {
			found = true
		}
	}
	if !found {
		t.Fatal("pidfd_send_signal missing from the signal filter syscalls")
	}

	ctx := ExtractSignalContext(&seccomp.ScmpNotifReq{
		Pid: 4242,
		Data: seccomp.ScmpNotifData{
			Syscall: seccomp.ScmpSyscall(unix.SYS_PIDFD_SEND_SIGNAL),
			Args:    []uint64{7, uint64(unix.SIGKILL)},
		},
	})
	if ctx.Signal != int(unix.SIGKILL) {
		t.Fatalf("signal = %d, want SIGKILL", ctx.Signal)
	}
	// fd 7 does not exist for this process, so the target must be marked
	// unresolved (-1) rather than silently 0.
	if ctx.TargetPID != -1 {
		t.Fatalf("target pid = %d, want -1 for an unresolvable pidfd", ctx.TargetPID)
	}
}
