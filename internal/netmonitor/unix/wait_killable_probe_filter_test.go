//go:build linux && cgo
// +build linux,cgo

package unix

import (
	"testing"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// recordingAdder implements fileMonitorRuleAdder, capturing every syscall
// passed to it so tests can assert which syscalls a rule installer covers
// without compiling a real BPF program.
type recordingAdder struct{ syscalls []seccomp.ScmpSyscall }

func (r *recordingAdder) AddRule(sc seccomp.ScmpSyscall, _ seccomp.ScmpAction) error {
	r.syscalls = append(r.syscalls, sc)
	return nil
}

func (r *recordingAdder) AddRuleConditional(sc seccomp.ScmpSyscall, _ seccomp.ScmpAction, _ []seccomp.ScmpCondition) error {
	r.syscalls = append(r.syscalls, sc)
	return nil
}

func (r *recordingAdder) has(nr int) bool {
	for _, sc := range r.syscalls {
		if int(sc) == nr {
			return true
		}
	}
	return false
}

// TestProbeFilterMirrorsProductionFileMonitor is the issue #369 Gap C1
// regression guard. It drives the probe's ACTUAL rule composition
// (addProbeFilterRules — the same path buildProbeFilterBytes uses) through a
// recording adder and asserts it traps the full bug-prone composition,
// crucially openat2. openat2's omission let the probe false-pass on glibc>=2.34
// kernels (ld.so loads shared libraries via openat2, so the probe child's
// /bin/true linker storm took the kernel fast path and never exercised the
// notify-dispatch path the kernel bug lives on).
//
// Driving addProbeFilterRules (not installFileMonitorRules in isolation) is
// what makes this a genuine guard: it fails if the probe drops the
// file-monitor family, the socket family, or the metadata family.
func TestProbeFilterMirrorsProductionFileMonitor(t *testing.T) {
	rec := &recordingAdder{}
	if err := addProbeFilterRules(rec); err != nil {
		t.Fatalf("addProbeFilterRules: %v", err)
	}

	for _, want := range []struct {
		nr   int
		name string
	}{
		{unix.SYS_OPENAT2, "openat2"},       // the regression that caused the false-pass
		{unix.SYS_OPENAT, "openat"},         // file_monitor
		{unix.SYS_UNLINKAT, "unlinkat"},     // file_monitor at-family
		{unix.SYS_RENAMEAT2, "renameat2"},   // file_monitor at-family
		{unix.SYS_CONNECT, "connect"},       // socket family
		{unix.SYS_SENDTO, "sendto"},         // socket family
		{unix.SYS_STATX, "statx"},           // metadata family
		{unix.SYS_FACCESSAT2, "faccessat2"}, // metadata family
	} {
		if !rec.has(want.nr) {
			t.Errorf("probe filter composition does not trap %s (nr=%d); no longer mirrors production", want.name, want.nr)
		}
	}
}

// TestSharedNotifySyscallHelpers pins the socket and metadata syscall sets that
// the wrapper and the probe now share (issue #369), so a future edit to one
// can't silently desync the probe's composition from production.
func TestSharedNotifySyscallHelpers(t *testing.T) {
	socket := map[int]bool{}
	for _, sc := range unixSocketNotifySyscalls() {
		socket[int(sc)] = true
	}
	for _, nr := range []int{unix.SYS_SOCKET, unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_SENDTO} {
		if !socket[nr] {
			t.Errorf("unixSocketNotifySyscalls missing nr=%d", nr)
		}
	}

	meta := map[int]bool{}
	for _, sc := range metadataNotifySyscalls() {
		meta[int(sc)] = true
	}
	for _, nr := range []int{unix.SYS_STATX, unix.SYS_NEWFSTATAT, unix.SYS_FACCESSAT2, unix.SYS_READLINKAT} {
		if !meta[nr] {
			t.Errorf("metadataNotifySyscalls missing nr=%d", nr)
		}
	}
}

// TestBuildProbeFilterBytes_Compiles verifies the probe filter still compiles
// to a non-empty BPF program after switching to the production composition
// (erans's "add openat2, existing probe build still works on a healthy kernel"
// check).
func TestBuildProbeFilterBytes_Compiles(t *testing.T) {
	prog, err := buildProbeFilterBytes()
	if err != nil {
		t.Fatalf("buildProbeFilterBytes: %v", err)
	}
	if len(prog) == 0 || len(prog)%8 != 0 {
		t.Fatalf("unexpected BPF program length %d (want non-zero multiple of 8)", len(prog))
	}
}
