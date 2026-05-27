//go:build linux

package ptrace

import "testing"

func TestAtSyscallExitStop_FallbackToToggle(t *testing.T) {
	tr := &Tracer{hasSyscallInfo: false}
	if !tr.atSyscallExitStop(0, true) {
		t.Fatal("fallback inSyscall=true must report exit")
	}
	if tr.atSyscallExitStop(0, false) {
		t.Fatal("fallback inSyscall=false must report not-exit")
	}
}
