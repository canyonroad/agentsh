//go:build linux

package ptrace

import (
	"testing"

	"github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

func TestFamilyChecker_Check_MatchAndMiss(t *testing.T) {
	c := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: 38, Action: seccomp.OnBlockErrno, Name: "AF_ALG"},
	})

	// AF_ALG on socket(2) → match.
	bf, ok := c.Check(uint64(unix.SYS_SOCKET), 38)
	if !ok || bf.Name != "AF_ALG" {
		t.Errorf("expected match for AF_ALG on SYS_SOCKET; got bf=%+v ok=%v", bf, ok)
	}

	// AF_INET on socket(2) → miss.
	if _, ok := c.Check(uint64(unix.SYS_SOCKET), 2); ok {
		t.Errorf("expected miss for AF_INET")
	}

	// AF_ALG on read(2) → miss (only socket/socketpair are checked).
	if _, ok := c.Check(uint64(unix.SYS_READ), 38); ok {
		t.Errorf("expected miss for AF_ALG on SYS_READ")
	}
}

func TestFamilyChecker_Check_Socketpair(t *testing.T) {
	c := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: 38, Action: seccomp.OnBlockErrno, Name: "AF_ALG"},
	})
	_, ok := c.Check(uint64(unix.SYS_SOCKETPAIR), 38)
	if !ok {
		t.Errorf("expected match for AF_ALG on SYS_SOCKETPAIR")
	}
}

func TestFamilyChecker_Empty(t *testing.T) {
	c := NewFamilyChecker(nil)
	if _, ok := c.Check(uint64(unix.SYS_SOCKET), 38); ok {
		t.Errorf("empty checker should never match")
	}
}

func TestFamilyChecker_MultipleEntries(t *testing.T) {
	c := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: 38, Action: seccomp.OnBlockErrno, Name: "AF_ALG"},
		{Family: 40, Action: seccomp.OnBlockKill, Name: "AF_VSOCK"},
		{Family: 21, Action: seccomp.OnBlockLog, Name: "AF_RDS"},
	})

	cases := []struct {
		syscall uint64
		family  uint64
		want    bool
		name    string
		action  seccomp.OnBlockAction
	}{
		{uint64(unix.SYS_SOCKET), 38, true, "AF_ALG", seccomp.OnBlockErrno},
		{uint64(unix.SYS_SOCKET), 40, true, "AF_VSOCK", seccomp.OnBlockKill},
		{uint64(unix.SYS_SOCKETPAIR), 21, true, "AF_RDS", seccomp.OnBlockLog},
		{uint64(unix.SYS_SOCKET), 2, false, "", ""},
		{uint64(unix.SYS_SOCKET), 10, false, "", ""},
	}

	for _, tc := range cases {
		bf, ok := c.Check(tc.syscall, tc.family)
		if ok != tc.want {
			t.Errorf("Check(%d, %d): ok=%v want=%v", tc.syscall, tc.family, ok, tc.want)
			continue
		}
		if ok {
			if bf.Name != tc.name {
				t.Errorf("Check(%d, %d): name=%q want=%q", tc.syscall, tc.family, bf.Name, tc.name)
			}
			if bf.Action != tc.action {
				t.Errorf("Check(%d, %d): action=%v want=%v", tc.syscall, tc.family, bf.Action, tc.action)
			}
		}
	}
}

func TestFamilyChecker_NilReceiver(t *testing.T) {
	var c *FamilyChecker
	if _, ok := c.Check(uint64(unix.SYS_SOCKET), 38); ok {
		t.Errorf("nil receiver should never match")
	}
}
