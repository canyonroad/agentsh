//go:build linux && cgo

package unix

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestAddFD_Constants(t *testing.T) {
	// Verify flag constants match the kernel header values from <linux/seccomp.h>.
	require.Equal(t, uint32(0x1), uint32(SECCOMP_ADDFD_FLAG_SETFD), "SECCOMP_ADDFD_FLAG_SETFD should be 0x1")
	require.Equal(t, uint32(0x2), uint32(SECCOMP_ADDFD_FLAG_SEND), "SECCOMP_ADDFD_FLAG_SEND should be 0x2")
}

func TestAddFD_IoctlNumber(t *testing.T) {
	// The ioctl number for SECCOMP_IOCTL_NOTIF_ADDFD is:
	//   _IOW(SECCOMP_IOC_MAGIC='!', 3, struct seccomp_notif_addfd)
	//   = 0x40182103
	require.Equal(t, uintptr(0x40182103), uintptr(ioctlNotifAddFD), "ioctl number should be 0x40182103")
}

func TestAddFD_StructLayout(t *testing.T) {
	// Verify struct size matches the kernel's seccomp_notif_addfd (24 bytes).
	// Layout: id(u64) + flags(u32) + srcfd(u32) + newfd(u32) + newfd_flags(u32) = 8+4+4+4+4 = 24
	var s seccompNotifAddFD
	require.Equal(t, uintptr(24), unsafe.Sizeof(s), "seccompNotifAddFD should be 24 bytes")

	// Verify field offsets match the kernel struct layout.
	require.Equal(t, uintptr(0), unsafe.Offsetof(s.id), "id should be at offset 0")
	require.Equal(t, uintptr(8), unsafe.Offsetof(s.flags), "flags should be at offset 8")
	require.Equal(t, uintptr(12), unsafe.Offsetof(s.srcfd), "srcfd should be at offset 12")
	require.Equal(t, uintptr(16), unsafe.Offsetof(s.newfd), "newfd should be at offset 16")
	require.Equal(t, uintptr(20), unsafe.Offsetof(s.newfdFlags), "newfdFlags should be at offset 20")
}

func TestAddFD_InvalidFD(t *testing.T) {
	// Calling NotifAddFD with an invalid notify fd should return an error.
	_, err := NotifAddFD(-1, 0, 0, -1, 0)
	require.Error(t, err, "NotifAddFD with invalid fd should fail")
}

func TestAddFD_FlagCombinations(t *testing.T) {
	// Verify that flag constants can be combined as expected.
	combined := uint32(SECCOMP_ADDFD_FLAG_SETFD | SECCOMP_ADDFD_FLAG_SEND)
	require.Equal(t, uint32(0x3), combined, "combined flags should be 0x3")

	// Verify flags are distinct bits.
	require.Equal(t, uint32(0), uint32(SECCOMP_ADDFD_FLAG_SETFD&SECCOMP_ADDFD_FLAG_SEND), "flags should use distinct bits")
}

func TestNotifIDValid_Constants(t *testing.T) {
	require.Equal(t, uintptr(0xC0082102), uintptr(ioctlNotifIDValidNew),
		"new ioctl should be 0xC0082102 (kernel 5.17+)")
	require.Equal(t, uintptr(0x40082102), uintptr(ioctlNotifIDValidOld),
		"old ioctl should be 0x40082102 (pre-5.17)")
}

func TestNotifIDValid_InvalidFD(t *testing.T) {
	err := NotifIDValid(-1, 0)
	require.Error(t, err, "NotifIDValid with invalid fd should fail")
}

func TestNotifSend_StructLayout(t *testing.T) {
	var s seccompNotifResp
	require.Equal(t, uintptr(24), unsafe.Sizeof(s), "seccompNotifResp should be 24 bytes")
	require.Equal(t, uintptr(0), unsafe.Offsetof(s.id), "id at offset 0")
	require.Equal(t, uintptr(8), unsafe.Offsetof(s.val), "val at offset 8")
	require.Equal(t, uintptr(16), unsafe.Offsetof(s.err), "err at offset 16")
	require.Equal(t, uintptr(20), unsafe.Offsetof(s.flags), "flags at offset 20")
}

func TestNotifSend_IoctlNumber(t *testing.T) {
	// _IOWR('!', 1, struct seccomp_notif_resp) = 0xC0182101
	require.Equal(t, uintptr(0xC0182101), uintptr(ioctlNotifSend))
}

func TestNotifSend_ContinueFlag(t *testing.T) {
	require.Equal(t, uint32(0x1), uint32(seccompUserNotifFlagContinue))
}

func TestNotifRespondDeny_InvalidFD(t *testing.T) {
	err := NotifRespondDeny(-1, 0, 13)
	require.Error(t, err, "NotifRespondDeny with invalid fd should fail")
}

func TestNotifRespondDeny_InvalidErrno(t *testing.T) {
	err := NotifRespondDeny(3, 0, 0)
	require.ErrorContains(t, err, "errno must be positive")
	err = NotifRespondDeny(3, 0, -13)
	require.ErrorContains(t, err, "errno must be positive")
}

func TestNotifRespondContinue_InvalidFD(t *testing.T) {
	err := NotifRespondContinue(-1, 0)
	require.Error(t, err, "NotifRespondContinue with invalid fd should fail")
}
