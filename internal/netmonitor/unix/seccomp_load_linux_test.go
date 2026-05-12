//go:build linux && cgo

package unix

import (
	"encoding/binary"
	"errors"
	"testing"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// TestExportBPFViaPipe builds a minimal filter and asserts the exporter
// returns a non-empty BPF program whose first instruction is a valid
// libseccomp prologue: BPF_LD | BPF_W | BPF_ABS loading a seccomp_data
// field (arch at offset 4 on >=2.2, nr at offset 0 on older versions).
func TestExportBPFViaPipe(t *testing.T) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filt.Release()

	if err := filt.AddRule(seccomp.ScmpSyscall(unix.SYS_GETPID), seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	prog, err := exportFilterBPF(filt)
	if err != nil {
		t.Fatalf("exportFilterBPF: %v", err)
	}
	if len(prog) == 0 {
		t.Fatalf("exportFilterBPF returned empty program")
	}
	if len(prog)%8 != 0 {
		t.Fatalf("BPF program length %d is not a multiple of 8 (sock_filter size)", len(prog))
	}
	// First sock_filter: code uint16, jt uint8, jf uint8, k uint32.
	// libseccomp prologue is BPF_LD|BPF_W|BPF_ABS (0x20) loading a seccomp_data
	// field: k=0 (nr) on older libseccomp or k=4 (arch) on >=2.2 which emits
	// an arch-check as the very first instruction.
	code := binary.LittleEndian.Uint16(prog[0:2])
	k := binary.LittleEndian.Uint32(prog[4:8])
	const bpfLdWAbs = 0x20
	if code != bpfLdWAbs {
		t.Fatalf("first BPF instruction code = 0x%x, want 0x%x (BPF_LD|BPF_W|BPF_ABS)", code, bpfLdWAbs)
	}
	// k must be a valid seccomp_data field offset: 0 (nr), 4 (arch), 8 (ip), or 16+ (args).
	if k != 0 && k != 4 {
		t.Fatalf("first BPF instruction k = %d, want 0 (seccomp_data.nr) or 4 (seccomp_data.arch)", k)
	}
}

// withStubbedSeams replaces the load and prctl seams for the duration
// of f, restoring them on return. The prctl stub always succeeds so
// tests do not flip NO_NEW_PRIVS on the test process itself.
func withStubbedSeams(t *testing.T, load func(flags uintptr, fprog *unix.SockFprog) (int, error)) {
	t.Helper()
	origLoad := loadFilterSyscall
	origPrctl := prctlSetNoNewPrivs
	loadFilterSyscall = load
	prctlSetNoNewPrivs = func() error { return nil }
	t.Cleanup(func() {
		loadFilterSyscall = origLoad
		prctlSetNoNewPrivs = origPrctl
	})
}

// minimalBPF returns 8 bytes representing a single sock_filter
// (BPF_RET | BPF_K, k=SECCOMP_RET_ALLOW=0x7fff0000). This is a
// well-formed but trivial program — enough to satisfy length checks
// without resembling a real libseccomp output.
func minimalBPF() []byte {
	const bpfRetK = 0x06
	const seccompRetAllow = 0x7fff0000
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b[0:2], bpfRetK)
	// jt, jf both 0
	binary.LittleEndian.PutUint32(b[4:8], seccompRetAllow)
	return b
}

func TestLoadRawFilter_RejectsEmptyProgram(t *testing.T) {
	withStubbedSeams(t, func(uintptr, *unix.SockFprog) (int, error) {
		t.Fatalf("loader must not be called on empty program")
		return 0, nil
	})
	_, err := loadRawFilter(nil, true)
	if err == nil {
		t.Fatalf("expected error on empty program, got nil")
	}
	if !errors.Is(err, err) || err.Error() == "" {
		t.Fatalf("expected descriptive error, got %v", err)
	}
}

func TestLoadRawFilter_RejectsUnalignedProgram(t *testing.T) {
	withStubbedSeams(t, func(uintptr, *unix.SockFprog) (int, error) {
		t.Fatalf("loader must not be called on unaligned program")
		return 0, nil
	})
	_, err := loadRawFilter(make([]byte, 7), true)
	if err == nil {
		t.Fatalf("expected error on unaligned program, got nil")
	}
}

func TestLoadRawFilter_SetsWaitKillFlagWhenRequested(t *testing.T) {
	var gotFlags uintptr
	withStubbedSeams(t, func(flags uintptr, _ *unix.SockFprog) (int, error) {
		gotFlags = flags
		return 42, nil
	})
	fd, err := loadRawFilter(minimalBPF(), true)
	if err != nil {
		t.Fatalf("loadRawFilter: %v", err)
	}
	if fd != 42 {
		t.Fatalf("fd = %d, want 42", fd)
	}
	wantFlags := uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV)
	if gotFlags != wantFlags {
		t.Fatalf("flags = 0x%x, want 0x%x", gotFlags, wantFlags)
	}
}

func TestLoadRawFilter_OmitsWaitKillFlagWhenNotRequested(t *testing.T) {
	var gotFlags uintptr
	withStubbedSeams(t, func(flags uintptr, _ *unix.SockFprog) (int, error) {
		gotFlags = flags
		return 17, nil
	})
	_, err := loadRawFilter(minimalBPF(), false)
	if err != nil {
		t.Fatalf("loadRawFilter: %v", err)
	}
	wantFlags := uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER)
	if gotFlags != wantFlags {
		t.Fatalf("flags = 0x%x, want 0x%x (no WAIT_KILLABLE)", gotFlags, wantFlags)
	}
}

func TestLoadRawFilter_PropagatesEINVAL(t *testing.T) {
	withStubbedSeams(t, func(uintptr, *unix.SockFprog) (int, error) {
		return -1, unix.EINVAL
	})
	_, err := loadRawFilter(minimalBPF(), true)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("expected unix.EINVAL, got %v", err)
	}
}

func TestLoadFilterWithRetry_RetriesOnEINVALAndDropsFlag(t *testing.T) {
	var seenFlags []uintptr
	withStubbedSeams(t, func(flags uintptr, _ *unix.SockFprog) (int, error) {
		seenFlags = append(seenFlags, flags)
		if len(seenFlags) == 1 {
			return -1, unix.EINVAL
		}
		return 99, nil
	})
	fd, err := loadFilterWithRetry(minimalBPF(), true, nil)
	if err != nil {
		t.Fatalf("loadFilterWithRetry: %v", err)
	}
	if fd != 99 {
		t.Fatalf("fd = %d, want 99", fd)
	}
	if len(seenFlags) != 2 {
		t.Fatalf("expected 2 syscall attempts, got %d", len(seenFlags))
	}
	if seenFlags[0]&uintptr(unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV) == 0 {
		t.Fatalf("first attempt missing WAIT_KILLABLE flag: 0x%x", seenFlags[0])
	}
	if seenFlags[1]&uintptr(unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV) != 0 {
		t.Fatalf("retry attempt still has WAIT_KILLABLE flag: 0x%x", seenFlags[1])
	}
}

func TestLoadFilterWithRetry_NoRetryWhenFlagNotSet(t *testing.T) {
	calls := 0
	withStubbedSeams(t, func(uintptr, *unix.SockFprog) (int, error) {
		calls++
		return -1, unix.EINVAL
	})
	_, err := loadFilterWithRetry(minimalBPF(), false, nil)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("expected EINVAL, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 attempt, got %d", calls)
	}
}

func TestLoadFilterWithRetry_NoRetryOnNonEINVAL(t *testing.T) {
	calls := 0
	withStubbedSeams(t, func(uintptr, *unix.SockFprog) (int, error) {
		calls++
		return -1, unix.EFAULT
	})
	_, err := loadFilterWithRetry(minimalBPF(), true, nil)
	if !errors.Is(err, unix.EFAULT) {
		t.Fatalf("expected EFAULT, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 attempt, got %d", calls)
	}
}

func TestLoadFilterWithRetry_BothAttemptsFail(t *testing.T) {
	calls := 0
	withStubbedSeams(t, func(uintptr, *unix.SockFprog) (int, error) {
		calls++
		return -1, unix.EINVAL
	})
	_, err := loadFilterWithRetry(minimalBPF(), true, nil)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("expected EINVAL after retry failure, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 attempts (initial + retry), got %d", calls)
	}
}
