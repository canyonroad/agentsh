//go:build linux && cgo

package unix

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"
	"unsafe"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// exportFilterBPF serializes a libseccomp filter into its kernel-ready
// BPF program bytes by piping ExportBPF through a pipe2 reader, then
// reading the read end into a buffer. This deliberately avoids
// ExportBPFMem (a libseccomp 2.6 function stubbed to -EOPNOTSUPP when
// libseccomp-golang is compiled against 2.5 headers) so the same code
// works against system libseccomp >=2.0.
func exportFilterBPF(filt *seccomp.ScmpFilter) ([]byte, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("seccomp export: pipe: %w", err)
	}

	type result struct {
		buf []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		var buf bytes.Buffer
		_, copyErr := io.Copy(&buf, r)
		_ = r.Close()
		done <- result{buf: buf.Bytes(), err: copyErr}
	}()

	exportErr := filt.ExportBPF(w)
	_ = w.Close()
	res := <-done

	if exportErr != nil {
		return nil, fmt.Errorf("seccomp export: %w", exportErr)
	}
	if res.err != nil {
		return nil, fmt.Errorf("seccomp export: read pipe: %w", res.err)
	}
	return res.buf, nil
}

// loadFilterSyscall and prctlSetNoNewPrivs are injectable seams. Tests
// replace them to assert flag computation and error handling without
// permanently installing a filter in the test process. Production uses
// realLoadFilterSyscall / realPrctlSetNoNewPrivs.
var (
	loadFilterSyscall  = realLoadFilterSyscall
	prctlSetNoNewPrivs = realPrctlSetNoNewPrivs
)

func realLoadFilterSyscall(flags uintptr, fprog *unix.SockFprog) (int, error) {
	r1, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		flags,
		uintptr(unsafe.Pointer(fprog)),
	)
	if errno != 0 {
		return -1, errno
	}
	return int(r1), nil
}

func realPrctlSetNoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

// loadRawFilter applies an exported BPF program to the current process
// using the seccomp(2) syscall directly, bypassing libseccomp's
// seccomp_load(). The flag SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
// (0x20, kernel >=5.19) is set when withWaitKill is true; the kernel
// returns EINVAL if it doesn't recognize the flag, which the retry
// wrapper handles.
//
// The returned fd is the user-notification listener fd from
// SECCOMP_FILTER_FLAG_NEW_LISTENER. Callers own its lifetime.
//
// prog must be the raw bytes from exportFilterBPF — a contiguous array
// of struct sock_filter (8 bytes each). An empty program is rejected
// explicitly to defend against future libseccomp regressions.
func loadRawFilter(prog []byte, withWaitKill bool) (int, error) {
	if len(prog) == 0 {
		return -1, errors.New("seccomp export produced empty filter")
	}
	if len(prog)%8 != 0 {
		return -1, fmt.Errorf("seccomp export produced unaligned filter: %d bytes (want multiple of 8)", len(prog))
	}

	if err := prctlSetNoNewPrivs(); err != nil {
		return -1, fmt.Errorf("prctl PR_SET_NO_NEW_PRIVS: %w", err)
	}

	// View the byte slice as []unix.SockFilter without copying. Each
	// sock_filter is 8 bytes (code u16, jt u8, jf u8, k u32). The
	// kernel reads the program during the syscall; we keep prog
	// alive via the returned KeepAlive at the end.
	n := len(prog) / 8
	filters := unsafe.Slice((*unix.SockFilter)(unsafe.Pointer(&prog[0])), n)
	fprog := unix.SockFprog{
		Len:    uint16(n),
		Filter: &filters[0],
	}

	flags := uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER)
	if withWaitKill {
		flags |= unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
	}

	fd, err := loadFilterSyscall(flags, &fprog)
	// Defensive: ensure prog and filters are not GC'd before the
	// syscall returns. The kernel snapshots the program internally,
	// but we still hold the only reference while it does.
	runtimeKeepAlive(prog)
	runtimeKeepAlive(filters)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

// runtimeKeepAlive is a tiny no-op wrapper so the unsafe.Slice +
// SockFprog construction stays GC-safe without importing runtime at
// the top of the file. Inlined to be free in release builds.
//
//go:noinline
func runtimeKeepAlive(_ interface{}) {}

// loadFilterWithRetry loads prog via loadRawFilter, retrying once
// without WAIT_KILLABLE_RECV if the kernel returns EINVAL — the
// rejection path for custom or vendor kernels that report >=5.19 but
// don't recognize the flag. Any other errno surfaces verbatim.
//
// snapshot is the structured-field slice produced by
// filterDiagnosticFields; it is embedded inline in failure-path WARN
// entries so a single visible log line carries enough context to
// triage hostile-kernel rejections (issue #282 EFAULT class).
//
// Log strings match the existing loadWithRetryOnWaitKillFailure
// helper byte-for-byte so log scrapers and the sigurg_probe_test
// regression check continue to function.
func loadFilterWithRetry(prog []byte, withWaitKill bool, snapshot []any) (int, error) {
	start := time.Now()
	fd, err := loadRawFilter(prog, withWaitKill)
	dur := time.Since(start)
	if err == nil {
		slog.Debug("seccomp: filter Load succeeded",
			"attempt", 1, "wait_kill", withWaitKill, "duration_ms", dur.Milliseconds())
		return fd, nil
	}
	slog.Warn("seccomp: filter Load failed",
		appendSnapshot(snapshot,
			"attempt", 1, "wait_kill", withWaitKill, "duration_ms", dur.Milliseconds(),
			"errno", errnoString(err), "error", err)...)
	if !withWaitKill {
		return -1, err
	}
	if !errors.Is(err, unix.EINVAL) {
		return -1, err
	}
	slog.Warn("seccomp: WaitKillable rejected at filter load time; falling back to SIGURG signal mask only",
		"error", err)

	start = time.Now()
	fd, err = loadRawFilter(prog, false)
	dur = time.Since(start)
	if err == nil {
		slog.Debug("seccomp: filter Load succeeded on retry without WaitKill",
			"attempt", 2, "duration_ms", dur.Milliseconds())
		return fd, nil
	}
	slog.Warn("seccomp: filter Load failed on retry without WaitKill",
		appendSnapshot(snapshot,
			"attempt", 2, "duration_ms", dur.Milliseconds(),
			"errno", errnoString(err), "error", err)...)
	return -1, err
}
