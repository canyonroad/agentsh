# libseccomp 2.5 System-Link Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the libseccomp 2.6 source-build + static-link with a raw-syscall load path that works against system libseccomp ≥2.5 — closes #296, removes ~600KB of static linkage, keeps Layer 1 (`WAIT_KILLABLE_RECV`) on kernel ≥5.19.

**Architecture:** Build the BPF program with libseccomp-golang (works on 2.5+), export it through a `pipe2`-based reader into bytes, then issue `seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER | WAIT_KILLABLE_RECV, &prog)` directly via `golang.org/x/sys/unix.Syscall`. The kernel flag is independent of libseccomp's userspace version. Retry-on-EINVAL semantics mirror today's `loadWithRetryOnWaitKillFailure`.

**Tech Stack:** Go, cgo, libseccomp-golang v0.11.0, `golang.org/x/sys/unix` (already has `SECCOMP_SET_MODE_FILTER`, `SECCOMP_FILTER_FLAG_NEW_LISTENER=0x8`, `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV=0x20`, `SockFprog`, `SockFilter`, `SYS_SECCOMP`, `PR_SET_NO_NEW_PRIVS`).

**Reference spec:** `docs/superpowers/specs/2026-05-11-libseccomp25-system-link-design.md`.

**File map:**
- Create: `internal/netmonitor/unix/seccomp_load_linux.go` (~140 lines) — `exportFilterBPF`, `loadRawFilter`, `loadFilterWithRetry`, syscall seams.
- Create: `internal/netmonitor/unix/seccomp_load_linux_test.go` (~200 lines) — unit tests for exporter, loader, retry, kernel-stub paths.
- Create: `internal/netmonitor/unix/sigurg_probe_test.go` (~80 lines) — re-exec helper exercising the full Install path.
- Create: `scripts/docker-test/sigurg_probe.go` (~60 lines) — standalone probe binary used in docker matrix smoke.
- Modify: `internal/netmonitor/unix/seccomp_linux.go` — replace `SetWaitKill`/`filt.Load`/`GetNotifFd` block (lines 297–534) with new export+load+log sequence.
- Modify: `internal/netmonitor/unix/seccomp_retry_test.go` — adapt to new `loadFilterWithRetry` signature.
- Modify: `internal/api/seccomp_wrapper_shim_install_test.go` — audit for references to deleted files.
- Modify: `.github/workflows/release.yml` — drop source-build step, switch to dynamic link, expand docker-test matrix.
- Modify: `.goreleaser.yml` — drop static CGO_LDFLAGS for amd64/arm64 Linux unixwrap entries.
- Modify: `docs/superpowers/specs/2026-04-14-libseccomp-2.6-defense-in-depth-design.md` — add superseded-by header.
- Delete: `internal/netmonitor/unix/seccomp_version_check.go`.
- Delete: `cmd/agentsh-unixwrap/seccomp_version_check.go`.
- Delete: `internal/netmonitor/unix/seccomp_waitkill_test.go` (functionality replaced by sigurg_probe_test.go + load_linux_test.go).
- Delete: `scripts/build-libseccomp.sh`.
- Delete: `scripts/libseccomp-signing-key.asc`.

---

## Task 1: Pipe-based BPF exporter

**Files:**
- Create: `internal/netmonitor/unix/seccomp_load_linux.go`
- Test: `internal/netmonitor/unix/seccomp_load_linux_test.go`

The exporter takes a `*seccomp.ScmpFilter`, returns the BPF program as `[]byte`. Uses `pipe2(O_CLOEXEC)` + `ExportBPF(writer)` + a goroutine reading the read end. Avoids `ExportBPFMem` which is itself a libseccomp 2.6 function (stubbed to `-EOPNOTSUPP` on 2.5).

- [ ] **Step 1: Create the empty file with build tags and imports**

`internal/netmonitor/unix/seccomp_load_linux.go`:

```go
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
// works against system libseccomp ≥2.0.
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
```

- [ ] **Step 2: Write the failing exporter test**

`internal/netmonitor/unix/seccomp_load_linux_test.go`:

```go
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
// returns a non-empty BPF program whose first instruction matches
// libseccomp's standard prologue: BPF_LD | BPF_W | BPF_ABS loading
// from offset 0 (the seccomp_data.nr field).
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
	// Standard libseccomp prologue is BPF_LD|BPF_W|BPF_ABS (0x20) at k=0 (nr).
	code := binary.LittleEndian.Uint16(prog[0:2])
	k := binary.LittleEndian.Uint32(prog[4:8])
	const bpfLdWAbs = 0x20
	if code != bpfLdWAbs {
		t.Fatalf("first BPF instruction code = 0x%x, want 0x%x", code, bpfLdWAbs)
	}
	if k != 0 {
		t.Fatalf("first BPF instruction k = %d, want 0 (seccomp_data.nr)", k)
	}
}
```

- [ ] **Step 3: Run the test**

```bash
cd /home/eran/work/agentsh && go test ./internal/netmonitor/unix/ -run TestExportBPFViaPipe -v
```

Expected: PASS. (The implementation in step 1 should already make it pass — TDD here is "write the test alongside" because the function is small enough that test-first writes itself in one step.)

- [ ] **Step 4: Commit**

```bash
git add internal/netmonitor/unix/seccomp_load_linux.go internal/netmonitor/unix/seccomp_load_linux_test.go
git commit -m "seccomp: pipe-based BPF exporter (libseccomp 2.5 compatible)

Avoids ExportBPFMem (libseccomp 2.6 only) by piping ExportBPF through
os.Pipe and reading the bytes back in a goroutine. Works against
system libseccomp >=2.0.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Raw seccomp(2) loader with syscall seam

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_load_linux.go`
- Modify: `internal/netmonitor/unix/seccomp_load_linux_test.go`

A test seam lets us unit-test flag computation, EINVAL handling, and empty-program rejection without permanently installing a filter into the test process. `loadFilterSyscall` and `prctlSetNoNewPrivs` are package vars that production initializes to the real syscalls; tests swap them.

- [ ] **Step 1: Add the loader, seams, and constants to seccomp_load_linux.go**

Append to `internal/netmonitor/unix/seccomp_load_linux.go`:

```go
// loadFilterSyscall and prctlSetNoNewPrivs are injectable seams. Tests
// replace them to assert flag computation and error handling without
// permanently installing a filter in the test process. Production uses
// realLoadFilterSyscall / realPrctlSetNoNewPrivs.
var (
	loadFilterSyscall = realLoadFilterSyscall
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
```

Note: `unix.Prctl` exists in `golang.org/x/sys/unix` — confirmed by `grep -n "func Prctl" /home/eran/go/pkg/mod/golang.org/x/sys@*/unix/syscall_linux.go` before authoring.

- [ ] **Step 2: Write failing tests for empty rejection, flag computation, kernel<5.19 path, and EINVAL retry-trigger**

Append to `internal/netmonitor/unix/seccomp_load_linux_test.go`:

```go
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
```

- [ ] **Step 3: Run the tests**

```bash
cd /home/eran/work/agentsh && go test ./internal/netmonitor/unix/ -run "TestLoadRawFilter|TestExportBPF" -v
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/netmonitor/unix/seccomp_load_linux.go internal/netmonitor/unix/seccomp_load_linux_test.go
git commit -m "seccomp: raw seccomp(2) loader with injectable syscall seam

loadRawFilter applies an exported BPF program via seccomp(2) directly,
setting SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV when requested. Test
seams (loadFilterSyscall, prctlSetNoNewPrivs) let unit tests exercise
flag computation and error paths without installing a real filter.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: EINVAL retry wrapper

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_load_linux.go`
- Modify: `internal/netmonitor/unix/seccomp_load_linux_test.go`

Mirrors today's `loadWithRetryOnWaitKillFailure` — on EINVAL with `withWaitKill=true`, retry once without the flag, emit the existing WARN log strings so dashboards and tests keyed off them keep working.

- [ ] **Step 1: Append the retry wrapper**

Append to `internal/netmonitor/unix/seccomp_load_linux.go`:

```go
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
```

(`appendSnapshot` and `errnoString` already exist in `seccomp_linux.go` — no need to redefine.)

- [ ] **Step 2: Write retry tests**

Append to `internal/netmonitor/unix/seccomp_load_linux_test.go`:

```go
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
```

- [ ] **Step 3: Run the new tests**

```bash
cd /home/eran/work/agentsh && go test ./internal/netmonitor/unix/ -run TestLoadFilterWithRetry -v
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/netmonitor/unix/seccomp_load_linux.go internal/netmonitor/unix/seccomp_load_linux_test.go
git commit -m "seccomp: EINVAL retry wrapper mirroring legacy semantics

loadFilterWithRetry replicates the WaitKill-rejection retry shape used
by loadWithRetryOnWaitKillFailure, including the WARN log strings that
log scrapers and regression tests key on.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Wire new load path into InstallFilterWithConfig

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go`

Replace the SetWaitKill+Load+GetNotifFd block. Emit the new structured startup log so docker tests can assert `wait_killable=true`.

- [ ] **Step 1: Read the current block to confirm exact line range**

```bash
cd /home/eran/work/agentsh && sed -n '295,335p;510,535p' internal/netmonitor/unix/seccomp_linux.go
```

Expected: surfaces the `waitKillSet := false` block at 297–315 and the `loadWithRetryOnWaitKillFailure` + `GetNotifFd` block at 520–534.

- [ ] **Step 2: Replace the SetWaitKill block (lines ~297–315)**

Replace this block in `internal/netmonitor/unix/seccomp_linux.go`:

```go
	// Enable SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (kernel 6.0+).
	// When active, non-fatal signals (including Go's ~10ms SIGURG preemption)
	// cannot interrupt seccomp_do_user_notification, preventing ERESTARTSYS loops.
	// The compile-time #error in seccomp_version_check.go guarantees the
	// libseccomp headers are >=2.6 and SetWaitKill is not a silent no-op.
	// If ProbeWaitKillable reports the kernel supports it but SetWaitKill
	// still fails, something is unexpected — warn loudly so operators can
	// investigate. Load() retry at the end of this function handles the
	// case where SetWaitKill succeeds but the kernel rejects the flag at
	// load time (custom/vendor kernels).
	waitKillSet := false
	if ProbeWaitKillable() {
		if err := filt.SetWaitKill(true); err != nil {
			slog.Warn("seccomp: WaitKillable unexpectedly unavailable despite kernel 6.0+; falling back to SIGURG signal mask only",
				"error", err)
		} else {
			waitKillSet = true
		}
	}
```

with:

```go
	// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (kernel >=5.19) is applied
	// at filter load time via the raw seccomp(2) syscall in
	// loadFilterWithRetry below — NOT through libseccomp's SetWaitKill,
	// whose silent-no-op behavior on pre-2.6 headers motivated this
	// design. The flag value is a kernel ABI constant in x/sys/unix.
	// See docs/superpowers/specs/2026-05-11-libseccomp25-system-link-design.md.
	wantWaitKill := ProbeWaitKillable()
```

- [ ] **Step 3: Replace the Load/GetNotifFd block (lines ~520–534)**

Replace this block:

```go
	snapshot := filterDiagnosticFields(filt, cfg, waitKillSet, ruleCounts)
	slog.Debug("seccomp: filter snapshot before Load", snapshot...)

	if err := loadWithRetryOnWaitKillFailure(filt, waitKillSet, snapshot, filt.Load); err != nil {
		return nil, err
	}
	fd, err := filt.GetNotifFd()
	if err != nil {
		// If no notify rules, fd will be -1, which is fine
		if !filterConfigNeedsNotifyFD(cfg, blockListMap, blockedFamilyMap, socketRules) {
			return &Filter{fd: -1, blockList: blockListMap, blockedFamilyMap: blockedFamilyMap, socketRules: socketRules}, nil
		}
		return nil, err
	}
	return &Filter{fd: fd, blockList: blockListMap, blockedFamilyMap: blockedFamilyMap, socketRules: socketRules}, nil
}
```

with:

```go
	snapshot := filterDiagnosticFields(filt, cfg, wantWaitKill, ruleCounts)
	slog.Debug("seccomp: filter snapshot before Load", snapshot...)

	// Export the filter to BPF bytes, then load it ourselves via
	// seccomp(2). This bypasses libseccomp's seccomp_load() so the
	// WAIT_KILLABLE_RECV flag can be set as a kernel ABI bit
	// regardless of the linked libseccomp version (see design doc).
	// We must export BEFORE Release; afterwards filt's C context is
	// gone but we still own the BPF bytes.
	prog, err := exportFilterBPF(filt)
	if err != nil {
		return nil, fmt.Errorf("export seccomp filter: %w", err)
	}
	filt.Release()

	rawFd, err := loadFilterWithRetry(prog, wantWaitKill, snapshot)
	if err != nil {
		return nil, err
	}
	// rawFd is the listener fd from SECCOMP_FILTER_FLAG_NEW_LISTENER.
	// loadFilterWithRetry returns >=0 on success; the legacy
	// "no notify rules, fd=-1" path is unreachable because we always
	// pass NEW_LISTENER (kernel returns the fd even for filters
	// without ActNotify rules — it's just never readable).
	libVer := libseccompRuntimeVersion()
	slog.Info("seccomp: filter loaded",
		"fd", rawFd,
		"wait_killable", wantWaitKill,
		"kernel_supports", wantWaitKill,
		"libseccomp_runtime", libVer)

	if !filterConfigNeedsNotifyFD(cfg, blockListMap, blockedFamilyMap, socketRules) {
		// Close the now-unused listener fd. The filter is still
		// installed; only the userspace dispatch handle is dropped.
		_ = unix.Close(rawFd)
		return &Filter{fd: -1, blockList: blockListMap, blockedFamilyMap: blockedFamilyMap, socketRules: socketRules}, nil
	}
	return &Filter{fd: seccomp.ScmpFd(rawFd), blockList: blockListMap, blockedFamilyMap: blockedFamilyMap, socketRules: socketRules}, nil
}

// libseccompRuntimeVersion returns the version of libseccomp that is
// actually linked at runtime (not the build-time headers). Used in the
// post-load startup log so docker matrix tests can confirm what
// userspace they are exercising.
func libseccompRuntimeVersion() string {
	major, minor, micro := seccomp.GetLibraryVersion()
	return fmt.Sprintf("%d.%d.%d", major, minor, micro)
}
```

- [ ] **Step 4: Cross-compile check**

```bash
cd /home/eran/work/agentsh && go build ./...
```

Expected: clean build. Any error means a missing import or signature mismatch — fix before proceeding.

- [ ] **Step 5: Run the package tests**

```bash
cd /home/eran/work/agentsh && go test ./internal/netmonitor/unix/ -run "TestLoadRawFilter|TestExportBPF|TestLoadFilterWithRetry" -v
```

Expected: all PASS. (The retry tests in the old `seccomp_retry_test.go` may now fail because they call the legacy `loadWithRetryOnWaitKillFailure` directly — that's fine, Task 5 deals with them.)

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go
git commit -m "seccomp: load filter via raw seccomp(2) instead of libseccomp Load

InstallFilterWithConfig now exports the filter to BPF bytes and applies
it directly via seccomp(2) with SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
when supported. The kernel flag is independent of libseccomp's
userspace version, so this works against system libseccomp >=2.5.

Emits a structured Info log on success so the docker matrix can assert
Layer 1 engagement.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Delete obsolete files and adapt remaining tests

**Files:**
- Delete: `internal/netmonitor/unix/seccomp_version_check.go`
- Delete: `cmd/agentsh-unixwrap/seccomp_version_check.go`
- Delete: `internal/netmonitor/unix/seccomp_waitkill_test.go`
- Modify: `internal/netmonitor/unix/seccomp_linux.go` (remove dead `loadWithRetryOnWaitKillFailure`)
- Modify: `internal/netmonitor/unix/seccomp_retry_test.go` (rewrite against `loadFilterWithRetry`)
- Modify: `internal/api/seccomp_wrapper_shim_install_test.go` (audit only)

The dead `loadWithRetryOnWaitKillFailure` and the version-check files are removed. The waitkill in-memory test goes away — its premise (libseccomp attribute readback proves the kernel flag is set) is no longer how we set the flag. Its functional-end-to-end sibling is reborn as `sigurg_probe_test.go` in Task 6 with the new log-line assertion.

- [ ] **Step 1: Delete the version-check files**

```bash
cd /home/eran/work/agentsh && \
  rm internal/netmonitor/unix/seccomp_version_check.go \
     cmd/agentsh-unixwrap/seccomp_version_check.go
```

- [ ] **Step 2: Delete seccomp_waitkill_test.go**

```bash
cd /home/eran/work/agentsh && rm internal/netmonitor/unix/seccomp_waitkill_test.go
```

- [ ] **Step 3: Remove dead `loadWithRetryOnWaitKillFailure` from seccomp_linux.go**

```bash
cd /home/eran/work/agentsh && grep -n "^func loadWithRetryOnWaitKillFailure\b\|^// loadWithRetryOnWaitKillFailure" internal/netmonitor/unix/seccomp_linux.go
```

Identify the comment-block start and the closing `}` of the function (around lines 675–743 in current main; verify with the grep). Delete the whole block including its leading comment.

`appendSnapshot` and `errnoString` STAY — they are still used by `loadFilterWithRetry` in the new file.

- [ ] **Step 4: Rewrite `seccomp_retry_test.go` against the new helper**

Replace the entire contents of `internal/netmonitor/unix/seccomp_retry_test.go` with:

```go
//go:build linux && cgo

package unix

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLoadFilterWithRetry_RetriesOnEINVAL is the regression check for
// the WAIT_KILLABLE-rejection fallback used by custom/vendor kernels
// that report kernel >=5.19 but return EINVAL when given the flag.
// (Equivalent unit-level coverage also lives in seccomp_load_linux_test.go;
// this file is the long-term home of retry-semantic regression checks.)
func TestLoadFilterWithRetry_RetriesOnEINVAL(t *testing.T) {
	var attempts []uintptr
	withStubbedSeams(t, func(flags uintptr, _ *unix.SockFprog) (int, error) {
		attempts = append(attempts, flags)
		if len(attempts) == 1 {
			return -1, unix.EINVAL
		}
		return 7, nil
	})
	fd, err := loadFilterWithRetry(minimalBPF(), true, nil)
	if err != nil {
		t.Fatalf("loadFilterWithRetry: %v", err)
	}
	if fd != 7 {
		t.Fatalf("fd = %d, want 7", fd)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(attempts))
	}
}

// TestLoadFilterWithRetry_PropagatesOriginalErrno is the regression
// check for issue #282 — non-EINVAL errnos must surface verbatim so
// hostile-kernel rejections (EFAULT on Runloop/Freestyle) land in the
// wrapper's stderr with their real cause, not a misleading
// "WaitKillable rejected" warning.
func TestLoadFilterWithRetry_PropagatesOriginalErrno(t *testing.T) {
	withStubbedSeams(t, func(uintptr, *unix.SockFprog) (int, error) {
		return -1, unix.EFAULT
	})
	_, err := loadFilterWithRetry(minimalBPF(), true, nil)
	if !errors.Is(err, unix.EFAULT) {
		t.Fatalf("expected EFAULT to propagate, got %v", err)
	}
}
```

- [ ] **Step 5: Audit `seccomp_wrapper_shim_install_test.go`**

```bash
cd /home/eran/work/agentsh && grep -n "seccomp_version_check\|SetWaitKill\|GetWaitKill" internal/api/seccomp_wrapper_shim_install_test.go
```

Expected: zero matches. If any reference exists, remove the line(s) — the file is testing shim installation, not seccomp version constants. If you find a reference, follow up by reading the surrounding test to confirm it's the obsolete check before deleting.

- [ ] **Step 6: Build and test**

```bash
cd /home/eran/work/agentsh && go build ./... && go test ./internal/netmonitor/unix/ -v
```

Expected: clean build; all tests in `internal/netmonitor/unix/` pass.

- [ ] **Step 7: Commit**

```bash
git add -A internal/netmonitor/unix/ cmd/agentsh-unixwrap/ internal/api/seccomp_wrapper_shim_install_test.go
git commit -m "seccomp: remove libseccomp 2.6 build guards and legacy load path

Deletes:
  - internal/netmonitor/unix/seccomp_version_check.go (#error guard)
  - cmd/agentsh-unixwrap/seccomp_version_check.go (duplicate)
  - internal/netmonitor/unix/seccomp_waitkill_test.go (relied on
    libseccomp attribute readback that the new load path no longer
    uses)
  - loadWithRetryOnWaitKillFailure from seccomp_linux.go

Adapts seccomp_retry_test.go to test loadFilterWithRetry directly.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Re-exec regression test asserting the new startup log line

**Files:**
- Create: `internal/netmonitor/unix/sigurg_probe_test.go`

Reborn version of the old `TestInstallFilterWithConfig_WaitKillLoadsCleanly`. Re-execs the test binary under a helper env, calls `InstallFilterWithConfig`, asserts the new `seccomp: filter loaded` Info line shows `wait_killable=true` on a kernel ≥6.0, and asserts neither fallback WARN fired. This is the canonical "Layer 1 engaged end-to-end" assertion for the Go test suite; the docker matrix is the same check against varying userspace libseccomp.

- [ ] **Step 1: Create the test**

`internal/netmonitor/unix/sigurg_probe_test.go`:

```go
//go:build linux && cgo

package unix

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestInstallFilter_EmitsWaitKillEngagedOnSupportedKernel re-execs
// the test binary to run InstallFilterWithConfig in a throwaway
// subprocess (because the filter is sticky), then parses the
// subprocess's combined output. It asserts:
//   1. The structured Info line "seccomp: filter loaded ...
//      wait_killable=true" was emitted — proof the kernel accepted
//      the flag through our raw seccomp(2) load path.
//   2. Neither WaitKill-fallback WARN line fired — proof we did NOT
//      silently drop into the EINVAL-retry-without-flag path on a
//      host that should support it.
//
// Together these close the regression surface for Layer 1 under the
// new raw-load architecture, replacing the white-box GetWaitKill
// readback used by the deleted seccomp_waitkill_test.go.
func TestInstallFilter_EmitsWaitKillEngagedOnSupportedKernel(t *testing.T) {
	if os.Getenv(sigurgProbeHelperEnv) == "1" {
		// Re-exec child path: install a minimal filter and exit.
		// Parent asserts on our combined stdout+stderr.
		cfg := FilterConfig{ExecveEnabled: true}
		if _, err := InstallFilterWithConfig(cfg); err != nil {
			t.Fatalf("InstallFilterWithConfig: %v", err)
		}
		return
	}

	if !ProbeWaitKillable() {
		t.Skip("kernel <6.0: WAIT_KILLABLE_RECV not supported on this host")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestInstallFilter_EmitsWaitKillEngagedOnSupportedKernel$")
	cmd.Env = append(os.Environ(), sigurgProbeHelperEnv+"=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

	if runErr != nil {
		lower := strings.ToLower(combined)
		if strings.Contains(lower, "permission denied") ||
			strings.Contains(lower, "operation not permitted") ||
			strings.Contains(lower, "seccomp not supported") ||
			strings.Contains(lower, "lacks user notify") {
			t.Skipf("host cannot install seccomp filter in this environment; skipping.\nhelper output:\n%s", combined)
		}
		t.Fatalf("sigurg probe subprocess failed: %v\ncombined output:\n%s", runErr, combined)
	}

	if !strings.Contains(combined, `wait_killable=true`) {
		t.Fatalf("startup log did not announce wait_killable=true — Layer 1 silently disabled.\ncombined output:\n%s", combined)
	}
	if strings.Contains(combined, "WaitKillable rejected at filter load time") {
		t.Fatalf("Layer 1 fell back at filter load time on a kernel >=5.19 — SIGURG fix degraded.\ncombined output:\n%s", combined)
	}
}

// sigurgProbeHelperEnv gates the re-exec body of the test. Setting it
// outside this test's parent->child dispatch is unsupported; the child
// will install a seccomp filter in whatever process reads the env var.
const sigurgProbeHelperEnv = "AGENTSH_TEST_SIGURG_PROBE_HELPER"
```

- [ ] **Step 2: Run the test**

```bash
cd /home/eran/work/agentsh && go test ./internal/netmonitor/unix/ -run TestInstallFilter_EmitsWaitKillEngagedOnSupportedKernel -v
```

Expected: PASS on Linux with kernel ≥6.0; SKIP on older kernels or environments without permission to install seccomp filters.

- [ ] **Step 3: Commit**

```bash
git add internal/netmonitor/unix/sigurg_probe_test.go
git commit -m "seccomp: re-exec regression test for new wait_killable log line

Asserts that InstallFilterWithConfig emits 'wait_killable=true' in
its structured startup log on kernel >=5.19, and that neither
WaitKillable-fallback WARN fired. Replaces the in-memory
GetWaitKill readback test deleted with the raw-load migration.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Docker matrix SIGURG sanity probe binary

**Files:**
- Create: `scripts/docker-test/sigurg_probe.go`
- Create: `scripts/docker-test/README.md` (one-paragraph doc explaining the probe's role and limits)

A standalone Go program that runs inside each docker matrix container. Wraps a target with `unixwrap`, hammers it with SIGURG for a few seconds, asserts no hang. Best-effort — the design doc is explicit that this is a sanity probe, not a strict regression catcher (the arm64 real-VM repro stays the manual gate).

- [ ] **Step 1: Create the probe**

`scripts/docker-test/sigurg_probe.go`:

```go
// sigurg_probe is a best-effort sanity check that the WAIT_KILLABLE_RECV
// flag is functionally engaged end-to-end. It is invoked inside every
// docker-test matrix cell to catch gross regressions where the kernel
// accepts the flag but it has been silently broken. See
// docs/superpowers/specs/2026-05-11-libseccomp25-system-link-design.md
// section "Functional smoke test in each cell".
//
// Limitations: the deterministic ERESTARTSYS repro from PR #225 requires
// arm64-VM-under-load conditions; on amd64 docker the race window is
// small enough that absence-of-hang is not a hard regression catcher.
// This program only catches the "kernel accepts flag but it does
// nothing" failure class.
//
// Build:    go build -o sigurg_probe scripts/docker-test/sigurg_probe.go
// Run:      ./sigurg_probe
// Success:  exit 0 within 5 seconds
// Failure:  exit non-zero, message on stderr
package main

import (
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	deadline := time.Now().Add(5 * time.Second)
	var iterations atomic.Int64

	// Goroutine 1: spam SIGURG at the current process. Go's runtime
	// uses SIGURG internally for async preemption (~10 ms cadence), so
	// even without our own signal traffic SIGURG lands inside any
	// blocking syscall. We add an explicit spam to widen the window.
	stop := make(chan struct{})
	go func() {
		pid := os.Getpid()
		for {
			select {
			case <-stop:
				return
			default:
				_ = syscall.Kill(pid, syscall.SIGURG)
				runtime.Gosched()
			}
		}
	}()

	// Goroutine 2 (this goroutine): busy-loop a syscall that, when run
	// under unixwrap's seccomp notify filter, traps to userspace and
	// hits the kernel's wait-for-notification path. Without
	// WAIT_KILLABLE_RECV a SIGURG mid-trap returns ERESTARTSYS and Go's
	// libc retries forever; with the flag the trap completes normally.
	//
	// Outside unixwrap (no filter), this is just a benign getpid loop
	// — the probe still asserts liveness but does not exercise the
	// notify path. The wrapping is provided by the docker invocation.
	for time.Now().Before(deadline) {
		_ = syscall.Getpid()
		iterations.Add(1)
	}
	close(stop)

	if iterations.Load() < 1000 {
		fmt.Fprintf(os.Stderr, "sigurg_probe: only %d iterations in 5s — likely hung\n", iterations.Load())
		os.Exit(2)
	}
	fmt.Fprintf(os.Stdout, "sigurg_probe: ok (%d iterations)\n", iterations.Load())
}
```

- [ ] **Step 2: Create the README**

`scripts/docker-test/README.md`:

```markdown
# Docker test probes

## sigurg_probe.go

Sanity check that the kernel's `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`
flag is functionally engaged when used with `unixwrap`. Invoked once per
docker matrix cell (see `.github/workflows/release.yml docker-test`).

This is a **best-effort sanity probe, not a strict regression catcher**.
The deterministic ERESTARTSYS reproducer from PR #225 requires arm64-VM-
under-load conditions; amd64 docker absence-of-hang is too small a
window to make false negatives impossible. The probe catches the gross
failure class where the kernel accepts the flag but the flag does
nothing. The arm64-VM reproducer remains the manual release gate (see
`docs/testing/arm64-sigurg-reproducer.md` when written).

Build and run:

    go build -o sigurg_probe scripts/docker-test/sigurg_probe.go
    unixwrap -- ./sigurg_probe
```

- [ ] **Step 3: Sanity-build and run the probe locally (no unixwrap wrap)**

```bash
cd /home/eran/work/agentsh && go build -o /tmp/sigurg_probe scripts/docker-test/sigurg_probe.go && /tmp/sigurg_probe
```

Expected: `sigurg_probe: ok (... iterations)` on stdout, exit 0.

- [ ] **Step 4: Commit**

```bash
git add scripts/docker-test/sigurg_probe.go scripts/docker-test/README.md
git commit -m "scripts: add sigurg_probe for docker matrix smoke tests

Best-effort sanity probe invoked in each docker-test cell to catch
gross WAIT_KILLABLE_RECV breakage. Not a substitute for the manual
arm64-VM reproducer; see design doc for limits.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Update release.yml — drop source build, dynamic link, expand matrix

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 1: Read the current relevant sections**

```bash
cd /home/eran/work/agentsh && grep -n "build-libseccomp\|libseccomp\|CGO_LDFLAGS\|docker-test\|PKG_CONFIG_LIBDIR\|PKG_CONFIG_PATH" .github/workflows/release.yml | head -60
```

This pins the exact line numbers for the next edits. Note them — the steps below describe what to edit, but use grep output to find the line in current main.

- [ ] **Step 2: Delete the source-build step for libseccomp 2.6**

Find the step named "Build static libseccomp 2.6 (amd64 + arm64)" (currently around lines 73–78). Delete the full step block including its `- name:`, `run:`, and any `env:` lines.

- [ ] **Step 3: Remove static-link CGO_LDFLAGS for amd64/arm64 unixwrap builds**

Find the unixwrap-linux-amd64 and unixwrap-linux-arm64 build steps. Each currently has:

```yaml
env:
  PKG_CONFIG_LIBDIR: /opt/libseccomp/amd64/lib/pkgconfig
  CGO_LDFLAGS: "-static -lseccomp"
```

(or arm64 equivalents). Remove both `PKG_CONFIG_LIBDIR` and `CGO_LDFLAGS` env keys. The dynamic link against system libseccomp 2.5.5 from apt will be used automatically.

Leave the Alpine build steps (`unixwrap-alpine-*`) untouched — they keep `-static -lseccomp` because Alpine ships static libseccomp 2.6 and the musl static binary is the entire point of that artifact.

- [ ] **Step 4: Update apt installation if needed**

```bash
cd /home/eran/work/agentsh && grep -n "apt-get install\|apt install" .github/workflows/release.yml | head -10
```

Confirm `libseccomp-dev` is already in the apt install line for the amd64/arm64 jobs. If not, add it. (It should be — the source build also requires the dev package for headers during the initial install on the runner.)

- [ ] **Step 5: Drop the `hashFiles('scripts/build-libseccomp.sh')` cache salt**

Find the line containing `hashFiles('scripts/build-libseccomp.sh')` in the cache key (~line 50). Remove the segment. Example before/after:

Before:
```yaml
key: release-v2-${{ runner.os }}-go-seccomp${{ hashFiles('scripts/build-libseccomp.sh') }}-${{ hashFiles('**/go.sum') }}
```

After:
```yaml
key: release-v3-${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
```

(Bumping the version namespace to `v3` invalidates the old static-link cache so the first post-merge run isn't poisoned by it.)

- [ ] **Step 6: Expand the docker-test matrix**

Find the `docker-test` job's matrix. Today it has Alpine plus ubuntu:22.04 and debian:bookworm (added in the 2026-04-14 PR). Replace the matrix entries with:

```yaml
strategy:
  fail-fast: false
  matrix:
    image:
      - ubuntu:22.04
      - ubuntu:24.04
      - debian:bookworm
      - debian:trixie
      - rockylinux:10
      - fedora:40
      - alpine:3.23
```

(Keep `fail-fast: false` so one container's regression doesn't mask others.)

- [ ] **Step 7: Add the sigurg probe smoke step to each docker-test cell**

Inside the docker-test job, after the existing notify smoke test step, add a step that builds and runs the probe inside the container:

```yaml
- name: SIGURG sanity probe
  run: |
    docker run --rm \
      --privileged \
      -v "${{ github.workspace }}:/work" \
      -w /work \
      ${{ matrix.image }} \
      bash -lc '
        set -euo pipefail
        # Install minimal toolchain. Distros vary; this is the
        # common-denominator path. apt-get / dnf / apk branch by
        # availability of the package manager.
        if command -v apt-get >/dev/null; then
          apt-get update && apt-get install -y --no-install-recommends ca-certificates libseccomp2
        elif command -v dnf >/dev/null; then
          dnf install -y libseccomp
        elif command -v apk >/dev/null; then
          apk add --no-cache libseccomp
        fi
        # Run the wrapped probe. Built binaries are in dist/ from
        # the prior matrix step.
        ./dist/unixwrap-linux-$(uname -m | sed s/x86_64/amd64/;s/aarch64/arm64/) \
          --execve-enabled \
          -- /work/dist/sigurg_probe
      '
```

The exact path to `unixwrap-*` and `sigurg_probe` depends on this workflow's existing dist layout — match the patterns used by the current matrix step that runs the basic smoke test. Use that step as the template; only the inner command (running `sigurg_probe`) differs.

Also add the `wait_killable=true` assertion. Append to the same shell snippet:

```bash
out=$(./dist/unixwrap-linux-amd64 --execve-enabled -- /work/dist/sigurg_probe 2>&1)
echo "$out"
echo "$out" | grep -q 'wait_killable=true' || { echo "FAIL: wait_killable not engaged"; exit 1; }
```

- [ ] **Step 8: Verify YAML parses**

```bash
cd /home/eran/work/agentsh && python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"
```

Expected: no output, exit 0. Any error means a syntax slip — fix before committing.

- [ ] **Step 9: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: drop libseccomp 2.6 source-build, expand docker-test matrix

amd64/arm64 unixwrap binaries now link dynamically against the
runner's libseccomp 2.5.5 (apt). Alpine static-link unchanged.

docker-test matrix expands to seven containers covering libseccomp
2.5.3 through 2.6.x runtimes (closes #296). Each cell runs the
sigurg_probe sanity check and asserts wait_killable=true in the
startup log.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Update .goreleaser.yml

**Files:**
- Modify: `.goreleaser.yml`

- [ ] **Step 1: Find the relevant entries**

```bash
cd /home/eran/work/agentsh && grep -n "CGO_LDFLAGS\|PKG_CONFIG_LIBDIR\|libseccomp\|unixwrap" .goreleaser.yml
```

- [ ] **Step 2: Drop static CGO_LDFLAGS for amd64/arm64 Linux unixwrap entries**

Find the `builds:` entries for `unixwrap-linux-amd64` and `unixwrap-linux-arm64`. Each currently has env entries like:

```yaml
env:
  - CGO_ENABLED=1
  - CGO_LDFLAGS=-static -lseccomp
  - PKG_CONFIG_LIBDIR=/opt/libseccomp/amd64/lib/pkgconfig
```

Remove the `CGO_LDFLAGS=-static -lseccomp` and `PKG_CONFIG_LIBDIR=...` lines. Keep `CGO_ENABLED=1`. Leave Alpine entries alone.

- [ ] **Step 3: Validate goreleaser config**

```bash
cd /home/eran/work/agentsh && command -v goreleaser >/dev/null && goreleaser check || echo "goreleaser not installed locally; YAML-syntax check only"
python3 -c "import yaml; yaml.safe_load(open('.goreleaser.yml'))"
```

Expected: `goreleaser check` clean if installed; YAML parses cleanly regardless.

- [ ] **Step 4: Commit**

```bash
git add .goreleaser.yml
git commit -m "goreleaser: dynamic-link unixwrap-linux-{amd64,arm64}

Mirrors the release.yml change. Static link is retained only for
the Alpine/musl artifacts where it is intentional.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Delete the source-build scripts and update the prior spec

**Files:**
- Delete: `scripts/build-libseccomp.sh`
- Delete: `scripts/libseccomp-signing-key.asc`
- Modify: `docs/superpowers/specs/2026-04-14-libseccomp-2.6-defense-in-depth-design.md`

- [ ] **Step 1: Delete the script and key**

```bash
cd /home/eran/work/agentsh && rm scripts/build-libseccomp.sh scripts/libseccomp-signing-key.asc
```

- [ ] **Step 2: Add a superseded-by header to the 2026-04-14 spec**

Insert the following lines immediately after the existing `# libseccomp 2.6 Defense-in-Depth Design` heading in `docs/superpowers/specs/2026-04-14-libseccomp-2.6-defense-in-depth-design.md`:

```markdown
> **Superseded by [2026-05-11 libseccomp 2.5 system-link design](./2026-05-11-libseccomp25-system-link-design.md).** The source-built static-link approach below is no longer the chosen architecture — issue #296 (RHEL 10 + EPEL only ship libseccomp 2.5.x) made the build-time 2.6 dependency a hard blocker for distro packagers. The replacement bypasses libseccomp-golang's silent-no-op SetWaitKill and sets `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` via the raw seccomp(2) syscall, decoupling Layer 1 from the linked libseccomp's userspace version. This document is retained for historical context.
```

- [ ] **Step 3: Verify the superseded link works**

```bash
cd /home/eran/work/agentsh && ls docs/superpowers/specs/2026-05-11-libseccomp25-system-link-design.md
```

Expected: file exists.

- [ ] **Step 4: Commit**

```bash
git add -A scripts/ docs/superpowers/specs/2026-04-14-libseccomp-2.6-defense-in-depth-design.md
git commit -m "cleanup: remove libseccomp 2.6 source-build artifacts

The 2026-04-14 source-build + static-link approach is superseded by
the raw seccomp(2) load path. scripts/build-libseccomp.sh and the
bundled signing key are no longer used by any workflow.

Closes #296.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full build**

```bash
cd /home/eran/work/agentsh && go build ./...
```

Expected: clean.

- [ ] **Step 2: Full test suite for the affected package**

```bash
cd /home/eran/work/agentsh && go test ./internal/netmonitor/unix/ ./internal/api/ -v
```

Expected: all PASS or SKIP. Any FAIL means a regression — investigate before continuing.

- [ ] **Step 3: Cross-compile sanity (Windows build is the CLAUDE.md gate)**

```bash
cd /home/eran/work/agentsh && GOOS=windows go build ./...
```

Expected: clean. (No seccomp code is compiled on Windows; the build tags handle this.)

- [ ] **Step 4: Confirm `#error` guards are gone**

```bash
cd /home/eran/work/agentsh && grep -rn "SCMP_VER_MAJOR\|SCMP_VER_MINOR\|seccomp_version_check" --include="*.go" .
```

Expected: zero matches.

- [ ] **Step 5: Confirm libseccomp source-build artifacts are gone**

```bash
cd /home/eran/work/agentsh && grep -rn "build-libseccomp.sh\|/opt/libseccomp\|libseccomp-signing-key" .
```

Expected: zero matches.

- [ ] **Step 6: Confirm `loadWithRetryOnWaitKillFailure` is gone (replaced by `loadFilterWithRetry`)**

```bash
cd /home/eran/work/agentsh && grep -rn "loadWithRetryOnWaitKillFailure" --include="*.go" .
```

Expected: zero matches.

- [ ] **Step 7: Confirm new startup log line is wired in**

```bash
cd /home/eran/work/agentsh && grep -n "wait_killable" internal/netmonitor/unix/seccomp_linux.go
```

Expected: one match in the new Info log call.

- [ ] **Step 8: Final commit (if any uncommitted housekeeping)**

```bash
cd /home/eran/work/agentsh && git status
```

If clean, nothing to commit. Otherwise stage and commit any straggler files.

---

## Self-review notes (already applied)

- **Spec coverage:** every section of the spec maps to a task — Architecture → Tasks 1–4; Error handling → Task 3 + retry tests in 2/3; Tests → Tasks 2, 3, 6, 7; CI → Tasks 7, 8, 9; Cleanups → Tasks 5, 10. The "functional smoke test in each cell" SIGURG sanity-probe item is Task 7.
- **Placeholder scan:** no TBDs; the only "match the patterns used by the current matrix step" instruction in Task 8 step 7 references existing workflow code the engineer can read — not a hidden placeholder, because the surrounding step already exists and provides the template.
- **Type consistency:** `loadFilterWithRetry(prog []byte, withWaitKill bool, snapshot []any) (int, error)` is consistent across Tasks 3–5. `loadRawFilter(prog []byte, withWaitKill bool) (int, error)` likewise. `wantWaitKill` (named in Task 4) is the local that feeds both `filterDiagnosticFields` and `loadFilterWithRetry`. Seam names (`loadFilterSyscall`, `prctlSetNoNewPrivs`) consistent across Tasks 2 and 5.
- **Risk:** Task 4 step 3 hand-writes a fairly large diff. The grep in step 1 is the protection — if the surrounding code shifts, the replacement will fail noisily.
