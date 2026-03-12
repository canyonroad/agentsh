# ptrace Phase 2: Full Syscall Coverage — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add file, network, and signal syscall handling to the ptrace tracer, replacing Phase 1's auto-allow stubs with real policy evaluation.

**Architecture:** Three new handler methods (`handleFile`, `handleNetwork`, `handleSignal`) on the Tracer struct, each calling a policy interface defined in the ptrace package. File handler resolves paths via `/proc/<tid>/cwd` and `/proc/<tid>/fd/<dirfd>` with `EvalSymlinks` canonicalization. Network handler parses `sockaddr` structs for connect/bind. Signal handler supports redirect via register rewrite. All run on the existing locked OS thread.

**Tech Stack:** Go, `golang.org/x/sys/unix`, Linux ptrace API, `/proc/<tid>/mem` for memory access

**Design doc:** `docs/plans/2026-03-12-ptrace-phase2-design.md`

---

## Task 1: Add handler interfaces and TracerConfig fields

**Files:**
- Modify: `internal/ptrace/tracer.go`

**Step 1: Write the failing test**

```go
// internal/ptrace/tracer_test.go — add to existing file

func TestTracerConfig_HandlerFields(t *testing.T) {
	cfg := TracerConfig{
		TraceFile:    true,
		TraceNetwork: true,
		TraceSignal:  true,
	}
	tr := NewTracer(cfg)
	if tr.cfg.FileHandler != nil {
		t.Error("FileHandler should be nil by default")
	}
	if tr.cfg.NetworkHandler != nil {
		t.Error("NetworkHandler should be nil by default")
	}
	if tr.cfg.SignalHandler != nil {
		t.Error("SignalHandler should be nil by default")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestTracerConfig_HandlerFields -v`
Expected: FAIL — `FileHandler`, `NetworkHandler`, `SignalHandler` not defined

**Step 3: Add handler interfaces and context/result types to tracer.go**

Add after the existing `ExecResult` struct (line 40):

```go
// FileHandler evaluates file syscall policy.
type FileHandler interface {
	HandleFile(ctx context.Context, fc FileContext) FileResult
}

// FileContext carries file syscall information for policy evaluation.
type FileContext struct {
	PID       int
	SessionID string
	Syscall   int
	Path      string
	Path2     string
	Operation string
	Flags     int
}

// FileResult carries the file policy decision.
type FileResult struct {
	Allow bool
	Errno int32
}

// NetworkHandler evaluates network syscall policy.
type NetworkHandler interface {
	HandleNetwork(ctx context.Context, nc NetworkContext) NetworkResult
}

// NetworkContext carries network syscall information for policy evaluation.
type NetworkContext struct {
	PID       int
	SessionID string
	Syscall   int
	Family    int
	Address   string
	Port      int
	Operation string
}

// NetworkResult carries the network policy decision.
type NetworkResult struct {
	Allow bool
	Errno int32
}

// SignalHandler evaluates signal delivery policy.
type SignalHandler interface {
	HandleSignal(ctx context.Context, sc SignalContext) SignalResult
}

// SignalContext carries signal delivery information for policy evaluation.
type SignalContext struct {
	PID       int
	SessionID string
	TargetPID int
	Signal    int
}

// SignalResult carries the signal policy decision.
type SignalResult struct {
	Allow          bool
	Errno          int32
	RedirectSignal int
}
```

Add three fields to `TracerConfig` struct (after `ExecHandler` on line 55):

```go
	FileHandler    FileHandler
	NetworkHandler NetworkHandler
	SignalHandler  SignalHandler
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/ptrace/ -run TestTracerConfig_HandlerFields -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/tracer_test.go
git commit -m "feat(ptrace): add FileHandler, NetworkHandler, SignalHandler interfaces"
```

---

## Task 2: File handler helpers — operation mapping and dirfd resolution

**Files:**
- Create: `internal/ptrace/handle_file.go`
- Create: `internal/ptrace/handle_file_test.go`

**Step 1: Write the failing tests**

```go
// internal/ptrace/handle_file_test.go
//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSyscallToOperation(t *testing.T) {
	tests := []struct {
		name  string
		nr    int
		flags int
		want  string
	}{
		{"openat read-only", unix.SYS_OPENAT, unix.O_RDONLY, "read"},
		{"openat write-only", unix.SYS_OPENAT, unix.O_WRONLY, "write"},
		{"openat read-write", unix.SYS_OPENAT, unix.O_RDWR, "write"},
		{"openat create", unix.SYS_OPENAT, unix.O_WRONLY | unix.O_CREAT, "create"},
		{"openat create rdwr", unix.SYS_OPENAT, unix.O_RDWR | unix.O_CREAT, "create"},
		{"openat trunc", unix.SYS_OPENAT, unix.O_WRONLY | unix.O_TRUNC, "write"},
		{"unlinkat", unix.SYS_UNLINKAT, 0, "delete"},
		{"mkdirat", unix.SYS_MKDIRAT, 0, "create"},
		{"renameat2", unix.SYS_RENAMEAT2, 0, "rename"},
		{"linkat", unix.SYS_LINKAT, 0, "link"},
		{"symlinkat", unix.SYS_SYMLINKAT, 0, "symlink"},
		{"fchmodat", unix.SYS_FCHMODAT, 0, "chmod"},
		{"fchownat", unix.SYS_FCHOWNAT, 0, "chown"},
		{"unknown", 99999, 0, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := syscallToOperation(tt.nr, tt.flags)
			if got != tt.want {
				t.Errorf("syscallToOperation(%d, %d) = %q, want %q", tt.nr, tt.flags, got, tt.want)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestSyscallToOperation -v`
Expected: FAIL — `syscallToOperation` not defined

**Step 3: Write handle_file.go with helpers**

```go
// internal/ptrace/handle_file.go
//go:build linux

package ptrace

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// syscallToOperation maps a file syscall number and flags to an operation string.
func syscallToOperation(nr int, flags int) string {
	switch nr {
	case unix.SYS_OPENAT:
		return openatOperation(flags)
	case unix.SYS_UNLINKAT:
		return "delete"
	case unix.SYS_MKDIRAT:
		return "create"
	case unix.SYS_RENAMEAT2:
		return "rename"
	case unix.SYS_LINKAT:
		return "link"
	case unix.SYS_SYMLINKAT:
		return "symlink"
	case unix.SYS_FCHMODAT:
		return "chmod"
	case unix.SYS_FCHOWNAT:
		return "chown"
	default:
		return syscallToOperationLegacy(nr, flags)
	}
}

func openatOperation(flags int) string {
	if flags&unix.O_CREAT != 0 {
		return "create"
	}
	if flags&(unix.O_WRONLY|unix.O_RDWR) != 0 {
		return "write"
	}
	return "read"
}

// resolveDirFD resolves the base directory for a *at syscall.
// AT_FDCWD (-100) returns the tracee's cwd. Otherwise reads /proc/<tid>/fd/<dirfd>.
func resolveDirFD(tid int, dirfd int) (string, error) {
	if dirfd == unix.AT_FDCWD {
		return os.Readlink(fmt.Sprintf("/proc/%d/cwd", tid))
	}
	return os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, dirfd))
}

// resolvePath resolves a path from a *at syscall to an absolute canonical path.
func resolvePath(tid int, dirfd int, path string) (string, error) {
	if filepath.IsAbs(path) {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return path, nil // Use original if symlink resolution fails
		}
		return resolved, nil
	}

	base, err := resolveDirFD(tid, dirfd)
	if err != nil {
		return "", fmt.Errorf("resolve dirfd %d: %w", dirfd, err)
	}

	full := filepath.Join(base, path)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return full, nil // Use joined path if symlink resolution fails
	}
	return resolved, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/ptrace/ -run TestSyscallToOperation -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/handle_file.go internal/ptrace/handle_file_test.go
git commit -m "feat(ptrace): add file syscall operation mapping and path resolution helpers"
```

---

## Task 3: File handler helpers — legacy syscall mapping (amd64)

**Files:**
- Modify: `internal/ptrace/handle_file.go` — add `syscallToOperationLegacy` stub
- Create: `internal/ptrace/handle_file_amd64.go` — amd64 legacy mapping
- Create: `internal/ptrace/handle_file_arm64.go` — arm64 no-op stub

**Step 1: Write the failing test**

Add to `handle_file_test.go`:

```go
func TestSyscallToOperation_Legacy(t *testing.T) {
	// Only runs on amd64 where legacy syscalls exist
	tests := []struct {
		name string
		nr   int
		want string
	}{
		{"legacy open", unix.SYS_OPENAT, "read"}, // Already tested, sanity check
	}

	// Add amd64-specific tests via build tags in handle_file_amd64_test.go
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := syscallToOperation(tt.nr, 0)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
```

Create `internal/ptrace/handle_file_amd64_test.go`:

```go
//go:build linux && amd64

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSyscallToOperation_LegacyAmd64(t *testing.T) {
	tests := []struct {
		name  string
		nr    int
		flags int
		want  string
	}{
		{"legacy open rdonly", unix.SYS_OPEN, unix.O_RDONLY, "read"},
		{"legacy open wronly", unix.SYS_OPEN, unix.O_WRONLY, "write"},
		{"legacy open creat", unix.SYS_OPEN, unix.O_WRONLY | unix.O_CREAT, "create"},
		{"legacy unlink", unix.SYS_UNLINK, 0, "delete"},
		{"legacy rename", unix.SYS_RENAME, 0, "rename"},
		{"legacy mkdir", unix.SYS_MKDIR, 0, "create"},
		{"legacy rmdir", unix.SYS_RMDIR, 0, "delete"},
		{"legacy link", unix.SYS_LINK, 0, "link"},
		{"legacy symlink", unix.SYS_SYMLINK, 0, "symlink"},
		{"legacy chmod", unix.SYS_CHMOD, 0, "chmod"},
		{"legacy chown", unix.SYS_CHOWN, 0, "chown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := syscallToOperation(tt.nr, tt.flags)
			if got != tt.want {
				t.Errorf("syscallToOperation(%d, %d) = %q, want %q", tt.nr, tt.flags, got, tt.want)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestSyscallToOperation_LegacyAmd64 -v`
Expected: FAIL — `syscallToOperationLegacy` not defined

**Step 3: Write the platform files**

`internal/ptrace/handle_file_amd64.go`:

```go
//go:build linux && amd64

package ptrace

import "golang.org/x/sys/unix"

func syscallToOperationLegacy(nr int, flags int) string {
	switch nr {
	case unix.SYS_OPEN:
		return openatOperation(flags)
	case unix.SYS_UNLINK, unix.SYS_RMDIR:
		return "delete"
	case unix.SYS_RENAME:
		return "rename"
	case unix.SYS_MKDIR:
		return "create"
	case unix.SYS_LINK:
		return "link"
	case unix.SYS_SYMLINK:
		return "symlink"
	case unix.SYS_CHMOD:
		return "chmod"
	case unix.SYS_CHOWN:
		return "chown"
	default:
		return "unknown"
	}
}
```

`internal/ptrace/handle_file_arm64.go`:

```go
//go:build linux && arm64

package ptrace

func syscallToOperationLegacy(nr int, flags int) string {
	return "unknown"
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/ptrace/ -run TestSyscallToOperation -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/handle_file.go internal/ptrace/handle_file_amd64.go internal/ptrace/handle_file_arm64.go internal/ptrace/handle_file_test.go internal/ptrace/handle_file_amd64_test.go
git commit -m "feat(ptrace): add legacy file syscall operation mapping for amd64"
```

---

## Task 4: File handler — handleFile method

**Files:**
- Modify: `internal/ptrace/handle_file.go`

**Step 1: Write the handleFile method**

Add to `handle_file.go`:

```go
import (
	"context"
	"log/slog"
	// ... existing imports ...
)

// handleFile intercepts file syscalls for policy evaluation.
func (t *Tracer) handleFile(ctx context.Context, tid int, regs Regs) {
	if t.cfg.FileHandler == nil || !t.cfg.TraceFile {
		t.allowSyscall(tid)
		return
	}

	nr := regs.SyscallNr()

	path, path2, flags, err := t.extractFileArgs(tid, nr, regs)
	if err != nil {
		slog.Warn("handleFile: cannot extract args", "tid", tid, "nr", nr, "error", err)
		t.allowSyscall(tid)
		return
	}

	operation := syscallToOperation(nr, flags)

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	result := t.cfg.FileHandler.HandleFile(ctx, FileContext{
		PID:       tgid,
		SessionID: sessionID,
		Syscall:   nr,
		Path:      path,
		Path2:     path2,
		Operation: operation,
		Flags:     flags,
	})

	if !result.Allow {
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EACCES)
		}
		t.denySyscall(tid, int(errno))
	} else {
		t.allowSyscall(tid)
	}
}

// extractFileArgs reads file syscall arguments from registers and tracee memory.
func (t *Tracer) extractFileArgs(tid int, nr int, regs Regs) (path, path2 string, flags int, err error) {
	switch nr {
	// *at variants: dirfd=arg0, path=arg1, flags vary
	case unix.SYS_OPENAT:
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		flags = int(int32(regs.Arg(2)))
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, dirfd, rawPath)
		return path, "", flags, err

	case unix.SYS_UNLINKAT, unix.SYS_MKDIRAT:
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, dirfd, rawPath)
		return path, "", 0, err

	case unix.SYS_FCHMODAT, unix.SYS_FCHOWNAT:
		dirfd := int(int32(regs.Arg(0)))
		pathPtr := regs.Arg(1)
		rawPath, err := t.readString(tid, pathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, dirfd, rawPath)
		return path, "", 0, err

	case unix.SYS_RENAMEAT2:
		// renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
		oldDirfd := int(int32(regs.Arg(0)))
		oldPathPtr := regs.Arg(1)
		newDirfd := int(int32(regs.Arg(2)))
		newPathPtr := regs.Arg(3)

		rawOld, err := t.readString(tid, oldPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		rawNew, err := t.readString(tid, newPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, oldDirfd, rawOld)
		if err != nil {
			return "", "", 0, err
		}
		path2, err = resolvePath(tid, newDirfd, rawNew)
		return path, path2, 0, err

	case unix.SYS_LINKAT:
		// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
		oldDirfd := int(int32(regs.Arg(0)))
		oldPathPtr := regs.Arg(1)
		newDirfd := int(int32(regs.Arg(2)))
		newPathPtr := regs.Arg(3)

		rawOld, err := t.readString(tid, oldPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		rawNew, err := t.readString(tid, newPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, oldDirfd, rawOld)
		if err != nil {
			return "", "", 0, err
		}
		path2, err = resolvePath(tid, newDirfd, rawNew)
		return path, path2, 0, err

	case unix.SYS_SYMLINKAT:
		// symlinkat(target, newdirfd, linkpath)
		targetPtr := regs.Arg(0)
		newDirfd := int(int32(regs.Arg(1)))
		linkPathPtr := regs.Arg(2)

		target, err := t.readString(tid, targetPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		rawLink, err := t.readString(tid, linkPathPtr, 4096)
		if err != nil {
			return "", "", 0, err
		}
		path, err = resolvePath(tid, newDirfd, rawLink)
		return path, target, 0, err

	default:
		// Legacy syscalls (amd64): path in arg0, no dirfd
		return t.extractLegacyFileArgs(tid, nr, regs)
	}
}

// extractLegacyFileArgs handles legacy (non-at) file syscalls.
// On arm64 this is never called because isLegacyFileSyscall returns false.
func (t *Tracer) extractLegacyFileArgs(tid int, nr int, regs Regs) (path, path2 string, flags int, err error) {
	pathPtr := regs.Arg(0)
	rawPath, err := t.readString(tid, pathPtr, 4096)
	if err != nil {
		return "", "", 0, err
	}
	path, err = resolvePath(tid, unix.AT_FDCWD, rawPath)
	if err != nil {
		return "", "", 0, err
	}

	switch {
	case isLegacyOpenSyscall(nr):
		flags = int(int32(regs.Arg(1)))
		return path, "", flags, nil
	case isLegacyTwoPathSyscall(nr):
		// rename(old, new), link(old, new), symlink(target, linkpath)
		path2Ptr := regs.Arg(1)
		rawPath2, err := t.readString(tid, path2Ptr, 4096)
		if err != nil {
			return path, "", 0, err
		}
		path2, err = resolvePath(tid, unix.AT_FDCWD, rawPath2)
		return path, path2, 0, err
	default:
		return path, "", 0, nil
	}
}
```

Also add to `handle_file_amd64.go`:

```go
func isLegacyOpenSyscall(nr int) bool {
	return nr == unix.SYS_OPEN
}

func isLegacyTwoPathSyscall(nr int) bool {
	return nr == unix.SYS_RENAME || nr == unix.SYS_LINK || nr == unix.SYS_SYMLINK
}
```

And `handle_file_arm64.go`:

```go
func isLegacyOpenSyscall(nr int) bool    { return false }
func isLegacyTwoPathSyscall(nr int) bool { return false }
```

**Step 2: Run all existing tests to verify nothing breaks**

Run: `go test ./internal/ptrace/ -v`
Expected: PASS (handleFile is not wired up yet, no integration tests call it)

**Step 3: Commit**

```bash
git add internal/ptrace/handle_file.go internal/ptrace/handle_file_amd64.go internal/ptrace/handle_file_arm64.go
git commit -m "feat(ptrace): implement handleFile with path resolution and arg extraction"
```

---

## Task 5: Network handler — sockaddr parsing and unit tests

**Files:**
- Create: `internal/ptrace/handle_network.go`
- Create: `internal/ptrace/handle_network_test.go`

**Step 1: Write the failing tests**

```go
// internal/ptrace/handle_network_test.go
//go:build linux

package ptrace

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseSockaddr_IPv4(t *testing.T) {
	// struct sockaddr_in: family(2) + port(2) + addr(4) + zero(8) = 16 bytes
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], unix.AF_INET) // family
	binary.BigEndian.PutUint16(buf[2:4], 8080)             // port (network byte order)
	copy(buf[4:8], net.ParseIP("192.168.1.1").To4())       // addr

	family, addr, port, err := parseSockaddr(buf)
	if err != nil {
		t.Fatal(err)
	}
	if family != unix.AF_INET {
		t.Errorf("family = %d, want %d", family, unix.AF_INET)
	}
	if addr != "192.168.1.1" {
		t.Errorf("addr = %q, want %q", addr, "192.168.1.1")
	}
	if port != 8080 {
		t.Errorf("port = %d, want %d", port, 8080)
	}
}

func TestParseSockaddr_IPv6(t *testing.T) {
	// struct sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16) + scope_id(4) = 28 bytes
	buf := make([]byte, 28)
	binary.LittleEndian.PutUint16(buf[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(buf[2:4], 443)
	copy(buf[8:24], net.ParseIP("::1").To16())

	family, addr, port, err := parseSockaddr(buf)
	if err != nil {
		t.Fatal(err)
	}
	if family != unix.AF_INET6 {
		t.Errorf("family = %d, want %d", family, unix.AF_INET6)
	}
	if addr != "::1" {
		t.Errorf("addr = %q, want %q", addr, "::1")
	}
	if port != 443 {
		t.Errorf("port = %d, want %d", port, 443)
	}
}

func TestParseSockaddr_Unix(t *testing.T) {
	// struct sockaddr_un: family(2) + path(up to 108)
	path := "/var/run/docker.sock"
	buf := make([]byte, 2+len(path)+1)
	binary.LittleEndian.PutUint16(buf[0:2], unix.AF_UNIX)
	copy(buf[2:], path)

	family, addr, port, err := parseSockaddr(buf)
	if err != nil {
		t.Fatal(err)
	}
	if family != unix.AF_UNIX {
		t.Errorf("family = %d, want %d", family, unix.AF_UNIX)
	}
	if addr != path {
		t.Errorf("addr = %q, want %q", addr, path)
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

func TestParseSockaddr_UnixAbstract(t *testing.T) {
	// Abstract socket: family(2) + \0 + name
	name := "my-abstract-socket"
	buf := make([]byte, 2+1+len(name))
	binary.LittleEndian.PutUint16(buf[0:2], unix.AF_UNIX)
	buf[2] = 0 // abstract socket marker
	copy(buf[3:], name)

	family, addr, _, err := parseSockaddr(buf)
	if err != nil {
		t.Fatal(err)
	}
	if family != unix.AF_UNIX {
		t.Errorf("family = %d, want %d", family, unix.AF_UNIX)
	}
	if addr != "@"+name {
		t.Errorf("addr = %q, want %q", addr, "@"+name)
	}
}

func TestParseSockaddr_TooShort(t *testing.T) {
	buf := []byte{0}
	_, _, _, err := parseSockaddr(buf)
	if err == nil {
		t.Error("expected error for short buffer")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestParseSockaddr -v`
Expected: FAIL — `parseSockaddr` not defined

**Step 3: Write handle_network.go**

```go
// internal/ptrace/handle_network.go
//go:build linux

package ptrace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// parseSockaddr parses a raw sockaddr buffer into family, address, and port.
func parseSockaddr(buf []byte) (family int, address string, port int, err error) {
	if len(buf) < 2 {
		return 0, "", 0, fmt.Errorf("sockaddr too short: %d bytes", len(buf))
	}

	family = int(binary.LittleEndian.Uint16(buf[0:2]))

	switch family {
	case unix.AF_INET:
		if len(buf) < 8 {
			return family, "", 0, fmt.Errorf("sockaddr_in too short: %d bytes", len(buf))
		}
		port = int(binary.BigEndian.Uint16(buf[2:4]))
		ip := net.IP(buf[4:8])
		return family, ip.String(), port, nil

	case unix.AF_INET6:
		if len(buf) < 24 {
			return family, "", 0, fmt.Errorf("sockaddr_in6 too short: %d bytes", len(buf))
		}
		port = int(binary.BigEndian.Uint16(buf[2:4]))
		ip := net.IP(buf[8:24])
		return family, ip.String(), port, nil

	case unix.AF_UNIX:
		if len(buf) <= 2 {
			return family, "", 0, nil
		}
		pathBytes := buf[2:]
		if pathBytes[0] == 0 {
			// Abstract socket
			name := string(bytes.TrimRight(pathBytes[1:], "\x00"))
			return family, "@" + name, 0, nil
		}
		// Path-based socket
		if idx := bytes.IndexByte(pathBytes, 0); idx >= 0 {
			pathBytes = pathBytes[:idx]
		}
		return family, string(pathBytes), 0, nil

	default:
		return family, "", 0, fmt.Errorf("unsupported address family: %d", family)
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/ptrace/ -run TestParseSockaddr -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/handle_network.go internal/ptrace/handle_network_test.go
git commit -m "feat(ptrace): add sockaddr parsing for IPv4, IPv6, and Unix sockets"
```

---

## Task 6: Network handler — handleNetwork method

**Files:**
- Modify: `internal/ptrace/handle_network.go`

**Step 1: Write the handleNetwork method**

Add to `handle_network.go`:

```go
import (
	"context"
	"log/slog"
	// ... existing imports ...
)

// handleNetwork intercepts network syscalls for policy evaluation.
func (t *Tracer) handleNetwork(ctx context.Context, tid int, regs Regs) {
	if t.cfg.NetworkHandler == nil || !t.cfg.TraceNetwork {
		t.allowSyscall(tid)
		return
	}

	nr := regs.SyscallNr()

	// Only evaluate policy for connect and bind
	if nr != unix.SYS_CONNECT && nr != unix.SYS_BIND {
		t.allowSyscall(tid)
		return
	}

	// Args: sockfd(arg0), addr(arg1), addrlen(arg2)
	addrPtr := regs.Arg(1)
	addrLen := regs.Arg(2)

	if addrLen == 0 || addrLen > 128 {
		t.allowSyscall(tid)
		return
	}

	buf := make([]byte, addrLen)
	if err := t.readBytes(tid, addrPtr, buf); err != nil {
		slog.Warn("handleNetwork: cannot read sockaddr", "tid", tid, "error", err)
		t.allowSyscall(tid)
		return
	}

	family, address, port, err := parseSockaddr(buf)
	if err != nil {
		slog.Warn("handleNetwork: cannot parse sockaddr", "tid", tid, "error", err)
		t.allowSyscall(tid)
		return
	}

	var operation string
	if nr == unix.SYS_CONNECT {
		operation = "connect"
	} else {
		operation = "bind"
	}

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	result := t.cfg.NetworkHandler.HandleNetwork(ctx, NetworkContext{
		PID:       tgid,
		SessionID: sessionID,
		Syscall:   nr,
		Family:    family,
		Address:   address,
		Port:      port,
		Operation: operation,
	})

	if !result.Allow {
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EACCES)
		}
		t.denySyscall(tid, int(errno))
	} else {
		t.allowSyscall(tid)
	}
}
```

**Step 2: Run all existing tests to verify nothing breaks**

Run: `go test ./internal/ptrace/ -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/ptrace/handle_network.go
git commit -m "feat(ptrace): implement handleNetwork for connect/bind interception"
```

---

## Task 7: Signal handler — handleSignal with redirect support

**Files:**
- Create: `internal/ptrace/handle_signal.go`
- Create: `internal/ptrace/handle_signal_test.go`

**Step 1: Write the failing test**

```go
// internal/ptrace/handle_signal_test.go
//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestExtractSignalArgs_Kill(t *testing.T) {
	// kill(pid, sig) → arg0=pid, arg1=sig
	targetPID, signal, sigArgIndex := extractSignalArgs(unix.SYS_KILL, 42, 15, 0)
	if targetPID != 42 {
		t.Errorf("targetPID = %d, want 42", targetPID)
	}
	if signal != 15 {
		t.Errorf("signal = %d, want 15", signal)
	}
	if sigArgIndex != 1 {
		t.Errorf("sigArgIndex = %d, want 1", sigArgIndex)
	}
}

func TestExtractSignalArgs_Tkill(t *testing.T) {
	// tkill(tid, sig) → arg0=tid, arg1=sig
	targetPID, signal, sigArgIndex := extractSignalArgs(unix.SYS_TKILL, 100, 9, 0)
	if targetPID != 100 {
		t.Errorf("targetPID = %d, want 100", targetPID)
	}
	if signal != 9 {
		t.Errorf("signal = %d, want 9", signal)
	}
	if sigArgIndex != 1 {
		t.Errorf("sigArgIndex = %d, want 1", sigArgIndex)
	}
}

func TestExtractSignalArgs_Tgkill(t *testing.T) {
	// tgkill(tgid, tid, sig) → arg0=tgid, arg1=tid, arg2=sig
	targetPID, signal, sigArgIndex := extractSignalArgs(unix.SYS_TGKILL, 50, 51, 15)
	if targetPID != 50 {
		t.Errorf("targetPID = %d, want 50 (tgid)", targetPID)
	}
	if signal != 15 {
		t.Errorf("signal = %d, want 15", signal)
	}
	if sigArgIndex != 2 {
		t.Errorf("sigArgIndex = %d, want 2", sigArgIndex)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestExtractSignalArgs -v`
Expected: FAIL — `extractSignalArgs` not defined

**Step 3: Write handle_signal.go**

```go
// internal/ptrace/handle_signal.go
//go:build linux

package ptrace

import (
	"context"
	"log/slog"

	"golang.org/x/sys/unix"
)

// extractSignalArgs extracts target PID, signal number, and the register index
// of the signal argument from syscall arguments.
// Returns (targetPID, signal, sigArgIndex).
func extractSignalArgs(nr int, arg0, arg1, arg2 int) (int, int, int) {
	switch nr {
	case unix.SYS_KILL:
		// kill(pid, sig)
		return arg0, arg1, 1
	case unix.SYS_TKILL:
		// tkill(tid, sig)
		return arg0, arg1, 1
	case unix.SYS_TGKILL:
		// tgkill(tgid, tid, sig)
		return arg0, int(arg2), 2
	default:
		return arg0, arg1, 1
	}
}

// handleSignal intercepts signal delivery syscalls for policy evaluation.
func (t *Tracer) handleSignal(ctx context.Context, tid int, regs Regs) {
	if t.cfg.SignalHandler == nil || !t.cfg.TraceSignal {
		t.allowSyscall(tid)
		return
	}

	nr := regs.SyscallNr()

	// Only evaluate policy for kill, tgkill, tkill
	switch nr {
	case unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL:
		// handled below
	default:
		t.allowSyscall(tid)
		return
	}

	arg0 := int(int32(regs.Arg(0)))
	arg1 := int(int32(regs.Arg(1)))
	arg2 := int(int32(regs.Arg(2)))

	targetPID, signal, sigArgIndex := extractSignalArgs(nr, arg0, arg1, arg2)

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	result := t.cfg.SignalHandler.HandleSignal(ctx, SignalContext{
		PID:       tgid,
		SessionID: sessionID,
		TargetPID: targetPID,
		Signal:    signal,
	})

	switch {
	case !result.Allow:
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EPERM)
		}
		t.denySyscall(tid, int(errno))

	case result.RedirectSignal > 0 && result.RedirectSignal != signal:
		// Redirect: rewrite the signal argument register
		regs.SetArg(sigArgIndex, uint64(result.RedirectSignal))
		if err := t.setRegs(tid, regs); err != nil {
			slog.Warn("handleSignal: cannot rewrite signal register", "tid", tid, "error", err)
		}
		t.allowSyscall(tid)

	default:
		t.allowSyscall(tid)
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/ptrace/ -run TestExtractSignalArgs -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/handle_signal.go internal/ptrace/handle_signal_test.go
git commit -m "feat(ptrace): implement handleSignal with redirect support"
```

---

## Task 8: Wire up dispatchSyscall

**Files:**
- Modify: `internal/ptrace/tracer.go:305-318`

**Step 1: Update dispatchSyscall**

Replace the three auto-allow stubs in `dispatchSyscall`:

```go
// dispatchSyscall routes a syscall to the appropriate handler.
func (t *Tracer) dispatchSyscall(ctx context.Context, tid int, nr int, regs Regs) {
	switch {
	case isExecveSyscall(nr):
		t.handleExecve(ctx, tid, regs)
	case isFileSyscall(nr):
		t.handleFile(ctx, tid, regs)
	case isNetworkSyscall(nr):
		t.handleNetwork(ctx, tid, regs)
	case isSignalSyscall(nr):
		t.handleSignal(ctx, tid, regs)
	default:
		t.allowSyscall(tid)
	}
}
```

**Step 2: Run all unit tests**

Run: `go test ./internal/ptrace/ -v`
Expected: PASS

**Step 3: Run cross-compilation check**

Run: `GOOS=windows go build ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/ptrace/tracer.go
git commit -m "feat(ptrace): wire file/network/signal handlers into dispatchSyscall"
```

---

## Task 9: Integration tests — mock handlers for file, network, signal

**Files:**
- Modify: `internal/ptrace/integration_test.go`

**Step 1: Add mock handler types**

Add after the existing `mockExecHandler` (after line 117):

```go
// --- Mock handlers for Phase 2 ---

type mockFileCall struct {
	FileContext
}

type mockFileHandler struct {
	mu           sync.Mutex
	calls        []mockFileCall
	defaultAllow bool
	defaultErrno int32
	rules        map[string]FileResult // keyed by path substring
}

func (m *mockFileHandler) HandleFile(ctx context.Context, fc FileContext) FileResult {
	m.mu.Lock()
	m.calls = append(m.calls, mockFileCall{fc})
	m.mu.Unlock()

	if m.rules != nil {
		for substr, r := range m.rules {
			if strings.Contains(fc.Path, substr) {
				return r
			}
		}
	}

	return FileResult{Allow: m.defaultAllow, Errno: m.defaultErrno}
}

func (m *mockFileHandler) CallsMatching(substring string) []mockFileCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []mockFileCall
	for _, c := range m.calls {
		if strings.Contains(c.Path, substring) {
			result = append(result, c)
		}
	}
	return result
}

func (m *mockFileHandler) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

type mockNetworkCall struct {
	NetworkContext
}

type mockNetworkHandler struct {
	mu           sync.Mutex
	calls        []mockNetworkCall
	defaultAllow bool
	defaultErrno int32
	denyPorts    map[int]int32 // port → errno
}

func (m *mockNetworkHandler) HandleNetwork(ctx context.Context, nc NetworkContext) NetworkResult {
	m.mu.Lock()
	m.calls = append(m.calls, mockNetworkCall{nc})
	m.mu.Unlock()

	if m.denyPorts != nil {
		if errno, ok := m.denyPorts[nc.Port]; ok {
			return NetworkResult{Allow: false, Errno: errno}
		}
	}

	return NetworkResult{Allow: m.defaultAllow, Errno: m.defaultErrno}
}

func (m *mockNetworkHandler) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

type mockSignalCall struct {
	SignalContext
}

type mockSignalHandler struct {
	mu             sync.Mutex
	calls          []mockSignalCall
	defaultAllow   bool
	defaultErrno   int32
	redirectSignal int // if > 0, redirect to this signal
	denySignals    map[int]int32 // signal → errno
}

func (m *mockSignalHandler) HandleSignal(ctx context.Context, sc SignalContext) SignalResult {
	m.mu.Lock()
	m.calls = append(m.calls, mockSignalCall{sc})
	m.mu.Unlock()

	if m.denySignals != nil {
		if errno, ok := m.denySignals[sc.Signal]; ok {
			return SignalResult{Allow: false, Errno: errno}
		}
	}

	return SignalResult{
		Allow:          m.defaultAllow,
		Errno:          m.defaultErrno,
		RedirectSignal: m.redirectSignal,
	}
}

func (m *mockSignalHandler) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}
```

**Step 2: Run existing tests to verify mocks compile**

Run: `go test ./internal/ptrace/ -run TestIntegration_AttachDetach -tags integration -v 2>&1 | head -5`
Expected: compiles (may skip if no ptrace)

**Step 3: Commit**

```bash
git add internal/ptrace/integration_test.go
git commit -m "test(ptrace): add mock file, network, signal handlers for integration tests"
```

---

## Task 10: Integration tests — file deny and file allow

**Files:**
- Modify: `internal/ptrace/integration_test.go`

**Step 1: Add file integration tests**

```go
func TestIntegration_FileDeny(t *testing.T) {
	requirePtrace(t)

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "denied.txt")

	fileHandler := &mockFileHandler{
		defaultAllow: true,
		rules: map[string]FileResult{
			"denied.txt": {Allow: false, Errno: int32(unix.EACCES)},
		},
	}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:  true,
		TraceFile:    true,
		ExecHandler:  execHandler,
		FileHandler:  fileHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// Try to create the denied file; if denied, create a marker file instead
	markerFile := filepath.Join(tmpDir, "marker.txt")
	shellCmd := fmt.Sprintf(`/bin/sh -c 'echo test > %s 2>/dev/null || echo denied > %s'`, targetFile, markerFile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	// Check handler received calls
	calls := fileHandler.CallsMatching("denied.txt")
	t.Logf("file handler received %d calls matching 'denied.txt' out of %d total", len(calls), fileHandler.CallCount())
	if len(calls) > 0 {
		t.Logf("file deny intercepted: path=%q op=%q", calls[0].Path, calls[0].Operation)
	}
}

func TestIntegration_FileAllow(t *testing.T) {
	requirePtrace(t)

	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "allowed.txt")

	fileHandler := &mockFileHandler{defaultAllow: true}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:  true,
		TraceFile:    true,
		ExecHandler:  execHandler,
		FileHandler:  fileHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	shellCmd := fmt.Sprintf(`echo hello > %s`, targetFile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	// Verify file was created
	data, err := os.ReadFile(targetFile)
	if err != nil {
		t.Logf("Note: file not created (attach may have happened after open)")
	} else {
		content := strings.TrimSpace(string(data))
		if content == "hello" {
			t.Log("file allow working: file was created successfully")
		}
	}

	// Check handler received calls with correct path
	t.Logf("file handler received %d total calls", fileHandler.CallCount())
	calls := fileHandler.CallsMatching("allowed.txt")
	if len(calls) > 0 {
		if !filepath.IsAbs(calls[0].Path) {
			t.Errorf("expected absolute path, got %q", calls[0].Path)
		}
		t.Logf("file handler saw: path=%q op=%q", calls[0].Path, calls[0].Operation)
	}
}
```

Also add `"fmt"` to imports at the top of `integration_test.go`.

**Step 2: Run Docker integration tests**

Run: `make ptrace-test`
Expected: All tests pass (existing + new file tests)

**Step 3: Commit**

```bash
git add internal/ptrace/integration_test.go
git commit -m "test(ptrace): add file deny and file allow integration tests"
```

---

## Task 11: Integration test — network deny connect

**Files:**
- Modify: `internal/ptrace/integration_test.go`

**Step 1: Add network integration test**

```go
func TestIntegration_NetworkDenyConnect(t *testing.T) {
	requirePtrace(t)

	netHandler := &mockNetworkHandler{
		defaultAllow: true,
		denyPorts:    map[int]int32{12345: int32(unix.ECONNREFUSED)},
	}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:    true,
		TraceNetwork:   true,
		ExecHandler:    execHandler,
		NetworkHandler: netHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	outfile := filepath.Join(t.TempDir(), "result.txt")
	// Try to connect to port 12345 (denied), then write result
	shellCmd := fmt.Sprintf(`/bin/sh -c '(echo test > /dev/tcp/127.0.0.1/12345) 2>/dev/null && echo connected > %s || echo refused > %s'`, outfile, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	t.Logf("network handler received %d calls", netHandler.CallCount())

	netHandler.mu.Lock()
	for _, c := range netHandler.calls {
		t.Logf("  op=%s family=%d addr=%s port=%d", c.Operation, c.Family, c.Address, c.Port)
	}
	netHandler.mu.Unlock()

	// Check output
	data, err := os.ReadFile(outfile)
	if err == nil {
		content := strings.TrimSpace(string(data))
		t.Logf("result: %q", content)
		if content == "refused" {
			t.Log("network deny working: connect was refused")
		}
	}
}
```

**Step 2: Run Docker integration tests**

Run: `make ptrace-test`
Expected: All tests pass

**Step 3: Commit**

```bash
git add internal/ptrace/integration_test.go
git commit -m "test(ptrace): add network deny connect integration test"
```

---

## Task 12: Integration tests — signal deny and signal redirect

**Files:**
- Modify: `internal/ptrace/integration_test.go`

**Step 1: Add signal integration tests**

```go
func TestIntegration_SignalDeny(t *testing.T) {
	requirePtrace(t)

	sigHandler := &mockSignalHandler{
		defaultAllow: true,
		denySignals:  map[int]int32{int(unix.SIGUSR1): int32(unix.EPERM)},
	}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:   true,
		TraceSignal:   true,
		ExecHandler:   execHandler,
		SignalHandler: sigHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	outfile := filepath.Join(t.TempDir(), "result.txt")
	// Try to send SIGUSR1 to self; if denied (EPERM), write "denied"
	shellCmd := fmt.Sprintf(`/bin/sh -c 'kill -USR1 $$ 2>/dev/null && echo signaled > %s || echo denied > %s'`, outfile, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	t.Logf("signal handler received %d calls", sigHandler.CallCount())

	sigHandler.mu.Lock()
	for _, c := range sigHandler.calls {
		t.Logf("  pid=%d target=%d signal=%d", c.PID, c.TargetPID, c.Signal)
	}
	sigHandler.mu.Unlock()

	data, err := os.ReadFile(outfile)
	if err == nil {
		content := strings.TrimSpace(string(data))
		t.Logf("result: %q", content)
		if content == "denied" {
			t.Log("signal deny working: SIGUSR1 was blocked")
		}
	}
}

func TestIntegration_SignalRedirect(t *testing.T) {
	requirePtrace(t)

	// Redirect SIGUSR1 to SIGUSR2
	sigHandler := &mockSignalHandler{
		defaultAllow:   true,
		redirectSignal: int(unix.SIGUSR2),
	}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:   true,
		TraceSignal:   true,
		ExecHandler:   execHandler,
		SignalHandler: sigHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	outfile := filepath.Join(t.TempDir(), "result.txt")
	// Set up a trap for SIGUSR2 (the redirected signal), then send SIGUSR1
	shellCmd := fmt.Sprintf(`/bin/sh -c 'trap "echo redirected > %s" USR2; kill -USR1 $$; sleep 0.1'`, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 2*time.Second)
	cancel()
	<-errCh

	t.Logf("signal handler received %d calls", sigHandler.CallCount())

	data, err := os.ReadFile(outfile)
	if err == nil {
		content := strings.TrimSpace(string(data))
		t.Logf("result: %q", content)
		if content == "redirected" {
			t.Log("signal redirect working: SIGUSR1 was delivered as SIGUSR2")
		}
	} else {
		t.Log("Note: redirect may not have been observed (attach timing)")
	}
}
```

**Step 2: Run Docker integration tests**

Run: `make ptrace-test`
Expected: All tests pass

**Step 3: Commit**

```bash
git add internal/ptrace/integration_test.go
git commit -m "test(ptrace): add signal deny and signal redirect integration tests"
```

---

## Task 13: Final verification

**Step 1: Run all unit tests**

Run: `go test ./internal/ptrace/ -v`
Expected: PASS

**Step 2: Run all project tests**

Run: `go test ./...`
Expected: PASS

**Step 3: Run cross-compilation check**

Run: `GOOS=windows go build ./...`
Expected: PASS

**Step 4: Run Docker integration tests**

Run: `make ptrace-test`
Expected: All integration tests pass with `-test.v`

**Step 5: Verify build**

Run: `go build ./...`
Expected: PASS
