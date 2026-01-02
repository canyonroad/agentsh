# Windows WinFsp Filesystem Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement WinFsp-based filesystem mounting for Windows with soft-delete and redirection, using a shared `fuse/` package for both macOS and Windows.

**Architecture:** Extract cgofuse logic from `darwin/` into shared `internal/platform/fuse/` package. Both darwin and windows delegate to this package. Add minifilter exclusion to prevent double-interception.

**Tech Stack:** Go, cgofuse (github.com/winfsp/cgofuse), WinFsp, Windows minifilter driver

**Design Doc:** `docs/plans/2026-01-02-windows-winfsp-design.md`

---

## Task 1: Create fuse package skeleton

**Files:**
- Create: `internal/platform/fuse/fuse.go`
- Create: `internal/platform/fuse/doc.go`

**Step 1: Create package documentation**

```go
// internal/platform/fuse/doc.go

// Package fuse provides cross-platform FUSE filesystem mounting
// using cgofuse. It works with FUSE-T on macOS and WinFsp on Windows.
//
// This package requires CGO to be enabled. When CGO is disabled,
// Mount() returns an error directing users to enable CGO.
package fuse
```

**Step 2: Create core types and interface stubs**

```go
// internal/platform/fuse/fuse.go

package fuse

import (
	"runtime"

	"github.com/agentsh/agentsh/internal/platform"
)

// Config holds FUSE mount configuration.
type Config struct {
	platform.FSConfig

	// VolumeName is the display name shown in file managers.
	VolumeName string

	// ReadOnly mounts the filesystem read-only.
	ReadOnly bool

	// Debug enables verbose FUSE logging.
	Debug bool
}

// InstallInstructions returns platform-specific install help.
func InstallInstructions() string {
	switch runtime.GOOS {
	case "darwin":
		return "Install FUSE-T: brew install fuse-t"
	case "windows":
		return "Install WinFsp: winget install WinFsp.WinFsp"
	default:
		return "FUSE not supported on this platform"
	}
}
```

**Step 3: Verify package compiles**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && go build ./internal/platform/fuse/...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/platform/fuse/
git commit -m "feat(fuse): create shared fuse package skeleton"
```

---

## Task 2: Create mount stubs (cgo/nocgo)

**Files:**
- Create: `internal/platform/fuse/mount_nocgo.go`
- Create: `internal/platform/fuse/mount_cgo.go`

**Step 1: Create no-CGO stub**

```go
// internal/platform/fuse/mount_nocgo.go
//go:build !cgo

package fuse

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

// Mount returns an error when CGO is disabled.
func Mount(cfg Config) (platform.FSMount, error) {
	return nil, fmt.Errorf("FUSE mounting requires CGO; build with CGO_ENABLED=1. %s", InstallInstructions())
}

// Available returns false when CGO is disabled.
func Available() bool {
	return false
}

// Implementation returns "none" when CGO is disabled.
func Implementation() string {
	return "none"
}

// cgoEnabled reports whether CGO is available.
const cgoEnabled = false
```

**Step 2: Create CGO stub (to be filled in later)**

```go
// internal/platform/fuse/mount_cgo.go
//go:build cgo

package fuse

import (
	"fmt"
	"runtime"

	"github.com/agentsh/agentsh/internal/platform"
)

// cgoEnabled reports whether CGO is available.
const cgoEnabled = true

// Available checks if FUSE is available on this platform.
func Available() bool {
	return checkAvailable()
}

// Implementation returns the FUSE implementation name.
func Implementation() string {
	return detectImplementation()
}

// Mount creates a FUSE mount using cgofuse.
func Mount(cfg Config) (platform.FSMount, error) {
	if !Available() {
		return nil, fmt.Errorf("FUSE not available: %s", InstallInstructions())
	}
	// TODO: Implement actual mounting
	return nil, fmt.Errorf("FUSE mounting not yet implemented on %s", runtime.GOOS)
}
```

**Step 3: Verify both build tags compile**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && CGO_ENABLED=0 go build ./internal/platform/fuse/... && CGO_ENABLED=1 go build ./internal/platform/fuse/...`
Expected: Both builds succeed

**Step 4: Commit**

```bash
git add internal/platform/fuse/
git commit -m "feat(fuse): add mount stubs for cgo and nocgo builds"
```

---

## Task 3: Add platform detection

**Files:**
- Create: `internal/platform/fuse/detect_darwin.go`
- Create: `internal/platform/fuse/detect_windows.go`
- Create: `internal/platform/fuse/detect_other.go`

**Step 1: Create macOS detection**

```go
// internal/platform/fuse/detect_darwin.go
//go:build darwin

package fuse

import "os"

// FUSE-T detection paths
var fuseTpaths = []string{
	"/usr/local/lib/libfuse-t.dylib",
	"/opt/homebrew/lib/libfuse-t.dylib",
	"/Library/Frameworks/FUSE-T.framework",
}

// macFUSE detection paths (fallback)
var macFUSEpaths = []string{
	"/Library/Filesystems/macfuse.fs",
	"/Library/Frameworks/macFUSE.framework",
}

func checkAvailable() bool {
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	for _, path := range macFUSEpaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func detectImplementation() string {
	for _, path := range fuseTpaths {
		if _, err := os.Stat(path); err == nil {
			return "fuse-t"
		}
	}
	for _, path := range macFUSEpaths {
		if _, err := os.Stat(path); err == nil {
			return "macfuse"
		}
	}
	return "none"
}
```

**Step 2: Create Windows detection**

```go
// internal/platform/fuse/detect_windows.go
//go:build windows

package fuse

import (
	"os"
	"os/exec"
	"path/filepath"
)

func checkAvailable() bool {
	paths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "WinFsp", "bin", "winfsp-x64.dll"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "WinFsp", "bin", "winfsp-x86.dll"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "winfsp-x64.dll"),
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Check registry for WinFsp installation
	cmd := exec.Command("reg", "query", `HKLM\SOFTWARE\WinFsp`, "/ve")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

func detectImplementation() string {
	if checkAvailable() {
		return "winfsp"
	}
	return "none"
}
```

**Step 3: Create fallback for other platforms**

```go
// internal/platform/fuse/detect_other.go
//go:build !darwin && !windows

package fuse

func checkAvailable() bool {
	return false
}

func detectImplementation() string {
	return "none"
}
```

**Step 4: Verify all platforms compile**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && GOOS=darwin go build ./internal/platform/fuse/... && GOOS=windows go build ./internal/platform/fuse/... && GOOS=linux go build ./internal/platform/fuse/...`
Expected: All builds succeed

**Step 5: Commit**

```bash
git add internal/platform/fuse/
git commit -m "feat(fuse): add platform detection for darwin and windows"
```

---

## Task 4: Extract FUSE operations from darwin

**Files:**
- Create: `internal/platform/fuse/fs.go`
- Create: `internal/platform/fuse/ops.go`

**Step 1: Create fuseFS struct (extracted from darwin/filesystem_cgo.go)**

```go
// internal/platform/fuse/fs.go
//go:build cgo

package fuse

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/winfsp/cgofuse/fuse"
)

// fuseFS implements fuse.FileSystemInterface with policy enforcement.
type fuseFS struct {
	fuse.FileSystemBase
	realRoot  string
	cfg       Config
	openFiles sync.Map   // uint64 -> *openFile
	nextFh    atomic.Uint64
	mountedAt time.Time

	// Stats
	totalOps      atomic.Int64
	allowedOps    atomic.Int64
	deniedOps     atomic.Int64
	redirectedOps atomic.Int64
}

// openFile tracks an open file handle.
type openFile struct {
	realPath string
	virtPath string
	flags    int
	file     *os.File
}

func newFuseFS(cfg Config) *fuseFS {
	return &fuseFS{
		realRoot:  cfg.SourcePath,
		cfg:       cfg,
		mountedAt: time.Now(),
	}
}

func (f *fuseFS) stats() platform.FSStats {
	return platform.FSStats{
		MountedAt:     f.mountedAt,
		TotalOps:      f.totalOps.Load(),
		AllowedOps:    f.allowedOps.Load(),
		DeniedOps:     f.deniedOps.Load(),
		RedirectedOps: f.redirectedOps.Load(),
	}
}

func (f *fuseFS) allocHandle() uint64 {
	return f.nextFh.Add(1)
}
```

**Step 2: Create shared operations file**

```go
// internal/platform/fuse/ops.go
//go:build cgo

package fuse

import (
	"os"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/winfsp/cgofuse/fuse"
)

// virtPath converts a FUSE path to the virtual path seen by the agent.
func (f *fuseFS) virtPath(path string) string {
	if path == "/" {
		return f.cfg.MountPoint
	}
	return filepath.Join(f.cfg.MountPoint, path)
}

// realPath converts a FUSE path to the real filesystem path.
func (f *fuseFS) realPath(path string) string {
	if path == "/" {
		return f.realRoot
	}
	return filepath.Join(f.realRoot, path)
}

// checkPolicy checks the policy for a file operation.
func (f *fuseFS) checkPolicy(virtPath string, operation platform.FileOperation) platform.Decision {
	if f.cfg.PolicyEngine == nil {
		return platform.DecisionAllow
	}
	return f.cfg.PolicyEngine.CheckFile(virtPath, operation)
}

// emitEvent emits a file event if an event channel is configured.
func (f *fuseFS) emitEvent(eventType, virtPath string, operation platform.FileOperation, decision platform.Decision, blocked bool) {
	f.totalOps.Add(1)
	if blocked {
		f.deniedOps.Add(1)
	} else {
		f.allowedOps.Add(1)
	}
	// TODO: Emit actual event to channel
}

// toErrno converts an os error to a FUSE errno.
func toErrno(err error) int {
	if err == nil {
		return 0
	}
	if os.IsNotExist(err) {
		return -fuse.ENOENT
	}
	if os.IsPermission(err) {
		return -fuse.EACCES
	}
	if os.IsExist(err) {
		return -fuse.EEXIST
	}
	return -fuse.EIO
}

// --- FUSE Operations ---

func (f *fuseFS) Statfs(path string, stat *fuse.Statfs_t) int {
	stat.Bsize = 4096
	stat.Frsize = 4096
	stat.Blocks = 1000000
	stat.Bfree = 500000
	stat.Bavail = 500000
	stat.Files = 100000
	stat.Ffree = 50000
	stat.Favail = 50000
	stat.Namemax = 255
	return 0
}

func (f *fuseFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) int {
	realPath := f.realPath(path)
	info, err := os.Lstat(realPath)
	if err != nil {
		return toErrno(err)
	}
	fillStat(stat, info)
	return 0
}

func (f *fuseFS) Opendir(path string) (int, uint64) {
	virtPath := f.virtPath(path)
	decision := f.checkPolicy(virtPath, platform.FileOpList)
	if decision == platform.DecisionDeny {
		f.emitEvent("dir_open", virtPath, platform.FileOpList, decision, true)
		return -fuse.EACCES, 0
	}
	f.emitEvent("dir_open", virtPath, platform.FileOpList, decision, false)

	realPath := f.realPath(path)
	if _, err := os.Stat(realPath); err != nil {
		return toErrno(err), 0
	}
	return 0, 0
}

func (f *fuseFS) Readdir(path string, fill func(name string, stat *fuse.Stat_t, ofst int64) bool, ofst int64, fh uint64) int {
	realPath := f.realPath(path)
	entries, err := os.ReadDir(realPath)
	if err != nil {
		return toErrno(err)
	}

	fill(".", nil, 0)
	fill("..", nil, 0)

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		var stat fuse.Stat_t
		fillStat(&stat, info)
		if !fill(entry.Name(), &stat, 0) {
			break
		}
	}
	return 0
}

func (f *fuseFS) Open(path string, flags int) (int, uint64) {
	virtPath := f.virtPath(path)

	operation := platform.FileOpRead
	if flags&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_TRUNC) != 0 {
		operation = platform.FileOpWrite
	}

	decision := f.checkPolicy(virtPath, operation)
	if decision == platform.DecisionDeny {
		f.emitEvent("file_open", virtPath, operation, decision, true)
		return -fuse.EACCES, 0
	}
	f.emitEvent("file_open", virtPath, operation, decision, false)

	realPath := f.realPath(path)
	file, err := os.OpenFile(realPath, flags, 0)
	if err != nil {
		return toErrno(err), 0
	}

	fh := f.allocHandle()
	f.openFiles.Store(fh, &openFile{
		realPath: realPath,
		virtPath: virtPath,
		flags:    flags,
		file:     file,
	})

	return 0, fh
}

func (f *fuseFS) Create(path string, flags int, mode uint32) (int, uint64) {
	virtPath := f.virtPath(path)

	decision := f.checkPolicy(virtPath, platform.FileOpCreate)
	if decision == platform.DecisionDeny {
		f.emitEvent("file_create", virtPath, platform.FileOpCreate, decision, true)
		return -fuse.EACCES, 0
	}
	f.emitEvent("file_create", virtPath, platform.FileOpCreate, decision, false)

	realPath := f.realPath(path)
	file, err := os.OpenFile(realPath, flags|os.O_CREATE, os.FileMode(mode))
	if err != nil {
		return toErrno(err), 0
	}

	fh := f.allocHandle()
	f.openFiles.Store(fh, &openFile{
		realPath: realPath,
		virtPath: virtPath,
		flags:    flags,
		file:     file,
	})

	return 0, fh
}

func (f *fuseFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	of, ok := f.openFiles.Load(fh)
	if !ok {
		return -fuse.EBADF
	}
	openFile := of.(*openFile)

	n, err := openFile.file.ReadAt(buff, ofst)
	if err != nil && n == 0 {
		return toErrno(err)
	}
	return n
}

func (f *fuseFS) Write(path string, buff []byte, ofst int64, fh uint64) int {
	of, ok := f.openFiles.Load(fh)
	if !ok {
		return -fuse.EBADF
	}
	openFile := of.(*openFile)

	decision := f.checkPolicy(openFile.virtPath, platform.FileOpWrite)
	if decision == platform.DecisionDeny {
		f.emitEvent("file_write", openFile.virtPath, platform.FileOpWrite, decision, true)
		return -fuse.EACCES
	}

	n, err := openFile.file.WriteAt(buff, ofst)
	if err != nil {
		return toErrno(err)
	}
	return n
}

func (f *fuseFS) Release(path string, fh uint64) int {
	of, ok := f.openFiles.LoadAndDelete(fh)
	if !ok {
		return 0
	}
	openFile := of.(*openFile)
	openFile.file.Close()
	return 0
}

func (f *fuseFS) Unlink(path string) int {
	virtPath := f.virtPath(path)

	decision := f.checkPolicy(virtPath, platform.FileOpDelete)
	if decision == platform.DecisionDeny {
		f.emitEvent("file_delete", virtPath, platform.FileOpDelete, decision, true)
		return -fuse.EACCES
	}
	f.emitEvent("file_delete", virtPath, platform.FileOpDelete, decision, false)

	realPath := f.realPath(path)
	if err := os.Remove(realPath); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Mkdir(path string, mode uint32) int {
	virtPath := f.virtPath(path)

	decision := f.checkPolicy(virtPath, platform.FileOpCreate)
	if decision == platform.DecisionDeny {
		f.emitEvent("dir_create", virtPath, platform.FileOpCreate, decision, true)
		return -fuse.EACCES
	}
	f.emitEvent("dir_create", virtPath, platform.FileOpCreate, decision, false)

	realPath := f.realPath(path)
	if err := os.Mkdir(realPath, os.FileMode(mode)); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Rmdir(path string) int {
	virtPath := f.virtPath(path)

	decision := f.checkPolicy(virtPath, platform.FileOpDelete)
	if decision == platform.DecisionDeny {
		f.emitEvent("dir_delete", virtPath, platform.FileOpDelete, decision, true)
		return -fuse.EACCES
	}
	f.emitEvent("dir_delete", virtPath, platform.FileOpDelete, decision, false)

	realPath := f.realPath(path)
	if err := os.Remove(realPath); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Rename(oldpath string, newpath string) int {
	virtOldPath := f.virtPath(oldpath)
	virtNewPath := f.virtPath(newpath)

	decision := f.checkPolicy(virtOldPath, platform.FileOpRename)
	if decision == platform.DecisionDeny {
		f.emitEvent("file_rename", virtOldPath, platform.FileOpRename, decision, true)
		return -fuse.EACCES
	}
	decision = f.checkPolicy(virtNewPath, platform.FileOpRename)
	if decision == platform.DecisionDeny {
		f.emitEvent("file_rename", virtNewPath, platform.FileOpRename, decision, true)
		return -fuse.EACCES
	}
	f.emitEvent("file_rename", virtOldPath, platform.FileOpRename, decision, false)

	realOldPath := f.realPath(oldpath)
	realNewPath := f.realPath(newpath)
	if err := os.Rename(realOldPath, realNewPath); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Chmod(path string, mode uint32) int {
	virtPath := f.virtPath(path)

	decision := f.checkPolicy(virtPath, platform.FileOpWrite)
	if decision == platform.DecisionDeny {
		f.emitEvent("file_chmod", virtPath, platform.FileOpWrite, decision, true)
		return -fuse.EACCES
	}
	f.emitEvent("file_chmod", virtPath, platform.FileOpWrite, decision, false)

	realPath := f.realPath(path)
	if err := os.Chmod(realPath, os.FileMode(mode)); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Symlink(target string, newpath string) int {
	virtPath := f.virtPath(newpath)

	decision := f.checkPolicy(virtPath, platform.FileOpCreate)
	if decision == platform.DecisionDeny {
		f.emitEvent("symlink_create", virtPath, platform.FileOpCreate, decision, true)
		return -fuse.EACCES
	}
	f.emitEvent("symlink_create", virtPath, platform.FileOpCreate, decision, false)

	realPath := f.realPath(newpath)
	if err := os.Symlink(target, realPath); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Readlink(path string) (int, string) {
	virtPath := f.virtPath(path)

	decision := f.checkPolicy(virtPath, platform.FileOpRead)
	if decision == platform.DecisionDeny {
		f.emitEvent("symlink_read", virtPath, platform.FileOpRead, decision, true)
		return -fuse.EACCES, ""
	}
	f.emitEvent("symlink_read", virtPath, platform.FileOpRead, decision, false)

	realPath := f.realPath(path)
	target, err := os.Readlink(realPath)
	if err != nil {
		return toErrno(err), ""
	}
	return 0, target
}

func (f *fuseFS) Link(oldpath string, newpath string) int {
	virtPath := f.virtPath(newpath)

	decision := f.checkPolicy(virtPath, platform.FileOpCreate)
	if decision == platform.DecisionDeny {
		f.emitEvent("link_create", virtPath, platform.FileOpCreate, decision, true)
		return -fuse.EACCES
	}
	f.emitEvent("link_create", virtPath, platform.FileOpCreate, decision, false)

	realOldPath := f.realPath(oldpath)
	realNewPath := f.realPath(newpath)
	if err := os.Link(realOldPath, realNewPath); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Truncate(path string, size int64, fh uint64) int {
	virtPath := f.virtPath(path)

	decision := f.checkPolicy(virtPath, platform.FileOpWrite)
	if decision == platform.DecisionDeny {
		f.emitEvent("file_truncate", virtPath, platform.FileOpWrite, decision, true)
		return -fuse.EACCES
	}
	f.emitEvent("file_truncate", virtPath, platform.FileOpWrite, decision, false)

	realPath := f.realPath(path)
	if err := os.Truncate(realPath, size); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Utimens(path string, tmsp []fuse.Timespec) int {
	realPath := f.realPath(path)
	if len(tmsp) < 2 {
		return -fuse.EINVAL
	}

	atime := timespecToTime(tmsp[0])
	mtime := timespecToTime(tmsp[1])

	if err := os.Chtimes(realPath, atime, mtime); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Access(path string, mask uint32) int {
	realPath := f.realPath(path)
	if _, err := os.Stat(realPath); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Flush(path string, fh uint64) int {
	of, ok := f.openFiles.Load(fh)
	if !ok {
		return 0
	}
	openFile := of.(*openFile)
	if err := openFile.file.Sync(); err != nil {
		return toErrno(err)
	}
	return 0
}

func (f *fuseFS) Fsync(path string, datasync bool, fh uint64) int {
	of, ok := f.openFiles.Load(fh)
	if !ok {
		return 0
	}
	openFile := of.(*openFile)
	if err := openFile.file.Sync(); err != nil {
		return toErrno(err)
	}
	return 0
}
```

**Step 3: Verify it compiles**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && go build ./internal/platform/fuse/...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/platform/fuse/
git commit -m "feat(fuse): extract FUSE operations from darwin"
```

---

## Task 5: Add platform-specific stat handling

**Files:**
- Create: `internal/platform/fuse/stat_unix.go`
- Create: `internal/platform/fuse/stat_windows.go`

**Step 1: Create Unix stat handling**

```go
// internal/platform/fuse/stat_unix.go
//go:build (darwin || linux || freebsd) && cgo

package fuse

import (
	"os"
	"syscall"
	"time"

	cgofuse "github.com/winfsp/cgofuse/fuse"
)

func fillStat(stat *cgofuse.Stat_t, info os.FileInfo) {
	stat.Size = info.Size()
	stat.Mtim = cgofuse.NewTimespec(info.ModTime())
	stat.Atim = stat.Mtim
	stat.Ctim = stat.Mtim

	mode := uint32(info.Mode().Perm())
	if info.IsDir() {
		mode |= cgofuse.S_IFDIR
	} else if info.Mode()&os.ModeSymlink != 0 {
		mode |= cgofuse.S_IFLNK
	} else {
		mode |= cgofuse.S_IFREG
	}
	stat.Mode = mode
	stat.Nlink = 1

	if sys := info.Sys(); sys != nil {
		if s, ok := sys.(*syscall.Stat_t); ok {
			stat.Uid = s.Uid
			stat.Gid = s.Gid
			stat.Nlink = uint32(s.Nlink)
			stat.Ino = s.Ino
			stat.Dev = uint64(s.Dev)
			fillStatTimes(stat, s)
		}
	}
}

func timespecToTime(ts cgofuse.Timespec) time.Time {
	return time.Unix(ts.Sec, ts.Nsec)
}

// Chown changes file ownership (Unix only).
func (f *fuseFS) Chown(path string, uid uint32, gid uint32) int {
	realPath := f.realPath(path)
	if err := os.Chown(realPath, int(uid), int(gid)); err != nil {
		return toErrno(err)
	}
	return 0
}
```

**Step 2: Create Darwin-specific time handling**

```go
// internal/platform/fuse/stat_darwin.go
//go:build darwin && cgo

package fuse

import (
	"syscall"
	"time"

	cgofuse "github.com/winfsp/cgofuse/fuse"
)

func fillStatTimes(stat *cgofuse.Stat_t, s *syscall.Stat_t) {
	stat.Atim = cgofuse.NewTimespec(time.Unix(s.Atimespec.Sec, s.Atimespec.Nsec))
	stat.Ctim = cgofuse.NewTimespec(time.Unix(s.Ctimespec.Sec, s.Ctimespec.Nsec))
}
```

**Step 3: Create Linux-specific time handling**

```go
// internal/platform/fuse/stat_linux.go
//go:build linux && cgo

package fuse

import (
	"syscall"
	"time"

	cgofuse "github.com/winfsp/cgofuse/fuse"
)

func fillStatTimes(stat *cgofuse.Stat_t, s *syscall.Stat_t) {
	stat.Atim = cgofuse.NewTimespec(time.Unix(s.Atim.Sec, s.Atim.Nsec))
	stat.Ctim = cgofuse.NewTimespec(time.Unix(s.Ctim.Sec, s.Ctim.Nsec))
}
```

**Step 4: Create Windows stat handling**

```go
// internal/platform/fuse/stat_windows.go
//go:build windows && cgo

package fuse

import (
	"os"
	"syscall"
	"time"

	cgofuse "github.com/winfsp/cgofuse/fuse"
)

func fillStat(stat *cgofuse.Stat_t, info os.FileInfo) {
	stat.Size = info.Size()
	stat.Mtim = cgofuse.NewTimespec(info.ModTime())
	stat.Atim = stat.Mtim
	stat.Ctim = stat.Mtim

	mode := uint32(info.Mode().Perm())
	if info.IsDir() {
		mode |= cgofuse.S_IFDIR
	} else if info.Mode()&os.ModeSymlink != 0 {
		mode |= cgofuse.S_IFLNK
	} else {
		mode |= cgofuse.S_IFREG
	}
	stat.Mode = mode
	stat.Nlink = 1

	// Windows: extract times from Win32FileAttributeData
	if sys := info.Sys(); sys != nil {
		if s, ok := sys.(*syscall.Win32FileAttributeData); ok {
			stat.Atim = cgofuse.NewTimespec(filetimeToTime(s.LastAccessTime))
			stat.Ctim = cgofuse.NewTimespec(filetimeToTime(s.CreationTime))
		}
	}
	// Windows: UID/GID not meaningful, leave as 0
}

func filetimeToTime(ft syscall.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds())
}

func timespecToTime(ts cgofuse.Timespec) time.Time {
	return time.Unix(ts.Sec, ts.Nsec)
}

// Chown is a no-op on Windows (ACLs managed separately).
func (f *fuseFS) Chown(path string, uid uint32, gid uint32) int {
	return 0
}
```

**Step 5: Verify all platforms compile**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && GOOS=darwin go build ./internal/platform/fuse/... && GOOS=windows go build ./internal/platform/fuse/... && GOOS=linux go build ./internal/platform/fuse/...`
Expected: All builds succeed

**Step 6: Commit**

```bash
git add internal/platform/fuse/
git commit -m "feat(fuse): add platform-specific stat handling"
```

---

## Task 6: Implement Mount function

**Files:**
- Modify: `internal/platform/fuse/mount_cgo.go`
- Create: `internal/platform/fuse/mount.go`

**Step 1: Create FuseMount type**

```go
// internal/platform/fuse/mount.go
//go:build cgo

package fuse

import (
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	cgofuse "github.com/winfsp/cgofuse/fuse"
)

// FuseMount represents an active FUSE mount.
type FuseMount struct {
	host      *cgofuse.FileSystemHost
	fuseFS    *fuseFS
	path      string
	source    string
	mountedAt time.Time
	done      chan struct{}
	closed    atomic.Bool
}

// Path returns the mount point path.
func (m *FuseMount) Path() string {
	return m.path
}

// SourcePath returns the underlying real filesystem path.
func (m *FuseMount) SourcePath() string {
	return m.source
}

// Stats returns current mount statistics.
func (m *FuseMount) Stats() platform.FSStats {
	if m.fuseFS == nil {
		return platform.FSStats{}
	}
	return m.fuseFS.stats()
}

// Close unmounts the filesystem.
func (m *FuseMount) Close() error {
	if m.closed.Swap(true) {
		return nil // Already closed
	}

	m.host.Unmount()

	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		// Force unmount timed out
	}

	return nil
}

var _ platform.FSMount = (*FuseMount)(nil)
```

**Step 2: Update mount_cgo.go with full implementation**

```go
// internal/platform/fuse/mount_cgo.go
//go:build cgo

package fuse

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	cgofuse "github.com/winfsp/cgofuse/fuse"
)

const cgoEnabled = true

func Available() bool {
	return checkAvailable()
}

func Implementation() string {
	return detectImplementation()
}

// Mount creates a FUSE mount using cgofuse.
func Mount(cfg Config) (platform.FSMount, error) {
	if !Available() {
		return nil, fmt.Errorf("FUSE not available: %s", InstallInstructions())
	}

	// Verify source path exists
	info, err := os.Stat(cfg.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("source path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("source path must be a directory: %s", cfg.SourcePath)
	}

	// Create mount point if needed
	if err := os.MkdirAll(cfg.MountPoint, 0755); err != nil {
		return nil, fmt.Errorf("create mount point: %w", err)
	}

	// Create the policy-enforcing filesystem
	fuseFS := newFuseFS(cfg)

	// Create cgofuse host
	host := cgofuse.NewFileSystemHost(fuseFS)

	// Mount in background goroutine (cgofuse Mount blocks)
	mountErr := make(chan error, 1)
	mountDone := make(chan struct{})

	go func() {
		defer close(mountDone)
		opts := mountOptions(cfg)
		ok := host.Mount(cfg.MountPoint, opts)
		if !ok {
			mountErr <- fmt.Errorf("cgofuse mount failed at %s", cfg.MountPoint)
		}
	}()

	// Wait for mount to complete or timeout
	select {
	case err := <-mountErr:
		return nil, err
	case <-time.After(5 * time.Second):
		if _, err := os.Stat(cfg.MountPoint); err != nil {
			host.Unmount()
			return nil, fmt.Errorf("mount timeout: %s", cfg.MountPoint)
		}
	}

	return &FuseMount{
		host:      host,
		fuseFS:    fuseFS,
		path:      cfg.MountPoint,
		source:    cfg.SourcePath,
		mountedAt: time.Now(),
		done:      mountDone,
	}, nil
}

// mountOptions returns platform-specific mount options.
func mountOptions(cfg Config) []string {
	volname := cfg.VolumeName
	if volname == "" {
		volname = "agentsh"
	}

	switch runtime.GOOS {
	case "darwin":
		opts := []string{
			"-o", "volname=" + volname,
			"-o", "local",
		}
		if cfg.Debug {
			opts = append(opts, "-d")
		}
		return opts
	case "windows":
		opts := []string{
			"--VolumePrefix=" + volname,
		}
		if cfg.Debug {
			opts = append(opts, "-d")
		}
		return opts
	default:
		return nil
	}
}
```

**Step 3: Verify it compiles**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && go build ./internal/platform/fuse/...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/platform/fuse/
git commit -m "feat(fuse): implement Mount function with FuseMount type"
```

---

## Task 7: Add soft-delete support

**Files:**
- Create: `internal/platform/fuse/softdelete.go`

**Step 1: Create soft-delete implementation**

```go
// internal/platform/fuse/softdelete.go
//go:build cgo

package fuse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	cgofuse "github.com/winfsp/cgofuse/fuse"
)

// softDelete moves a file to trash instead of deleting.
func (f *fuseFS) softDelete(realPath, virtPath string) int {
	if f.cfg.TrashConfig == nil || !f.cfg.TrashConfig.Enabled {
		return -cgofuse.EACCES
	}

	// Generate unique trash path
	trashPath := f.trashPath(realPath)

	// Ensure trash directory exists
	trashDir := filepath.Dir(trashPath)
	if err := os.MkdirAll(trashDir, 0755); err != nil {
		return toErrno(err)
	}

	// Optionally hash file before moving
	var hash string
	if f.cfg.TrashConfig.HashFiles {
		var err error
		hash, err = f.hashFile(realPath)
		if err != nil {
			// Log error but continue with soft-delete
			hash = ""
		}
	}

	// Move to trash
	if err := os.Rename(realPath, trashPath); err != nil {
		return toErrno(err)
	}

	// Generate restore token
	token := f.generateRestoreToken(virtPath, trashPath, hash)

	// Notify callback
	if f.cfg.NotifySoftDelete != nil {
		f.cfg.NotifySoftDelete(virtPath, token)
	}

	f.emitEvent("file_soft_delete", virtPath, platform.FileOpDelete, platform.DecisionAllow, false)
	return 0
}

// trashPath generates a unique path in the trash directory.
func (f *fuseFS) trashPath(realPath string) string {
	baseName := filepath.Base(realPath)
	timestamp := time.Now().UnixNano()
	trashName := fmt.Sprintf("%s.%d", baseName, timestamp)
	return filepath.Join(f.cfg.TrashConfig.TrashDir, trashName)
}

// hashFile computes the SHA256 hash of a file.
func (f *fuseFS) hashFile(path string) (string, error) {
	// Check file size limit
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if f.cfg.TrashConfig.HashLimitBytes > 0 && info.Size() > f.cfg.TrashConfig.HashLimitBytes {
		return "", nil // Skip hashing large files
	}

	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// generateRestoreToken creates a token for restoring a soft-deleted file.
func (f *fuseFS) generateRestoreToken(virtPath, trashPath, hash string) string {
	// Simple token format: base64 of JSON or similar
	// For now, just return the trash path as the token
	return trashPath
}
```

**Step 2: Update Unlink to use soft-delete**

Modify `internal/platform/fuse/ops.go` - update the Unlink function:

```go
func (f *fuseFS) Unlink(path string) int {
	virtPath := f.virtPath(path)
	realPath := f.realPath(path)

	decision := f.checkPolicy(virtPath, platform.FileOpDelete)

	// Handle soft-delete
	if decision == platform.DecisionSoftDelete {
		return f.softDelete(realPath, virtPath)
	}

	if decision == platform.DecisionDeny {
		f.emitEvent("file_delete", virtPath, platform.FileOpDelete, decision, true)
		return -fuse.EACCES
	}
	f.emitEvent("file_delete", virtPath, platform.FileOpDelete, decision, false)

	if err := os.Remove(realPath); err != nil {
		return toErrno(err)
	}
	return 0
}
```

**Step 3: Verify it compiles**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && go build ./internal/platform/fuse/...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/platform/fuse/
git commit -m "feat(fuse): add soft-delete support"
```

---

## Task 8: Add unit tests

**Files:**
- Create: `internal/platform/fuse/fuse_test.go`

**Step 1: Create test file**

```go
// internal/platform/fuse/fuse_test.go

package fuse

import (
	"runtime"
	"testing"
)

func TestInstallInstructions(t *testing.T) {
	instructions := InstallInstructions()
	if instructions == "" {
		t.Error("InstallInstructions returned empty string")
	}

	switch runtime.GOOS {
	case "darwin":
		if instructions != "Install FUSE-T: brew install fuse-t" {
			t.Errorf("unexpected darwin instructions: %s", instructions)
		}
	case "windows":
		if instructions != "Install WinFsp: winget install WinFsp.WinFsp" {
			t.Errorf("unexpected windows instructions: %s", instructions)
		}
	}
}

func TestImplementation(t *testing.T) {
	impl := Implementation()
	// Should be one of: fuse-t, macfuse, winfsp, none
	valid := map[string]bool{
		"fuse-t":  true,
		"macfuse": true,
		"winfsp":  true,
		"none":    true,
	}
	if !valid[impl] {
		t.Errorf("unexpected implementation: %s", impl)
	}
}
```

**Step 2: Run tests**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && go test ./internal/platform/fuse/... -v`
Expected: Tests pass

**Step 3: Commit**

```bash
git add internal/platform/fuse/
git commit -m "test(fuse): add unit tests for fuse package"
```

---

## Task 9: Update darwin to use shared fuse package

**Files:**
- Modify: `internal/platform/darwin/filesystem.go`
- Modify: `internal/platform/darwin/filesystem_cgo.go`
- Modify: `internal/platform/darwin/filesystem_nocgo.go`
- Delete: `internal/platform/darwin/fuse_ops.go`

**Step 1: Update filesystem.go**

```go
// internal/platform/darwin/filesystem.go
//go:build darwin

package darwin

import (
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/platform/fuse"
)

// Filesystem implements platform.FilesystemInterceptor for macOS.
type Filesystem struct {
	mu     sync.Mutex
	mounts map[string]platform.FSMount
}

// NewFilesystem creates a new macOS filesystem interceptor.
func NewFilesystem() *Filesystem {
	return &Filesystem{
		mounts: make(map[string]platform.FSMount),
	}
}

// Available returns whether FUSE is available.
func (fs *Filesystem) Available() bool {
	return fuse.Available()
}

// Implementation returns the FUSE implementation name.
func (fs *Filesystem) Implementation() string {
	return fuse.Implementation()
}

// Unmount removes a FUSE mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.mounts, mount.Path())
	return mount.Close()
}

var _ platform.FilesystemInterceptor = (*Filesystem)(nil)
```

**Step 2: Update filesystem_cgo.go**

```go
// internal/platform/darwin/filesystem_cgo.go
//go:build darwin && cgo

package darwin

import (
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/platform/fuse"
)

// Mount creates a FUSE mount.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.mounts[cfg.MountPoint]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	mount, err := fuse.Mount(fuse.Config{
		FSConfig:   cfg,
		VolumeName: "agentsh",
	})
	if err != nil {
		return nil, err
	}

	fs.mounts[cfg.MountPoint] = mount
	return mount, nil
}

const cgoEnabled = true
```

**Step 3: Update filesystem_nocgo.go**

```go
// internal/platform/darwin/filesystem_nocgo.go
//go:build darwin && !cgo

package darwin

import (
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/platform/fuse"
)

// Mount returns an error when CGO is disabled.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	return fuse.Mount(fuse.Config{FSConfig: cfg})
}

const cgoEnabled = false
```

**Step 4: Delete old fuse_ops.go**

```bash
rm internal/platform/darwin/fuse_ops.go
```

**Step 5: Verify darwin tests pass**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && go test ./internal/platform/darwin/... -v`
Expected: Tests pass

**Step 6: Commit**

```bash
git add internal/platform/darwin/
git commit -m "refactor(darwin): use shared fuse package"
```

---

## Task 10: Update windows to use shared fuse package

**Files:**
- Modify: `internal/platform/windows/filesystem.go`

**Step 1: Update filesystem.go**

```go
// internal/platform/windows/filesystem.go
//go:build windows

package windows

import (
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/platform/fuse"
)

// Filesystem implements platform.FilesystemInterceptor for Windows using WinFsp.
type Filesystem struct {
	mu     sync.Mutex
	mounts map[string]platform.FSMount
}

// NewFilesystem creates a new Windows filesystem interceptor.
func NewFilesystem() *Filesystem {
	return &Filesystem{
		mounts: make(map[string]platform.FSMount),
	}
}

// Available returns whether WinFsp is available.
func (fs *Filesystem) Available() bool {
	return fuse.Available()
}

// Implementation returns the WinFsp implementation name.
func (fs *Filesystem) Implementation() string {
	return fuse.Implementation()
}

// Mount creates a WinFsp mount.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.Available() {
		return nil, fmt.Errorf("WinFsp not available: %s", fuse.InstallInstructions())
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.mounts[cfg.MountPoint]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	mount, err := fuse.Mount(fuse.Config{
		FSConfig:   cfg,
		VolumeName: "agentsh",
	})
	if err != nil {
		return nil, err
	}

	fs.mounts[cfg.MountPoint] = mount
	return mount, nil
}

// Unmount removes a WinFsp mount.
func (fs *Filesystem) Unmount(mount platform.FSMount) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	delete(fs.mounts, mount.Path())
	return mount.Close()
}

var _ platform.FilesystemInterceptor = (*Filesystem)(nil)
```

**Step 2: Verify windows builds**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && GOOS=windows go build ./internal/platform/windows/...`
Expected: Build succeeds

**Step 3: Run windows tests**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && go test ./internal/platform/windows/... -v`
Expected: Tests pass

**Step 4: Commit**

```bash
git add internal/platform/windows/
git commit -m "feat(windows): use shared fuse package for WinFsp support"
```

---

## Task 11: Add minifilter process exclusion - protocol

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/inc/protocol.h`

**Step 1: Add MSG_EXCLUDE_PROCESS message type**

Add to the AGENTSH_MSG_TYPE enum after MSG_METRICS_REPLY:

```c
    MSG_EXCLUDE_PROCESS = 107,
```

**Step 2: Add exclude process message struct**

Add after AGENTSH_METRICS struct:

```c
// Process exclusion (user-mode -> driver)
typedef struct _AGENTSH_EXCLUDE_PROCESS {
    AGENTSH_MESSAGE_HEADER Header;
    ULONG ProcessId;
} AGENTSH_EXCLUDE_PROCESS, *PAGENTSH_EXCLUDE_PROCESS;
```

**Step 3: Commit**

```bash
git add drivers/windows/agentsh-minifilter/
git commit -m "feat(minifilter): add MSG_EXCLUDE_PROCESS protocol message"
```

---

## Task 12: Add minifilter process exclusion - driver

**Files:**
- Modify: `drivers/windows/agentsh-minifilter/src/filesystem.c`
- Modify: `drivers/windows/agentsh-minifilter/src/driver.c`

**Step 1: Add excluded process tracking**

In `filesystem.c`, add near the top after includes:

```c
// Excluded process ID (agentsh itself when using WinFsp)
static volatile ULONG gExcludedProcessId = 0;

BOOLEAN AgentshIsExcludedProcess(ULONG ProcessId) {
    return ProcessId != 0 && ProcessId == gExcludedProcessId;
}

void AgentshSetExcludedProcess(ULONG ProcessId) {
    InterlockedExchange(&gExcludedProcessId, ProcessId);
}
```

**Step 2: Add exclusion check to pre-callbacks**

In each pre-callback (AgentshPreCreate, AgentshPreWrite, AgentshPreSetInfo), add at the start:

```c
    ULONG processId = HandleToULong(PsGetCurrentProcessId());

    // Skip if this is the excluded process (agentsh using WinFsp)
    if (AgentshIsExcludedProcess(processId)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
```

**Step 3: Handle message in driver.c**

In the message handler, add case for MSG_EXCLUDE_PROCESS:

```c
    case MSG_EXCLUDE_PROCESS:
        {
            PAGENTSH_EXCLUDE_PROCESS excludeMsg = (PAGENTSH_EXCLUDE_PROCESS)InputBuffer;
            if (InputBufferLength >= sizeof(AGENTSH_EXCLUDE_PROCESS)) {
                AgentshSetExcludedProcess(excludeMsg->ProcessId);
                status = STATUS_SUCCESS;
            }
        }
        break;
```

**Step 4: Commit**

```bash
git add drivers/windows/agentsh-minifilter/
git commit -m "feat(minifilter): implement process exclusion for WinFsp coexistence"
```

---

## Task 13: Add minifilter process exclusion - Go client

**Files:**
- Modify: `internal/platform/windows/driver_client.go`

**Step 1: Add message constant**

Add to the message types constants:

```go
    MsgExcludeProcess      = 107
```

**Step 2: Add ExcludeSelf method**

Add method to DriverClient:

```go
// ExcludeSelf tells the minifilter to skip file operations from this process.
// Call this before mounting WinFsp to avoid double-interception.
func (c *DriverClient) ExcludeSelf() error {
    pid := uint32(os.Getpid())

    // Build message: header + processId
    msg := make([]byte, 16+4) // Header (16) + ProcessId (4)
    binary.LittleEndian.PutUint32(msg[0:4], MsgExcludeProcess)
    binary.LittleEndian.PutUint32(msg[4:8], uint32(len(msg)))
    binary.LittleEndian.PutUint64(msg[8:16], uint64(c.nextMessageID()))
    binary.LittleEndian.PutUint32(msg[16:20], pid)

    return c.sendRawMessage(msg)
}
```

**Step 3: Run windows tests**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && go test ./internal/platform/windows/... -v`
Expected: Tests pass

**Step 4: Commit**

```bash
git add internal/platform/windows/
git commit -m "feat(windows): add ExcludeSelf to driver client for WinFsp coexistence"
```

---

## Task 14: Integration - call ExcludeSelf before mount

**Files:**
- Modify: `internal/platform/windows/filesystem.go`

**Step 1: Update Mount to call ExcludeSelf**

Update the Mount function:

```go
// Mount creates a WinFsp mount.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	if !fs.Available() {
		return nil, fmt.Errorf("WinFsp not available: %s", fuse.InstallInstructions())
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.mounts[cfg.MountPoint]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	// Tell minifilter to exclude our process to avoid double-interception
	if client := GetDriverClient(); client != nil {
		if err := client.ExcludeSelf(); err != nil {
			// Log warning but continue - WinFsp will still work
			// just might have duplicate events
		}
	}

	mount, err := fuse.Mount(fuse.Config{
		FSConfig:   cfg,
		VolumeName: "agentsh",
	})
	if err != nil {
		return nil, err
	}

	fs.mounts[cfg.MountPoint] = mount
	return mount, nil
}
```

**Step 2: Verify it compiles**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && GOOS=windows go build ./internal/platform/windows/...`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add internal/platform/windows/
git commit -m "feat(windows): call ExcludeSelf before WinFsp mount"
```

---

## Task 15: Run all tests and verify

**Step 1: Run all platform tests**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && go test ./internal/platform/... -v`
Expected: All tests pass

**Step 2: Cross-compile for all platforms**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && GOOS=darwin go build ./... && GOOS=windows go build ./... && GOOS=linux go build ./...`
Expected: All builds succeed

**Step 3: Commit any fixes if needed**

```bash
git status
# If clean, no commit needed
```

---

## Task 16: Final cleanup and PR preparation

**Step 1: Review all changes**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && git log --oneline main..HEAD`
Expected: See all commits from this implementation

**Step 2: Run full test suite**

Run: `cd /home/eran/work/agentsh/.worktrees/windows-winfsp && go test ./... -v`
Expected: All tests pass

**Step 3: Push branch**

```bash
git push -u origin feature/windows-winfsp
```

**Step 4: Create PR using superpowers:finishing-a-development-branch skill**

---

## Summary

| Task | Description | Files Changed |
|------|-------------|---------------|
| 1 | Create fuse package skeleton | 2 new |
| 2 | Create mount stubs | 2 new |
| 3 | Add platform detection | 3 new |
| 4 | Extract FUSE operations | 2 new |
| 5 | Add platform-specific stat | 4 new |
| 6 | Implement Mount function | 2 modified |
| 7 | Add soft-delete support | 1 new, 1 modified |
| 8 | Add unit tests | 1 new |
| 9 | Update darwin to use shared | 3 modified, 1 deleted |
| 10 | Update windows to use shared | 1 modified |
| 11 | Minifilter exclusion - protocol | 1 modified |
| 12 | Minifilter exclusion - driver | 2 modified |
| 13 | Minifilter exclusion - Go | 1 modified |
| 14 | Integration - ExcludeSelf | 1 modified |
| 15 | Run all tests | - |
| 16 | Final cleanup and PR | - |
