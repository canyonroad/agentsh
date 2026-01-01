//go:build darwin && cgo

package darwin

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/winfsp/cgofuse/fuse"
)

// virtPath converts a FUSE path to the virtual path seen by the agent.
func (f *fuseFS) virtPath(path string) string {
	// FUSE paths are relative to mount point, starting with /
	// Virtual paths should be absolute starting with /workspace or similar
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

	if f.cfg.EventChannel == nil {
		return
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
	// Check for syscall.Errno
	if errno, ok := err.(syscall.Errno); ok {
		return -int(errno)
	}
	return -fuse.EIO
}

// --- FUSE Operations ---

// Statfs returns filesystem statistics.
func (f *fuseFS) Statfs(path string, stat *fuse.Statfs_t) int {
	// Return reasonable defaults
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

// Getattr gets file attributes.
func (f *fuseFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) int {
	realPath := f.realPath(path)
	info, err := os.Lstat(realPath)
	if err != nil {
		return toErrno(err)
	}
	fillStat(stat, info)
	return 0
}

// fillStat fills a fuse.Stat_t from os.FileInfo.
func fillStat(stat *fuse.Stat_t, info os.FileInfo) {
	stat.Size = info.Size()
	stat.Mtim = fuse.NewTimespec(info.ModTime())
	stat.Atim = stat.Mtim
	stat.Ctim = stat.Mtim

	mode := uint32(info.Mode().Perm())
	if info.IsDir() {
		mode |= fuse.S_IFDIR
	} else if info.Mode()&os.ModeSymlink != 0 {
		mode |= fuse.S_IFLNK
	} else {
		mode |= fuse.S_IFREG
	}
	stat.Mode = mode
	stat.Nlink = 1

	// Get UID/GID from syscall stat if available
	if sys := info.Sys(); sys != nil {
		if s, ok := sys.(*syscall.Stat_t); ok {
			stat.Uid = s.Uid
			stat.Gid = s.Gid
			stat.Nlink = uint32(s.Nlink)
			stat.Ino = s.Ino
			stat.Dev = uint64(s.Dev)
			stat.Atim = fuse.NewTimespec(time.Unix(s.Atimespec.Sec, s.Atimespec.Nsec))
			stat.Ctim = fuse.NewTimespec(time.Unix(s.Ctimespec.Sec, s.Ctimespec.Nsec))
		}
	}
}

// Opendir opens a directory.
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

// Readdir reads directory contents.
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

// Open opens a file.
func (f *fuseFS) Open(path string, flags int) (int, uint64) {
	virtPath := f.virtPath(path)

	// Determine operation based on flags
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

// Create creates and opens a file.
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

// Read reads from a file.
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

// Write writes to a file.
func (f *fuseFS) Write(path string, buff []byte, ofst int64, fh uint64) int {
	of, ok := f.openFiles.Load(fh)
	if !ok {
		return -fuse.EBADF
	}
	openFile := of.(*openFile)

	// Check write policy
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

// Release closes a file handle.
func (f *fuseFS) Release(path string, fh uint64) int {
	of, ok := f.openFiles.LoadAndDelete(fh)
	if !ok {
		return 0
	}
	openFile := of.(*openFile)
	openFile.file.Close()
	return 0
}

// Unlink removes a file.
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

// Mkdir creates a directory.
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

// Rmdir removes a directory.
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

// Rename renames a file or directory.
func (f *fuseFS) Rename(oldpath string, newpath string) int {
	virtOldPath := f.virtPath(oldpath)
	virtNewPath := f.virtPath(newpath)

	// Check both paths
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

// Chmod changes file permissions.
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

// Symlink creates a symbolic link.
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

// Readlink reads a symbolic link.
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

// Link creates a hard link.
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

// Truncate truncates a file.
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

// Utimens sets file access and modification times.
func (f *fuseFS) Utimens(path string, tmsp []fuse.Timespec) int {
	realPath := f.realPath(path)
	if len(tmsp) < 2 {
		return -fuse.EINVAL
	}

	atime := time.Unix(tmsp[0].Sec, tmsp[0].Nsec)
	mtime := time.Unix(tmsp[1].Sec, tmsp[1].Nsec)

	if err := os.Chtimes(realPath, atime, mtime); err != nil {
		return toErrno(err)
	}
	return 0
}

// Access checks file access permissions.
func (f *fuseFS) Access(path string, mask uint32) int {
	realPath := f.realPath(path)
	if _, err := os.Stat(realPath); err != nil {
		return toErrno(err)
	}
	return 0
}

// Chown changes file ownership.
func (f *fuseFS) Chown(path string, uid uint32, gid uint32) int {
	realPath := f.realPath(path)
	if err := os.Chown(realPath, int(uid), int(gid)); err != nil {
		return toErrno(err)
	}
	return 0
}

// Flush flushes cached data.
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

// Fsync synchronizes file contents.
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
