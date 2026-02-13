// internal/platform/fuse/ops.go
//go:build cgo

package fuse

import (
	"os"
	"path/filepath"
	"time"

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
// Uses the source path (not mount point) for policy evaluation because
// policy rules reference ${PROJECT_ROOT} which resolves to the workspace source path.
func (f *fuseFS) checkPolicy(fusePath string, operation platform.FileOperation) platform.Decision {
	if f.cfg.PolicyEngine == nil {
		return platform.DecisionAllow
	}
	return f.cfg.PolicyEngine.CheckFile(f.realPath(fusePath), operation)
}

// emitEvent emits a file event if an event channel is configured.
func (f *fuseFS) emitEvent(eventType, virtPath string, operation platform.FileOperation, decision platform.Decision, blocked bool) {
	f.totalOps.Add(1)
	if blocked {
		f.deniedOps.Add(1)
	} else {
		f.allowedOps.Add(1)
	}

	// Skip if no event channel configured
	if f.cfg.EventChannel == nil {
		return
	}

	// Build the event
	event := platform.IOEvent{
		Timestamp: time.Now(),
		SessionID: f.cfg.SessionID,
		Type:      platform.EventType(eventType),
		Path:      virtPath,
		Operation: operation,
		Decision:  decision,
		Platform:  "fuse",
	}

	// Get command ID if function is available
	if f.cfg.CommandIDFunc != nil {
		event.CommandID = f.cfg.CommandIDFunc()
	}

	// Non-blocking send to avoid slowing down FUSE operations
	select {
	case f.cfg.EventChannel <- event:
	default:
		// Channel full or closed, drop the event
	}
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
	decision := f.checkPolicy(path, platform.FileOpList)
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

	decision := f.checkPolicy(path, operation)
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
		fusePath: path,
		flags:    flags,
		file:     file,
	})

	return 0, fh
}

func (f *fuseFS) Create(path string, flags int, mode uint32) (int, uint64) {
	virtPath := f.virtPath(path)

	decision := f.checkPolicy(path, platform.FileOpCreate)
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
		fusePath: path,
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

	decision := f.checkPolicy(openFile.fusePath, platform.FileOpWrite)
	if decision == platform.DecisionDeny {
		f.emitEvent("file_write", openFile.virtPath, platform.FileOpWrite, decision, true)
		return -fuse.EACCES
	}
	f.emitEvent("file_write", openFile.virtPath, platform.FileOpWrite, decision, false)

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
	realPath := f.realPath(path)

	decision := f.checkPolicy(path, platform.FileOpDelete)

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

func (f *fuseFS) Mkdir(path string, mode uint32) int {
	virtPath := f.virtPath(path)

	decision := f.checkPolicy(path, platform.FileOpCreate)
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

	decision := f.checkPolicy(path, platform.FileOpDelete)
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

	decision := f.checkPolicy(oldpath, platform.FileOpRename)
	if decision == platform.DecisionDeny {
		f.emitEvent("file_rename", virtOldPath, platform.FileOpRename, decision, true)
		return -fuse.EACCES
	}
	decision = f.checkPolicy(newpath, platform.FileOpRename)
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

	decision := f.checkPolicy(path, platform.FileOpWrite)
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

	decision := f.checkPolicy(newpath, platform.FileOpCreate)
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

	decision := f.checkPolicy(path, platform.FileOpRead)
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

	decision := f.checkPolicy(newpath, platform.FileOpCreate)
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

	decision := f.checkPolicy(path, platform.FileOpWrite)
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
