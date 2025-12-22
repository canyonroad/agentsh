package fsmonitor

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/trash"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type Emitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

type Hooks struct {
	SessionID string
	Session   *session.Session
	Policy    *policy.Engine
	Approvals *approvals.Manager
	Emit      Emitter
	FUSEAudit *FUSEAuditHooks
}

func NewMonitoredLoopbackRoot(realRoot string, hooks *Hooks) (fs.InodeEmbedder, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(realRoot, &st); err != nil {
		return nil, err
	}

	lbRoot := &fs.LoopbackRoot{
		Path: realRoot,
		Dev:  uint64(st.Dev),
	}

	lbRoot.NewNode = func(rootData *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
		return &node{
			LoopbackNode: fs.LoopbackNode{RootData: rootData},
			hooks:        hooks,
		}
	}

	rootNode := lbRoot.NewNode(lbRoot, nil, "", &st)
	lbRoot.RootNode = rootNode
	return rootNode, nil
}

type node struct {
	fs.LoopbackNode
	hooks *Hooks
}

func (n *node) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	virt := n.virtualPath()
	dec := n.check(ctx, virt, "open")
	dec = n.maybeApprove(ctx, dec, "file", virt, "open")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "file_open", virt, "open", 0, dec, true, nil)
		return nil, 0, syscall.EACCES
	}

	n.emitFileEvent(ctx, "file_open", virt, "open", 0, dec, false, nil)
	if flags&uint32(syscall.O_TRUNC) != 0 {
		var inner fs.FileHandle
		var fFlags uint32
		errno = applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), "truncate_open", virt, "", "", nil, func() syscall.Errno {
			inner, fFlags, errno = n.LoopbackNode.Open(ctx, flags)
			return errno
		})
		if errno != 0 {
			return nil, 0, errno
		}
		return &fileHandle{inner: inner, n: n, virtPath: virt}, fFlags, errno
	}

	fh, fuseFlags, errno = n.LoopbackNode.Open(ctx, flags)
	if errno != 0 {
		return fh, fuseFlags, errno
	}
	return &fileHandle{inner: fh, n: n, virtPath: virt}, fuseFlags, errno
}

func (n *node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	virt := n.virtualChildPath(name)
	dec := n.check(ctx, virt, "create")
	dec = n.maybeApprove(ctx, dec, "file", virt, "create")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "file_create", virt, "create", 0, dec, true, nil)
		return nil, nil, 0, syscall.EACCES
	}

	inode, fh, fuseFlags, errno = n.LoopbackNode.Create(ctx, name, flags, mode, out)
	if errno != 0 {
		return inode, fh, fuseFlags, errno
	}

	extra := map[string]any{}
	if rp, err := n.realPath(virt, true); err == nil {
		if st, err := os.Stat(rp); err == nil {
			extra["size"] = st.Size()
			if stat, ok := st.Sys().(*syscall.Stat_t); ok {
				extra["nlink"] = stat.Nlink
			}
		}
	}
	n.emitFileEvent(ctx, "file_create", virt, "create", 0, dec, false, extra)

	return inode, &fileHandle{inner: fh, n: n, virtPath: virt}, fuseFlags, errno
}

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	virt := n.virtualChildPath(name)
	dec := n.check(ctx, virt, "delete")
	dec = n.maybeApprove(ctx, dec, "file", virt, "delete")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "file_delete", virt, "delete", 0, dec, true, nil)
		return syscall.EACCES
	}
	n.emitFileEvent(ctx, "file_delete", virt, "delete", 0, dec, false, nil)
	realPath, _ := n.realPath(virt, false)
	return applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), "unlink", virt, "", realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
		return n.LoopbackNode.Unlink(ctx, name)
	})
}

func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	virt := n.virtualChildPath(name)
	dec := n.check(ctx, virt, "rmdir")
	dec = n.maybeApprove(ctx, dec, "file", virt, "rmdir")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "dir_delete", virt, "rmdir", 0, dec, true, nil)
		return syscall.EACCES
	}
	n.emitFileEvent(ctx, "dir_delete", virt, "rmdir", 0, dec, false, nil)
	realPath, _ := n.realPath(virt, false)
	return applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), "rmdir", virt, "", realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
		return n.LoopbackNode.Rmdir(ctx, name)
	})
}

func (n *node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	virt := n.virtualChildPath(name)
	dec := n.check(ctx, virt, "mkdir")
	dec = n.maybeApprove(ctx, dec, "file", virt, "mkdir")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "dir_create", virt, "mkdir", 0, dec, true, nil)
		return nil, syscall.EACCES
	}
	n.emitFileEvent(ctx, "dir_create", virt, "mkdir", 0, dec, false, nil)
	return n.LoopbackNode.Mkdir(ctx, name, mode, out)
}

func (n *node) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	virtFrom := n.virtualChildPath(name)
	virtTo := path.Clean("/workspace/" + sanitizeName(newName))
	newParentNode, ok := newParent.(*node)
	if ok {
		virtTo = newParentNode.virtualChildPath(newName)
	}
	crossMount := !ok || newParentNode.RootData != n.RootData
	realPath, errReal := n.realPath(virtFrom, false)
	if errReal != nil {
		crossMount = true
	}
	intoMount := crossMount && ok && newParentNode.RootData == n.RootData

	decFrom := n.checkWithExist(ctx, virtFrom, "rename", true)
	decTo := n.checkWithExist(ctx, virtTo, "rename", false)
	dec := combinePathDecisionsForRename(decFrom, decTo)
	dec = n.maybeApprove(ctx, dec, "file", fmt.Sprintf("%s -> %s", virtFrom, virtTo), "rename")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "file_rename", virtFrom, "rename", 0, dec, true, map[string]any{"to_path": virtTo})
		return syscall.EACCES
	}
	n.emitFileEvent(ctx, "file_rename", virtFrom, "rename", 0, dec, false, map[string]any{"to_path": virtTo, "cross_mount": crossMount})

	// Cross-mount inside -> outside: treat as a delete.
	if crossMount && !intoMount {
		return applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), "unlink", virtFrom, "", realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
			return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
		})
	}

	errno := applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), "rename", virtFrom, virtTo, realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
		return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
	})
	if errno != 0 {
		return errno
	}

	// Cross-mount outside -> inside: emit a create event with metadata after the move completes.
	if intoMount {
		extra := map[string]any{"from_path": virtFrom, "cross_mount": true}
		if rp, err := newParentNode.realPath(virtTo, true); err == nil {
			if st, err := os.Stat(rp); err == nil {
				extra["size"] = st.Size()
				if stat, ok := st.Sys().(*syscall.Stat_t); ok {
					extra["nlink"] = stat.Nlink
				}
			}
		}
		n.emitFileEvent(ctx, "file_create", virtTo, "create", 0, dec, false, extra)
	}

	return errno
}

func (n *node) OpendirHandle(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	virt := n.virtualPath()
	dec := n.check(ctx, virt, "list")
	dec = n.maybeApprove(ctx, dec, "file", virt, "list")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "dir_list", virt, "list", 0, dec, true, nil)
		return nil, 0, syscall.EACCES
	}
	n.emitFileEvent(ctx, "dir_list", virt, "list", 0, dec, false, nil)
	return n.LoopbackNode.OpendirHandle(ctx, flags)
}

func (n *node) Opendir(ctx context.Context) syscall.Errno {
	virt := n.virtualPath()
	dec := n.check(ctx, virt, "list")
	dec = n.maybeApprove(ctx, dec, "file", virt, "list")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "dir_list", virt, "list", 0, dec, true, nil)
		return syscall.EACCES
	}
	n.emitFileEvent(ctx, "dir_list", virt, "list", 0, dec, false, nil)
	// LoopbackNode's default Opendir is OK; directory reads flow through Readdir.
	return 0
}

func (n *node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	virt := n.virtualPath()
	dec := n.check(ctx, virt, "list")
	dec = n.maybeApprove(ctx, dec, "file", virt, "list")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "dir_list", virt, "list", 0, dec, true, nil)
		return nil, syscall.EACCES
	}
	n.emitFileEvent(ctx, "dir_list", virt, "list", 0, dec, false, nil)
	return n.LoopbackNode.Readdir(ctx)
}

func (n *node) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	virt := n.virtualPath()
	dec := n.check(ctx, virt, "stat")
	dec = n.maybeApprove(ctx, dec, "file", virt, "stat")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "file_stat", virt, "stat", 0, dec, true, nil)
		return syscall.EACCES
	}
	n.emitFileEvent(ctx, "file_stat", virt, "stat", 0, dec, false, nil)
	return n.LoopbackNode.Getattr(ctx, f, out)
}

func (n *node) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	virt := n.virtualPath()
	// Most common for agents: chmod.
	if in.Valid&fuse.FATTR_MODE != 0 {
		dec := n.check(ctx, virt, "chmod")
		dec = n.maybeApprove(ctx, dec, "file", virt, "chmod")
		extra := map[string]any{"mode": fmt.Sprintf("0%o", in.Mode)}
		if dec.EffectiveDecision == types.DecisionDeny {
			n.emitFileEvent(ctx, "file_chmod", virt, "chmod", 0, dec, true, extra)
			return syscall.EACCES
		}
		n.emitFileEvent(ctx, "file_chmod", virt, "chmod", 0, dec, false, extra)
		return n.LoopbackNode.Setattr(ctx, f, in, out)
	}

	if in.Valid&fuse.FATTR_SIZE != 0 {
		return applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), "truncate", virt, "", "", nil, func() syscall.Errno {
			return n.LoopbackNode.Setattr(ctx, f, in, out)
		})
	}

	return n.LoopbackNode.Setattr(ctx, f, in, out)
}

func (n *node) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (node *fs.Inode, errno syscall.Errno) {
	virt := n.virtualChildPath(name)
	dec := n.checkWithExist(ctx, virt, "create", false)
	dec = n.maybeApprove(ctx, dec, "file", virt, "create")
	extra := map[string]any{"target": target}
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "symlink_create", virt, "create", 0, dec, true, extra)
		return nil, syscall.EACCES
	}
	n.emitFileEvent(ctx, "symlink_create", virt, "create", 0, dec, false, extra)
	return n.LoopbackNode.Symlink(ctx, target, name, out)
}

func (n *node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	virt := n.virtualPath()
	dec := n.check(ctx, virt, "readlink")
	dec = n.maybeApprove(ctx, dec, "file", virt, "readlink")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "symlink_read", virt, "readlink", 0, dec, true, nil)
		return nil, syscall.EACCES
	}
	n.emitFileEvent(ctx, "symlink_read", virt, "readlink", 0, dec, false, nil)
	return n.LoopbackNode.Readlink(ctx)
}

type fileHandle struct {
	inner    fs.FileHandle
	n        *node
	virtPath string
}

func (f *fileHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	dec := f.n.check(ctx, f.virtPath, "read")
	dec = f.n.maybeApprove(ctx, dec, "file", f.virtPath, "read")
	if dec.EffectiveDecision == types.DecisionDeny {
		f.n.emitFileEvent(ctx, "file_read", f.virtPath, "read", int64(len(dest)), dec, true, nil)
		return nil, syscall.EACCES
	}
	f.n.emitFileEvent(ctx, "file_read", f.virtPath, "read", int64(len(dest)), dec, false, nil)
	if r, ok := f.inner.(fs.FileReader); ok {
		return r.Read(ctx, dest, off)
	}
	return nil, syscall.ENOSYS
}

func (f *fileHandle) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	dec := f.n.check(ctx, f.virtPath, "write")
	dec = f.n.maybeApprove(ctx, dec, "file", f.virtPath, "write")
	if dec.EffectiveDecision == types.DecisionDeny {
		f.n.emitFileEvent(ctx, "file_write", f.virtPath, "write", int64(len(data)), dec, true, nil)
		return 0, syscall.EACCES
	}
	nwritten := uint32(0)
	var errno syscall.Errno
	if w, ok := f.inner.(fs.FileWriter); ok {
		nwritten, errno = w.Write(ctx, data, off)
	} else {
		errno = syscall.ENOSYS
	}
	extra := map[string]any{}
	if errno == 0 {
		if real, err := f.n.realPath(f.virtPath, true); err == nil {
			if st, err := os.Stat(real); err == nil {
				extra["size"] = st.Size()
			}
		}
	}
	f.n.emitFileEvent(ctx, "file_write", f.virtPath, "write", int64(nwritten), dec, errno != 0, extra)
	return nwritten, errno
}

func (f *fileHandle) Release(ctx context.Context) syscall.Errno {
	if r, ok := f.inner.(fs.FileReleaser); ok {
		return r.Release(ctx)
	}
	return 0
}

func (n *node) check(ctx context.Context, virtPath string, op string) policy.Decision {
	mustExist := op != "create" && op != "mkdir"
	return n.checkWithExist(ctx, virtPath, op, mustExist)
}

func (n *node) checkWithExist(_ context.Context, virtPath string, op string, mustExist bool) policy.Decision {
	realRoot := ""
	if n.RootData != nil {
		realRoot = n.RootData.Path
	}
	if realRoot != "" {
		if _, err := resolveRealPathUnderRoot(realRoot, virtPath, mustExist); err != nil {
			return policy.Decision{
				PolicyDecision:    types.DecisionDeny,
				EffectiveDecision: types.DecisionDeny,
				Rule:              "workspace-escape",
				Message:           err.Error(),
			}
		}
	}

	if n.hooks == nil || n.hooks.Policy == nil {
		return policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	return n.hooks.Policy.CheckFile(virtPath, op)
}

func combinePathDecisionsForRename(a, b policy.Decision) policy.Decision {
	if a.EffectiveDecision == types.DecisionDeny {
		return a
	}
	if b.EffectiveDecision == types.DecisionDeny {
		return b
	}

	if a.PolicyDecision == types.DecisionApprove || b.PolicyDecision == types.DecisionApprove {
		out := a
		if a.PolicyDecision != types.DecisionApprove {
			out = b
		}
		out.PolicyDecision = types.DecisionApprove
		out.EffectiveDecision = types.DecisionAllow
		if a.EffectiveDecision == types.DecisionApprove || b.EffectiveDecision == types.DecisionApprove {
			out.EffectiveDecision = types.DecisionApprove
		}
		if out.Approval == nil {
			if a.Approval != nil {
				out.Approval = a.Approval
			} else if b.Approval != nil {
				out.Approval = b.Approval
			}
		}
		return out
	}

	return policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
}

func (n *node) maybeApprove(ctx context.Context, dec policy.Decision, kind, target, op string) policy.Decision {
	if dec.PolicyDecision != types.DecisionApprove || dec.EffectiveDecision != types.DecisionApprove {
		return dec
	}
	if n.hooks == nil || n.hooks.Approvals == nil {
		return dec
	}
	req := approvals.Request{
		ID:        "approval-" + uuid.NewString(),
		SessionID: n.hooks.SessionID,
		CommandID: "",
		Kind:      kind,
		Target:    target,
		Rule:      dec.Rule,
		Message:   dec.Message,
		Fields: map[string]any{
			"operation": op,
		},
	}
	if n.hooks.Session != nil {
		req.CommandID = n.hooks.Session.CurrentCommandID()
	}
	res, err := n.hooks.Approvals.RequestApproval(ctx, req)
	if dec.Approval != nil {
		dec.Approval.ID = req.ID
	}
	if err != nil || !res.Approved {
		dec.EffectiveDecision = types.DecisionDeny
	} else {
		dec.EffectiveDecision = types.DecisionAllow
	}
	return dec
}

func (n *node) emitFileEvent(ctx context.Context, evType string, virtPath string, op string, bytes int64, dec policy.Decision, blocked bool, extra map[string]any) {
	if n.hooks == nil || n.hooks.Emit == nil {
		return
	}
	commandID := ""
	if n.hooks.Session != nil {
		commandID = n.hooks.Session.CurrentCommandID()
	}
	pid := 0
	if caller, ok := fuse.FromContext(ctx); ok {
		pid = int(caller.Pid)
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      evType,
		SessionID: n.hooks.SessionID,
		CommandID: commandID,
		PID:       pid,
		Path:      virtPath,
		Operation: op,
		Fields:    map[string]any{},
		Policy: &types.PolicyInfo{
			Decision:          dec.PolicyDecision,
			EffectiveDecision: dec.EffectiveDecision,
			Rule:              dec.Rule,
			Message:           dec.Message,
			Approval:          dec.Approval,
		},
	}
	ev.Fields["bytes"] = bytes
	ev.Fields["blocked"] = blocked
	for k, v := range extra {
		ev.Fields[k] = v
	}
	if err := n.hooks.Emit.AppendEvent(ctx, ev); err != nil {
		fmt.Fprintf(os.Stderr, "fuse: failed to append event (type=%s path=%s): %v\n", evType, virtPath, err)
	}
	n.hooks.Emit.Publish(ev)
}

func (n *node) virtualPath() string {
	rel := ""
	if n.RootData != nil && n.RootData.RootNode != nil {
		rel = n.Path(n.RootData.RootNode.EmbeddedInode())
	} else {
		rel = n.Path(nil)
	}
	if rel == "" || rel == "." {
		return "/workspace"
	}
	return path.Clean("/workspace/" + filepath.ToSlash(rel))
}

func (n *node) virtualChildPath(name string) string {
	base := n.virtualPath()
	if base == "/workspace" {
		return path.Clean("/workspace/" + sanitizeName(name))
	}
	return path.Clean(base + "/" + sanitizeName(name))
}

func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Clean("/" + name)
	return strings.TrimPrefix(name, "/")
}

func (n *node) auditHooks() *FUSEAuditHooks {
	if n == nil || n.hooks == nil {
		return nil
	}
	return n.hooks.FUSEAudit
}

func (n *node) hooksSessionID() string {
	if n == nil || n.hooks == nil {
		return ""
	}
	return n.hooks.SessionID
}

func (n *node) realPath(virt string, mustExist bool) (string, error) {
	root := ""
	if n.RootData != nil {
		root = n.RootData.Path
	}
	return resolveRealPathUnderRoot(root, virt, mustExist)
}

func (n *node) makeDivertFunc(realPath string) func() (*trash.Entry, error) {
	h := n.auditHooks()
	if h == nil || realPath == "" {
		return nil
	}
	trashPath := h.Config.TrashPath
	if trashPath == "" {
		trashPath = ".agentsh_trash"
	}
	if !filepath.IsAbs(trashPath) && n.RootData != nil {
		trashPath = filepath.Join(n.RootData.Path, trashPath)
	}
	sessionID := n.hooksSessionID()
	hashLimit := h.HashLimitBytes
	return func() (*trash.Entry, error) {
		return trash.Divert(realPath, trash.Config{
			TrashDir:       trashPath,
			Session:        sessionID,
			HashLimitBytes: hashLimit,
		})
	}
}
