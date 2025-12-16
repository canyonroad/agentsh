package fsmonitor

import (
	"context"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
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
		n.emitFileEvent(ctx, "file_open", virt, "open", 0, dec, true)
		return nil, 0, syscall.EACCES
	}

	n.emitFileEvent(ctx, "file_open", virt, "open", 0, dec, false)
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
		n.emitFileEvent(ctx, "file_create", virt, "create", 0, dec, true)
		return nil, nil, 0, syscall.EACCES
	}

	n.emitFileEvent(ctx, "file_create", virt, "create", 0, dec, false)
	inode, fh, fuseFlags, errno = n.LoopbackNode.Create(ctx, name, flags, mode, out)
	if errno != 0 {
		return inode, fh, fuseFlags, errno
	}
	return inode, &fileHandle{inner: fh, n: n, virtPath: virt}, fuseFlags, errno
}

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	virt := n.virtualChildPath(name)
	dec := n.check(ctx, virt, "delete")
	dec = n.maybeApprove(ctx, dec, "file", virt, "delete")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "file_delete", virt, "delete", 0, dec, true)
		return syscall.EACCES
	}
	n.emitFileEvent(ctx, "file_delete", virt, "delete", 0, dec, false)
	return n.LoopbackNode.Unlink(ctx, name)
}

func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	virt := n.virtualChildPath(name)
	dec := n.check(ctx, virt, "rmdir")
	dec = n.maybeApprove(ctx, dec, "file", virt, "rmdir")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "dir_delete", virt, "rmdir", 0, dec, true)
		return syscall.EACCES
	}
	n.emitFileEvent(ctx, "dir_delete", virt, "rmdir", 0, dec, false)
	return n.LoopbackNode.Rmdir(ctx, name)
}

func (n *node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	virt := n.virtualChildPath(name)
	dec := n.check(ctx, virt, "mkdir")
	dec = n.maybeApprove(ctx, dec, "file", virt, "mkdir")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "dir_create", virt, "mkdir", 0, dec, true)
		return nil, syscall.EACCES
	}
	n.emitFileEvent(ctx, "dir_create", virt, "mkdir", 0, dec, false)
	return n.LoopbackNode.Mkdir(ctx, name, mode, out)
}

func (n *node) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	virtFrom := n.virtualChildPath(name)
	dec := n.check(ctx, virtFrom, "rename")
	dec = n.maybeApprove(ctx, dec, "file", virtFrom, "rename")
	if dec.EffectiveDecision == types.DecisionDeny {
		n.emitFileEvent(ctx, "file_rename", virtFrom, "rename", 0, dec, true)
		return syscall.EACCES
	}
	n.emitFileEvent(ctx, "file_rename", virtFrom, "rename", 0, dec, false)
	return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
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
		f.n.emitFileEvent(ctx, "file_read", f.virtPath, "read", int64(len(dest)), dec, true)
		return nil, syscall.EACCES
	}
	f.n.emitFileEvent(ctx, "file_read", f.virtPath, "read", int64(len(dest)), dec, false)
	if r, ok := f.inner.(fs.FileReader); ok {
		return r.Read(ctx, dest, off)
	}
	return nil, syscall.ENOSYS
}

func (f *fileHandle) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	dec := f.n.check(ctx, f.virtPath, "write")
	dec = f.n.maybeApprove(ctx, dec, "file", f.virtPath, "write")
	if dec.EffectiveDecision == types.DecisionDeny {
		f.n.emitFileEvent(ctx, "file_write", f.virtPath, "write", int64(len(data)), dec, true)
		return 0, syscall.EACCES
	}
	f.n.emitFileEvent(ctx, "file_write", f.virtPath, "write", int64(len(data)), dec, false)
	if w, ok := f.inner.(fs.FileWriter); ok {
		return w.Write(ctx, data, off)
	}
	return 0, syscall.ENOSYS
}

func (f *fileHandle) Release(ctx context.Context) syscall.Errno {
	if r, ok := f.inner.(fs.FileReleaser); ok {
		return r.Release(ctx)
	}
	return 0
}

func (n *node) check(_ context.Context, virtPath string, op string) policy.Decision {
	// Prevent symlink/.. traversal outside the session workspace root.
	realRoot := ""
	if n.RootData != nil {
		realRoot = n.RootData.Path
	}
	mustExist := op != "create" && op != "mkdir"
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

func (n *node) emitFileEvent(ctx context.Context, evType string, virtPath string, op string, bytes int64, dec policy.Decision, blocked bool) {
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
		Fields: map[string]any{
			"bytes":   bytes,
			"blocked": blocked,
		},
		Policy: &types.PolicyInfo{
			Decision:          dec.PolicyDecision,
			EffectiveDecision: dec.EffectiveDecision,
			Rule:              dec.Rule,
			Message:           dec.Message,
			Approval:          dec.Approval,
		},
	}
	_ = n.hooks.Emit.AppendEvent(ctx, ev)
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
