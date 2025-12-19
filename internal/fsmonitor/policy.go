package fsmonitor

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/fsmonitor/audit"
	"github.com/agentsh/agentsh/internal/trash"
)

type auditSink interface {
	Log(audit.Event) error
}

// FUSEAuditHooks carries audit config and sink for the FUSE layer.
type FUSEAuditHooks struct {
	Sink             auditSink
	Config           config.FUSEAuditConfig
	NotifySoftDelete func(path, token string)
	HashLimitBytes   int64
}

// applyAuditPolicy enforces the configured mode for a destructive operation and logs it.
// It returns an errno to use for the FUSE handler.
func applyAuditPolicy(ctx context.Context, hooks *FUSEAuditHooks, sessionID string, op string, path string, dest string, realPath string, divert func() (*trash.Entry, error), run func() syscall.Errno) syscall.Errno {
	if hooks == nil {
		return run()
	}

	if hooks.Config.Enabled != nil && !*hooks.Config.Enabled {
		return run()
	}

	mode := hooks.Config.Mode
	if mode == "" {
		mode = "monitor"
	}
	strict := hooks.Config.StrictOnAuditFailure || mode == "strict"
	// strict behaves like monitor but fails the operation if logging fails.
	if mode == "strict" {
		mode = "monitor"
	}

	var size int64
	var nlink int
	if realPath != "" {
		if st, err := os.Lstat(realPath); err == nil {
			size = st.Size()
			if stat, ok := st.Sys().(*syscall.Stat_t); ok {
				nlink = int(stat.Nlink)
			}
		}
	}

	send := func(result string, reason string, token string) error {
		if hooks.Sink == nil {
			return nil
		}
		return hooks.Sink.Log(audit.Event{
			Op:         op,
			Path:       path,
			DstPath:    dest,
			Result:     result,
			Reason:     reason,
			TrashToken: token,
			Session:    sessionID,
			Size:       size,
			LinkCount:  nlink,
		})
	}

	handleSendErr := func(errno syscall.Errno, err error) syscall.Errno {
		if err == nil {
			return errno
		}
		if strict {
			return syscall.EIO
		}
		return errno
	}

	switch mode {
	case "soft_block":
		return handleSendErr(syscall.EACCES, send("blocked", "soft_block", ""))
	case "soft_delete":
		if divert == nil {
			return handleSendErr(syscall.EIO, send("error", "soft_delete_no_handler", ""))
		}
		entry, err := divert()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Already gone; treat as allowed/no-op.
				return handleSendErr(0, send("allowed", "not_found", ""))
			}
			return handleSendErr(syscall.EIO, send("error", err.Error(), ""))
		}
		if entry != nil && entry.Size > 0 {
			size = entry.Size
		}
		if hooks.NotifySoftDelete != nil && entry != nil {
			hooks.NotifySoftDelete(path, entry.Token)
		}
		return handleSendErr(0, send("diverted", "soft_delete", entry.Token))
	default: // monitor
		errno := run()
		res := "allowed"
		if errno != 0 {
			res = "error"
		}
		return handleSendErr(errno, send(res, "", ""))
	}
}
