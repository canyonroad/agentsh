//go:build linux && cgo

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/netmonitor"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// recoverTimeout is the maximum time to spend persisting a panic event
// in the recovery path. Prevents a slow store from blocking broker delivery.
const recoverTimeout = 5 * time.Second
// This prevents blocking forever if the wrapper fails to set up seccomp.
const recvFDTimeout = 10 * time.Second

// notifyEmitterAdapter adapts the API's event store/broker to the unix handler's Emitter interface.
type notifyEmitterAdapter struct {
	store  eventStore
	broker eventBroker
}

func (a *notifyEmitterAdapter) AppendEvent(ctx context.Context, ev types.Event) error {
	return a.store.AppendEvent(ctx, ev)
}

func (a *notifyEmitterAdapter) Publish(ev types.Event) {
	a.broker.Publish(ev)
}

// createExecveHandler creates an ExecveHandler from the configuration.
// Returns nil if the config is not valid or policy is nil.
func createExecveHandler(cfg config.ExecveConfig, pol *policy.Engine, approvalMgr *approvals.Manager) any {
	if !cfg.Enabled {
		return nil
	}

	// Create depth tracker for process ancestry tracking
	dt := unixmon.NewDepthTracker()

	handlerCfg := unixmon.ExecveHandlerConfig{
		MaxArgc:               cfg.MaxArgc,
		MaxArgvBytes:          cfg.MaxArgvBytes,
		OnTruncated:           cfg.OnTruncated,
		ApprovalTimeout:       cfg.ApprovalTimeout,
		ApprovalTimeoutAction: cfg.ApprovalTimeoutAction,
		InternalBypass:        cfg.InternalBypass,
	}

	// Create policy checker wrapper if policy engine exists
	var policyChecker unixmon.PolicyChecker
	if pol != nil {
		policyChecker = &policyEngineWrapper{engine: pol}
	}

	h := unixmon.NewExecveHandler(handlerCfg, policyChecker, dt, nil)
	if pol != nil {
		if tc := pol.TransparentOverrides(); tc != nil {
			h.SetTransparentOverrides(&netmonitor.TransparentOverrides{
				Add:    tc.Add,
				Remove: tc.Remove,
			})
		}
	}
	if approvalMgr != nil {
		h.SetApprover(&approvalRequesterAdapter{mgr: approvalMgr})
	}
	return h
}

// policyEngineWrapper adapts policy.Engine to unixmon.PolicyChecker.
type policyEngineWrapper struct {
	engine *policy.Engine
}

func (w *policyEngineWrapper) CheckExecve(filename string, argv []string, depth int) unixmon.PolicyDecision {
	dec := w.engine.CheckExecve(filename, argv, depth)
	// Return both PolicyDecision (for logging) and EffectiveDecision (for enforcement)
	return unixmon.PolicyDecision{
		Decision:          string(dec.PolicyDecision),
		EffectiveDecision: string(dec.EffectiveDecision),
		Rule:              dec.Rule,
		Message:           dec.Message,
		Redirect:          dec.Redirect,
	}
}

// approvalRequesterAdapter adapts approvals.Manager to unixmon.ApprovalRequester.
type approvalRequesterAdapter struct {
	mgr *approvals.Manager
}

func (a *approvalRequesterAdapter) RequestExecApproval(ctx context.Context, req unixmon.ApprovalRequest) (bool, error) {
	apr := approvals.Request{
		ID:        "approval-" + uuid.NewString(),
		SessionID: req.SessionID,
		Kind:      "command",
		Target:    req.Command,
		Rule:      req.Rule,
		Message:   req.Reason,
		Fields: map[string]any{
			"command": req.Command,
			"args":    req.Args,
			"source":  "execve",
		},
	}
	res, err := a.mgr.RequestApproval(ctx, apr)
	if err != nil {
		return false, err
	}
	return res.Approved, nil
}

// notifyHandlerRecover is the deferred recovery function for the notify handler
// goroutine. It logs the panic with a stack trace, persists an event to the
// store, and publishes it to the broker (both best-effort). Each sink is
// isolated so one panicking doesn't prevent the other from running. Extracted
// for testability.
func notifyHandlerRecover(sessID string, store eventStore, broker eventBroker) {
	r := recover()
	if r == nil {
		return
	}
	slog.Error("panic in notify handler", "recover", r, "session_id", sessID, "stack", string(debug.Stack()))
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      string(events.EventNotifyHandlerPanic),
		SessionID: sessID,
		Fields: map[string]any{
			"error": fmt.Sprint(r),
		},
	}
	// Run store and broker delivery concurrently so a slow/blocking store
	// cannot prevent broker publish. Both are best-effort with panic guards.
	delivered := make(chan struct{})
	if store != nil {
		go func() {
			defer func() { recover() }()
			ctx, cancel := context.WithTimeout(context.Background(), recoverTimeout)
			defer cancel()
			_ = store.AppendEvent(ctx, ev)
		}()
	}
	if broker != nil {
		go func() {
			defer close(delivered)
			defer func() { recover() }()
			broker.Publish(ev)
		}()
	} else {
		close(delivered)
	}
	// Wait for broker delivery (bounded) but don't wait for store.
	select {
	case <-delivered:
	case <-time.After(recoverTimeout):
	}
}

// startNotifyHandler receives the seccomp notify fd from the parent socket and
// starts the ServeNotify handler in a goroutine. It returns immediately.
// The handler runs until ctx is cancelled or the fd is closed.
// If execveHandler is non-nil, uses ServeNotifyWithExecve for execve interception.
func startNotifyHandler(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker, execveHandler any, fileMonitorCfg config.SandboxSeccompFileMonitorConfig, landlockEnabled bool, ptraceReady chan<- error) {
	if parentSock == nil {
		return
	}

	// Run the entire receive and serve logic in a goroutine to return immediately
	go func() {
		defer notifyHandlerRecover(sessID, store, broker)
		defer parentSock.Close()
		// Ensure ptraceReady is always signaled on all exit paths to prevent
		// the main goroutine from blocking forever in hybrid mode.
		defer func() {
			if ptraceReady != nil {
				select {
				case ptraceReady <- fmt.Errorf("notify handler exited without signaling READY"):
				default: // already signaled
				}
			}
		}()
		slog.Debug("notify handler started", "session_id", sessID)

		// Get the wrapper's PID from socket credentials for session tracking
		// This is the process that will exec the user's command
		var wrapperPID int
		ucred, err := unix.GetsockoptUcred(int(parentSock.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			slog.Debug("failed to get socket peer credentials", "error", err)
		} else {
			wrapperPID = int(ucred.Pid)
			slog.Debug("got wrapper PID from socket credentials", "wrapper_pid", wrapperPID, "session_id", sessID)
		}

		// Set SO_RCVTIMEO directly on the socket. unixmon.RecvFD calls recvmsg
		// on the raw fd, bypassing Go's netpoll — so SetReadDeadline wouldn't
		// apply. SO_RCVTIMEO is a kernel-level timeout that works with raw
		// blocking recvmsg.
		tv := unix.NsecToTimeval(recvFDTimeout.Nanoseconds())
		if err := unix.SetsockoptTimeval(int(parentSock.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			slog.Debug("failed to set SO_RCVTIMEO on notify socket", "error", err, "session_id", sessID)
			// Don't return - RecvFD will still work, just without a timeout
		}

		// Receive the notify fd from the wrapper process
		slog.Debug("waiting to receive notify fd from wrapper", "session_id", sessID)
		notifyFD, err := unixmon.RecvFD(parentSock)
		if err != nil {
			slog.Debug("failed to receive notify fd", "error", err, "session_id", sessID)
			return
		}

		if notifyFD == nil {
			slog.Debug("received nil notify fd", "session_id", sessID)
			return
		}
		slog.Debug("received notify fd from wrapper", "fd", notifyFD.Fd(), "session_id", sessID)
		defer notifyFD.Close()

		// Clear SO_RCVTIMEO now that FD handoff is complete. Otherwise the
		// 10s timeout we set for RecvFD would persist on the socket and
		// shorten the later READY byte read below (which expects 30s).
		if err := unix.SetsockoptTimeval(int(parentSock.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{}); err != nil {
			slog.Debug("failed to clear SO_RCVTIMEO on notify socket", "error", err, "session_id", sessID)
		}

		// Close the notify FD when context is cancelled to unblock any stuck
		// NotifReceive ioctl. The done channel ensures this goroutine exits
		// if the handler returns early (error/setup failure) while context
		// is still active.
		handlerDone := make(chan struct{})
		defer close(handlerDone)
		go func() {
			select {
			case <-ctx.Done():
				notifyFD.Close()
			case <-handlerDone:
			}
		}()

		emitter := &notifyEmitterAdapter{store: store, broker: broker}

		// Create file handler if configured
		fileHandler := createFileHandler(fileMonitorCfg, pol, emitter, landlockEnabled)

		// Type-assert and set emitter on execve handler if configured
		var h *unixmon.ExecveHandler
		if execveHandler != nil {
			h, _ = execveHandler.(*unixmon.ExecveHandler)
			if h != nil {
				h.SetEmitter(emitter)
				// Register the wrapper as session root for depth tracking
				// The wrapper's exec will be the first command (depth 0)
				if wrapperPID > 0 {
					h.RegisterSession(wrapperPID, sessID)
				}

				// Create stub symlink for execve redirect
				stubPath, err := exec.LookPath("agentsh-stub")
				if err == nil {
					// Normalize to absolute path in case LookPath returns relative
					if !filepath.IsAbs(stubPath) {
						if abs, err := filepath.Abs(stubPath); err == nil {
							stubPath = abs
						}
					}
					unixmon.SetStubBinaryPath(stubPath)
					symlinkPath, cleanup, symlinkErr := unixmon.CreateStubSymlink(stubPath)
					if symlinkErr == nil {
						h.SetStubSymlinkPath(symlinkPath)
						defer cleanup()
					} else {
						slog.Warn("exec: failed to create stub symlink", "error", symlinkErr, "session_id", sessID)
					}
				} else {
					slog.Warn("exec: agentsh-stub not found, redirect will deny", "error", err, "session_id", sessID)
				}
			}
		}

		// Probe: verify ProcessVMReadv (or /proc/mem fallback) works against
		// the wrapper before starting. Catches Yama, missing CAP_SYS_PTRACE,
		// or other LSM restrictions at startup instead of on first notification.
		if wrapperPID > 0 {
			pvrErr, memErr := probeMemoryAccess(wrapperPID)
			if pvrErr != nil && memErr != nil {
				if fileHandler != nil || h != nil || pol != nil {
					slog.Error("seccomp notify: ProcessVMReadv and /proc/mem both failed — "+
						"handler cannot read tracee memory for path resolution",
						"wrapper_pid", wrapperPID,
						"pvr_error", pvrErr, "mem_error", memErr,
						"session_id", sessID,
						"hint", "check kernel.yama.ptrace_scope, ensure CAP_SYS_PTRACE, "+
							"or set sandbox.seccomp.file_monitor.enabled: false")
					return // Don't send ACK — wrapper fails with clear handshake error
				}
				slog.Warn("ProcessVMReadv probe failed, monitoring may be degraded",
					"wrapper_pid", wrapperPID, "pvr_error", pvrErr, "mem_error", memErr)
			} else if pvrErr != nil {
				// /proc/mem fallback works for file monitoring, but socket monitoring
				// uses ProcessVMReadv directly (ReadSockaddr has no /proc/mem fallback).
				if pol != nil {
					slog.Warn("ProcessVMReadv failed — socket monitoring will be degraded "+
						"(ReadSockaddr requires ProcessVMReadv), /proc/mem fallback works for file monitoring",
						"wrapper_pid", wrapperPID, "pvr_error", pvrErr)
				} else {
					slog.Debug("ProcessVMReadv failed but /proc/mem fallback works",
						"wrapper_pid", wrapperPID, "pvr_error", pvrErr)
				}
			}
		}

		// Send ACK to wrapper so it knows the notify handler is ready before exec.
		if _, err := parentSock.Write([]byte{1}); err != nil {
			slog.Debug("notify: ACK write to wrapper failed", "error", err, "session_id", sessID)
		}

		// Start ServeNotifyWithExecve BEFORE reading READY to ensure notifications
		// can be processed by the time the wrapper exec's after receiving GO.
		serveDone := make(chan struct{})
		go func() {
			defer close(serveDone)
			slog.Debug("starting ServeNotifyWithExecve", "session_id", sessID, "has_execve_handler", h != nil, "has_file_handler", fileHandler != nil, "has_policy", pol != nil)
			unixmon.ServeNotifyWithExecve(ctx, notifyFD, sessID, pol, emitter, h, fileHandler)
			slog.Debug("ServeNotifyWithExecve returned", "session_id", sessID)
		}()

		// If ptrace sync is enabled, read the READY byte from the wrapper
		// and signal the main goroutine that ptrace can now be attached.
		if ptraceReady != nil {
			// Use 30s timeout for READY (wrapper does signal filter + Landlock
			// setup after ACK). SO_RCVTIMEO is used instead of SetReadDeadline
			// because parentSock wraps a raw socketpair fd that isn't
			// registered with Go's netpoll, so deadlines are a silent no-op.
			readyTv := unix.NsecToTimeval((30 * time.Second).Nanoseconds())
			if err := unix.SetsockoptTimeval(int(parentSock.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &readyTv); err != nil {
				slog.Debug("failed to set SO_RCVTIMEO for READY read", "error", err, "session_id", sessID)
			}
			readyBuf := make([]byte, 1)
			// Retry on EINTR (signal interruption during read).
			var readyErr error
			for {
				_, readyErr = parentSock.Read(readyBuf)
				if readyErr != nil && errors.Is(readyErr, syscall.EINTR) {
					continue
				}
				break
			}
			// Clear SO_RCVTIMEO so it doesn't leak to any later reads.
			_ = unix.SetsockoptTimeval(int(parentSock.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{})
			if readyErr != nil {
				ptraceReady <- fmt.Errorf("read READY byte: %w", readyErr)
			} else if readyBuf[0] != 'R' {
				ptraceReady <- fmt.Errorf("unexpected READY byte: got 0x%02x, expected 'R'", readyBuf[0])
			} else {
				ptraceReady <- nil
			}
		}

		<-serveDone // wait for ServeNotifyWithExecve to finish
	}()
}
