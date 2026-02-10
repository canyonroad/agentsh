//go:build linux && cgo

package api

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// recvFDTimeout is the timeout for receiving the notify fd from the wrapper.
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

// startNotifyHandler receives the seccomp notify fd from the parent socket and
// starts the ServeNotify handler in a goroutine. It returns immediately.
// The handler runs until ctx is cancelled or the fd is closed.
// If execveHandler is non-nil, uses ServeNotifyWithExecve for execve interception.
func startNotifyHandler(ctx context.Context, parentSock *os.File, sessID string, pol *policy.Engine, store eventStore, broker eventBroker, execveHandler any) {
	if parentSock == nil {
		return
	}

	// Run the entire receive and serve logic in a goroutine to return immediately
	go func() {
		defer parentSock.Close()
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

		// Set a read deadline to prevent blocking forever if wrapper fails.
		// Note: This may fail on some file types (e.g., socketpairs in Docker/containers),
		// but we should still continue and try to receive the FD. RecvFD will block until
		// it receives the FD or the socket is closed by the wrapper.
		if err := parentSock.SetReadDeadline(time.Now().Add(recvFDTimeout)); err != nil {
			slog.Debug("failed to set read deadline on notify socket (continuing)", "error", err)
			// Don't return - continue to RecvFD
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

		emitter := &notifyEmitterAdapter{store: store, broker: broker}

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
		slog.Debug("starting ServeNotifyWithExecve", "session_id", sessID, "has_execve_handler", h != nil, "has_policy", pol != nil)
		unixmon.ServeNotifyWithExecve(ctx, notifyFD, sessID, pol, emitter, h)
		slog.Debug("ServeNotifyWithExecve returned", "session_id", sessID)
	}()
}
