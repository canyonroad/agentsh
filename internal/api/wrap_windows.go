//go:build windows

package api

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"

	winplat "github.com/agentsh/agentsh/internal/platform/windows"
)

var (
	errWrapNotSupported = errors.New("wrap requires the agentsh driver on Windows")
	errWrapperNotFound  = errors.New("agentsh-stub binary not found (agentsh-stub not in PATH)")
)

func recvFDFromConn(sock *os.File) (*os.File, error) {
	return nil, fmt.Errorf("SCM_RIGHTS not available on Windows")
}

func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int) {
	// Not used on Windows — the driver handles exec interception directly.
}

func getConnPeerPID(conn *net.UnixConn) int {
	return 0
}

func startSignalHandlerForWrap(ctx context.Context, signalFD *os.File, sessionID string, a *App) {
	if signalFD != nil {
		signalFD.Close()
	}
}

// winPolicyCheckerAdapter adapts policy.Engine to winplat.WinExecPolicyChecker.
type winPolicyCheckerAdapter struct {
	engine *policy.Engine
}

func (w *winPolicyCheckerAdapter) CheckCommand(cmd, cmdLine string) winplat.WinExecPolicyResult {
	// Parse the command line into args for the policy engine
	args := winplat.SplitCommandLine(cmdLine)

	// Normalize to basename without extension, matching how policies
	// reference commands (e.g., "cmd", "git", "powershell").
	command := filepath.Base(cmd)
	command = strings.TrimSuffix(command, filepath.Ext(command))
	if command == "" && len(args) > 0 {
		fallback := filepath.Base(args[0])
		command = strings.TrimSuffix(fallback, filepath.Ext(fallback))
	}

	// Drop arg0 to match other call sites (policy args patterns expect
	// arguments only, not the command repeated as first element).
	policyArgs := args
	if len(policyArgs) > 0 {
		policyArgs = policyArgs[1:]
	}

	dec := w.engine.CheckCommand(command, policyArgs)
	return winplat.WinExecPolicyResult{
		Decision:          string(dec.PolicyDecision),
		EffectiveDecision: string(dec.EffectiveDecision),
		Rule:              dec.Rule,
		Message:           dec.Message,
	}
}

// wrapInitWindows handles wrap initialization on Windows using driver-based exec interception.
func (a *App) wrapInitWindows(ctx context.Context, s *session.Session, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, int, error) {
	// Resolve stub binary
	stubBin := "agentsh-stub"
	stubPath, err := exec.LookPath(stubBin)
	if err != nil {
		return types.WrapInitResponse{}, http.StatusServiceUnavailable, errWrapperNotFound
	}

	// Generate a session token from the session ID (deterministic)
	h := sha256.Sum256([]byte(sessionID))
	sessionToken := binary.LittleEndian.Uint64(h[:8])

	// Start driver handler in the background
	if err := startDriverHandlerForWrap(ctx, sessionID, sessionToken, 0, stubPath, a); err != nil {
		return types.WrapInitResponse{}, http.StatusServiceUnavailable, fmt.Errorf("start driver handler: %w", err)
	}

	// Emit wrap_init event
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "wrap_init",
		SessionID: sessionID,
		Fields: map[string]any{
			"mechanism":     "driver",
			"stub_binary":   stubPath,
			"agent_command": req.AgentCommand,
			"agent_args":    req.AgentArgs,
		},
	}
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)

	// On Windows, no wrapper binary is needed — the driver intercepts system-wide.
	return types.WrapInitResponse{
		StubBinary: stubPath,
	}, http.StatusOK, nil
}

// startDriverHandlerForWrap connects to the agentsh driver, registers the session,
// and sets up the suspended process handler for exec interception.
func startDriverHandlerForWrap(ctx context.Context, sessionID string, sessionToken uint64, rootPID uint32, stubBinary string, a *App) error {
	dc := winplat.NewDriverClient()
	if err := dc.Connect(); err != nil {
		return fmt.Errorf("connect to driver: %w", err)
	}

	// Register the session with the driver
	if err := dc.RegisterSession(sessionToken, rootPID, ""); err != nil {
		dc.Disconnect()
		return fmt.Errorf("register session: %w", err)
	}

	// Create the policy checker adapter if a policy engine is available
	var checker winplat.WinExecPolicyChecker
	if a.policy != nil {
		checker = &winPolicyCheckerAdapter{engine: a.policy}
	}

	// Create the exec handler with the policy checker
	execHandler := winplat.NewWinExecHandler(checker, stubBinary)

	// Muted PID set: stub processes and their direct children are auto-resumed
	// to prevent infinite recursion when the driver re-intercepts stub-spawned commands.
	var mutedPIDs sync.Map // key: uint32, value: struct{}

	// Set the suspended process handler
	dc.SetSuspendedProcessHandler(func(req *winplat.SuspendedProcessRequest) winplat.ExecDecision {
		if req == nil {
			return winplat.ExecDecisionResume
		}

		// Recursion guard: auto-resume muted PIDs and their direct children
		if _, muted := mutedPIDs.Load(req.ProcessId); muted {
			slog.Debug("wrap: auto-resuming muted stub process", "pid", req.ProcessId)
			return winplat.ExecDecisionResume
		}
		if _, parentMuted := mutedPIDs.Load(req.ParentId); parentMuted {
			slog.Debug("wrap: auto-resuming child of muted stub", "pid", req.ProcessId, "parent", req.ParentId)
			// Remove parent mute after first child resumes to narrow the bypass
			// to only the single redirected command, not subsequent children.
			mutedPIDs.Delete(req.ParentId)
			return winplat.ExecDecisionResume
		}

		decision := execHandler.HandleSuspended(req)

		// Emit exec_intercept event for audit
		decisionStr := execDecisionString(decision)
		parsedArgs := winplat.SplitCommandLine(req.CommandLine)
		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: time.Now().UTC(),
			Type:      "exec_intercept",
			SessionID: sessionID,
			Fields: map[string]any{
				"pid":          req.ProcessId,
				"parent_pid":   req.ParentId,
				"image_path":   req.ImagePath,
				"command":      filepath.Base(req.ImagePath),
				"argv":         parsedArgs,
				"command_line": strings.TrimSpace(req.CommandLine),
				"decision":     decisionStr,
				"mechanism":    "driver",
			},
		}
		_ = a.store.AppendEvent(ctx, ev)
		a.broker.Publish(ev)

		switch decision {
		case winplat.ExecDecisionResume:
			if err := winplat.ResumeProcessByPID(req.ProcessId); err != nil {
				slog.Error("wrap: failed to resume process", "pid", req.ProcessId, "error", err)
			}
		case winplat.ExecDecisionTerminate:
			if err := winplat.TerminateProcessByPID(req.ProcessId, 1); err != nil {
				slog.Error("wrap: failed to terminate process", "pid", req.ProcessId, "error", err)
			}
		case winplat.ExecDecisionRedirect:
			go func() {
				cfg := winplat.RedirectConfig{
					StubBinary: stubBinary,
					SessionID:  sessionID,
				}
				var spawnedPID uint32
				if err := winplat.HandleRedirect(req, cfg, func(stubPID uint32) {
					spawnedPID = stubPID
					mutedPIDs.Store(stubPID, struct{}{})
					slog.Debug("wrap: muted stub PID", "stub_pid", stubPID)
				}); err != nil {
					slog.Error("wrap: redirect failed", "pid", req.ProcessId, "error", err)
				}
				// Clean up muted PID after stub exits to prevent unbounded growth
				if spawnedPID != 0 {
					mutedPIDs.Delete(spawnedPID)
				}
			}()
		}

		return decision
	})

	// Clean up when context is cancelled
	go func() {
		<-ctx.Done()
		dc.UnregisterSession(sessionToken)
		dc.Disconnect()
	}()

	slog.Info("wrap: driver handler started", "session_id", sessionID, "policy_enabled", checker != nil)
	return nil
}

// execDecisionString returns a human-readable string for an ExecDecision.
func execDecisionString(d winplat.ExecDecision) string {
	switch d {
	case winplat.ExecDecisionResume:
		return "allow"
	case winplat.ExecDecisionTerminate:
		return "deny"
	case winplat.ExecDecisionRedirect:
		return "redirect"
	default:
		return "unknown"
	}
}
