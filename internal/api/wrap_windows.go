//go:build windows

package api

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"time"

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

func startNotifyHandlerForWrap(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool) {
	// Not used on Windows — the driver handles exec interception directly.
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

	// Create the exec handler
	execHandler := winplat.NewWinExecHandler(nil, stubBinary)
	// TODO: Wire up policy checker when available

	// Set the suspended process handler
	dc.SetSuspendedProcessHandler(func(req *winplat.SuspendedProcessRequest) winplat.ExecDecision {
		decision := execHandler.HandleSuspended(req)
		if req == nil {
			return decision
		}

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
				if err := winplat.HandleRedirect(req, cfg); err != nil {
					slog.Error("wrap: redirect failed", "pid", req.ProcessId, "error", err)
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

	slog.Info("wrap: driver handler started", "session_id", sessionID)
	return nil
}
