package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// wrapInit handles POST /api/v1/sessions/{id}/wrap-init.
// It returns the seccomp wrapper configuration for the CLI to launch the agent
// through the wrapper, and starts listening for the notify fd on a Unix socket.
func (a *App) wrapInit(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	s, ok := a.sessions.Get(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	var req types.WrapInitRequest
	if ok := decodeJSON(w, r, &req, "invalid json"); !ok {
		return
	}

	resp, code, err := a.wrapInitCore(r.Context(), s, sessionID, req)
	if err != nil {
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, code, resp)
}

// wrapInitCore contains the core logic for wrap initialization.
// Exported for testing via the App struct.
func (a *App) wrapInitCore(ctx context.Context, s *session.Session, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, int, error) {
	// Only supported on Linux
	if runtime.GOOS != "linux" {
		return types.WrapInitResponse{}, http.StatusBadRequest, errWrapNotSupported
	}

	// Resolve wrapper binary
	wrapperBin := strings.TrimSpace(a.cfg.Sandbox.UnixSockets.WrapperBin)
	if wrapperBin == "" {
		wrapperBin = "agentsh-unixwrap"
	}

	// Resolve to absolute path
	wrapperPath, err := exec.LookPath(wrapperBin)
	if err != nil {
		return types.WrapInitResponse{}, http.StatusServiceUnavailable, errWrapperNotFound
	}

	// Resolve stub binary (optional, for redirect support)
	stubBin := "agentsh-stub"
	stubPath, _ := exec.LookPath(stubBin)

	// Build seccomp config
	execveEnabled := a.cfg.Sandbox.Seccomp.Execve.Enabled
	seccompCfg := seccompWrapperConfig{
		UnixSocketEnabled:   a.cfg.Sandbox.Seccomp.UnixSocket.Enabled,
		BlockedSyscalls:     a.cfg.Sandbox.Seccomp.Syscalls.Block,
		SignalFilterEnabled: false, // Signal filter not supported in wrap mode yet
		ExecveEnabled:       execveEnabled,
	}

	// Check if unix socket monitoring is enabled at all
	unixEnabled := a.cfg.Sandbox.UnixSockets.Enabled != nil && *a.cfg.Sandbox.UnixSockets.Enabled
	if unixEnabled {
		seccompCfg.UnixSocketEnabled = true
	}

	cfgJSON, err := json.Marshal(seccompCfg)
	if err != nil {
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}

	// Create a Unix listener socket for receiving the notify fd from the CLI.
	// The CLI will:
	// 1. Create a socketpair (parent/child)
	// 2. Pass child fd to agentsh-unixwrap as ExtraFile
	// 3. Receive the notify fd from unixwrap on the parent socket
	// 4. Connect to this listener and forward the notify fd
	notifySocketPath := filepath.Join(os.TempDir(), "agentsh-notify-"+sessionID+".sock")

	// Remove stale socket if it exists
	_ = os.Remove(notifySocketPath)

	listener, err := net.Listen("unix", notifySocketPath)
	if err != nil {
		return types.WrapInitResponse{}, http.StatusInternalServerError, err
	}

	// Start background goroutine to accept the notify fd connection
	go a.acceptNotifyFD(ctx, listener, notifySocketPath, sessionID, s, execveEnabled)

	// Emit wrap_init event
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "wrap_init",
		SessionID: sessionID,
		Fields: map[string]any{
			"wrapper_binary": wrapperPath,
			"agent_command":  req.AgentCommand,
			"agent_args":     req.AgentArgs,
			"notify_socket":  notifySocketPath,
		},
	}
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)

	return types.WrapInitResponse{
		WrapperBinary: wrapperPath,
		StubBinary:    stubPath,
		SeccompConfig: string(cfgJSON),
		NotifySocket:  notifySocketPath,
		WrapperEnv: map[string]string{
			"AGENTSH_SECCOMP_CONFIG": string(cfgJSON),
		},
	}, http.StatusOK, nil
}

// acceptNotifyFD listens on the Unix socket for a single connection from the CLI,
// receives the seccomp notify fd, and starts the notify handler.
func (a *App) acceptNotifyFD(ctx context.Context, listener net.Listener, socketPath string, sessionID string, s *session.Session, execveEnabled bool) {
	defer listener.Close()
	defer os.Remove(socketPath)

	// Set a timeout for accepting the connection
	if dl, ok := listener.(*net.UnixListener); ok {
		dl.SetDeadline(time.Now().Add(30 * time.Second))
	}

	conn, err := listener.Accept()
	if err != nil {
		slog.Debug("wrap: failed to accept notify connection", "session_id", sessionID, "error", err)
		return
	}
	defer conn.Close()

	// Receive the notify fd from the CLI via SCM_RIGHTS
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		slog.Debug("wrap: connection is not a Unix connection", "session_id", sessionID)
		return
	}

	file, err := unixConn.File()
	if err != nil {
		slog.Debug("wrap: failed to get file from connection", "session_id", sessionID, "error", err)
		return
	}

	// Use the existing RecvFD infrastructure to receive the notify fd
	notifyFD, err := recvFDFromConn(file)
	file.Close()
	if err != nil {
		slog.Debug("wrap: failed to receive notify fd", "session_id", sessionID, "error", err)
		return
	}
	if notifyFD == nil {
		slog.Debug("wrap: received nil notify fd", "session_id", sessionID)
		return
	}

	slog.Info("wrap: received notify fd", "session_id", sessionID, "fd", notifyFD.Fd())

	// Start the notify handler using existing infrastructure
	startNotifyHandlerForWrap(ctx, notifyFD, sessionID, a, execveEnabled)
}
